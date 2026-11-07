"""Fuzz engine — orchestrates adversarial payload delivery to MCP tools."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .delivery import DeliveryEvidence, DeliveryStatus, verify_delivery, verify_send
from .payloads import INDIRECT_CANARY, Payload, Severity, generate_all_for_param

# Markdown image pointing at an external URL inside a tool *output*: the
# exfiltration channel of the EchoLeak (CVE-2025-32711) pattern.
_EXFIL_MD_RE = re.compile(r"!\[[^\]]*\]\(\s*https?://", re.IGNORECASE)


def _payload_reflected(payload_value: object, text: str) -> bool:
    """Did attacker-controlled bytes reach the tool output?

    Checks the payload verbatim and quote-stripped (servers often echo
    inside their own quoting). Payloads shorter than 6 chars are never
    flagged: for a 1-char payload coincidence is indistinguishable from
    reflection (e.g. payload "0" matching "count: 10"), so not flagging is
    the evidence-graded behavior.
    """
    s = str(payload_value)
    if len(s) < 6:
        return False
    if s in text:
        return True
    stripped = s.strip("'\"")
    return stripped in text


class ResultCategory(Enum):
    SAFE = "safe"
    FINDING = "finding"
    CRASH = "crash"
    ERROR = "error"
    # Twyman's law (mcp-guard#65): the fault was not confirmed delivered, so
    # the probe has no verdict. INCONCLUSIVE is never counted as a pass.
    INCONCLUSIVE = "inconclusive"


@dataclass
class FuzzResult:
    tool_name: str
    probe_name: str
    payload_value: object
    category: ResultCategory
    rule_id: str
    severity: str
    detail: str = ""
    response_preview: str = ""
    # Fault-delivery evidence (mcp-guard#65): confirmed on the transport's
    # flight recorder, independent of the response channel. UNKNOWN is the
    # fail-closed default — a result built without evidence never counts as
    # a confirmed delivery.
    delivery: DeliveryStatus = DeliveryStatus.UNKNOWN
    delivery_detail: str = ""


class Transport(Protocol):
    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        """Flight recorder (mcp-guard#65): the exact JSON-RPC envelope of the
        most recent tools/call send, plus the id of its response (None when
        no response arrived). The independent channel for fault-delivery
        verification — a transport that cannot prove delivery cannot produce
        a SAFE verdict.

        Deliberate split: the seam is required here (new transports must
        implement it) but the engine reads it leniently via getattr (see
        `_flight_recorder`): transports written before the seam degrade to
        UNKNOWN delivery instead of raising, so an old double fails closed
        rather than crashing the run. Implementations must invalidate the
        recorded exchange when a send never happens (e.g. the server is
        already dead), so a stale envelope can never stand in for a call
        that was never sent."""
        ...


class FuzzEngine:
    def __init__(self, transport: Transport, delay_ms: int = 0):
        self._transport = transport
        self._delay_ms = delay_ms

    def fuzz_tool(self, tool: dict[str, Any]) -> list[FuzzResult]:
        tool_name = tool.get("name", "unknown")
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        if not properties:
            return self._fuzz_no_schema(tool_name)

        results: list[FuzzResult] = []
        for param_name, param_schema in properties.items():
            payloads = generate_all_for_param(param_name, param_schema)
            for payload in payloads:
                result = self._fire_payload(tool_name, param_name, payload, required)
                results.append(result)

        return results

    def _fuzz_no_schema(self, tool_name: str) -> list[FuzzResult]:
        from .payloads import (
            generate_overflow,
            generate_prompt_injection,
            generate_shell_injection,
            generate_ssrf,
        )

        all_payloads = (
            generate_shell_injection()
            + generate_ssrf()
            + generate_overflow()[:2]
            + generate_prompt_injection()
        )
        results: list[FuzzResult] = []
        for payload in all_payloads:
            result = self._fire_payload(tool_name, payload.rule_id, payload, set())
            results.append(result)
        return results

    def _flight_recorder(self) -> tuple[dict[str, Any] | None, Any, str | None]:
        """The transport's flight recorder for the just-fired call.

        Returns (envelope, response_id, recorder_error): (None, None, None)
        when the transport exposes no recorder; recorder_error names the
        exception type when the recorder raised or returned a malformed
        value. Any failure degrades to UNKNOWN delivery (fail-closed), never
        aborts the run — but the cause is carried in the detail string, not
        swallowed silently.
        """
        last_exchange = getattr(self._transport, "last_exchange", None)
        if last_exchange is None:
            return None, None, None
        try:
            envelope, response_id = last_exchange()
        except Exception as exc:  # noqa: BLE001 — any recorder failure is UNKNOWN
            return None, None, type(exc).__name__
        return envelope, response_id, None

    def _delivery_evidence(self, tool_name: str, arguments: dict[str, Any]) -> DeliveryEvidence:
        """Full delivery check for the just-fired call (send + correlation)."""
        envelope, response_id, recorder_error = self._flight_recorder()
        if recorder_error is not None:
            return DeliveryEvidence(
                status=DeliveryStatus.UNKNOWN,
                detail=f"flight recorder raised {recorder_error}: delivery unverifiable",
            )
        if (
            envelope is None
            and response_id is None
            and getattr(self._transport, "last_exchange", None) is None
        ):
            return DeliveryEvidence(
                status=DeliveryStatus.UNKNOWN,
                detail="transport exposes no flight recorder: delivery unverifiable",
            )
        return verify_delivery(envelope, response_id, tool_name, arguments)

    def _inconclusive(
        self,
        tool_name: str,
        param_name: str,
        payload: Payload,
        evidence: DeliveryEvidence,
    ) -> FuzzResult:
        """A probe without confirmed fault delivery has no verdict (mcp-guard#65).

        It is discarded as inconclusive — never counted as passed, never
        hidden: the rule id and severity are kept so the gap stays visible.
        """
        return FuzzResult(
            tool_name=tool_name,
            probe_name=param_name,
            payload_value=payload.value,
            category=ResultCategory.INCONCLUSIVE,
            rule_id=payload.rule_id,
            severity=payload.severity.value,
            detail=f"Fault delivery unconfirmed — no verdict: {evidence.detail}",
            delivery=evidence.status,
            delivery_detail=evidence.detail,
        )

    def _fire_payload(
        self, tool_name: str, param_name: str, payload: Payload, required: set[str]
    ) -> FuzzResult:
        args: dict[str, Any] = {param_name: payload.value}
        if self._delay_ms > 0:
            time.sleep(self._delay_ms / 1000.0)
        try:
            response = self._transport.call_tool(tool_name, args)
        except ConnectionError:
            # The server died. Confirm the fault actually went out first:
            # a payload written before the death is a genuine CRASH; a
            # server already dead before the write never received it, so the
            # probe is INCONCLUSIVE — one real crash must not manufacture
            # phantom CRASH findings for every unfired payload.
            envelope, _, _ = self._flight_recorder()
            send = verify_send(envelope, tool_name, args)
            if send.status is DeliveryStatus.DELIVERED:
                return FuzzResult(
                    tool_name=tool_name,
                    probe_name=param_name,
                    payload_value=payload.value,
                    category=ResultCategory.CRASH,
                    rule_id=payload.rule_id,
                    severity=payload.severity.value,
                    detail="Server crashed or connection lost after payload",
                    delivery=DeliveryStatus.DELIVERED,
                    delivery_detail=send.detail,
                )
            return self._inconclusive(tool_name, param_name, payload, send)
        except Exception as exc:  # noqa: BLE001
            # The transport failed (JSON-RPC error response, timeout, ...).
            # Route through the same delivery check as the success path:
            # a recorded send with a matching response id is a delivered
            # fault with an error outcome (ERROR + DELIVERED); anything
            # unconfirmed is INCONCLUSIVE — an errored probe is not a pass.
            evidence = self._delivery_evidence(tool_name, args)
            if evidence.status is DeliveryStatus.DELIVERED:
                return FuzzResult(
                    tool_name=tool_name,
                    probe_name=param_name,
                    payload_value=payload.value,
                    category=ResultCategory.ERROR,
                    rule_id=payload.rule_id,
                    severity=payload.severity.value,
                    detail=f"Unexpected exception: {exc}",
                    delivery=DeliveryStatus.DELIVERED,
                    delivery_detail=evidence.detail,
                )
            return self._inconclusive(tool_name, param_name, payload, evidence)

        evidence = self._delivery_evidence(tool_name, args)
        if evidence.status is not DeliveryStatus.DELIVERED:
            return self._inconclusive(tool_name, param_name, payload, evidence)

        result = self._classify_response(tool_name, param_name, payload, response)
        result.delivery = evidence.status
        result.delivery_detail = evidence.detail
        return result

    def _classify_response(
        self,
        tool_name: str,
        param_name: str,
        payload: Payload,
        response: dict[str, Any],
    ) -> FuzzResult:
        is_error = response.get("isError", False)
        content = response.get("content", [])
        text = ""
        if content and isinstance(content, list):
            text = " ".join(c.get("text", "") for c in content if isinstance(c, dict))

        if is_error:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.SAFE,
                rule_id=payload.rule_id,
                severity=payload.severity.value,
                detail="Server rejected payload (expected error)",
                response_preview=text[:200],
            )

        text_lower = text.lower()

        # Indirect prompt injection (OWASP ASI01): the server reflected our
        # canary-bearing probe into its tool *output*. A downstream agent
        # reading that output receives attacker-shaped "instructions" on the
        # data channel — the seed of goal hijack. Checked only for
        # indirect-injection probes so normal input echo is not flagged.
        if payload.rule_id == "indirect-injection" and INDIRECT_CANARY in text:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id="reflection-untrusted-echo",
                severity="high",
                detail=(
                    "Server reflected attacker-controlled input into tool output — "
                    "seed for indirect prompt injection (OWASP ASI01)"
                ),
                response_preview=text[:200],
            )

        # Exfil-shaped channel in tool output (EchoLeak pattern): a markdown
        # image to an external URL gives injected content a way to phone home.
        if payload.rule_id == "indirect-injection" and _EXFIL_MD_RE.search(text):
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id="indirect-injection-exfil-channel",
                severity="critical",
                detail="Tool output contains markdown image to external URL — exfil channel",
                response_preview=text[:200],
            )

        leaked = any(
            kw in text_lower
            for kw in (
                "traceback",
                "exception",
                "stack trace",
                "error:",
                "internal",
                "password",
                "secret",
                "token",
            )
        )
        if leaked:
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id=f"{payload.rule_id}-info-leak",
                severity="high",
                detail=f"Payload accepted, response leaks internal info: {text[:100]}",
                response_preview=text[:200],
            )

        # Evidence-graded default (mcp-guard#107): severity follows what we
        # OBSERVED, not the payload's potential. Cross-repo evidence
        # (mcp-guard vs agentgate demo server, 2026-10-02): a pure dict lookup
        # that echoes input in a "not found" message drew 20 CRITICAL
        # shell-injection findings — there is no shell. A fuzzer that cries
        # critical on zero evidence drowns real findings in noise.
        if _payload_reflected(payload.value, text):
            if payload.rule_id in ("prompt-injection", "indirect-injection"):
                # The reflection IS the attack: a downstream agent reads
                # these instructions on the data channel.
                severity = payload.severity.value
            else:
                # Execution-class payload (shell/sqli/...): reflection is
                # not execution. Unconfirmed — medium, never critical.
                severity = Severity.MEDIUM.value
            return FuzzResult(
                tool_name=tool_name,
                probe_name=param_name,
                payload_value=payload.value,
                category=ResultCategory.FINDING,
                rule_id=f"{payload.rule_id}-unconfirmed-reflection",
                severity=severity,
                detail=(
                    "Payload reflected in tool output without execution "
                    "evidence. For prompt-injection payloads the reflection "
                    "itself reaches a downstream agent; for execution-class "
                    "payloads this is unconfirmed."
                ),
                response_preview=text[:200],
            )
        # Deliberately FINDING (not SAFE) at INFO: for a pre-deployment
        # security fuzzer the safe direction of error is non-negotiable. A
        # silently-executed payload is observationally identical to a
        # neutralized one; resolving that ambiguity as SAFE would let the
        # CLI's CLEAN verdict assert safety it cannot verify. INFO keeps it
        # visible and filterable without crying wolf.
        return FuzzResult(
            tool_name=tool_name,
            probe_name=param_name,
            payload_value=payload.value,
            category=ResultCategory.FINDING,
            rule_id=f"{payload.rule_id}-no-observable-effect",
            severity=Severity.INFO.value,
            detail=(
                "Payload produced no observable effect: not reflected, no "
                "error, no leak. Silent execution cannot be ruled out by "
                "black-box probing alone — informational, not a clean bill."
            ),
            response_preview=text[:200],
        )
