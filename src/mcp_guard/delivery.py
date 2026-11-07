"""Twyman-law fault-delivery verification (mcp-guard#65).

Source (established): Kohavi, Tang & Xu, *Trustworthy Online Controlled
Experiments* (2020), ch. 18 (Twyman's law — any figure that looks interesting
or different is usually wrong; most extreme results are instrumentation,
data-loss, or computation errors) and ch. 21 (telemetry fidelity as a
trust-related guardrail metric: independent fidelity metrics, e.g. dual
logging, as standing guardrails; assert-like checks built into the
experimentation system).

Adaptation: every fuzz probe is an experiment whose treatment is the injected
payload. A verdict of "fault tolerated" (SAFE) is meaningless if the payload
never actually landed — the exact failure mode Twyman's law predicts: an
interesting-looking success that is really an instrumentation miss. The
mapping: fault-delivery evidence is mcp-guard's telemetry-fidelity guardrail.
The independent channel is the transport's flight recorder — the exact
JSON-RPC envelope written to the server — correlated with the response id.
A probe without confirmed delivery is INCONCLUSIVE, never SAFE.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class DeliveryStatus(Enum):
    """Was the injected fault confirmed to reach the target tool?"""

    DELIVERED = "delivered"
    UNDELIVERED = "undelivered"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DeliveryEvidence:
    """The independent-channel verdict for one fired payload."""

    status: DeliveryStatus
    request_id: int | None = None
    response_id: Any = None
    detail: str = ""


def verify_send(
    envelope: dict[str, Any] | None,
    tool_name: str,
    arguments: dict[str, Any],
) -> DeliveryEvidence:
    """Did the transport write this exact call to the server?

    Checks only the send side (flight-recorder envelope vs intended call).
    Used on the crash path, where no response exists to correlate: a server
    that died *after* the write was hit by the fault (CRASH); a server that
    was already dead before the write never received it (INCONCLUSIVE, not
    a phantom CRASH).
    """
    if envelope is None:
        return DeliveryEvidence(
            status=DeliveryStatus.UNKNOWN,
            detail="no flight-recorder entry: the transport did not record the send",
        )
    if envelope.get("method") != "tools/call":
        return DeliveryEvidence(
            status=DeliveryStatus.UNDELIVERED,
            request_id=envelope.get("id"),
            detail=f"flight recorder shows method {envelope.get('method')!r}, not 'tools/call'",
        )
    params = envelope.get("params")
    if not isinstance(params, dict):
        return DeliveryEvidence(
            status=DeliveryStatus.UNDELIVERED,
            request_id=envelope.get("id"),
            detail="flight-recorder envelope has no params object",
        )
    if params.get("name") != tool_name:
        return DeliveryEvidence(
            status=DeliveryStatus.UNDELIVERED,
            request_id=envelope.get("id"),
            detail=(
                f"flight recorder shows tool {params.get('name')!r} called, expected {tool_name!r}"
            ),
        )
    if params.get("arguments") != arguments:
        return DeliveryEvidence(
            status=DeliveryStatus.UNDELIVERED,
            request_id=envelope.get("id"),
            detail="sent arguments differ from the intended payload",
        )
    return DeliveryEvidence(
        status=DeliveryStatus.DELIVERED,
        request_id=envelope.get("id"),
        detail="flight recorder confirms the exact call was written",
    )


def verify_delivery(
    envelope: dict[str, Any] | None,
    response_id: Any,
    tool_name: str,
    arguments: dict[str, Any],
) -> DeliveryEvidence:
    """Full delivery check: send confirmed AND response correlated to it.

    The response id must match the request id (compared as strings: JSON-RPC
    ids may be numbers or strings across servers). A present-but-mismatched
    id is UNDELIVERED — a stale or replayed response attributed to the wrong
    payload. A missing response id is UNKNOWN — correlation is unverifiable,
    which is not the same as confirmed.
    """
    send = verify_send(envelope, tool_name, arguments)
    if send.status is not DeliveryStatus.DELIVERED:
        return send
    if response_id is None:
        return DeliveryEvidence(
            status=DeliveryStatus.UNKNOWN,
            request_id=send.request_id,
            detail="response carries no id: request/response correlation unverifiable",
        )
    if str(response_id) != str(send.request_id):
        return DeliveryEvidence(
            status=DeliveryStatus.UNDELIVERED,
            request_id=send.request_id,
            response_id=response_id,
            detail=(
                f"response id {response_id!r} does not match request id "
                f"{send.request_id!r}: stale or replayed response"
            ),
        )
    return DeliveryEvidence(
        status=DeliveryStatus.DELIVERED,
        request_id=send.request_id,
        response_id=response_id,
        detail="flight recorder + response id agree: fault delivered",
    )
