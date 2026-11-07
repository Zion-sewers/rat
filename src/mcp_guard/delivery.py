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

import json
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
    # JSON-RPC ids may be numbers or strings across servers; Any is the
    # honest type here, not a shortcut.
    request_id: Any = None
    response_id: Any = None
    detail: str = ""


def _json_equal(a: Any, b: Any) -> bool:
    """Strict JSON equality: Python `==` conflates values JSON distinguishes
    (`1 == True`, `0 == False`, `1.0 == 1`), and type-confusion payloads
    exist precisely to distinguish them. Canonical JSON dumps separate all
    three; non-serializable values fall back to `==`."""
    try:
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    except (TypeError, ValueError):
        return bool(a == b)


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

    The envelope proves the local write; only the response-id correlation in
    `verify_delivery` proves the server answered. A malformed recorder entry
    (not a dict) is UNKNOWN, never an exception: the check must never crash
    on the malformed input it exists to catch.
    """
    if not isinstance(envelope, dict):
        return DeliveryEvidence(
            status=DeliveryStatus.UNKNOWN,
            detail="flight-recorder entry is not an object: delivery unverifiable",
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
    if not _json_equal(params.get("arguments"), arguments):
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
    payload. A missing id on either side is UNKNOWN — correlation is
    unverifiable, which is not the same as confirmed.
    """
    send = verify_send(envelope, tool_name, arguments)
    if send.status is not DeliveryStatus.DELIVERED:
        return send
    if send.request_id is None:
        return DeliveryEvidence(
            status=DeliveryStatus.UNKNOWN,
            detail="request carried no id: request/response correlation unverifiable",
        )
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
