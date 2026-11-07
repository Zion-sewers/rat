"""Adversarial tests for the evidence-graded classifier (mcp-guard#107).

The false-positive factory: _classify_response's old default branch flagged
"Payload accepted without error" as FINDING with the payload's severity —
20 CRITICAL shell-injection findings on agentgate's dict-lookup demo server
(2026-10-02 cross-repo run), which has no shell, no SQL, no execution sink.
Severity must follow observed evidence, not the payload's potential.
"""

from typing import Any

from mcp_guard.fuzzer import FuzzEngine, ResultCategory, _payload_reflected


def _exchange(calls: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, Any]:
    """Flight recorder shared by the test doubles: exact envelope of the
    last call + its response id (mcp-guard#65)."""
    if not calls:
        return None, None
    last = calls[-1]
    return (
        {
            "jsonrpc": "2.0",
            "id": len(calls),
            "method": "tools/call",
            "params": {"name": last["tool"], "arguments": last["arguments"]},
        },
        len(calls),
    )


class EchoLookupTransport:
    """Simulates agentgate's demo server: pure dict lookup, echoes input
    verbatim inside a benign 'not found' message. No execution sink."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        sku = next(iter(arguments.values()))
        return {"content": [{"type": "text", "text": f"sku {sku}: not found"}]}

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        return _exchange(self.calls)


class NeutralTransport:
    """Swallows every payload with 'ok'. No reflection, no error, no leak."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"content": [{"type": "text", "text": "ok"}]}

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        return _exchange(self.calls)


_LOOKUP_TOOL = {
    "name": "inventory_lookup",
    "description": "Look up warehouse stock",
    "inputSchema": {
        "type": "object",
        "properties": {"sku": {"type": "string"}},
        "required": ["sku"],
    },
}


def test_benign_echo_is_not_critical_shell_injection():
    """The exact cross-repo failure: dict-lookup echo drew 20 CRITICALs."""
    engine = FuzzEngine(transport=EchoLookupTransport())
    results = engine.fuzz_tool(_LOOKUP_TOOL)
    assert len(results) > 0
    critical_shell = [
        r for r in results if r.rule_id.startswith("shell-injection") and r.severity == "critical"
    ]
    assert not critical_shell, f"false positives: {[r.payload_value for r in critical_shell][:3]}"


def test_reflection_is_still_recorded_not_hidden():
    """Downgrading is not deleting: the reflection must remain a FINDING,
    graded medium (unconfirmed), so the signal isn't lost."""
    engine = FuzzEngine(transport=EchoLookupTransport())
    results = engine.fuzz_tool(_LOOKUP_TOOL)
    reflected = [r for r in results if "unconfirmed-reflection" in r.rule_id]
    assert len(reflected) > 0, "reflection signal must be preserved"
    assert all(r.category == ResultCategory.FINDING for r in reflected)
    shell_reflected = [r for r in reflected if r.rule_id.startswith("shell-injection")]
    assert shell_reflected, "shell payloads were reflected in the echo"
    assert all(r.severity == "medium" for r in shell_reflected)


def test_neutralized_payload_is_info_finding_not_silent_safe():
    """No reflection, no error, no leak: the safe direction of error for a
    security fuzzer is to keep it VISIBLE. Silent execution is
    observationally identical to neutralization — resolving that as SAFE
    would let a CLEAN verdict overclaim. INFO: filterable, not wolf-crying."""
    engine = FuzzEngine(transport=NeutralTransport())
    results = engine.fuzz_tool(_LOOKUP_TOOL)
    assert len(results) > 0
    for r in results:
        assert r.category == ResultCategory.FINDING
        assert r.severity == "info"
        assert "no-observable-effect" in r.rule_id
    above_info = [r for r in results if r.severity not in ("info",)]
    assert not above_info, "neutralized payloads must never exceed INFO"


def test_reflection_helper_edge_cases():
    assert _payload_reflected("'; rm -rf /'", "sku '; rm -rf /': not found")
    assert _payload_reflected("longtoken123", "xxlongtoken123xx")
    assert not _payload_reflected("'; rm -rf /'", "ok")
    assert not _payload_reflected("", "anything")
    # short payloads: coincidence is indistinguishable from reflection
    assert not _payload_reflected("abc", "xxabcxx")
    assert not _payload_reflected("0", "count: 10")
