"""Red-team battery for indirect prompt injection via tool outputs (OWASP ASI01).

Wired into CI through the standard pytest run. Each test drives the real
FuzzEngine against a mock transport — no live network, no model calls.
"""

from typing import Any

from mcp_guard.fuzzer import FuzzEngine, ResultCategory
from mcp_guard.payloads import INDIRECT_CANARY, generate_indirect_injection


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


class EchoTransport:
    """Mock MCP server that reflects attacker input into its tool output."""

    def __init__(self, transform=None):
        self.transform = transform or (lambda v: f"Result: {v}")
        self.calls: list[dict[str, Any]] = []

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        echoed = " ".join(str(v) for v in arguments.values())
        return {"content": [{"type": "text", "text": self.transform(echoed)}]}

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        return _exchange(self.calls)


class CleanTransport:
    """Mock MCP server that never reflects input."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"content": [{"type": "text", "text": "done"}]}

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        return _exchange(self.calls)


class RejectTransport:
    """Mock MCP server that rejects everything with an error."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"isError": True, "content": [{"type": "text", "text": "invalid input"}]}

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        return _exchange(self.calls)


_TOOL = {
    "name": "read_doc",
    "description": "Read a document",
    "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
}


def _reflection_findings(results):
    return [r for r in results if r.rule_id == "reflection-untrusted-echo"]


def test_probes_all_carry_canary():
    probes = generate_indirect_injection()
    assert len(probes) >= 3
    assert all(p.rule_id == "indirect-injection" for p in probes)
    assert all(INDIRECT_CANARY in str(p.value) for p in probes)


def test_reflecting_server_flagged():
    engine = FuzzEngine(transport=EchoTransport())
    findings = _reflection_findings(engine.fuzz_tool(_TOOL))
    assert findings, "reflecting server must be flagged for indirect injection"
    assert all(f.category == ResultCategory.FINDING for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_clean_server_not_flagged():
    engine = FuzzEngine(transport=CleanTransport())
    assert _reflection_findings(engine.fuzz_tool(_TOOL)) == []


def test_rejecting_server_not_flagged():
    engine = FuzzEngine(transport=RejectTransport())
    assert _reflection_findings(engine.fuzz_tool(_TOOL)) == []


def test_exfil_channel_detected_even_without_canary():
    """Server strips the canary but keeps the exfil URL: still a finding."""

    def strip_canary(echoed: str) -> str:
        return echoed.replace(INDIRECT_CANARY, "[redacted]")

    engine = FuzzEngine(transport=EchoTransport(transform=strip_canary))
    exfil = [r for r in engine.fuzz_tool(_TOOL) if r.rule_id == "indirect-injection-exfil-channel"]
    assert exfil, "exfil-shaped markdown in tool output must be flagged"
    assert all(f.severity == "critical" for f in exfil)


def test_finding_detail_names_owasp_category():
    engine = FuzzEngine(transport=EchoTransport())
    findings = _reflection_findings(engine.fuzz_tool(_TOOL))
    assert any("ASI01" in f.detail for f in findings)
