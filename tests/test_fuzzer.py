"""RED: Failing tests for fuzz engine core."""

import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_guard.delivery import DeliveryStatus
from mcp_guard.fuzzer import FuzzEngine, FuzzResult, ResultCategory
from mcp_guard.transport import StdioTransport


class FakeTransport:
    """Simulates an MCP server for testing the fuzz engine."""

    def __init__(self, responses=None, reject_all=False):
        self.calls: list[dict] = []
        self.responses = responses or {}
        self.crashed = False
        self.reject_all = reject_all

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        if self.crashed:
            raise ConnectionError("Server crashed")
        if self.reject_all:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Invalid input rejected"}],
            }
        key = f"{tool_name}:{sorted(arguments.items())}"
        return self.responses.get(key, {"content": [{"type": "text", "text": "ok"}]})

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        """Flight recorder: exact envelope of the last call + its response id."""
        if not self.calls:
            return None, None
        last = self.calls[-1]
        return (
            {
                "jsonrpc": "2.0",
                "id": len(self.calls),
                "method": "tools/call",
                "params": {"name": last["tool"], "arguments": last["arguments"]},
            },
            len(self.calls),
        )


def test_fuzzer_enumerates_and_fuzzes_single_tool():
    """FuzzEngine should accept a tool schema, generate payloads, fire them."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "execute",
        "description": "Run a command",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    }

    results = engine.fuzz_tool(tool)
    assert len(results) > 0, "Fuzzer must produce results"
    assert all(isinstance(r, FuzzResult) for r in results)
    assert len(transport.calls) > 0, "Fuzzer must have called the tool"


def test_fuzzer_detects_crash():
    """When server crashes mid-fuzz, fuzzer must detect it."""
    transport = FakeTransport()
    transport.crashed = True
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "fragile",
        "description": "Crashes easily",
        "inputSchema": {
            "type": "object",
            "properties": {"input": {"type": "string"}},
            "required": ["input"],
        },
    }

    results = engine.fuzz_tool(tool)
    crash_results = [r for r in results if r.category == ResultCategory.CRASH]
    assert len(crash_results) > 0, "Must detect server crash"


def test_fuzzer_classifies_expected_errors_as_safe():
    """A clean error response (e.g. validation rejection) should be SAFE, not a finding."""
    transport = FakeTransport(reject_all=True)
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "safe_tool",
        "description": "Safely rejects bad input",
        "inputSchema": {
            "type": "object",
            "properties": {"input": {"type": "string"}},
            "required": ["input"],
        },
    }

    results = engine.fuzz_tool(tool)
    findings = [r for r in results if r.category != ResultCategory.SAFE]
    assert len(findings) == 0, "Expected errors should be classified as SAFE"


def test_fuzz_result_has_reproduction_info():
    """Every FuzzResult must include enough info to reproduce."""
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)

    tool = {
        "name": "test",
        "description": "Test tool",
        "inputSchema": {
            "type": "object",
            "properties": {"x": {"type": "string"}},
            "required": ["x"],
        },
    }

    results = engine.fuzz_tool(tool)
    for r in results:
        assert r.tool_name == "test"
        assert hasattr(r, "payload_value")
        assert r.probe_name != ""


def test_delay_ms_throttles_payload_delivery():
    """--delay-ms was accepted and stored but never slept (dead flag).
    Every fired payload must pause for the configured delay."""
    import time as time_module

    sleeps: list[float] = []
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport, delay_ms=50)

    tool = {"name": "slow", "inputSchema": {}}
    real_sleep = time_module.sleep
    try:
        time_module.sleep = sleeps.append  # type: ignore[method-assign]
        results = engine.fuzz_tool(tool)
    finally:
        time_module.sleep = real_sleep

    assert len(sleeps) == len(results) == len(transport.calls), (
        "one delay per fired payload, regardless of composition"
    )
    assert all(s == 0.05 for s in sleeps), f"delay must equal delay_ms/1000: {sleeps[:3]}"


def test_delay_ms_zero_means_no_sleep():
    """Default delay_ms=0 must not sleep at all."""
    import time as time_module

    transport = FakeTransport()
    engine = FuzzEngine(transport=transport)
    real_sleep = time_module.sleep
    slept = False
    try:

        def _spy(s: float) -> None:
            nonlocal slept
            slept = True

        time_module.sleep = _spy  # type: ignore[method-assign]
        engine.fuzz_tool({"name": "fast", "inputSchema": {}})
    finally:
        time_module.sleep = real_sleep
    assert not slept, "delay_ms=0 must never sleep"


FAKE_SERVER_NON_OBJECT_CALL_RESULT = (
    "import json, sys\n"
    "\n"
    "def send(obj):\n"
    "    sys.stdout.write(json.dumps(obj) + chr(10))\n"
    "    sys.stdout.flush()\n"
    "\n"
    "for line in sys.stdin:\n"
    "    try:\n"
    "        req = json.loads(line)\n"
    "    except json.JSONDecodeError:\n"
    "        continue\n"
    "    method = req.get('method')\n"
    "    rid = req.get('id')\n"
    "    if method == 'initialize':\n"
    "        send({'jsonrpc': '2.0', 'id': rid, 'result': {'protocolVersion': '2024-11-05'}})\n"
    "    elif method == 'tools/list':\n"
    "        send({'jsonrpc': '2.0', 'id': rid, 'result': {'tools': []}})\n"
    "    elif method == 'tools/call':\n"
    "        send({'jsonrpc': '2.0', 'id': rid, 'result': 'not-an-object'})\n"
)


def _bad_call_server(tmp_path: Path) -> Path:
    server = tmp_path / "bad_call_server.py"
    server.write_text(FAKE_SERVER_NON_OBJECT_CALL_RESULT)
    return server


def test_call_tool_non_object_result_raises_connection_error(tmp_path: Path):
    """Arch round-5 B1: a tools/call whose result is not an object fails
    closed as ConnectionError at the transport chokepoint, never as an
    AttributeError in a consumer."""
    server = _bad_call_server(tmp_path)
    with (
        StdioTransport([sys.executable, str(server)]) as transport,
        pytest.raises(ConnectionError, match="malformed"),
    ):
        transport.call_tool("echo", {"x": "1"})


def test_fuzzer_classifies_non_object_call_result_instead_of_crashing(tmp_path: Path):
    """Arch round-5 B1: the fuzz run completes with a classified report
    (CRASH + DELIVERED per probe) instead of dying mid-run on
    AttributeError in _classify_response."""
    server = _bad_call_server(tmp_path)
    with StdioTransport([sys.executable, str(server)]) as transport:
        engine = FuzzEngine(transport=transport)
        tool = {
            "name": "echo",
            "description": "echo",
            "inputSchema": {
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "required": ["x"],
            },
        }
        results = engine.fuzz_tool(tool)
    assert len(results) > 0
    assert all(r.category is ResultCategory.CRASH for r in results)
    assert all(r.delivery is DeliveryStatus.DELIVERED for r in results)
