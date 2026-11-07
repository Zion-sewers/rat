"""Premortem gate battery for mcp-guard#27's fuzz gate.

``docs/spec.md`` documents 5 fuzzer failure modes. Each test below pins the
code mitigation for exactly one mode. The ``fuzz-gate`` CI job runs ONLY
this file (the matrix ``test`` job excludes it via
``--ignore=tests/test_premortem_gates.py``), so a green fuzz-gate means the
5 failure modes were actually exercised — not just the unit suite re-run.
"""

from __future__ import annotations

import io
import json
import time
from typing import Any

from mcp_guard.fuzzer import FuzzEngine, FuzzResult, ResultCategory
from mcp_guard.transport import StdioTransport

TOOL = {
    "name": "execute",
    "description": "Run a command",
    "inputSchema": {
        "type": "object",
        "properties": {"cmd": {"type": "string"}},
        "required": ["cmd"],
    },
}


class FakeTransport:
    """Deterministic in-process stand-in for an MCP server."""

    def __init__(self, crash: bool = False, reject_all: bool = False):
        self.calls: list[dict[str, Any]] = []
        self.crash = crash
        self.reject_all = reject_all

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        if self.crash:
            # The write happened before the death: the fault landed, the
            # server died on receipt. Record the send first, then raise.
            raise ConnectionError("Server crashed")
        if self.reject_all:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Invalid input rejected"}],
            }
        return {"content": [{"type": "text", "text": "ok"}]}

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


class _StubProc:
    """Minimal stand-in for subprocess.Popen[str] with canned stdout."""

    def __init__(self, stdout_text: str):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(stdout_text)

    def poll(self) -> None:
        return None


def _transport_with_stdout(stdout_text: str) -> tuple[StdioTransport, _StubProc]:
    t: StdioTransport = StdioTransport(["true"], timeout=5.0)
    proc = _StubProc(stdout_text)
    t._proc = proc  # type: ignore[assignment]
    return t, proc


def test_mode1_server_crash_does_not_kill_fuzzer() -> None:
    """Premortem mode 1: a payload crashes the server process.

    The fuzzer must record CRASH findings and keep going — the crash must
    never propagate out of fuzz_tool and kill the run.
    """
    engine = FuzzEngine(transport=FakeTransport(crash=True))
    results: list[FuzzResult] = engine.fuzz_tool(TOOL)
    assert len(results) > 0, "crashing server must still yield findings"
    assert all(r.category == ResultCategory.CRASH for r in results), (
        "every payload against a dead server must be classified CRASH, "
        f"got {[r.category for r in results]}"
    )


def test_mode2_rate_limit_delay_is_honored() -> None:
    """Premortem mode 2: aggressive fuzzing triggers server throttling.

    The --delay-ms mitigation must actually sleep between payloads.
    """
    transport = FakeTransport()
    engine = FuzzEngine(transport=transport, delay_ms=25)
    start = time.monotonic()
    engine.fuzz_tool(TOOL)
    elapsed = time.monotonic() - start
    calls = len(transport.calls)
    assert calls > 0
    assert elapsed >= calls * 0.025 * 0.8, (
        f"delay_ms=25 not honored: {calls} calls in {elapsed:.3f}s"
    )


def test_mode3_expected_errors_are_not_findings() -> None:
    """Premortem mode 3: a tool correctly rejects bad input with an error.

    Expected errors must classify SAFE — flagging them would drown real
    findings in false positives.
    """
    engine = FuzzEngine(transport=FakeTransport(reject_all=True))
    results = engine.fuzz_tool(TOOL)
    assert len(results) > 0
    assert all(r.category == ResultCategory.SAFE for r in results), (
        "expected-error responses must classify SAFE, not FINDING"
    )


def test_mode4_payload_ordering_is_deterministic() -> None:
    """Premortem mode 4: same payload, different results across runs.

    Payload ordering must be deterministic for a fixed tool schema so
    runs are reproducible and diffable.
    """
    first = [r.payload_value for r in FuzzEngine(FakeTransport()).fuzz_tool(TOOL)]
    second = [r.payload_value for r in FuzzEngine(FakeTransport()).fuzz_tool(TOOL)]
    assert first == second, "payload firing order must be deterministic"
    assert len(first) > 0


def test_mode5_unknown_protocol_fields_degrade_gracefully() -> None:
    """Premortem mode 5: MCP protocol version drift.

    Unknown future fields in a valid JSON-RPC response must be ignored,
    not crash the transport.
    """
    response = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"ok": True, "futureUnknownField": [1, 2, 3]},
        }
    )
    t, _ = _transport_with_stdout(response + "\n")
    result = t._read_response()
    assert result == {"ok": True, "futureUnknownField": [1, 2, 3]}


def test_mode5_protocol_version_is_pinned() -> None:
    """Premortem mode 5: the handshake pins a known protocol version.

    Drift mitigation starts with declaring exactly which version we speak.
    """
    init_response = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}})
    t, proc = _transport_with_stdout(init_response + "\n")
    t._initialize()
    sent = [json.loads(line) for line in proc.stdin.getvalue().splitlines()]
    initialize = next(m for m in sent if m.get("method") == "initialize")
    assert initialize["params"]["protocolVersion"] == "2024-11-05", (
        "handshake must pin the protocol version against drift"
    )
