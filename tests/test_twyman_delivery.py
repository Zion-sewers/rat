"""Adversarial tests for Twyman-law fault-delivery verification (mcp-guard#65).

Kohavi ch.18/21 (established): surprising results are instrumentation bugs
first. Adaptation: every fuzz probe is an experiment whose treatment is the
injected payload. The fault-delivery evidence is the transport's flight
recorder (the exact JSON-RPC envelope written) correlated with the response
id — an independent channel from the response content itself.

Enforcement rows (this file IS the enforcement row: mcp-guard has no
agentgate-style anatomy/E-row registry, so the executable tests + the
verify_counts + CI gates are the enforcement, not prose):
- E1: a probe whose envelope/id do not check out is INCONCLUSIVE, never SAFE.
- E2: a transport with no flight recorder cannot produce a SAFE verdict.
- E3: a crash after a recorded send is CRASH; a server already dead before
  the send yields INCONCLUSIVE, never a phantom CRASH.
- E4: a 100% SAFE run with incomplete delivery evidence, or with zero bytes
  of response text, triggers the Twyman audit and withholds CLEAN.
- E5: a 100% SAFE run with full delivery and varied error text does NOT
  trigger: that is a real validator, not a surprising result.
"""

from __future__ import annotations

import io
import json
import sys
from typing import Any

import pytest

from mcp_guard.cli import main
from mcp_guard.delivery import (
    DeliveryStatus,
    verify_delivery,
    verify_send,
)
from mcp_guard.fuzzer import FuzzEngine, FuzzResult, ResultCategory
from mcp_guard.report import FuzzReport, twyman_audit

_TOOL = {
    "name": "echo",
    "description": "Echo input",
    "inputSchema": {
        "type": "object",
        "properties": {"q": {"type": "string"}},
        "required": ["q"],
    },
}


def _envelope(tool: str = "echo", args: dict | None = None, rid: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args or {"q": "x"}},
    }


# --- verify_delivery / verify_send -------------------------------------------


def test_matching_envelope_and_id_is_delivered() -> None:
    ev = verify_delivery(_envelope(), 1, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.DELIVERED


def test_string_and_int_ids_correlate() -> None:
    """JSON-RPC ids may be numbers or strings across servers; compare as str."""
    ev = verify_delivery(_envelope(rid=3), "3", "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.DELIVERED


def test_mismatched_response_id_is_undelivered() -> None:
    """A stale or replayed response attributed to the wrong payload."""
    ev = verify_delivery(_envelope(rid=1), 9999, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNDELIVERED
    assert "9999" in ev.detail and "1" in ev.detail


def test_wrong_tool_is_undelivered() -> None:
    ev = verify_delivery(_envelope(tool="other"), 1, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNDELIVERED


def test_mutated_arguments_are_undelivered() -> None:
    ev = verify_delivery(_envelope(args={"q": "y"}), 1, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNDELIVERED


def test_wrong_method_is_undelivered() -> None:
    env = _envelope()
    env["method"] = "tools/list"
    ev = verify_delivery(env, 1, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNDELIVERED


def test_missing_envelope_is_unknown_not_delivered() -> None:
    ev = verify_delivery(None, 1, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNKNOWN


def test_missing_response_id_is_unknown_not_delivered() -> None:
    """A response without an id cannot be correlated: unverifiable, not proof."""
    ev = verify_delivery(_envelope(), None, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNKNOWN


def test_verify_send_checks_the_write_not_the_response() -> None:
    assert verify_send(_envelope(), "echo", {"q": "x"}).status is DeliveryStatus.DELIVERED
    assert verify_send(None, "echo", {"q": "x"}).status is DeliveryStatus.UNKNOWN
    assert (
        verify_send(_envelope(tool="other"), "echo", {"q": "x"}).status
        is DeliveryStatus.UNDELIVERED
    )


# --- Engine: fail-closed delivery --------------------------------------------


class _RecordingTransport:
    """Test double with a correct flight recorder."""

    def __init__(self, respond_id: Any = "match", reject_all: bool = True):
        self.calls: list[dict[str, Any]] = []
        self.respond_id = respond_id
        self.reject_all = reject_all

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        if self.reject_all:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "invalid input"}],
            }
        return {"content": [{"type": "text", "text": "ok"}]}

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
        if not self.calls:
            return None, None
        last = self.calls[-1]
        rid = len(self.calls)
        return (
            {
                "jsonrpc": "2.0",
                "id": rid,
                "method": "tools/call",
                "params": {"name": last["tool"], "arguments": last["arguments"]},
            },
            rid if self.respond_id == "match" else self.respond_id,
        )


class _NoRecorderTransport:
    """A transport that cannot prove delivery: no flight recorder at all."""

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"isError": True, "content": [{"type": "text", "text": "invalid input"}]}


class _CrashTransport:
    """Dies on receipt (records the send first) or was already dead."""

    def __init__(self, record_before_raise: bool):
        self.calls: list[dict[str, Any]] = []
        self.record_before_raise = record_before_raise

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.record_before_raise:
            self.calls.append({"tool": tool_name, "arguments": arguments})
        raise ConnectionError("Server crashed")

    def last_exchange(self) -> tuple[dict[str, Any] | None, Any]:
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


class _ExplodingTransport(_RecordingTransport):
    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("boom")


def test_confirmed_delivery_keeps_safe_verdict() -> None:
    results = FuzzEngine(transport=_RecordingTransport()).fuzz_tool(_TOOL)
    assert results, "reject-all server must yield results"
    assert all(r.category is ResultCategory.SAFE for r in results)
    assert all(r.delivery is DeliveryStatus.DELIVERED for r in results)


def test_mismatched_response_id_is_inconclusive_never_safe() -> None:
    """The exact Twyman failure: a stale response must not become a pass."""
    results = FuzzEngine(transport=_RecordingTransport(respond_id=9999)).fuzz_tool(_TOOL)
    assert results
    assert all(r.category is ResultCategory.INCONCLUSIVE for r in results)
    assert all(r.delivery is DeliveryStatus.UNDELIVERED for r in results)
    assert not any(r.category is ResultCategory.SAFE for r in results)


def test_no_recorder_is_inconclusive_never_safe() -> None:
    results = FuzzEngine(transport=_NoRecorderTransport()).fuzz_tool(_TOOL)
    assert results
    assert all(r.category is ResultCategory.INCONCLUSIVE for r in results)
    assert all(r.delivery is DeliveryStatus.UNKNOWN for r in results)


def test_crash_after_recorded_send_is_crash() -> None:
    results = FuzzEngine(transport=_CrashTransport(record_before_raise=True)).fuzz_tool(_TOOL)
    assert results
    assert all(r.category is ResultCategory.CRASH for r in results)
    assert all(r.delivery is DeliveryStatus.DELIVERED for r in results)


def test_server_already_dead_is_inconclusive_not_phantom_crash() -> None:
    """One real crash must not manufacture phantom CRASH findings for every
    unfired payload: a send that never happened has no verdict."""
    results = FuzzEngine(transport=_CrashTransport(record_before_raise=False)).fuzz_tool(_TOOL)
    assert results
    assert all(r.category is ResultCategory.INCONCLUSIVE for r in results)
    assert not any(r.category is ResultCategory.CRASH for r in results)


def test_unexpected_exception_is_error_with_unknown_delivery() -> None:
    results = FuzzEngine(transport=_ExplodingTransport()).fuzz_tool(_TOOL)
    assert results
    assert all(r.category is ResultCategory.ERROR for r in results)
    assert all(r.delivery is DeliveryStatus.UNKNOWN for r in results)


def test_classified_results_carry_delivery_evidence() -> None:
    """FINDING results are stamped with the delivery proof, not left UNKNOWN."""
    results = FuzzEngine(transport=_RecordingTransport(reject_all=False)).fuzz_tool(_TOOL)
    findings = [r for r in results if r.category is ResultCategory.FINDING]
    assert findings
    assert all(r.delivery is DeliveryStatus.DELIVERED for r in findings)


# --- Twyman audit + report verdict -------------------------------------------


def _result(
    category: ResultCategory,
    delivery: DeliveryStatus = DeliveryStatus.DELIVERED,
    preview: str = "invalid input",
    severity: str = "info",
) -> FuzzResult:
    return FuzzResult(
        tool_name="echo",
        probe_name="q",
        payload_value="x",
        category=category,
        rule_id="r",
        severity=severity,
        response_preview=preview,
        delivery=delivery,
    )


def _report(results: list[FuzzResult]) -> FuzzReport:
    tools = len({r.tool_name for r in results}) or 1
    return FuzzReport(
        server_command="fake",
        tools_fuzzed=tools,
        total_payloads=len(results),
        results=results,
    )


def test_twyman_triggers_on_perfect_pass_rate_with_unconfirmed_delivery() -> None:
    results = [_result(ResultCategory.SAFE, DeliveryStatus.UNKNOWN) for _ in range(5)]
    audit = twyman_audit(results)
    assert audit.triggered
    assert audit.safe_rate == 1.0
    assert _report(results).verdict == "INCONCLUSIVE"


def test_twyman_triggers_on_perfect_pass_rate_with_empty_responses() -> None:
    results = [_result(ResultCategory.SAFE, preview="") for _ in range(5)]
    assert twyman_audit(results).triggered
    assert _report(results).verdict == "INCONCLUSIVE"


def test_twyman_does_not_trigger_on_real_validator() -> None:
    """Negative control: full delivery + varied error text is a real
    validator, not a surprising result. CLEAN is earned, not assumed."""
    results = [_result(ResultCategory.SAFE, preview=f"rejected: reason {i}") for i in range(5)]
    assert not twyman_audit(results).triggered
    assert _report(results).verdict == "CLEAN"


def test_twyman_does_not_trigger_when_findings_exist() -> None:
    results = [_result(ResultCategory.SAFE) for _ in range(4)] + [
        _result(ResultCategory.FINDING, severity="info")
    ]
    assert not twyman_audit(results).triggered
    assert _report(results).verdict == "FINDINGS"


def test_twyman_empty_run_does_not_trigger() -> None:
    assert not twyman_audit([]).triggered


def test_inconclusive_beats_findings_in_verdict_precedence() -> None:
    results = [_result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN)] + [
        _result(ResultCategory.FINDING, severity="high")
    ]
    assert _report(results).verdict == "INCONCLUSIVE"


def test_crashes_still_beat_inconclusive() -> None:
    results = [_result(ResultCategory.CRASH, severity="critical")] + [
        _result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN)
    ]
    assert _report(results).verdict == "VULNERABLE"


def test_verify_counts_covers_inconclusive_and_delivery() -> None:
    report = _report(
        [
            _result(ResultCategory.SAFE),
            _result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN),
            _result(ResultCategory.FINDING, severity="high"),
        ]
    )
    report.verify_counts()  # must not raise
    assert report.delivery_summary() == {"delivered": 2, "undelivered": 0, "unknown": 1}
    assert len(report.inconclusive) == 1


def test_json_carries_delivery_and_twyman_audit() -> None:
    # 100% SAFE with zero confirmed deliveries: T1 triggers, verdict is
    # INCONCLUSIVE even though no probe is individually inconclusive.
    buf = io.StringIO()
    _report(
        [
            _result(ResultCategory.SAFE, DeliveryStatus.UNKNOWN),
            _result(ResultCategory.SAFE, DeliveryStatus.UNKNOWN),
        ]
    ).to_json(buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["inconclusive"] == 0
    assert data["summary"]["delivery"] == {"delivered": 0, "undelivered": 0, "unknown": 2}
    assert data["summary"]["twyman_audit"]["triggered"] is True
    assert data["summary"]["verdict"] == "INCONCLUSIVE"
    assert data["results"] == []  # SAFE results stay out of the JSON array
    assert data["summary"]["twyman_audit"]["safe_rate"] == 1.0


def test_json_inconclusive_results_carry_delivery_fields() -> None:
    buf = io.StringIO()
    _report([_result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN)]).to_json(buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["inconclusive"] == 1
    assert data["results"][0]["category"] == "inconclusive"
    assert data["results"][0]["delivery"] == "unknown"
    assert "delivery_detail" in data["results"][0]


def test_table_prints_inconclusive_verdict() -> None:
    buf = io.StringIO()
    _report([_result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN)]).to_table(buf)
    text = buf.getvalue()
    assert "VERDICT: INCONCLUSIVE" in text
    assert "Inconclusive:" in text
    assert "Delivery:" in text


def test_sarif_skips_inconclusive_but_records_verdict() -> None:
    buf = io.StringIO()
    _report(
        [
            _result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN),
            _result(ResultCategory.FINDING, severity="high"),
        ]
    ).to_sarif(buf)
    data = json.loads(buf.getvalue())
    props = data["runs"][0]["properties"]
    assert props["mcp-guard.verdict"] == "INCONCLUSIVE"
    assert props["mcp-guard.inconclusive"] == "1"
    assert len(data["runs"][0]["results"]) == 1  # only the FINDING


# --- End-to-end: real StdioTransport + real fake MCP server -------------------

_FAKE_SERVER = """\
import json, sys

mode = sys.argv[1]
for line in sys.stdin:
    try:
        req = json.loads(line)
    except Exception:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {},
                  "serverInfo": {"name": "fake", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "inputSchema": {"type": "object",
                  "properties": {"q": {"type": "string"}}}}]}
    elif method == "tools/call":
        if mode == "wrong-id":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": 9999,
                "result": {"isError": True,
                "content": [{"type": "text", "text": "nope"}]}}) + "\\n")
            sys.stdout.flush()
            continue
        text = "" if mode == "silent" else "invalid input"
        result = {"isError": True, "content": [{"type": "text", "text": text}]}
    else:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                 "result": result}) + "\\n")
    sys.stdout.flush()
"""


@pytest.fixture
def fake_server(tmp_path):
    path = tmp_path / "fake_server.py"
    path.write_text(_FAKE_SERVER, encoding="utf-8")
    return str(path)


def test_e2e_honest_validator_exits_clean(fake_server, capsys) -> None:
    """Real transport, real subprocess: matching ids + error text -> CLEAN.
    main() returns normally (no sys.exit) on a clean run."""
    assert main(["fuzz", "--", sys.executable, fake_server, "good"]) is None
    assert "VERDICT: CLEAN" in capsys.readouterr().out


def test_e2e_stale_response_ids_exit_inconclusive(fake_server) -> None:
    """Real transport, real subprocess: the server answers every call with
    id 9999. The fault-delivery check catches the mismatch on the
    independent channel -> INCONCLUSIVE, exit 1, never CLEAN."""
    with pytest.raises(SystemExit) as exc:
        main(["fuzz", "--", sys.executable, fake_server, "wrong-id"])
    assert exc.value.code == 1


def test_e2e_silent_validator_triggers_twyman_audit(fake_server) -> None:
    """Real transport, real subprocess: 100% SAFE with zero bytes of
    response text -> Twyman audit withholds CLEAN, exit 1."""
    with pytest.raises(SystemExit) as exc:
        main(["fuzz", "--", sys.executable, fake_server, "silent"])
    assert exc.value.code == 1
