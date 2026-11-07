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
- E6 (fix-forward): an exception path consults the same delivery check —
  a recorded send with a matching response id is ERROR with DELIVERED
  evidence; anything unconfirmed is INCONCLUSIVE.
- E7 (fix-forward): any ERROR probe withholds CLEAN at run level, so an
  all-ERROR run is INCONCLUSIVE with exit 1, never CLEAN with exit 0 — and
  errors sit above findings in verdict precedence, so one INFO finding
  cannot flip an error-dominated run back to a passing exit code.
- E8 (fix-forward): a malformed recorder entry degrades to UNKNOWN, never
  an exception; a dead server invalidates the recorder.
- E9 (fix-forward 2): `fuzz --help` renders (the flag help text is
  argparse-safe); the T2 override is recorded in SARIF too; the JSON
  summary carries an `errors` count asserted by `verify_counts`; the table
  has an ERRORS detail section; the override note prints only where T2
  was actually suppressed.
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


def test_missing_request_id_is_unknown_not_undelivered() -> None:
    """No request id means no correlation is possible — UNKNOWN, not a
    mismatch verdict, and never DELIVERED (not even for id 'None')."""
    env = _envelope()
    del env["id"]
    ev = verify_delivery(env, 1, "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNKNOWN
    ev = verify_delivery(env, "None", "echo", {"q": "x"})
    assert ev.status is DeliveryStatus.UNKNOWN


def test_non_dict_envelope_is_unknown_not_a_crash() -> None:
    """A malformed recorder entry must never abort the verification — or
    the run. UNKNOWN degrades to INCONCLUSIVE downstream."""
    ev = verify_send(["not", "a", "dict"], "echo", {"q": "x"})  # type: ignore[arg-type]
    assert ev.status is DeliveryStatus.UNKNOWN
    ev = verify_delivery("not-a-dict", 1, "echo", {"q": "x"})  # type: ignore[arg-type]
    assert ev.status is DeliveryStatus.UNKNOWN


def test_json_distinct_values_are_not_equal() -> None:
    """Type-confusion payloads exist to distinguish these: JSON `1` vs
    `true` vs `1.0` must not verify as the same delivered argument."""
    assert (
        verify_send(_envelope(args={"q": 1}), "echo", {"q": True}).status
        is DeliveryStatus.UNDELIVERED
    )
    assert (
        verify_send(_envelope(args={"q": 1}), "echo", {"q": 1.0}).status
        is DeliveryStatus.UNDELIVERED
    )
    assert (
        verify_send(_envelope(args={"q": 0}), "echo", {"q": False}).status
        is DeliveryStatus.UNDELIVERED
    )
    assert (
        verify_send(_envelope(args={"q": 1}), "echo", {"q": 1}).status is DeliveryStatus.DELIVERED
    )


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
    """Raises without recording anything: the fault never went out."""

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("boom")


class _ErrorAfterSendTransport(_RecordingTransport):
    """Records the send, then raises: the fault landed, the transport
    failed afterwards (e.g. a JSON-RPC error response)."""

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        raise RuntimeError("MCP error: {'code': -32602, 'message': 'Invalid params'}")


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


def test_error_after_recorded_send_keeps_error_with_confirmed_delivery() -> None:
    """The fault landed (recorded send + matching response id) and the
    transport failed afterwards: ERROR, but with DELIVERED evidence — the
    probe is an error outcome, not an unconfirmed one."""
    results = FuzzEngine(transport=_ErrorAfterSendTransport()).fuzz_tool(_TOOL)
    assert results
    assert all(r.category is ResultCategory.ERROR for r in results)
    assert all(r.delivery is DeliveryStatus.DELIVERED for r in results)


def test_exception_without_delivery_evidence_is_inconclusive() -> None:
    """Fix-forward for the B1 hole: an exception with no recorded send is
    not an ERROR to count — it is a probe with no verdict."""
    results = FuzzEngine(transport=_ExplodingTransport()).fuzz_tool(_TOOL)
    assert results
    assert all(r.category is ResultCategory.INCONCLUSIVE for r in results)
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
    detail: str = "",
) -> FuzzResult:
    return FuzzResult(
        tool_name="echo",
        probe_name="q",
        payload_value="x",
        category=category,
        rule_id="r",
        severity=severity,
        detail=detail,
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


def test_all_error_run_withholds_clean() -> None:
    """Fix-forward B1: a run whose probes all errored has no verdict about
    any tool — it is INCONCLUSIVE, never CLEAN, even with delivery
    confirmed. The fault landed; what the tool did with it is unknown."""
    results = [
        _result(ResultCategory.ERROR, DeliveryStatus.DELIVERED, severity="high"),
        _result(ResultCategory.ERROR, DeliveryStatus.DELIVERED, severity="high"),
    ]
    assert _report(results).verdict == "INCONCLUSIVE"


def test_error_with_unconfirmed_delivery_withholds_clean() -> None:
    results = [_result(ResultCategory.SAFE)] + [
        _result(ResultCategory.ERROR, DeliveryStatus.UNKNOWN, severity="high")
    ]
    assert _report(results).verdict == "INCONCLUSIVE"


def test_errors_withhold_clean_even_with_findings() -> None:
    """Fix-forward 2 (B2): errors sit above findings in verdict precedence.
    One INFO finding must not flip an error-dominated run back to a passing
    exit code — but the finding is still listed, only the label yields."""
    results = [_result(ResultCategory.FINDING, severity="high")] + [
        _result(ResultCategory.ERROR, DeliveryStatus.DELIVERED, severity="high")
    ]
    assert _report(results).verdict == "INCONCLUSIVE"
    buf = io.StringIO()
    _report(results).to_json(buf)
    data = json.loads(buf.getvalue())
    assert len(data["results"]) == 2  # the finding is still reported
    assert data["summary"]["errors"] == 1


def test_crashes_still_beat_inconclusive() -> None:
    results = [_result(ResultCategory.CRASH, severity="critical")] + [
        _result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN)
    ]
    assert _report(results).verdict == "VULNERABLE"


def test_by_severity_counts_verdicts_only() -> None:
    """INCONCLUSIVE/ERROR severities describe the attack payload, not a
    verdict — they must not appear in the findings histogram."""
    report = _report(
        [
            _result(ResultCategory.FINDING, severity="high"),
            _result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN, severity="critical"),
            _result(ResultCategory.ERROR, DeliveryStatus.UNKNOWN, severity="critical"),
        ]
    )
    buf = io.StringIO()
    report.to_json(buf)
    assert json.loads(buf.getvalue())["summary"]["by_severity"] == {"high": 1}


def test_verify_counts_covers_inconclusive_and_delivery() -> None:
    report = _report(
        [
            _result(ResultCategory.SAFE),
            _result(ResultCategory.INCONCLUSIVE, DeliveryStatus.UNKNOWN),
            _result(ResultCategory.FINDING, severity="high"),
            _result(ResultCategory.ERROR, DeliveryStatus.UNKNOWN, severity="high"),
        ]
    )
    report.verify_counts()  # must not raise
    assert report.delivery_summary() == {"delivered": 2, "undelivered": 0, "unknown": 2}
    assert len(report.inconclusive) == 1
    assert len(report.errors) == 1
    buf = io.StringIO()
    report.to_json(buf)
    assert json.loads(buf.getvalue())["summary"]["errors"] == 1


def test_table_has_errors_detail_section() -> None:
    buf = io.StringIO()
    _report(
        [
            _result(
                ResultCategory.ERROR,
                DeliveryStatus.DELIVERED,
                severity="high",
                detail="Unexpected exception: boom",
            )
        ]
    ).to_table(buf)
    text = buf.getvalue()
    assert "Errors:" in text
    assert "ERRORS" in text
    assert "Unexpected exception: boom" in text


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
    assert data["summary"]["errors"] == 0
    assert data["summary"]["delivery"] == {"delivered": 0, "undelivered": 0, "unknown": 2}
    assert data["summary"]["twyman_audit"]["triggered"] is True
    assert data["summary"]["verdict"] == "INCONCLUSIVE"
    assert data["summary"]["twyman_audit"]["allow_empty_error_responses"] is False
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
    assert "Errors:" in text
    assert "Delivery:" in text


def test_sarif_records_inconclusive_as_note() -> None:
    """SARIF keeps the per-probe story: inconclusive probes are note-level
    results under a dedicated rule, never warnings, never dropped."""
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
    sarif_results = data["runs"][0]["results"]
    assert len(sarif_results) == 2
    note = [r for r in sarif_results if r["level"] == "note"]
    assert len(note) == 1
    assert note[0]["ruleId"] == "fault-delivery-unconfirmed"
    assert any(
        rule["id"] == "fault-delivery-unconfirmed"
        for rule in data["runs"][0]["tool"]["driver"]["rules"]
    )


def test_sarif_error_probes_use_probe_error_rule() -> None:
    """ERROR probes are not findings: they get their own rule id so a
    SARIF consumer never reads 'no verdict' probes as findings."""
    buf = io.StringIO()
    _report(
        [
            _result(
                ResultCategory.ERROR,
                DeliveryStatus.DELIVERED,
                severity="high",
                detail="Unexpected exception: boom",
            ),
            _result(ResultCategory.FINDING, severity="high"),
        ]
    ).to_sarif(buf)
    data = json.loads(buf.getvalue())
    sarif_results = data["runs"][0]["results"]
    assert len(sarif_results) == 2
    probe_errors = [r for r in sarif_results if r["ruleId"] == "probe-error"]
    assert len(probe_errors) == 1
    assert "Unexpected exception: boom" in probe_errors[0]["message"]["text"]
    findings = [r for r in sarif_results if r["ruleId"] == "r"]
    assert len(findings) == 1
    props = data["runs"][0]["properties"]
    assert props["mcp-guard.errors"] == "1"


def test_sarif_records_t2_override() -> None:
    report = _report([_result(ResultCategory.SAFE, preview="")])
    report.allow_empty_error_responses = True
    buf = io.StringIO()
    report.to_sarif(buf)
    props = json.loads(buf.getvalue())["runs"][0]["properties"]
    assert props["mcp-guard.allow_empty_error_responses"] == "True"
    assert props["mcp-guard.verdict"] == "CLEAN"


def test_override_note_prints_only_where_t2_was_suppressed() -> None:
    """The override note is claimed only where it did something: on the
    silent-validator run it prints; on a FINDINGS run it must not."""
    silent = _report([_result(ResultCategory.SAFE, preview="")])
    silent.allow_empty_error_responses = True
    buf = io.StringIO()
    silent.to_table(buf)
    assert "--allow-empty-error-responses" in buf.getvalue()

    findings = _report([_result(ResultCategory.FINDING, severity="high")])
    findings.allow_empty_error_responses = True
    buf = io.StringIO()
    findings.to_table(buf)
    assert "--allow-empty-error-responses" not in buf.getvalue()


# --- End-to-end: real StdioTransport + real fake MCP server -------------------

_FAKE_SERVER = """\
import json, sys

mode = sys.argv[1]
calls = 0
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
        calls += 1
        if mode == "wrong-id":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": 9999,
                "result": {"isError": True,
                "content": [{"type": "text", "text": "nope"}]}}) + "\\n")
            sys.stdout.flush()
            continue
        if mode == "rpc-error" or (mode == "flaky" and calls == 1):
            # Protocol-layer rejection of the call, id-correlated: the
            # fault reached the server, but no tool verdict exists.
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32602, "message": "Invalid params"}}) + "\\n")
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


def test_fuzz_help_renders() -> None:
    """Fix-forward 2 (B1): the flag help text contains a literal percent
    sign, which argparse would %-format into a ValueError. The help surface
    is the flag's discovery surface — it must render."""
    with pytest.raises(SystemExit) as exc:
        main(["fuzz", "--help"])
    assert exc.value.code == 0


def test_e2e_rpc_error_on_every_call_is_inconclusive_not_clean(fake_server) -> None:
    """Fix-forward B1, end to end: the server answers every call with a
    JSON-RPC error. The faults landed (id-correlated), but no tool verdict
    exists — INCONCLUSIVE, exit 1, never CLEAN."""
    with pytest.raises(SystemExit) as exc:
        main(["fuzz", "--", sys.executable, fake_server, "rpc-error"])
    assert exc.value.code == 1


def test_e2e_flaky_first_call_error_with_findings_is_inconclusive(fake_server) -> None:
    """Fix-forward 2 (B2), end to end: one errored probe among findings.
    The verdict is INCONCLUSIVE and the exit code is 1 — one INFO finding
    must not flip an error-containing run back to a passing exit code."""
    with pytest.raises(SystemExit) as exc:
        main(["fuzz", "--format", "json", "--", sys.executable, fake_server, "flaky"])
    assert exc.value.code == 1


def test_e2e_silent_validator_with_override_exits_clean(fake_server, capsys) -> None:
    """The audit has a defined completion: an operator who knows the server
    is a terse validator passes --allow-empty-error-responses, and the
    override is recorded, not silent."""
    assert (
        main(["fuzz", "--allow-empty-error-responses", "--", sys.executable, fake_server, "silent"])
        is None
    )
    assert "VERDICT: CLEAN" in capsys.readouterr().out


def test_dead_server_invalidates_flight_recorder() -> None:
    """A send that never happens must not leave the previous call's
    envelope standing in for it: after the death the recorder is empty."""
    import io as _io

    from mcp_guard.transport import StdioTransport

    class _StubProc:
        """Alive for the first exchange, dead afterwards."""

        def __init__(self) -> None:
            self.stdin = _io.StringIO()
            self.stdout = _io.StringIO('{"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}\n')
            self._alive = True

        def poll(self):
            return None if self._alive else 0

    proc = _StubProc()
    transport = StdioTransport(["true"], timeout=5.0)
    transport._proc = proc  # type: ignore[assignment]
    transport.call_tool("echo", {"q": "x"})
    assert transport.last_exchange()[0] is not None
    proc._alive = False
    with pytest.raises(ConnectionError):
        transport.call_tool("echo", {"q": "y"})
    assert transport.last_exchange() == (None, None)
