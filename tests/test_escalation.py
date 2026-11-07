"""Rule-of-two escalation + PII pseudonymization before any output (rat #69).

Every test here is behavioral: an escalated call without a second approval
must never reach the server, and no raw PII may appear in any emitted
report byte. PII fixtures use example.com / 555 numbers / the standard
Luhn-passing test card / +972-50 synthetic numbers so no real personal
data appears anywhere.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_guard.escalation import (
    EscalationRequiredError,
    InputTrust,
    SecondApproval,
    evaluate_rule_of_two,
    scrub_for_output,
)
from mcp_guard.fuzzer import FuzzResult, ResultCategory
from mcp_guard.gateway import (
    AuditKind,
    Gateway,
    GatewayPolicy,
    PiiTokenizer,
    TrustDeniedError,
    TrustLevel,
)
from mcp_guard.lifecycle import Lifecycle, ServerRegistry, ServerSpec
from mcp_guard.report import FuzzReport
from mcp_guard.transport import JsonDict

REPO_ROOT = Path(__file__).resolve().parent.parent

EMAIL = "jane.doe@example.com"
PHONE = "555-123-4567"
IL_PHONE = "+972-50-123-4567"
SSN = "123-45-6789"
CARD = "4111-1111-1111-1111"  # Luhn-passing test number
# Synthetic fixture, never a real key: built from parts so the repo's
# secret-scan does not trip on a test constant.
API_KEY = "sk-" + "test" * 5


class FakeTransport:
    """Records every send; answers canned tool results."""

    def __init__(self, results: dict[str, dict] | None = None) -> None:
        self.calls: list[dict] = []
        self.results = results or {}
        self._id = 0

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        self._id += 1
        return self.results.get(tool_name, {"content": [{"type": "text", "text": "ok"}]})

    def last_exchange(self) -> tuple[dict | None, object]:
        if not self.calls:
            return None, None
        last = self.calls[-1]
        return (
            {
                "jsonrpc": "2.0",
                "id": self._id,
                "method": "tools/call",
                "params": {"name": last["tool"], "arguments": last["arguments"]},
            },
            self._id,
        )


def _policy() -> GatewayPolicy:
    return GatewayPolicy(
        tools={
            "read_record": TrustLevel.HIGH,
            "delete_record": TrustLevel.HIGH,
            "search": TrustLevel.MEDIUM,
        },
        mutating_tools=frozenset({"delete_record"}),
        default_trust=TrustLevel.LOW,
    )


APPROVAL = SecondApproval(approver="dana", reason="verified ticket #12")


# --- rule-of-two evaluation: the 8-factor truth table -----------------------


@pytest.mark.parametrize(
    ("target", "input_trust", "mutating", "triggered"),
    [
        (TrustLevel.HIGH, InputTrust.UNTRUSTED, True, True),
        (TrustLevel.HIGH, InputTrust.UNTRUSTED, False, False),
        (TrustLevel.HIGH, InputTrust.TRUSTED, True, False),
        (TrustLevel.HIGH, InputTrust.TRUSTED, False, False),
        (TrustLevel.MEDIUM, InputTrust.UNTRUSTED, True, False),
        (TrustLevel.MEDIUM, InputTrust.TRUSTED, True, False),
        (TrustLevel.LOW, InputTrust.UNTRUSTED, True, False),
        (TrustLevel.LOW, InputTrust.TRUSTED, False, False),
    ],
)
def test_rule_of_two_truth_table(
    target: TrustLevel, input_trust: InputTrust, mutating: bool, triggered: bool
) -> None:
    decision = evaluate_rule_of_two(target, input_trust, mutating)
    assert decision.triggered is triggered
    assert decision.sensitive is (target is TrustLevel.HIGH)
    assert decision.untrusted_input is (input_trust is InputTrust.UNTRUSTED)
    assert decision.mutating is mutating


def test_rule_of_two_reasons_name_factors_never_content() -> None:
    decision = evaluate_rule_of_two(TrustLevel.HIGH, InputTrust.UNTRUSTED, True)
    assert decision.reasons == (
        "sensitive tool (high trust)",
        "untrusted input",
        "state mutation",
    )


# --- gateway enforcement -----------------------------------------------------


def test_escalated_call_without_approval_never_sends() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(EscalationRequiredError) as exc:
        gateway.call_tool("delete_record", {"id": "7"}, TrustLevel.HIGH, InputTrust.UNTRUSTED)
    assert "second approval" in str(exc.value)
    assert transport.calls == [], "escalated call reached the server"
    assert gateway.last_exchange() == (None, None), "denied call left a flight record"
    kinds = [e.kind for e in gateway.audit_log.events()]
    assert kinds == [AuditKind.ESCALATION_REQUIRED]


def test_undeclared_input_is_untrusted_not_trusted() -> None:
    """Omitting input_trust must not dodge escalation: the default is UNTRUSTED."""
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(EscalationRequiredError):
        gateway.call_tool("delete_record", {"id": "7"}, TrustLevel.HIGH)
    assert transport.calls == []


def test_escalated_call_with_approval_sends_and_audits_approver() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    result = gateway.call_tool(
        "delete_record", {"id": "7"}, TrustLevel.HIGH, InputTrust.UNTRUSTED, APPROVAL
    )
    assert transport.calls == [{"tool": "delete_record", "arguments": {"id": "7"}}]
    assert result == {"content": [{"type": "text", "text": "ok"}]}
    approved = [e for e in gateway.audit_log.events() if e.kind is AuditKind.ESCALATION_APPROVED]
    assert len(approved) == 1
    assert approved[0].approver == "dana"
    assert approved[0].to_dict()["approver"] == "dana"
    # The reason text is never recorded (operator free text could carry content).
    assert "verified ticket" not in json.dumps(gateway.audit_log.to_json())


def test_trust_denial_precedes_escalation() -> None:
    """A LOW caller on a HIGH mutating tool gets TrustDeniedError, and the
    audit shows the trust denial only — no escalation event is recorded
    for a call that was already refused."""
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("delete_record", {"id": "7"}, TrustLevel.LOW, InputTrust.UNTRUSTED)
    assert transport.calls == []
    kinds = [e.kind for e in gateway.audit_log.events()]
    assert kinds == [AuditKind.CALL_DENIED]


def test_non_sensitive_mutating_call_needs_no_approval() -> None:
    """MEDIUM is not the sensitive tier: a mutating MEDIUM tool on
    untrusted input proceeds without a second approval."""
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    gateway.call_tool("search", {"q": "x"}, TrustLevel.MEDIUM, InputTrust.UNTRUSTED)
    assert len(transport.calls) == 1
    kinds = [e.kind for e in gateway.audit_log.events()]
    assert AuditKind.ESCALATION_REQUIRED not in kinds
    assert AuditKind.ESCALATION_APPROVED not in kinds


def test_sensitive_non_mutating_call_needs_no_approval() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    gateway.call_tool("read_record", {"id": "1"}, TrustLevel.HIGH, InputTrust.UNTRUSTED)
    assert len(transport.calls) == 1


def test_sensitive_mutating_call_on_trusted_input_needs_no_approval() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    gateway.call_tool("delete_record", {"id": "7"}, TrustLevel.HIGH, InputTrust.TRUSTED)
    assert len(transport.calls) == 1


def test_approval_on_non_escalated_call_is_harmless() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    gateway.call_tool("search", {"q": "x"}, TrustLevel.MEDIUM, InputTrust.TRUSTED, APPROVAL)
    assert len(transport.calls) == 1
    kinds = [e.kind for e in gateway.audit_log.events()]
    assert AuditKind.ESCALATION_APPROVED not in kinds


def test_second_approval_requires_approver_and_reason() -> None:
    with pytest.raises(ValueError):
        SecondApproval(approver="", reason="ok")
    with pytest.raises(ValueError):
        SecondApproval(approver="  ", reason="ok")
    with pytest.raises(ValueError):
        SecondApproval(approver="dana", reason="")
    with pytest.raises(ValueError):
        SecondApproval(approver="dana", reason="   ")


def test_gateway_rejects_wrong_input_trust_and_approval_types() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TypeError):
        gateway.call_tool("search", {"q": "x"}, TrustLevel.MEDIUM, "untrusted")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        gateway.call_tool("search", {"q": "x"}, TrustLevel.MEDIUM, InputTrust.TRUSTED, True)  # type: ignore[arg-type]
    assert transport.calls == []


def test_input_trust_parse_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        InputTrust.parse("maybe")
    assert InputTrust.parse("trusted") is InputTrust.TRUSTED
    assert InputTrust.parse("untrusted") is InputTrust.UNTRUSTED


# --- policy: mutating_tools --------------------------------------------------


def test_policy_mutating_tools_parsed_and_queried() -> None:
    policy = GatewayPolicy.from_mapping(
        {"tools": {"delete_record": "high"}, "mutating_tools": ["delete_record"]}
    )
    assert policy.is_mutating("delete_record") is True
    assert policy.is_mutating("read_record") is False
    assert policy.trust_of("delete_record") is TrustLevel.HIGH


def test_policy_without_mutating_tools_nothing_mutates() -> None:
    policy = GatewayPolicy.from_mapping({"tools": {"delete_record": "high"}})
    assert policy.is_mutating("delete_record") is False
    assert policy.mutating_tools == frozenset()


def test_policy_mutating_tools_wrong_shapes_fail_closed() -> None:
    with pytest.raises(TypeError):
        GatewayPolicy.from_mapping({"mutating_tools": "delete_record"})
    with pytest.raises(TypeError):
        GatewayPolicy.from_mapping({"mutating_tools": ["delete_record", 7]})
    with pytest.raises(TypeError):
        GatewayPolicy.from_mapping({"mutating_tools": {"delete_record": True}})
    with pytest.raises(TypeError):
        GatewayPolicy.from_mapping({"tools": {"a": "high"}, "mutating_tools": None})


def test_policy_is_mutating_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        _policy().is_mutating(7)  # type: ignore[arg-type]


# --- detector: +972 Israeli mobile; 9-digit gap pinned -----------------------


def test_israeli_plus972_mobile_is_tokenized() -> None:
    tokenizer = PiiTokenizer()
    text, applied = tokenizer.tokenize_text(f"call me at {IL_PHONE} please")
    assert IL_PHONE not in text
    assert applied[0].kind.value == "phone"
    assert "[PHONE_1]" in text


def test_bare_nine_digit_run_is_not_a_national_id() -> None:
    """Pinned gap (rat #69): the source conditions the 9-digit national
    ID on column context the free-text detector lacks, so a bare 9-digit
    order number must NOT tokenize."""
    tokenizer = PiiTokenizer()
    text, applied = tokenizer.tokenize_text("order 123456789 shipped")
    assert text == "order 123456789 shipped"
    assert applied == ()


def test_detector_is_linear_on_long_letter_run() -> None:
    """Regression (rat #69 fix-forward): the unbounded email local part
    made RegexDetector.detect quadratic on the fuzzer's 1M-char overflow
    payloads — the report scrub hung test_twyman_delivery. A 200k letter
    run with no "@" must return unchanged, fast."""
    tokenizer = PiiTokenizer()
    text, applied = tokenizer.tokenize_text("A" * 200_000)
    assert len(text) == 200_000
    assert applied == ()


def test_detector_is_linear_on_long_digit_run() -> None:
    tokenizer = PiiTokenizer()
    text, applied = tokenizer.tokenize_text("1" * 200_000)
    assert len(text) == 200_000
    assert applied == ()


def test_long_run_with_email_at_the_end_still_tokenizes() -> None:
    tokenizer = PiiTokenizer()
    text, applied = tokenizer.tokenize_text("A" * 100_000 + " " + EMAIL)
    assert EMAIL not in text
    assert applied[0].kind.value == "email"


def test_scrub_for_output_recurses_and_never_serializes_mapping() -> None:
    tokenizer = PiiTokenizer()
    value = {"contact": EMAIL, "phones": [PHONE, IL_PHONE], "nested": {"card": CARD}}
    scrubbed = scrub_for_output(value, tokenizer)
    assert isinstance(scrubbed, dict)
    assert EMAIL not in json.dumps(scrubbed)
    assert PHONE not in json.dumps(scrubbed)
    assert IL_PHONE not in json.dumps(scrubbed)
    assert CARD not in json.dumps(scrubbed)
    assert scrubbed["contact"] == "[EMAIL_1]"
    assert tokenizer.token_count == 4


# --- lifecycle threading -----------------------------------------------------


class _ServerTransport:
    """In-memory stand-in for a server transport (no subprocess)."""

    def __init__(self, command: tuple[str, ...] = ()) -> None:
        self.command = command
        self._alive = False
        self.calls: list[JsonDict] = []

    def start(self) -> None:
        self._alive = True

    def stop(self) -> None:
        self._alive = False

    @property
    def is_alive(self) -> bool:
        return self._alive

    @property
    def pid(self) -> int | None:
        return 4242

    def list_tools(self) -> list[JsonDict]:
        return [{"name": "delete_record"}, {"name": "search"}]

    def call_tool(self, tool_name: str, arguments: JsonDict) -> JsonDict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"content": [{"type": "text", "text": "ok"}]}

    def last_exchange(self) -> tuple[JsonDict | None, object]:
        if not self.calls:
            return None, None
        return {"jsonrpc": "2.0", "id": len(self.calls), "method": "tools/call"}, len(self.calls)


def _lifecycle() -> tuple[Lifecycle, list[_ServerTransport]]:
    created: list[_ServerTransport] = []

    def factory(command: tuple[str, ...]) -> _ServerTransport:
        transport = _ServerTransport(command)
        created.append(transport)
        return transport

    registry = ServerRegistry(servers={"s1": ServerSpec("s1", ("fake-s1",))})
    return Lifecycle(registry, _policy(), factory), created


def test_lifecycle_threads_escalation_to_gateway() -> None:
    lifecycle, created = _lifecycle()
    lifecycle.begin_task("t1", ["s1"])
    with pytest.raises(EscalationRequiredError):
        lifecycle.call_tool("t1", "s1", "delete_record", {"id": "7"}, TrustLevel.HIGH)
    assert created[0].calls == []
    lifecycle.call_tool(
        "t1", "s1", "delete_record", {"id": "7"}, TrustLevel.HIGH, InputTrust.UNTRUSTED, APPROVAL
    )
    assert len(created[0].calls) == 1
    lifecycle.end_task("t1")


# --- report scrubbing: no raw PII in any emitted byte ------------------------


def _result(
    tool: str,
    category: ResultCategory,
    severity: str = "high",
    detail: str = "",
    response_preview: str = "",
    payload_value: object = "probe",
    delivery_detail: str = "",
) -> FuzzResult:
    return FuzzResult(
        tool_name=tool,
        probe_name="p1",
        payload_value=payload_value,
        category=category,
        rule_id="R1",
        severity=severity,
        detail=detail,
        response_preview=response_preview,
        delivery_detail=delivery_detail,
    )


def _pii_report() -> FuzzReport:
    results = [
        _result(
            "lookup",
            ResultCategory.FINDING,
            detail=f"server echoed {EMAIL}",
            response_preview=f"contact {IL_PHONE} or {EMAIL}",
            payload_value=f"call {EMAIL}",
            delivery_detail=f"delivered, echoed {PHONE}",
        ),
        _result(
            "lookup",
            ResultCategory.CRASH,
            severity="critical",
            detail=f"crash dump mentions card {CARD}",
            response_preview=f"key {API_KEY} in response",
            payload_value={"nested": SSN},
        ),
        _result(
            "lookup",
            ResultCategory.ERROR,
            detail=f"error for {EMAIL}",
            response_preview="",
            payload_value="x",
        ),
        _result(
            "lookup",
            ResultCategory.INCONCLUSIVE,
            detail=f"no verdict; ssn {SSN} seen",
            response_preview="",
            payload_value="y",
        ),
        _result("lookup", ResultCategory.SAFE, severity="info"),
    ]
    return FuzzReport(
        server_command="npx some-server",
        tools_fuzzed=1,
        total_payloads=5,
        results=results,
    )


RAW_SECRETS = (EMAIL, PHONE, IL_PHONE, SSN, CARD, API_KEY)


def _assert_no_raw_pii(emitted: str) -> None:
    for secret in RAW_SECRETS:
        assert secret not in emitted, f"raw PII leaked into report: {secret}"


def test_report_table_scrubs_every_section() -> None:
    report = _pii_report()
    buf = io.StringIO()
    report.to_table(buf)
    emitted = buf.getvalue()
    _assert_no_raw_pii(emitted)
    assert "[EMAIL_1]" in emitted
    assert "[PHONE_" in emitted
    assert "[CREDIT_CARD_1]" in emitted
    assert "[SSN_1]" in emitted
    # No [API_KEY_1] here by design: the table never prints a crash's
    # response_preview (payload + detail only), and the key lives in the
    # preview — the JSON test below pins it where it is emitted.
    assert "VERDICT: VULNERABLE" in emitted


def test_report_json_scrubs_payload_detail_and_preview() -> None:
    report = _pii_report()
    buf = io.StringIO()
    report.to_json(buf)
    emitted = buf.getvalue()
    _assert_no_raw_pii(emitted)
    data = json.loads(emitted)
    assert data["summary"]["verdict"] == "VULNERABLE"
    assert data["summary"]["findings"] == 1
    assert data["summary"]["total_payloads"] == 5
    blob = json.dumps(data["results"])
    assert "[EMAIL_1]" in blob
    assert "[PHONE_" in blob
    # The API key lives in the crash's response_preview, which JSON emits.
    assert "[API_KEY_1]" in blob


def test_report_sarif_scrubs_messages() -> None:
    report = _pii_report()
    buf = io.StringIO()
    report.to_sarif(buf)
    emitted = buf.getvalue()
    _assert_no_raw_pii(emitted)
    data = json.loads(emitted)
    assert data["runs"][0]["properties"]["mcp-guard.verdict"] == "VULNERABLE"
    messages = json.dumps(data["runs"][0]["results"])
    assert "[EMAIL_1]" in messages
    assert "[CREDIT_CARD_1]" in messages


def test_report_scrub_is_emit_only_raw_results_untouched() -> None:
    report = _pii_report()
    buf = io.StringIO()
    report.to_json(buf)
    assert report.results[0].detail == f"server echoed {EMAIL}"
    assert report.results[0].response_preview == f"contact {IL_PHONE} or {EMAIL}"
    assert report.results[0].payload_value == f"call {EMAIL}"
    # Counts still recompute from the raw results after scrubbing.
    report.verify_counts()


def test_report_scrub_then_truncate_never_leaks_a_straddling_span() -> None:
    """PII starting before the 60-char table cut and ending after it must
    not leak: scrubbing runs on the full string before truncation."""
    payload = "x" * 55 + " " + EMAIL + " tail"
    result = _result(
        "lookup",
        ResultCategory.FINDING,
        detail="d",
        response_preview="r",
        payload_value=payload,
    )
    report = FuzzReport(
        server_command="npx some-server",
        tools_fuzzed=1,
        total_payloads=1,
        results=[result],
    )
    buf = io.StringIO()
    report.to_table(buf)
    emitted = buf.getvalue()
    assert EMAIL not in emitted
    assert "x" * 55 in emitted


# --- CLI: input_trust / approval lines ---------------------------------------


_FAKE_SERVER = """\
import json, sys

TOOLS = [
    {"name": "delete_record", "description": "Delete a record"},
    {"name": "lookup_faq", "description": "Answer a question"},
]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "initialize":
        send({"jsonrpc": "2.0", "id": req["id"], "result": {"protocolVersion": "1", "capabilities": {}, "serverInfo": {"name": "fake", "version": "0"}}})
    elif req.get("method") == "tools/list":
        send({"jsonrpc": "2.0", "id": req["id"], "result": {"tools": TOOLS}})
    elif req.get("method") == "tools/call":
        name = req["params"]["name"]
        if name == "delete_record":
            text = "deleted record for jane.doe@example.com"
        else:
            text = "faq answer"
        send({"jsonrpc": "2.0", "id": req["id"], "result": {"content": [{"type": "text", "text": text}]}})
    elif req.get("method") == "notifications/initialized":
        pass
"""


def test_cli_gateway_rule_of_two_end_to_end(tmp_path: Path) -> None:
    server = tmp_path / "fake_server.py"
    server.write_text(_FAKE_SERVER, encoding="utf-8")
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "tools": {"delete_record": "high"},
                "mutating_tools": ["delete_record"],
                "default_trust": "low",
            }
        ),
        encoding="utf-8",
    )
    requests = "\n".join(
        [
            # Escalated, no approval: denied, never sent.
            json.dumps({"tool": "delete_record", "arguments": {"id": "7"}, "caller_trust": "high"}),
            # Same call with a second approval: allowed.
            json.dumps(
                {
                    "tool": "delete_record",
                    "arguments": {"id": "7"},
                    "caller_trust": "high",
                    "approval": {"approver": "dana", "reason": "verified ticket"},
                }
            ),
            # Bad input_trust: error line, session lives.
            json.dumps(
                {
                    "tool": "lookup_faq",
                    "arguments": {"q": "hours"},
                    "caller_trust": "low",
                    "input_trust": "maybe",
                }
            ),
            # Bad approval shape: error line, session lives.
            json.dumps(
                {
                    "tool": "lookup_faq",
                    "arguments": {"q": "hours"},
                    "caller_trust": "low",
                    "approval": {"approver": "dana"},
                }
            ),
            json.dumps({"tool": "lookup_faq", "arguments": {"q": "hours"}, "caller_trust": "low"}),
        ]
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_guard.cli",
            "gateway",
            "--policy",
            str(policy_file),
            "--",
            sys.executable,
            str(server),
        ],
        input=requests,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert lines[1]["denied"] is True
    assert "escalation required" in lines[1]["reason"]
    assert lines[1]["audit"][0]["kind"] == "escalation_required"
    assert lines[2]["tool"] == "delete_record" and "denied" not in lines[2]
    assert lines[2]["audit"][0]["kind"] == "escalation_approved"
    assert lines[2]["audit"][0]["approver"] == "dana"
    assert "error" in lines[3] and "unknown input trust" in lines[3]["error"]
    assert "error" in lines[4] and "approver" in lines[4]["error"]
    assert lines[5]["tool"] == "lookup_faq" and "denied" not in lines[5]
    assert lines[6]["event"] == "gateway_closed"
    # No raw PII anywhere on stdout: the approved call's result was tokenized.
    assert EMAIL not in proc.stdout
