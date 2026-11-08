"""Deterministic intake normalization — schema-gated entry (rat #76).

Every test here is behavioral: a malformed input must return a
structured fallback with a stable error code and never reach the
server; a well-formed input must proceed with canonical, truncated
arguments; and the audit log must record the outcome on every call
without ever carrying content. Fixtures use example.com / 555 numbers
so no real personal data appears anywhere.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

from mcp_guard.gateway import AuditKind, Gateway, GatewayPolicy, TrustLevel
from mcp_guard.identity import IdentityVault, PermissionScope
from mcp_guard.intake import (
    CALIBRATION,
    IntakeErrorCode,
    IntakeFailure,
    IntakePolicy,
    NormalizedIntake,
    normalize_input,
    structured_fallback,
)

SECRET_VALUE = "s3cret-value-that-must-never-appear-in-a-log"


class FakeTransport:
    """Records every send; answers canned tool results."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self._id = 0

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        self._id += 1
        return {"content": [{"type": "text", "text": "ok"}]}

    def last_exchange(self) -> tuple[dict | None, object]:
        if not self.calls:
            return None, None
        return None, self._id


def _gateway(
    policy: GatewayPolicy | None = None, **kwargs: object
) -> tuple[Gateway, FakeTransport]:
    transport = FakeTransport()
    gateway = Gateway(transport, policy or GatewayPolicy(), **kwargs)  # type: ignore[arg-type]
    return gateway, transport


def _intake_events(gateway: Gateway) -> list:
    return [e for e in gateway.audit_log.events() if e.kind is AuditKind.INTAKE]


# --- Calibration sets: every case asserts its expected verdict ----------


@pytest.mark.parametrize(
    "name,tool,args,kwargs,expected",
    CALIBRATION,
    ids=[case[0] for case in CALIBRATION],
)
def test_calibration_cases(name, tool, args, kwargs, expected) -> None:
    policy = kwargs.get("policy", IntakePolicy())  # type: ignore[attr-defined]
    metadata = kwargs.get("metadata")
    outcome = normalize_input(tool, args, policy=policy, metadata=metadata)
    if expected is None:
        assert isinstance(outcome, NormalizedIntake), f"{name}: expected ok, got {outcome!r}"
    else:
        assert isinstance(outcome, IntakeFailure), f"{name}: expected fail, got {outcome!r}"
        assert outcome.error_code.value == expected, f"{name}: wrong code"
        assert outcome.policy_tag == policy.tag


def test_calibration_covers_every_error_code() -> None:
    """The set must exercise all six codes, or a code is unpinned."""
    codes = {case[4] for case in CALIBRATION if case[4] is not None}
    assert codes == {code.value for code in IntakeErrorCode}


# --- normalize_input: shape, truncation, determinism ---------------------


def test_tool_name_is_stripped_not_rejected() -> None:
    outcome = normalize_input("  read  ", {"path": "notes.txt"})
    assert isinstance(outcome, NormalizedIntake)
    assert outcome.tool_name == "read"


def test_truncation_is_head_plus_marker_plus_tail() -> None:
    policy = IntakePolicy(head_chars=4, tail_chars=3, marker="[TRUNCATED]")
    outcome = normalize_input("read", {"text": "abcdefghijklmnop"}, policy=policy)
    assert isinstance(outcome, NormalizedIntake)
    assert outcome.arguments["text"] == "abcd[TRUNCATED]nop"
    assert outcome.truncated is True
    assert outcome.truncated_fields == ("text",)


def test_string_at_exact_budget_is_not_truncated() -> None:
    policy = IntakePolicy(head_chars=4, tail_chars=3, marker="[TRUNCATED]")
    outcome = normalize_input("read", {"text": "abcdefg"}, policy=policy)
    assert isinstance(outcome, NormalizedIntake)
    assert outcome.arguments["text"] == "abcdefg"
    assert outcome.truncated is False


def test_nested_strings_truncate_with_paths() -> None:
    policy = IntakePolicy(head_chars=2, tail_chars=2, marker="[T]")
    outcome = normalize_input("read", {"a": {"b": ["x" * 10, "tiny"]}}, policy=policy)
    assert isinstance(outcome, NormalizedIntake)
    assert outcome.arguments["a"]["b"][0] == "xx[T]xx"
    assert outcome.arguments["a"]["b"][1] == "tiny"
    assert outcome.truncated_fields == ("a.b[0]",)


def test_keys_are_sorted_and_values_untouched() -> None:
    outcome = normalize_input("read", {"z": 1, "a": "b", "m": None})
    assert isinstance(outcome, NormalizedIntake)
    assert list(outcome.arguments.keys()) == ["a", "m", "z"]
    assert outcome.arguments == {"a": "b", "m": None, "z": 1}


def test_normalization_is_byte_deterministic() -> None:
    request = {"text": "a" * 3000, "nested": {"n": [1, "b" * 3000]}, "z": 1}
    first = normalize_input("read", request)
    second = normalize_input("read", request)
    assert isinstance(first, NormalizedIntake) and isinstance(second, NormalizedIntake)
    assert json.dumps(first.arguments, sort_keys=True) == json.dumps(
        second.arguments, sort_keys=True
    )
    assert first.truncated_fields == second.truncated_fields


def test_deep_nesting_fails_cleanly_not_recursion_error() -> None:
    deep: dict = {}
    cursor = deep
    for _ in range(100):
        cursor["x"] = {}
        cursor = cursor["x"]
    outcome = normalize_input("read", deep)
    assert isinstance(outcome, IntakeFailure)
    assert outcome.error_code is IntakeErrorCode.INVALID_ARGUMENTS


def test_non_mapping_metadata_fails() -> None:
    outcome = normalize_input("read", {}, metadata=["locale"])  # type: ignore[arg-type]
    assert isinstance(outcome, IntakeFailure)
    assert outcome.error_code is IntakeErrorCode.INVALID_ARGUMENTS


def test_missing_metadata_names_the_field_not_the_value() -> None:
    policy = IntakePolicy(required_metadata=("locale", "tier"))
    outcome = normalize_input("read", {}, policy=policy, metadata={"locale": "en-US"})
    assert isinstance(outcome, IntakeFailure)
    assert outcome.error_code is IntakeErrorCode.MISSING_METADATA
    assert "tier" in outcome.detail
    assert SECRET_VALUE not in outcome.detail


def test_blank_metadata_value_is_missing() -> None:
    policy = IntakePolicy(required_metadata=("locale",))
    outcome = normalize_input("read", {}, policy=policy, metadata={"locale": "   "})
    assert isinstance(outcome, IntakeFailure)
    assert outcome.error_code is IntakeErrorCode.MISSING_METADATA


def test_require_identity_without_bound_identity_fails() -> None:
    policy = IntakePolicy(require_identity=True)
    outcome = normalize_input("read", {}, policy=policy, identity_bound=False)
    assert isinstance(outcome, IntakeFailure)
    assert outcome.error_code is IntakeErrorCode.MISSING_IDENTITY
    outcome = normalize_input("read", {}, policy=policy, identity_bound=True)
    assert isinstance(outcome, NormalizedIntake)


def test_structured_fallback_shape() -> None:
    failure = IntakeFailure(IntakeErrorCode.INVALID_TOOL, "intake-v1", "tool name is empty")
    fallback = structured_fallback(failure)
    assert fallback == {
        "mcp_guard_intake": {
            "status": "fallback",
            "error_code": "INTAKE_INVALID_TOOL",
            "policy_tag": "intake-v1",
        }
    }


def test_policy_validation_fails_closed() -> None:
    with pytest.raises(ValueError):
        IntakePolicy(head_chars=0, tail_chars=0)
    with pytest.raises(ValueError):
        IntakePolicy(marker="")
    with pytest.raises(ValueError):
        IntakePolicy(tag="  ")
    with pytest.raises(TypeError):
        IntakePolicy.from_mapping({"head_chars": "many"})
    with pytest.raises(ValueError):
        IntakePolicy.from_mapping({"mode": "audit", "head_chars": -1})
    policy = IntakePolicy.from_mapping(
        {"tag": "intake-v2", "required_metadata": ["locale"], "require_identity": True}
    )
    assert policy.tag == "intake-v2"
    assert policy.required_metadata == ("locale",)
    assert policy.require_identity is True


# --- Gateway integration: the gate is the entry path ----------------------


def test_malformed_call_returns_fallback_and_never_sends() -> None:
    gateway, transport = _gateway()
    result = gateway.call_tool("   ", {"path": "notes.txt"})
    assert result == {
        "mcp_guard_intake": {
            "status": "fallback",
            "error_code": "INTAKE_INVALID_TOOL",
            "policy_tag": "intake-v1",
        }
    }
    assert transport.calls == []
    events = _intake_events(gateway)
    assert len(events) == 1
    assert events[0].intake_outcome == "fail"
    assert events[0].intake_error_code == "INTAKE_INVALID_TOOL"
    assert events[0].intake_policy_tag == "intake-v1"


def test_non_json_arguments_never_send() -> None:
    gateway, transport = _gateway()
    result = gateway.call_tool("read", {"data": b"\x00\x01"})  # type: ignore[arg-type]
    assert result["mcp_guard_intake"]["error_code"] == "INTAKE_NON_JSON_VALUE"
    assert transport.calls == []


def test_well_formed_call_proceeds_with_truncated_arguments() -> None:
    policy = GatewayPolicy(intake=IntakePolicy(head_chars=4, tail_chars=3, marker="[TRUNCATED]"))
    gateway, transport = _gateway(policy)
    result = gateway.call_tool("read", {"text": "abcdefghijklmnop"})
    assert "mcp_guard_intake" not in result
    assert len(transport.calls) == 1
    assert transport.calls[0]["arguments"] == {"text": "abcd[TRUNCATED]nop"}
    events = _intake_events(gateway)
    assert len(events) == 1
    assert events[0].intake_outcome == "ok"
    assert events[0].intake_truncated is True
    assert events[0].intake_truncated_fields == ("text",)


def test_intake_event_is_recorded_on_every_call() -> None:
    gateway, _ = _gateway()
    gateway.call_tool("read", {"path": "notes.txt"})
    gateway.call_tool("   ", {})
    gateway.call_tool("read", {"path": "other.txt"})
    events = _intake_events(gateway)
    assert [e.intake_outcome for e in events] == ["ok", "fail", "ok"]
    assert all(e.intake_policy_tag == "intake-v1" for e in events)


def test_intake_failure_precedes_trust_and_identity_verdicts() -> None:
    """A malformed request gets no trust verdict and no send, even for a
    tool the caller could never invoke: the audit log holds the INTAKE
    fail event and no CALL_DENIED event."""
    policy = GatewayPolicy(tools={"delete_record": TrustLevel.HIGH})
    gateway, transport = _gateway(policy)
    result = gateway.call_tool("delete_record", {"x": float("nan")}, caller_trust=TrustLevel.LOW)  # type: ignore[arg-type]
    assert result["mcp_guard_intake"]["error_code"] == "INTAKE_NON_JSON_VALUE"
    assert transport.calls == []
    kinds = [e.kind for e in gateway.audit_log.events()]
    assert AuditKind.CALL_DENIED not in kinds
    assert AuditKind.INTAKE in kinds


def test_audit_log_never_carries_argument_or_metadata_values() -> None:
    policy = GatewayPolicy(
        intake=IntakePolicy(required_metadata=("locale",), head_chars=4, tail_chars=3)
    )
    gateway, _ = _gateway(policy)
    gateway.call_tool(
        "read",
        {"secret": SECRET_VALUE, "text": "y" * 50},
        metadata={"locale": SECRET_VALUE},
    )
    gateway.call_tool("read", {"secret": SECRET_VALUE}, metadata={})
    audit_json = json.dumps(gateway.audit_log.to_json())
    assert SECRET_VALUE not in audit_json
    assert "y" * 50 not in audit_json


def test_required_metadata_enforced_at_the_gateway() -> None:
    policy = GatewayPolicy(intake=IntakePolicy(required_metadata=("locale",)))
    gateway, transport = _gateway(policy)
    result = gateway.call_tool("read", {"path": "notes.txt"})
    assert result["mcp_guard_intake"]["error_code"] == "INTAKE_MISSING_METADATA"
    assert transport.calls == []
    result = gateway.call_tool("read", {"path": "notes.txt"}, metadata={"locale": "en-US"})
    assert "mcp_guard_intake" not in result
    assert len(transport.calls) == 1


def test_require_identity_enforced_at_the_gateway() -> None:
    policy = GatewayPolicy(intake=IntakePolicy(require_identity=True))
    gateway, transport = _gateway(policy)
    result = gateway.call_tool("read", {"path": "notes.txt"})
    assert result["mcp_guard_intake"]["error_code"] == "INTAKE_MISSING_IDENTITY"
    assert transport.calls == []

    scope = PermissionScope(
        user_id="user@example.com",
        servers=frozenset({"default"}),
        tools=frozenset({"read"}),
    )
    vault = IdentityVault()
    identity = vault.issue_context(scope)
    gateway2, transport2 = _gateway(policy, identity=identity)
    result = gateway2.call_tool("read", {"path": "notes.txt"})
    assert "mcp_guard_intake" not in result
    assert len(transport2.calls) == 1


def test_policy_file_intake_section_parses() -> None:
    policy = GatewayPolicy.from_mapping(
        {
            "tools": {"read": "low"},
            "intake": {"head_chars": 10, "tail_chars": 5, "required_metadata": ["locale"]},
        }
    )
    assert policy.intake.head_chars == 10
    assert policy.intake.tail_chars == 5
    assert policy.intake.required_metadata == ("locale",)
    with pytest.raises(TypeError):
        GatewayPolicy.from_mapping({"intake": "audit"})


# --- CLI: intake subcommand + gateway metadata passthrough ----------------


def test_cli_intake_clean_request_exits_zero(tmp_path: Path, capsys) -> None:
    from mcp_guard.cli import main

    request = tmp_path / "request.json"
    request.write_text(json.dumps({"tool": "read", "arguments": {"path": "notes.txt"}}))
    main(["intake", "--file", str(request)])
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["tool"] == "read"
    assert out["arguments"] == {"path": "notes.txt"}
    assert out["policy_tag"] == "intake-v1"
    assert out["truncated"] is False


def test_cli_intake_malformed_request_exits_one(tmp_path: Path, capsys) -> None:
    from mcp_guard.cli import main

    request = tmp_path / "request.json"
    request.write_text(json.dumps({"tool": "   ", "arguments": {}}))
    with pytest.raises(SystemExit) as excinfo:
        main(["intake", "--file", str(request)])
    assert excinfo.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert out["fallback"]["error_code"] == "INTAKE_INVALID_TOOL"
    assert out["fallback"]["status"] == "fallback"


def test_cli_intake_missing_file_exits_two(tmp_path: Path) -> None:
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as excinfo:
        main(["intake", "--file", str(tmp_path / "nope.json")])
    assert excinfo.value.code == 2


def test_cli_intake_invalid_json_exits_two(tmp_path: Path) -> None:
    from mcp_guard.cli import main

    request = tmp_path / "request.json"
    request.write_text("{not json")
    with pytest.raises(SystemExit) as excinfo:
        main(["intake", "--file", str(request)])
    assert excinfo.value.code == 2


def test_cli_intake_policy_file_supplies_budgets(tmp_path: Path, capsys) -> None:
    from mcp_guard.cli import main

    request = tmp_path / "request.json"
    request.write_text(json.dumps({"tool": "read", "arguments": {"text": "abcdefghijklmnop"}}))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps({"intake": {"head_chars": 4, "tail_chars": 3, "tag": "intake-test"}})
    )
    main(["intake", "--file", str(request), "--policy", str(policy_file)])
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["arguments"]["text"] == "abcd[TRUNCATED]nop"
    assert out["policy_tag"] == "intake-test"
    assert out["truncated_fields"] == ["text"]


def test_cli_intake_required_metadata_from_policy(tmp_path: Path, capsys) -> None:
    from mcp_guard.cli import main

    request = tmp_path / "request.json"
    request.write_text(json.dumps({"tool": "read", "arguments": {}}))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"intake": {"required_metadata": ["locale"]}}))
    with pytest.raises(SystemExit) as excinfo:
        main(["intake", "--file", str(request), "--policy", str(policy_file)])
    assert excinfo.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["fallback"]["error_code"] == "INTAKE_MISSING_METADATA"


def test_control_characters_in_values_pass_as_documented() -> None:
    # Round-2 fix-forward (rat #76, impl A2): control characters are
    # checked only in the tool NAME. A control character in an argument
    # value is a valid JSON string, JSON-escaped on the wire and in the
    # audit log — the gate passes it and the server owns the value.
    outcome = normalize_input("read", {"x": "a\x01b"})
    assert isinstance(outcome, NormalizedIntake)
    assert outcome.arguments == {"x": "a\x01b"}


def test_intake_event_records_stripped_name_and_trust() -> None:
    # Round-2 fix-forward (rat #76, impl A1): the INTAKE event must
    # agree with enforcement, which runs on the normalized name — a
    # padded name recorded raw would show the wrong target trust. The
    # call is then trust-denied (HIGH tool, LOW caller) — expected:
    # the INTAKE event is recorded before the trust check, so it is
    # asserted around the denial, not after a success.
    from mcp_guard.gateway import TrustDeniedError

    policy = GatewayPolicy(tools={"read": TrustLevel.HIGH})
    gateway, _ = _gateway(policy)
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("  read  ", {"path": "notes.txt"})
    events = _intake_events(gateway)
    assert len(events) == 1
    assert events[0].tool_name == "read"
    assert events[0].target_trust is TrustLevel.HIGH


def test_lone_surrogate_via_json_loads_reaches_gateway_as_fallback() -> None:
    # Round-2 fix-forward (rat #76, impl B1): the live path is real —
    # the CLI gateway reads stdin JSON and json.loads accepts "\ud800"
    # escapes, so a surrogate smuggled in as JSON text must fail at
    # the gate, never reach the transport.
    args = json.loads('{"x": "\\ud800"}')
    gateway, transport = _gateway()
    result = gateway.call_tool("read", args)
    assert result["mcp_guard_intake"]["error_code"] == "INTAKE_NON_JSON_VALUE"
    assert transport.calls == []


# --- CLI: round-2 fix-forward --------------------------------------------


def test_cli_intake_lone_surrogate_file_exits_one(tmp_path: Path, capsys) -> None:
    from mcp_guard.cli import main

    request = tmp_path / "request.json"
    request.write_text('{"tool": "read", "arguments": {"x": "\\ud800"}}', encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        main(["intake", "--file", str(request)])
    assert excinfo.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["fallback"]["error_code"] == "INTAKE_NON_JSON_VALUE"


def test_cli_intake_identity_bound_flag(tmp_path: Path, capsys) -> None:
    from mcp_guard.cli import main

    request = tmp_path / "request.json"
    request.write_text(json.dumps({"tool": "read", "arguments": {}}))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"intake": {"require_identity": True}}))
    # Without the flag the offline surface has no identity bound, so
    # the policy always falls back.
    with pytest.raises(SystemExit) as excinfo:
        main(["intake", "--file", str(request), "--policy", str(policy_file)])
    assert excinfo.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["fallback"]["error_code"] == "INTAKE_MISSING_IDENTITY"
    # With the flag the same request returns ok.
    main(["intake", "--file", str(request), "--policy", str(policy_file), "--identity-bound"])
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True


# --- CLI gateway session: fallback marker line (round-2, arch B1) ---------

FAKE_SERVER = """\
import json, sys

TOOLS = [
    {"name": "lookup", "description": "answer a question",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05"}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": "answer"}]}})
"""


def _run_cli_gateway(args: list[str], stdin: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "mcp_guard.cli", *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
        cwd=str(REPO_ROOT),
    )


def test_cli_gateway_fallback_line_carries_marker(tmp_path: Path) -> None:
    # Round-2 fix-forward (rat #76, arch B1): a fallback is not a
    # result — the gateway session line carries an explicit top-level
    # "fallback": true plus the stable error code, so a consumer need
    # not parse the result body to tell a fallback from a tool result.
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"tools": {}, "default_trust": "low"}), encoding="utf-8")
    lines_in = "\n".join(
        [
            json.dumps({"tool": "lookup", "arguments": {"q": "hours"}}),
            '{"tool": "lookup", "arguments": {"q": NaN}}',
            json.dumps({"tool": "lookup", "arguments": {}, "metadata": "not-an-object"}),
        ]
    )
    proc = _run_cli_gateway(
        ["gateway", "--policy", str(policy), "--", sys.executable, str(server)],
        lines_in + "\n",
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert lines[0]["tools"] and [t["name"] for t in lines[0]["tools"]] == ["lookup"]
    # The well-formed call prints a bare result line: no marker.
    assert lines[1]["tool"] == "lookup"
    assert "result" in lines[1]
    assert "fallback" not in lines[1]
    # The NaN call fails intake: marker line, stable code, audit event.
    assert lines[2]["fallback"] is True
    assert lines[2]["error_code"] == "INTAKE_NON_JSON_VALUE"
    assert lines[2]["result"]["mcp_guard_intake"]["status"] == "fallback"
    intake = [e for e in lines[2]["audit"] if e["kind"] == "intake"]
    assert len(intake) == 1 and intake[0]["intake_outcome"] == "fail"
    # A non-object metadata routes to the same fallback shape (the
    # shape verdict belongs to intake, not to the shell).
    assert lines[3]["fallback"] is True
    assert lines[3]["error_code"] == "INTAKE_INVALID_ARGUMENTS"
