"""Central MCP gateway — trust levels + pre-model tokenization (rat #66).

Every test here is behavioral: a denied call must never reach the server,
tokenized results must never carry raw PII, and the audit log must never
contain content. PII fixtures use example.com / 555 numbers / the standard
Luhn-passing test card so no real personal data appears anywhere.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_guard.fuzzer import FuzzEngine
from mcp_guard.gateway import (
    AuditKind,
    Gateway,
    GatewayPolicy,
    PiiKind,
    PiiMatch,
    PiiTokenizer,
    TrustDeniedError,
    TrustLevel,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

EMAIL = "jane.doe@example.com"
PHONE = "555-123-4567"
SSN = "123-45-6789"
CARD = "4111-1111-1111-1111"  # Luhn-passing test number
# Synthetic fixture, never a real key: built from parts so the repo's
# secret-scan does not trip on a test constant.
API_KEY = "sk-" + "abcdefghij12345678"


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
        tools={"read_record": TrustLevel.HIGH, "search": TrustLevel.MEDIUM},
        default_trust=TrustLevel.LOW,
    )


# --- trust-level enforcement -------------------------------------------------


def test_low_caller_cannot_trigger_high_tool() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("read_record", {"id": "1"}, TrustLevel.LOW)
    assert transport.calls == [], "denied call reached the server"


def test_medium_caller_cannot_trigger_high_tool() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("read_record", {"id": "1"}, TrustLevel.MEDIUM)
    assert transport.calls == []


def test_undeclared_caller_is_low_not_root() -> None:
    """Omitting caller_trust must not escalate: the default is LOW."""
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("read_record", {"id": "1"})
    assert transport.calls == []


def test_equal_trust_allowed_and_higher_caller_allowed() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    gateway.call_tool("search", {"q": "x"}, TrustLevel.MEDIUM)
    gateway.call_tool("search", {"q": "x"}, TrustLevel.HIGH)
    gateway.call_tool("read_record", {"id": "1"}, TrustLevel.HIGH)
    assert len(transport.calls) == 3


def test_unlisted_tool_defaults_to_low() -> None:
    assert _policy().trust_of("never_listed") is TrustLevel.LOW


def test_denial_is_recorded_in_audit_log() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("read_record", {"id": "1"}, TrustLevel.LOW)
    events = gateway.audit_log.events()
    assert len(events) == 1
    assert events[0].kind is AuditKind.CALL_DENIED
    assert events[0].tool_name == "read_record"
    assert events[0].caller_trust is TrustLevel.LOW
    assert events[0].target_trust is TrustLevel.HIGH


def test_denial_message_carries_no_arguments() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TrustDeniedError) as excinfo:
        gateway.call_tool("read_record", {"secret_arg": "s3cr3t-value"}, TrustLevel.LOW)
    assert "s3cr3t-value" not in str(excinfo.value)


# --- policy parsing ----------------------------------------------------------


def test_policy_from_mapping_round_trip() -> None:
    policy = GatewayPolicy.from_mapping(
        {"tools": {"a": "high", "b": "medium"}, "default_trust": "low"}
    )
    assert policy.trust_of("a") is TrustLevel.HIGH
    assert policy.trust_of("b") is TrustLevel.MEDIUM
    assert policy.trust_of("other") is TrustLevel.LOW


def test_policy_unknown_level_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown trust level"):
        GatewayPolicy.from_mapping({"tools": {"a": "godmode"}})


def test_policy_non_object_fails_closed() -> None:
    with pytest.raises(TypeError):
        GatewayPolicy.from_mapping(["not", "an", "object"])  # type: ignore[arg-type]


def test_annotate_tools_marks_levels_without_mutating() -> None:
    gateway = Gateway(FakeTransport(), _policy())
    tools = [{"name": "read_record"}, {"name": "other"}]
    annotated = gateway.annotate_tools(tools)
    assert annotated[0]["mcp_guard_trust_level"] == "high"
    assert annotated[1]["mcp_guard_trust_level"] == "low"
    assert "mcp_guard_trust_level" not in tools[0], "input tool dict mutated"


# --- PII tokenization --------------------------------------------------------


def test_each_pii_kind_tokenizes() -> None:
    tokenizer = PiiTokenizer()
    text, applied = tokenizer.tokenize_text(
        f"mail {EMAIL} phone {PHONE} ssn {SSN} card {CARD} key {API_KEY}"
    )
    assert {a.kind for a in applied} == {
        PiiKind.EMAIL,
        PiiKind.PHONE,
        PiiKind.SSN,
        PiiKind.CREDIT_CARD,
        PiiKind.API_KEY,
    }
    for secret in (EMAIL, PHONE, SSN, CARD, API_KEY):
        assert secret not in text
    assert "[EMAIL_1]" in text and "[PHONE_1]" in text and "[SSN_1]" in text
    assert "[CREDIT_CARD_1]" in text and "[API_KEY_1]" in text


def test_same_value_gets_same_token_different_values_differ() -> None:
    tokenizer = PiiTokenizer()
    text, _ = tokenizer.tokenize_text(f"{EMAIL} then {EMAIL} and {PHONE}")
    assert text.count("[EMAIL_1]") == 2
    assert "[EMAIL_2]" not in text
    text2, _ = tokenizer.tokenize_text("other@example.com")
    assert "[EMAIL_2]" in text2


def test_luhn_failing_number_is_not_a_card() -> None:
    tokenizer = PiiTokenizer()
    text, applied = tokenizer.tokenize_text("order 4111-1111-1111-1112 shipped")
    assert not applied, "Luhn-failing 16-digit run tokenized as a card"
    assert "4111-1111-1111-1112" in text


def test_tokenization_recurses_into_nested_results() -> None:
    tokenizer = PiiTokenizer()
    value, applied = tokenizer.tokenize_value(
        {"content": [{"type": "text", "text": f"reach {EMAIL}"}], "count": 3}
    )
    assert isinstance(value, dict)
    content = value["content"]
    assert isinstance(content, list)
    first = content[0]
    assert isinstance(first, dict)
    assert first["text"] == "reach [EMAIL_1]"
    assert value["count"] == 3
    assert len(applied) == 1


def test_detokenize_resolves_only_minted_tokens() -> None:
    tokenizer = PiiTokenizer()
    tokenizer.tokenize_text(f"contact {EMAIL}")
    # Minted token resolves back to the value.
    out, n = tokenizer.detokenize_text("send to [EMAIL_1] please")
    assert out == f"send to {EMAIL} please"
    assert n == 1
    # Token-shaped text the gateway never minted passes through untouched.
    out, n = tokenizer.detokenize_text("send to [EMAIL_9] please")
    assert out == "send to [EMAIL_9] please"
    assert n == 0


def test_detokenize_does_not_corrupt_numbered_tokens() -> None:
    """[EMAIL_1] must not corrupt [EMAIL_10] during resolution."""
    tokenizer = PiiTokenizer()
    values = [f"user{i}@example.com" for i in range(1, 12)]
    tokenizer.tokenize_text(" ".join(values))
    out, n = tokenizer.detokenize_text("cc [EMAIL_10] and [EMAIL_1]")
    assert out == f"cc {values[9]} and {values[0]}"
    assert n == 2


def test_clear_wipes_the_mapping() -> None:
    tokenizer = PiiTokenizer()
    tokenizer.tokenize_text(EMAIL)
    assert tokenizer.token_count == 1
    tokenizer.clear()
    assert tokenizer.token_count == 0
    out, n = tokenizer.detokenize_text("[EMAIL_1]")
    assert out == "[EMAIL_1]" and n == 0


def test_bare_ten_digit_run_is_a_phone() -> None:
    """Fail-closed layer-1 call, documented in RegexDetector: a bare
    10-digit run tokenizes as a phone number."""
    tokenizer = PiiTokenizer()
    _, applied = tokenizer.tokenize_text("call 5551234567")
    assert [a.kind for a in applied] == [PiiKind.PHONE]


def test_custom_detector_seam_is_real() -> None:
    """A Detector plugged into the tokenizer is actually consulted."""

    class WordDetector:
        def detect(self, text: str) -> list[PiiMatch]:
            idx = text.find("SECRETWORD")
            if idx < 0:
                return []
            return [PiiMatch(kind=PiiKind.API_KEY, start=idx, end=idx + len("SECRETWORD"))]

    tokenizer = PiiTokenizer(detectors=(WordDetector(),))
    text, applied = tokenizer.tokenize_text("the SECRETWORD is here")
    assert "SECRETWORD" not in text
    assert applied[0].token == "[API_KEY_1]"


def test_github_token_shape_tokenizes() -> None:
    """The gh[p]_ character class still matches GitHub token shapes."""
    tokenizer = PiiTokenizer()
    token_value = "gh" + "p_" + "abcdefghij1234567890"
    text, applied = tokenizer.tokenize_text(f"key {token_value} here")
    assert token_value not in text
    assert [a.kind for a in applied] == [PiiKind.API_KEY]
    assert "[API_KEY_1]" in text


def test_card_digits_never_also_match_as_phone() -> None:
    tokenizer = PiiTokenizer()
    _, applied = tokenizer.tokenize_text(f"charge {CARD}")
    assert [a.kind for a in applied] == [PiiKind.CREDIT_CARD]


# --- audit log: events, never content ----------------------------------------


def test_audit_log_never_contains_content() -> None:
    transport = FakeTransport(
        results={"read_record": {"content": [{"type": "text", "text": f"{EMAIL} {PHONE} {SSN}"}]}}
    )
    gateway = Gateway(transport, _policy())
    result = gateway.call_tool("read_record", {"id": "1"}, TrustLevel.HIGH)
    assert EMAIL not in json.dumps(result)
    audit_json = json.dumps(gateway.audit_log.to_json())
    for secret in (EMAIL, PHONE, SSN):
        assert secret not in audit_json
    kinds = [e.kind for e in gateway.audit_log.events()]
    assert AuditKind.PII_TOKENIZED in kinds
    assert AuditKind.CALL_ALLOWED in kinds
    tokenized = next(e for e in gateway.audit_log.events() if e.kind is AuditKind.PII_TOKENIZED)
    assert sorted(tokenized.token_kinds) == ["email", "phone", "ssn"]
    assert tokenized.token_count == 3


def test_token_resolution_is_audited() -> None:
    transport = FakeTransport(
        results={"read_record": {"content": [{"type": "text", "text": f"{EMAIL}"}]}}
    )
    gateway = Gateway(transport, _policy())
    gateway.call_tool("read_record", {"id": "1"}, TrustLevel.HIGH)
    gateway.call_tool("search", {"q": "[EMAIL_1]"}, TrustLevel.HIGH)
    assert transport.calls[1]["arguments"] == {"q": EMAIL}, "token not resolved into call"
    kinds = [e.kind for e in gateway.audit_log.events()]
    assert AuditKind.TOKEN_RESOLVED in kinds


def test_audit_events_carry_request_ids() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    gateway.call_tool("search", {"q": "x"}, TrustLevel.HIGH)
    allowed = next(e for e in gateway.audit_log.events() if e.kind is AuditKind.CALL_ALLOWED)
    assert allowed.request_id == 1


# --- gateway as a drop-in transport ------------------------------------------


def test_gateway_is_a_drop_in_transport_for_the_fuzzer() -> None:
    """FuzzEngine accepts any Transport; the gateway implements it."""
    transport = FakeTransport()
    gateway = Gateway(transport, GatewayPolicy())
    engine = FuzzEngine(transport=gateway)  # type: ignore[arg-type]
    tool = {
        "name": "echo",
        "inputSchema": {"type": "object", "properties": {"msg": {"type": "string"}}},
    }
    results = engine.fuzz_tool(tool)
    assert results, "fuzzer produced no results through the gateway"
    assert transport.calls, "no call reached the server through the gateway"


# --- CLI proxy end-to-end ----------------------------------------------------

FAKE_SERVER = """\
import json, sys

TOOLS = [
    {"name": "read_record", "description": "read a record",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
    {"name": "lookup_faq", "description": "answer a question",
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
        params = req.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "read_record":
            text = "record for jane.doe@example.com phone 555-123-4567"
        else:
            text = "faq answer for " + json.dumps(args)
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": text}]}})
"""


def test_cli_gateway_proxy_end_to_end(tmp_path: Path) -> None:
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps({"tools": {"read_record": "high"}, "default_trust": "low"}),
        encoding="utf-8",
    )
    requests = "\n".join(
        [
            json.dumps({"tool": "lookup_faq", "arguments": {"q": "hours"}, "caller_trust": "low"}),
            json.dumps({"tool": "read_record", "arguments": {"id": "42"}, "caller_trust": "low"}),
            json.dumps({"tool": "read_record", "arguments": {"id": "42"}, "caller_trust": "high"}),
            json.dumps(
                {"tool": "lookup_faq", "arguments": {"q": "[EMAIL_1]"}, "caller_trust": "low"}
            ),
            "not json at all",
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
    assert lines[0]["tools"][0]["mcp_guard_trust_level"] == "high"
    assert lines[0]["tools"][1]["mcp_guard_trust_level"] == "low"
    assert lines[1]["tool"] == "lookup_faq" and "denied" not in lines[1]
    assert lines[2]["denied"] is True
    assert "trust denied" in lines[2]["reason"]
    assert "[EMAIL_1]" in json.dumps(lines[3]["result"])
    assert "[PHONE_1]" in json.dumps(lines[3]["result"])
    # Round trip: the token went back into a call and came back tokenized.
    assert "[EMAIL_1]" in json.dumps(lines[4]["result"])
    assert lines[5]["error"].startswith("invalid JSON")
    assert lines[6]["event"] == "gateway_closed"
    # No raw PII anywhere on stdout: results are tokenized, audit is events.
    for secret in (EMAIL, PHONE):
        assert secret not in proc.stdout


def test_cli_gateway_rejects_bad_policy(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"tools": {"a": "godmode"}}), encoding="utf-8")
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
            "-c",
            "pass",
        ],
        input="",
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 1
    assert "Invalid gateway policy" in proc.stderr


# --- fix-forward: dict keys, last_exchange, detokenize robustness --------

# (rat #66 critique round 1: B1/B2 blocking + A1/A2/A3/A4/A6/A7 advisories)


def test_pii_in_dict_keys_is_tokenized() -> None:
    """B1: a result keyed by an identifier must not leak PII via the key."""
    tokenizer = PiiTokenizer()
    value, applied = tokenizer.tokenize_value({EMAIL: "x", "nested": {PHONE: "y"}, "plain": "ok"})
    assert isinstance(value, dict)
    assert EMAIL not in value and PHONE not in str(value)
    assert value == {"[EMAIL_1]": "x", "nested": {"[PHONE_1]": "y"}, "plain": "ok"}
    assert {a.kind for a in applied} == {PiiKind.EMAIL, PiiKind.PHONE}


def test_detokenize_resolves_tokens_in_dict_keys() -> None:
    """B1 (symmetric): tokens in keys resolve back on later calls."""
    tokenizer = PiiTokenizer()
    tokenizer.tokenize_value({EMAIL: "x"})
    out, n = tokenizer.detokenize_value({"[EMAIL_1]": "call me"})
    assert out == {EMAIL: "call me"}
    assert n == 1


def test_tuple_values_are_tokenized() -> None:
    """A7: tuples recurse like lists ('every string', not 'every string
    except in tuples')."""
    tokenizer = PiiTokenizer()
    value, applied = tokenizer.tokenize_value((EMAIL, ["call", PHONE]))
    assert value == ("[EMAIL_1]", ["call", "[PHONE_1]"])
    assert len(applied) == 2
    out, n = tokenizer.detokenize_value(value)
    assert out == (EMAIL, ["call", PHONE])
    assert n == 2


def test_last_exchange_withholds_the_envelope() -> None:
    """B2: the flight recorder must never hand out detokenized arguments."""
    transport = FakeTransport(
        results={"read_record": {"content": [{"type": "text", "text": f"{EMAIL}"}]}}
    )
    gateway = Gateway(transport, _policy())
    gateway.call_tool("read_record", {"id": "1"}, TrustLevel.HIGH)
    gateway.call_tool("search", {"q": "[EMAIL_1]"}, TrustLevel.HIGH)
    envelope, response_id = gateway.last_exchange()
    assert envelope is None
    assert response_id == 2
    assert EMAIL not in json.dumps(gateway.audit_log.to_json())


def test_last_exchange_is_none_before_any_call_and_after_denial() -> None:
    """B2: no envelope before a call; a denied call invalidates the record,
    so a stale id can never stand in for a call that was never sent."""
    gateway = Gateway(FakeTransport(), _policy())
    assert gateway.last_exchange() == (None, None)
    gateway.call_tool("search", {"q": "x"}, TrustLevel.HIGH)
    assert gateway.last_exchange() == (None, 1)
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("read_record", {"id": "1"}, TrustLevel.LOW)
    assert gateway.last_exchange() == (None, None)


def test_detokenize_with_backslash_value_does_not_raise() -> None:
    """A1: a minted value containing backslashes / group references must
    resolve via a replacement function, never raise re.error."""

    class BackslashDetector:
        def detect(self, text: str) -> list[PiiMatch]:
            idx = text.find("MARKER")
            if idx < 0:
                return []
            return [PiiMatch(kind=PiiKind.API_KEY, start=idx, end=idx + len("MARKER"))]

    tokenizer = PiiTokenizer(detectors=(BackslashDetector(),))
    # Mint a value whose text contains a backslash group reference.
    tokenizer._values["[API_KEY_1]"] = r"C:\temp\1"
    tokenizer._by_value[(PiiKind.API_KEY, r"C:\temp\1")] = "[API_KEY_1]"
    out, n = tokenizer.detokenize_text("key is [API_KEY_1] here")
    assert out == r"key is C:\temp\1 here"
    assert n == 1


def test_detokenize_is_single_pass() -> None:
    """A4: a substituted value is never re-scanned, so a minted value
    containing token-shaped text cannot cascade into a second resolution.

    Setup: [EMAIL_1]..[EMAIL_10] minted, then a span containing the
    literal text "[EMAIL_1]" minted as [EMAIL_11]. Resolving [EMAIL_11]
    must yield the literal inner text, not the value behind [EMAIL_1]."""

    class SpanDetector:
        def detect(self, text: str) -> list[PiiMatch]:
            start = text.find("MARKER")
            if start < 0:
                return []
            end = text.find("END", start) + len("END")
            return [PiiMatch(kind=PiiKind.EMAIL, start=start, end=end)]

    from mcp_guard.gateway import RegexDetector

    tokenizer = PiiTokenizer(detectors=(RegexDetector(), SpanDetector()))
    for i in range(1, 11):
        tokenizer.tokenize_text(f"user{i}@example.com")
    tokenizer.tokenize_text("MARKER [EMAIL_1] END")
    out, n = tokenizer.detokenize_text("see [EMAIL_11]")
    assert out == "see MARKER [EMAIL_1] END"
    assert n == 1


def test_clear_never_rebinds_a_stale_token() -> None:
    """A2: counters are monotonic across clear(), so [EMAIL_1] from a
    previous session can never silently resolve to a new value."""
    tokenizer = PiiTokenizer()
    tokenizer.tokenize_text(EMAIL)
    tokenizer.clear()
    assert tokenizer.token_count == 0
    out, n = tokenizer.detokenize_text("[EMAIL_1]")
    assert out == "[EMAIL_1]" and n == 0
    text, _ = tokenizer.tokenize_text("other@example.com")
    assert "[EMAIL_2]" in text
    assert "[EMAIL_1]" not in text


def test_nineteen_digit_and_dot_separated_cards_tokenize() -> None:
    """A3: real Visa 19-digit cards and dot-separated 16-digit cards are
    cards, not order numbers."""
    tokenizer = PiiTokenizer()
    _, applied = tokenizer.tokenize_text("card 4111111111111111110 here")
    assert [a.kind for a in applied] == [PiiKind.CREDIT_CARD]
    _, applied = tokenizer.tokenize_text("card 4111.1111.1111.1111 here")
    assert [a.kind for a in applied] == [PiiKind.CREDIT_CARD]


def test_string_caller_trust_is_a_type_error_not_attribute_error() -> None:
    """A6: the gateway boundary validates its inputs with a diagnosable
    error instead of crashing on '.rank'."""
    gateway = Gateway(FakeTransport(), _policy())
    with pytest.raises(TypeError, match="caller_trust must be a TrustLevel"):
        gateway.call_tool("search", {"q": "x"}, "high")  # type: ignore[arg-type]


def test_annotate_tools_with_non_string_name_lists_as_unknown() -> None:
    """A6: a malformed tool listing never crashes the trust annotation."""
    gateway = Gateway(FakeTransport(), _policy())
    annotated = gateway.annotate_tools([{"name": 123}])  # type: ignore[list-item]
    assert annotated[0]["mcp_guard_trust_level"] == "low"
