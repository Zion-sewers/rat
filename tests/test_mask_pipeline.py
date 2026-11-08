"""Mask-then-unmask pipeline for external model calls (rat #74).

Every test here is adversarial: a blocked value must never be
recoverable through a later unmask, a placeholder must never resolve
outside the session that minted it, no placeholder may be unmasked
mid-stream, and the reverse dictionary must never reach any
serialized surface. PII fixtures use example.com / 555 numbers / the
standard Luhn-passing test card so no real personal data appears
anywhere.

Pipeline tokens carry a per-instance session tag
(``[MASKn_EMAIL_1]``), so tests never hardcode a token string: they
read the minted token from ``MaskedPrompt.applied`` instead.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_guard.gateway import PiiKind, PiiMatch, PiiTokenizer
from mcp_guard.mask_pipeline import (
    MaskAction,
    MaskBlockedError,
    MaskPipeline,
    MaskPolicy,
    MaskSessionClosedError,
)

EMAIL = "jane.doe@example.com"
OTHER_EMAIL = "other@example.com"
PHONE = "555-123-4567"
SSN = "123-45-6789"
CARD = "4111-1111-1111-1111"  # Luhn-passing test number
# Synthetic fixture, never a real key: built from parts so the repo's
# secret-scan does not trip on a test constant.
API_KEY = "sk-" + "testkey1234567890"


class FakeModelClient:
    """Stand-in for an external model: it sees only masked text.

    ``complete`` / ``stream`` record every prompt they receive, so a
    test can prove raw PII never reached the model, and they echo the
    placeholders back, the way a model that was shown tokens answers.
    """

    def __init__(self) -> None:
        self.received: list[str] = []

    def complete(self, prompt: str) -> str:
        """One complete response echoing the masked prompt."""
        self.received.append(prompt)
        return f"Noted: {prompt}. I will help."

    def stream(self, prompt: str) -> list[str]:
        """Chunks echoing the masked prompt, one split mid-token."""
        self.received.append(prompt)
        half = len(prompt) // 2
        return [f"Noted: {prompt[:half]}", f"{prompt[half:]}. I will help."]


# --- round-trip: mask, then unmask a complete response ----------------


def test_round_trip_restores_values_and_masked_text_carries_none() -> None:
    """A1: mask -> model echoes placeholders -> unmask restores all.

    The masked prompt must contain none of the raw values (detection
    without masking is not protection), and the unmasked response must
    restore every value exactly.
    """
    pipeline = MaskPipeline()
    prompt = f"email {EMAIL}, call {PHONE}, ssn {SSN}, card {CARD}"
    masked = pipeline.mask_prompt(prompt)
    for raw in (EMAIL, PHONE, SSN, CARD):
        assert raw not in masked.masked_text
    assert masked.token_kinds == ("credit_card", "email", "phone", "ssn")
    response = f"contact {masked.masked_text} for details"
    text, resolved = pipeline.unmask_response(response)
    assert resolved == 4
    assert text == f"contact {prompt} for details"


def test_api_key_round_trip_restores_the_value() -> None:
    """A1b: the api_key class round-trips like the rest (earlier the
    suite only asserted its absence, never its restoration)."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"key is {API_KEY}")
    assert API_KEY not in masked.masked_text
    text, resolved = pipeline.unmask_response(f"use {masked.masked_text} now")
    assert text == f"use key is {API_KEY} now"
    assert resolved == 1


def test_same_value_same_token_different_values_different_tokens() -> None:
    """A2: determinism within a session (correlation) without collision."""
    pipeline = MaskPipeline()
    first = pipeline.mask_prompt(f"a {EMAIL} b {EMAIL} c")
    token = first.applied[0].token
    assert first.masked_text.count(token) == 2
    second = pipeline.mask_prompt(f"d {OTHER_EMAIL} e")
    assert second.applied[0].token != token
    assert token not in second.masked_text


def test_unminted_token_shaped_text_passes_through_untouched() -> None:
    """A3: a model echoing a placeholder it never saw recovers nothing."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}")
    never_minted = masked.applied[0].token.replace("_1]", "_9]")
    text, resolved = pipeline.unmask_response(f"see {never_minted} and [PHONE_3]")
    assert text == f"see {never_minted} and [PHONE_3]"
    assert resolved == 0


def test_literal_placeholder_shaped_user_text_never_resolves() -> None:
    """A4: user text that already looks like a placeholder is not PII
    and must never resolve to another value's secret."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt("my token is [EMAIL_1], ignore it")
    assert masked.applied == ()
    assert masked.masked_text == "my token is [EMAIL_1], ignore it"
    text, resolved = pipeline.unmask_response("echo [EMAIL_1] back")
    assert text == "echo [EMAIL_1] back"
    assert resolved == 0


def test_pipeline_tokens_do_not_resolve_against_the_gateway() -> None:
    """A5: separate namespaces, checkable from the token string alone.
    The gateway mints [EMAIL_1]; the pipeline mints a tagged token;
    neither resolves against the other's map."""
    gateway_tokenizer = PiiTokenizer()
    gateway_tokenizer.tokenize_text(f"reach {EMAIL}")
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {OTHER_EMAIL}")
    pipeline_token = masked.applied[0].token
    assert pipeline_token != "[EMAIL_1]"
    assert pipeline_token.startswith("[MASK")
    text, resolved = pipeline.unmask_response("see [EMAIL_1]")
    assert text == "see [EMAIL_1]"
    assert resolved == 0
    out, n = gateway_tokenizer.detokenize_text(f"see {pipeline_token}")
    assert out == f"see {pipeline_token}"
    assert n == 0


def test_empty_prompt_and_empty_response_are_noops() -> None:
    """A6: empty strings mask/unmask cleanly instead of erroring."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt("")
    assert masked.masked_text == ""
    assert masked.applied == ()
    text, resolved = pipeline.unmask_response("")
    assert text == ""
    assert resolved == 0


# --- per-class mask-vs-block policy -----------------------------------


def test_block_policy_denies_before_any_masked_text_leaves() -> None:
    """B1: a blocked class raises; no masked prompt is ever returned,
    and the error names kinds only, never values."""
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    with pytest.raises(MaskBlockedError) as excinfo:
        pipeline.mask_prompt(f"key is {API_KEY} and mail {EMAIL}")
    assert "api_key" in str(excinfo.value)
    assert API_KEY not in str(excinfo.value)
    assert excinfo.value.kinds == (PiiKind.API_KEY,)
    assert pipeline.events()[0].kind == "blocked"
    assert pipeline.events()[0].token_kinds == ("api_key",)


def test_blocked_event_counts_spans_not_kinds() -> None:
    """B1b: a blocked event's token_count counts spans (two api_key
    values -> 2), the same unit as "masked" events — not distinct
    kinds, which would read 1 here and understate what was blocked."""
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    other_key = "sk-" + "otherkey1234567890"
    with pytest.raises(MaskBlockedError):
        pipeline.mask_prompt(f"keys {API_KEY} and {other_key}")
    event = pipeline.events_json()[0]
    assert event["kind"] == "blocked"
    assert event["token_kinds"] == ["api_key"]
    assert event["token_count"] == 2


def test_blocked_value_leaves_no_token_to_recover_later() -> None:
    """B2: block-before-mint in a single pass — a blocked prompt mints
    nothing recoverable, so a later response echoing the would-be
    placeholder recovers nothing. This is the exfil path a
    mint-then-keep design would leave open: the response channel is
    attacker-influenced, and the model never saw the placeholder, so
    it must not resolve."""
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    allowed = pipeline.mask_prompt(f"reach {EMAIL}")
    email_token = allowed.applied[0].token
    would_be_key_token = email_token.replace("EMAIL_1", "API_KEY_1")
    with pytest.raises(MaskBlockedError):
        pipeline.mask_prompt(f"key is {API_KEY}")
    text, resolved = pipeline.unmask_response(f"the key is {would_be_key_token}")
    assert text == f"the key is {would_be_key_token}"
    assert resolved == 0
    # The allowed class still resolves: the block revoked only its own mint.
    text, resolved = pipeline.unmask_response(f"reach {email_token}")
    assert text == f"reach {EMAIL}"
    assert resolved == 1


def test_blocked_prompt_never_revokes_an_earlier_prompts_tokens() -> None:
    """B2b: revoke is fresh-only — a blocked prompt that shares a value
    with an earlier, already-disclosed prompt must not break that
    prompt's unmasking. The earlier prompt went to the model; its
    response echoing the token must still resolve."""
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    first = pipeline.mask_prompt(f"reach {EMAIL}")
    first_token = first.applied[0].token
    with pytest.raises(MaskBlockedError):
        pipeline.mask_prompt(f"key is {API_KEY} and reach {EMAIL}")
    text, resolved = pipeline.unmask_response(f"done, reach {first_token}")
    assert text == f"done, reach {EMAIL}"
    assert resolved == 1


def test_non_blocked_classes_still_mask_under_a_block_policy() -> None:
    """B3: blocking one class does not break masking for the rest."""
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    masked = pipeline.mask_prompt(f"reach {EMAIL} or {PHONE}")
    assert EMAIL not in masked.masked_text
    assert PHONE not in masked.masked_text
    assert len(masked.applied) == 2


def test_default_block_blocks_every_detected_class() -> None:
    """B4: default=block is fail-closed for every class at once."""
    pipeline = MaskPipeline(policy=MaskPolicy(default=MaskAction.BLOCK))
    with pytest.raises(MaskBlockedError) as excinfo:
        pipeline.mask_prompt(f"reach {EMAIL}")
    assert excinfo.value.kinds == (PiiKind.EMAIL,)


def test_default_policy_masks_everything() -> None:
    """B5: with no policy file at all, every detected class masks."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"key {API_KEY} mail {EMAIL}")
    assert API_KEY not in masked.masked_text
    assert EMAIL not in masked.masked_text


# --- policy parsing fails closed --------------------------------------


def test_policy_parsing_rejects_unknown_kind_action_and_shapes() -> None:
    """C1: unknown kind/action strings and wrong shapes fail closed,
    never silently default to mask."""
    with pytest.raises(ValueError, match="unknown PII kind"):
        MaskPolicy.from_mapping({"per_kind": {"name": "mask"}})
    with pytest.raises(ValueError, match="unknown mask action"):
        MaskPolicy.from_mapping({"per_kind": {"email": "redact"}})
    with pytest.raises(ValueError, match="unknown mask action"):
        MaskPolicy.from_mapping({"default": "allow"})
    with pytest.raises(TypeError):
        MaskPolicy.from_mapping({"default": 3})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        MaskPolicy.from_mapping({"per_kind": ["email"]})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        MaskPolicy.from_mapping("mask")  # type: ignore[arg-type]


def test_policy_rejects_unknown_top_level_keys() -> None:
    """C1b: a typo'd key such as "per_kinds" must fail loudly instead
    of silently dropping every block rule and falling back to
    mask-everything."""
    with pytest.raises(ValueError, match="unknown key"):
        MaskPolicy.from_mapping({"per_kinds": {"api_key": "block"}})
    with pytest.raises(ValueError, match="unknown key"):
        MaskPolicy.from_mapping({"default": "mask", "future": True})


def test_policy_rejects_approver_as_a_dead_rule() -> None:
    """C2: 'approver' is never produced by any detector, so a rule for
    it could never fire — rejected, not silently accepted."""
    with pytest.raises(ValueError, match="approver"):
        MaskPolicy.from_mapping({"per_kind": {"approver": "block"}})
    with pytest.raises(ValueError, match="approver"):
        MaskPolicy(per_kind=((PiiKind.APPROVER, MaskAction.BLOCK),))


def test_policy_accepts_only_known_keys() -> None:
    """C3: the two known keys parse; nothing else is needed."""
    policy = MaskPolicy.from_mapping({"default": "mask", "per_kind": {"api_key": "block"}})
    assert policy.action_for(PiiKind.API_KEY) is MaskAction.BLOCK
    assert policy.action_for(PiiKind.EMAIL) is MaskAction.MASK


def test_direct_construction_validates_like_from_mapping() -> None:
    """C4: the dead-entry and shape rules hold on the direct path too,
    not just the file-load path."""
    with pytest.raises(ValueError, match="twice"):
        MaskPolicy(
            per_kind=(
                (PiiKind.EMAIL, MaskAction.MASK),
                (PiiKind.EMAIL, MaskAction.BLOCK),
            )
        )
    with pytest.raises(TypeError):
        MaskPolicy(per_kind=((PiiKind.EMAIL, "mask"),))  # type: ignore[tuple-item]
    with pytest.raises(TypeError):
        MaskPolicy(default="mask")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        MaskPolicy().action_for("email")  # type: ignore[arg-type]


def test_pipeline_rejects_a_non_policy_at_construction() -> None:
    """C5: a mistyped policy fails at construction with a diagnosable
    error, not later as AttributeError inside mask_prompt."""
    with pytest.raises(TypeError, match="must be a MaskPolicy"):
        MaskPipeline(policy="mask")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a tuple of Detector"):
        MaskPipeline(detectors="regex")  # type: ignore[arg-type]


# --- session scoping: rotation, no cross-session resolution ------------


def test_two_pipelines_mint_different_strings_for_same_value() -> None:
    """D0: the session tag — two pipelines mint different strings for
    the same value, so no placeholder string is shared across
    sessions in one process (across processes the 64-bit random tag
    makes a shared string negligible, see the subprocess test)."""
    first = MaskPipeline()
    second = MaskPipeline()
    a = first.mask_prompt(f"reach {EMAIL}").applied[0].token
    b = second.mask_prompt(f"reach {EMAIL}").applied[0].token
    assert a != b
    assert re.fullmatch(r"\[MASK[0-9a-f]{16}_EMAIL_1\]", a) is not None
    assert re.fullmatch(r"\[MASK[0-9a-f]{16}_EMAIL_1\]", b) is not None


def test_session_tags_differ_across_processes() -> None:
    """D0b: rotation holds across process restarts, not just within
    one process — two separate interpreters mint different token
    strings for the same value, so a stale placeholder from a dead
    process can never resolve in a fresh one."""
    repo_root = Path(__file__).resolve().parent.parent
    code = (
        "import sys; sys.path.insert(0, 'src');"
        "from mcp_guard.mask_pipeline import MaskPipeline;"
        f"print(MaskPipeline().mask_prompt('reach {EMAIL}').applied[0].token)"
    )
    tokens: list[str] = []
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=repo_root,
            check=True,
            timeout=30,
        )
        tokens.append(proc.stdout.strip())
    assert tokens[0] != tokens[1]
    assert re.fullmatch(r"\[MASK[0-9a-f]{16}_EMAIL_1\]", tokens[0]) is not None


def test_session_a_placeholder_never_resolves_in_session_b() -> None:
    """D1: the issue's core criterion, on the aliasing case the old
    suite missed — session B mints a DIFFERENT value first, and a
    stale session-A placeholder must still resolve to nothing."""
    session_a = MaskPipeline()
    a_token = session_a.mask_prompt(f"reach {EMAIL}").applied[0].token
    session_a.end_session()
    session_b = MaskPipeline()
    session_b.mask_prompt(f"reach {OTHER_EMAIL}")
    text, resolved = session_b.unmask_response(f"contact {a_token} now")
    assert text == f"contact {a_token} now"
    assert resolved == 0


def test_closed_pipeline_refuses_mask_and_unmask() -> None:
    """D2: after end_session the pipeline raises instead of silently
    returning masked text as if it were a final answer."""
    pipeline = MaskPipeline()
    pipeline.mask_prompt(f"reach {EMAIL}")
    pipeline.end_session()
    assert pipeline.is_closed
    with pytest.raises(MaskSessionClosedError):
        pipeline.mask_prompt(f"reach {EMAIL}")
    with pytest.raises(MaskSessionClosedError):
        pipeline.unmask_response("contact [EMAIL_1]")
    with pytest.raises(MaskSessionClosedError):
        pipeline.new_stream()


def test_end_session_is_idempotent() -> None:
    """D3: a harness finally-block may close twice without an error."""
    pipeline = MaskPipeline()
    pipeline.end_session()
    pipeline.end_session()
    assert pipeline.is_closed
    assert pipeline.events()[-1].kind == "session_ended"


def test_closed_error_names_the_real_rule() -> None:
    """D3b: the closed-session error tells the operator the rule that
    was broken (mask/unmask only within the session), not the
    idempotent end_session call."""
    pipeline = MaskPipeline()
    pipeline.end_session()
    with pytest.raises(MaskSessionClosedError, match="only within the session"):
        pipeline.mask_prompt("x")


def test_tokenizer_is_owned_not_injected() -> None:
    """D4: the pipeline constructs its own tokenizer; there is no
    parameter that could share a reverse dictionary with the gateway
    or a sibling pipeline, and no end_session can wipe a map it does
    not own."""
    with pytest.raises(TypeError):
        MaskPipeline(tokenizer=PiiTokenizer())  # type: ignore[call-arg]
    first = MaskPipeline()
    second = MaskPipeline()
    first.mask_prompt(f"reach {EMAIL}")
    first.end_session()
    # The sibling session is untouched by the first pipeline's close.
    masked = second.mask_prompt(f"reach {OTHER_EMAIL}")
    assert len(masked.applied) == 1


def test_custom_detector_plugs_in_without_sharing_state() -> None:
    """D5: the detectors seam (not a tokenizer) is the customization
    point: a custom detector's spans mask under this pipeline's own
    session tag, and nothing is shared with other pipelines."""

    class SpanDetector:
        def detect(self, text: str) -> list[PiiMatch]:
            start = text.find("MARKER")
            if start < 0:
                return []
            end = text.find("END", start) + len("END")
            return [PiiMatch(kind=PiiKind.EMAIL, start=start, end=end)]

    pipeline = MaskPipeline(detectors=(SpanDetector(),))
    masked = pipeline.mask_prompt("say MARKER hello END now")
    assert "MARKER" not in masked.masked_text
    assert masked.applied[0].token.startswith("[MASK")
    text, resolved = pipeline.unmask_response(masked.masked_text)
    assert text == "say MARKER hello END now"
    assert resolved == 1


def test_revoke_withdraws_tokens_without_rebinding() -> None:
    """D6: tokenizer-level revoke — withdrawn tokens resolve to
    nothing, and re-minting the same value takes a NEW number, so a
    revoked string can never rebind to a different value."""
    tokenizer = PiiTokenizer()
    _, applied = tokenizer.tokenize_text(EMAIL)
    assert tokenizer.token_count == 1
    tokenizer.revoke(applied)
    assert tokenizer.token_count == 0
    out, n = tokenizer.detokenize_text(applied[0].token)
    assert out == applied[0].token
    assert n == 0
    _, applied2 = tokenizer.tokenize_text(EMAIL)
    assert applied2[0].token != applied[0].token
    out, n = tokenizer.detokenize_text(applied2[0].token)
    assert out == EMAIL
    assert n == 1


def test_revoke_rejects_non_token_items_before_mutating() -> None:
    """D6b: revoke validates its items first: a bad item raises before
    any token is withdrawn, so a mistyped call cannot half-revoke."""
    tokenizer = PiiTokenizer()
    _, applied = tokenizer.tokenize_text(EMAIL)
    with pytest.raises(TypeError):
        tokenizer.revoke(("not-a-token",))  # type: ignore[tuple-item]
    assert tokenizer.token_count == 1
    # Mixed tuple: the valid entry must survive the raise untouched.
    with pytest.raises(TypeError):
        tokenizer.revoke((applied[0], "not-a-token"))  # type: ignore[tuple-item]
    assert tokenizer.token_count == 1
    out, n = tokenizer.detokenize_text(applied[0].token)
    assert out == EMAIL
    assert n == 1
    tokenizer.revoke(applied)
    assert tokenizer.token_count == 0


# --- streaming: no mid-stream unmask -----------------------------------


def test_streaming_chunks_stay_masked_until_finish() -> None:
    """E1: feed returns each chunk unchanged (placeholders intact, raw
    values absent); only finish unmasks, exactly once."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}")
    token = masked.applied[0].token
    stream = pipeline.new_stream()
    first = stream.feed(f"Hello {masked.masked_text}, ")
    assert EMAIL not in first
    assert token in first
    second = stream.feed("thanks!")
    assert second == "thanks!"
    text, resolved = stream.finish()
    assert resolved == 1
    assert text == f"Hello reach {EMAIL}, thanks!"
    assert stream.is_finished


def test_streaming_finish_twice_and_feed_after_finish_raise() -> None:
    """E2: finish is exactly-once; a finished stream takes no more chunks."""
    pipeline = MaskPipeline()
    stream = pipeline.new_stream()
    stream.feed("hi")
    stream.finish()
    with pytest.raises(ValueError, match="already finished"):
        stream.finish()
    with pytest.raises(ValueError, match="already finished"):
        stream.feed("late")


def test_streaming_close_before_finish_refuses_to_unmask() -> None:
    """E3: ending the session mid-stream means the buffered response
    can never be unmasked — it fails loudly, never silently masked —
    and the buffered (still masked) text stays retrievable."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}")
    stream = pipeline.new_stream()
    stream.feed(masked.masked_text)
    pipeline.end_session()
    with pytest.raises(MaskSessionClosedError):
        stream.finish()
    with pytest.raises(MaskSessionClosedError):
        stream.feed("more")
    assert stream.buffered_text == masked.masked_text
    assert EMAIL not in stream.buffered_text


def test_empty_stream_finishes_cleanly() -> None:
    """E4: a response with no chunks and no placeholders is a no-op."""
    pipeline = MaskPipeline()
    stream = pipeline.new_stream()
    text, resolved = stream.finish()
    assert text == ""
    assert resolved == 0


# --- end-to-end: a model client in the loop ----------------------------


def test_fake_model_client_end_to_end() -> None:
    """F0: the whole loop with a client between mask and unmask — the
    model receives no raw PII, and the final answer is complete."""
    client = FakeModelClient()
    pipeline = MaskPipeline()
    try:
        masked = pipeline.mask_prompt(f"contact {EMAIL} or {PHONE}")
        raw_response = client.complete(masked.masked_text)
        answer, resolved = pipeline.unmask_response(raw_response)
    finally:
        pipeline.end_session()
    for received in client.received:
        assert EMAIL not in received
        assert PHONE not in received
    assert resolved == 2
    assert answer == f"Noted: contact {EMAIL} or {PHONE}. I will help."


def test_fake_model_client_blocked_prompt_never_reaches_the_model() -> None:
    """F0b: under a block policy the client is never called at all."""
    client = FakeModelClient()
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    try:
        with pytest.raises(MaskBlockedError):
            pipeline.mask_prompt(f"key is {API_KEY}")
    finally:
        pipeline.end_session()
    assert client.received == []


def test_fake_model_client_streaming_end_to_end() -> None:
    """F0c: the streamed loop — chunks flow masked (one split
    mid-token), finish restores the complete answer."""
    client = FakeModelClient()
    pipeline = MaskPipeline()
    try:
        masked = pipeline.mask_prompt(f"reach {EMAIL} please")
        stream = pipeline.new_stream()
        for chunk in client.stream(masked.masked_text):
            forwarded = stream.feed(chunk)
            assert EMAIL not in forwarded
        answer, resolved = stream.finish()
    finally:
        pipeline.end_session()
    assert client.received == [masked.masked_text]
    assert resolved == 1
    assert answer == f"Noted: reach {EMAIL} please. I will help."


# --- the reverse dictionary never reaches a serialized surface ---------


def test_audit_events_and_reprs_carry_no_raw_values() -> None:
    """G1: events JSON, the pipeline repr, and the masked-prompt repr
    contain kinds and counts only — the raw values appear nowhere."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}, key {API_KEY}")
    pipeline.unmask_response(masked.masked_text)
    blob = json.dumps(pipeline.events_json())
    for raw in (EMAIL, API_KEY):
        assert raw not in blob
        assert raw not in repr(pipeline)
        assert raw not in repr(masked)
    kinds = [e["kind"] for e in pipeline.events_json()]
    assert kinds == ["masked", "unmasked"]
    assert pipeline.events_json()[0]["token_kinds"] == ["api_key", "email"]


def test_unmasked_events_carry_the_restored_kinds() -> None:
    """G2: an unmasked event names which kinds were restored, not just
    a count — an operator auditing what came back sees the kinds."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}, call {PHONE}")
    pipeline.unmask_response(f"done {masked.masked_text}")
    event = pipeline.events_json()[-1]
    assert event["kind"] == "unmasked"
    assert event["token_kinds"] == ["email", "phone"]
    assert event["token_count"] == 2


def test_non_string_inputs_fail_with_a_type_error() -> None:
    """G3: malformed inputs fail diagnosably instead of crashing inside
    a detector or the stream buffer."""
    pipeline = MaskPipeline()
    with pytest.raises(TypeError):
        pipeline.mask_prompt(123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        pipeline.unmask_response(None)  # type: ignore[arg-type]
    stream = pipeline.new_stream()
    with pytest.raises(TypeError):
        stream.feed(b"bytes")  # type: ignore[arg-type]
