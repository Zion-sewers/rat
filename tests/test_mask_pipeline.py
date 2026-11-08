"""Mask-then-unmask pipeline for external model calls (rat #74).

Every test here is adversarial: a blocked value must never be
recoverable through a later unmask, a placeholder must never resolve
outside the session that minted it, no placeholder may be unmasked
mid-stream, and the reverse dictionary must never reach any
serialized surface. PII fixtures use example.com / 555 numbers / the
standard Luhn-passing test card so no real personal data appears
anywhere.
"""

from __future__ import annotations

import json

import pytest

from mcp_guard.gateway import PiiKind, PiiTokenizer
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


def test_same_value_same_token_different_values_different_tokens() -> None:
    """A2: determinism within a session (correlation) without collision."""
    pipeline = MaskPipeline()
    first = pipeline.mask_prompt(f"a {EMAIL} b {EMAIL} c")
    assert first.masked_text.count("[EMAIL_1]") == 2
    second = pipeline.mask_prompt(f"d {OTHER_EMAIL} e")
    assert "[EMAIL_2]" in second.masked_text
    assert "[EMAIL_1]" not in second.masked_text


def test_unminted_token_shaped_text_passes_through_untouched() -> None:
    """A3: a model echoing a placeholder it never saw recovers nothing."""
    pipeline = MaskPipeline()
    pipeline.mask_prompt(f"reach {EMAIL}")
    text, resolved = pipeline.unmask_response("see [EMAIL_9] and [PHONE_3]")
    assert text == "see [EMAIL_9] and [PHONE_3]"
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


def test_pipeline_tokens_do_not_resolve_in_a_fresh_tokenizer() -> None:
    """A5: separate namespace — gateway/tool-call tokens and pipeline
    tokens never resolve against each other."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}")
    assert "[EMAIL_1]" in masked.masked_text
    fresh = PiiTokenizer()
    text, resolved = fresh.detokenize_text("[EMAIL_1]")
    assert text == "[EMAIL_1]"
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


def test_blocked_value_leaves_no_token_to_recover_later() -> None:
    """B2: block-before-mint — a blocked prompt mints nothing, so a
    later response echoing the would-be placeholder recovers nothing.
    This is the exfil path a mint-then-block design would leave open:
    the response channel is attacker-influenced, and the model never
    saw the placeholder, so it must not resolve."""
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    with pytest.raises(MaskBlockedError):
        pipeline.mask_prompt(f"key is {API_KEY}")
    text, resolved = pipeline.unmask_response("the key is [API_KEY_1]")
    assert text == "the key is [API_KEY_1]"
    assert resolved == 0


def test_non_blocked_classes_still_mask_under_a_block_policy() -> None:
    """B3: blocking one class does not break masking for the rest."""
    policy = MaskPolicy.from_mapping({"per_kind": {"api_key": "block"}})
    pipeline = MaskPipeline(policy=policy)
    masked = pipeline.mask_prompt(f"reach {EMAIL} or {PHONE}")
    assert EMAIL not in masked.masked_text
    assert PHONE not in masked.masked_text
    assert "[EMAIL_1]" in masked.masked_text
    assert "[PHONE_1]" in masked.masked_text


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


def test_policy_rejects_approver_as_a_dead_rule() -> None:
    """C2: 'approver' is never produced by any detector, so a rule for
    it could never fire — rejected, not silently accepted."""
    with pytest.raises(ValueError, match="approver"):
        MaskPolicy.from_mapping({"per_kind": {"approver": "block"}})
    with pytest.raises(ValueError, match="approver"):
        MaskPolicy(per_kind=((PiiKind.APPROVER, MaskAction.BLOCK),))


def test_policy_ignores_unknown_top_level_keys() -> None:
    """C3: forward-compatible — unknown keys do not break parsing."""
    policy = MaskPolicy.from_mapping(
        {"default": "mask", "per_kind": {"api_key": "block"}, "future": True}
    )
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


# --- session scoping: rotation, no cross-session resolution ------------


def test_session_a_placeholder_never_resolves_in_session_b() -> None:
    """D1: the issue's core criterion — end the session, start a new
    pipeline, and session A's placeholder resolves to nothing."""
    session_a = MaskPipeline()
    masked = session_a.mask_prompt(f"reach {EMAIL}")
    assert "[EMAIL_1]" in masked.masked_text
    session_a.end_session()
    session_b = MaskPipeline()
    text, resolved = session_b.unmask_response("contact [EMAIL_1] now")
    assert text == "contact [EMAIL_1] now"
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


def test_detect_kinds_mints_nothing() -> None:
    """D4: the block-decision probe leaves the reverse dictionary empty,
    so deciding never creates a token an attacker could resolve."""
    tokenizer = PiiTokenizer()
    kinds = tokenizer.detect_kinds(f"{EMAIL} and {PHONE}")
    assert kinds == (PiiKind.EMAIL, PiiKind.PHONE)
    assert tokenizer.token_count == 0
    with pytest.raises(TypeError):
        tokenizer.detect_kinds(123)  # type: ignore[arg-type]


# --- streaming: no mid-stream unmask -----------------------------------


def test_streaming_chunks_stay_masked_until_finish() -> None:
    """E1: feed returns each chunk unchanged (placeholders intact, raw
    values absent); only finish unmasks, exactly once."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}")
    stream = pipeline.new_stream()
    first = stream.feed(f"Hello {masked.masked_text}, ")
    assert EMAIL not in first
    assert "[EMAIL_1]" in first
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
    can never be unmasked — it fails loudly, never silently masked."""
    pipeline = MaskPipeline()
    masked = pipeline.mask_prompt(f"reach {EMAIL}")
    stream = pipeline.new_stream()
    stream.feed(masked.masked_text)
    pipeline.end_session()
    with pytest.raises(MaskSessionClosedError):
        stream.finish()
    with pytest.raises(MaskSessionClosedError):
        stream.feed("more")


def test_empty_stream_finishes_cleanly() -> None:
    """E4: a response with no chunks and no placeholders is a no-op."""
    pipeline = MaskPipeline()
    stream = pipeline.new_stream()
    text, resolved = stream.finish()
    assert text == ""
    assert resolved == 0


# --- the reverse dictionary never reaches a serialized surface ---------


def test_audit_events_and_reprs_carry_no_raw_values() -> None:
    """F1: events JSON, the pipeline repr, and the masked-prompt repr
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


def test_non_string_inputs_fail_with_a_type_error() -> None:
    """F2: malformed inputs fail diagnosably instead of crashing inside
    a detector or the stream buffer."""
    pipeline = MaskPipeline()
    with pytest.raises(TypeError):
        pipeline.mask_prompt(123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        pipeline.unmask_response(None)  # type: ignore[arg-type]
    stream = pipeline.new_stream()
    with pytest.raises(TypeError):
        stream.feed(b"bytes")  # type: ignore[arg-type]
