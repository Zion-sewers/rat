"""Mask-then-unmask pipeline for external model calls (rat #74).

Source: Chip Huyen, *AI Engineering* ch.10, input guardrails — detect
sensitive classes, then mask with a placeholder or block the query; if
the response contains the placeholder, use a PII reverse dictionary to
unmask before returning to the user.

This is the harness-side guardrail around an external model call, and
it is deliberately distinct from the gateway's tool-call path
(rat #66): the gateway tokenizes tool results before the model sees
them and resolves tokens back into tool calls; this pipeline masks an
outbound prompt before it is sent to an external model and unmasks the
model's complete response before it reaches the user. The two paths
use separate tokenizer namespaces (see below): a token minted for a
tool result never resolves in a model response, and vice versa.

One pipeline instance is one session:

- ``mask_prompt`` detects, applies the per-class mask-vs-block policy,
  and returns the masked prompt. A blocked class raises
  ``MaskBlockedError`` BEFORE any masked text is handed out — detection
  runs first and mints nothing for a blocked prompt, so a blocked
  value can never be recovered through a later unmask.
- ``unmask_response`` resolves minted placeholders in a COMPLETE
  response only. There is no per-chunk unmask entry point: a streamed
  response goes through ``StreamingResponse``, whose ``feed`` forwards
  each chunk still masked and whose ``finish`` unmasks exactly once,
  at completion.
- ``end_session`` wipes the reverse dictionary and closes the
  pipeline. A placeholder minted in session A never resolves in
  session B: the map is gone and the pipeline refuses further
  mask/unmask calls with ``MaskSessionClosedError`` instead of
  silently returning masked text as if it were final.

The reverse dictionary lives in memory only (the ``PiiTokenizer`` the
pipeline owns) and is never serialized: pipeline audit events record
kinds and counts only, never values, and the pipeline exposes no
accessor to the map. This is the one structure exempt from the
log-everything discipline, as the issue states.

Deliberate boundaries (not hidden):
- Detection is the same two layers as the gateway: layer-1 regex over
  structured formats (email, phone, SSN, Luhn cards, API-key shapes);
  names need the layer-2 ``Detector`` seam, which stays open. A class
  no detector produces (``PiiKind.APPROVER``) cannot appear in a
  mask policy: a rule for it could never fire, so ``from_mapping``
  rejects it instead of letting an operator believe it is enforced.
- Masking is deterministic within a session (same value -> same token,
  so the model can correlate across records) and rotated across
  sessions (monotonic counters + ``clear`` on ``end_session``).
- Only tokens this pipeline minted in this session resolve. Token-shaped
  text it never minted — including a placeholder the model echoes
  without ever seeing — passes through untouched.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from .gateway import PiiKind, PiiTokenizer, TokenApplied
from .transport import JsonDict

__all__ = [
    "MaskAction",
    "MaskBlockedError",
    "MaskEvent",
    "MaskPipeline",
    "MaskPolicy",
    "MaskSessionClosedError",
    "MaskedPrompt",
    "StreamingResponse",
]


class MaskAction(str, Enum):
    """Per-class policy: mask the value, or block the whole prompt."""

    MASK = "mask"
    BLOCK = "block"

    @classmethod
    def parse(cls, value: str) -> MaskAction:
        """Parse a policy-file action string; unknown actions fail closed.

        ValueError names the valid actions only: the rejected value is
        operator-supplied config, but it is echoed nowhere else, and a
        typo must never silently become a mask.
        """
        if not isinstance(value, str):
            raise TypeError("mask action must be a string")
        for action in cls:
            if action.value == value:
                return action
        raise ValueError("unknown mask action: expected one of mask, block")


@dataclass(frozen=True)
class MaskPolicy:
    """Mask-vs-block policy, configurable per sensitive class.

    ``per_kind`` overrides the ``default`` action for listed classes
    only; an unlisted class takes the default. The default is MASK:
    masking preserves answer completeness, blocking is the exception
    an operator opts into per class. ``APPROVER`` can never appear in
    ``per_kind`` — no detector produces it, so a rule for it could
    never fire (rejected in ``from_mapping`` and ``__post_init__``,
    the same dead-entry rule as ``GatewayPolicy.mutating_tools``).
    """

    per_kind: tuple[tuple[PiiKind, MaskAction], ...] = ()
    default: MaskAction = MaskAction.MASK

    def __post_init__(self) -> None:
        """Reject malformed or dead per-kind entries on every path."""
        if not isinstance(self.default, MaskAction):
            raise TypeError(f"mask policy default {self.default!r} is not a MaskAction")
        seen: list[PiiKind] = []
        for entry in self.per_kind:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise TypeError("mask policy per-kind entries must be (PiiKind, MaskAction) pairs")
            kind, action = entry
            if not isinstance(kind, PiiKind):
                raise TypeError(f"mask policy kind {kind!r} is not a PiiKind")
            if not isinstance(action, MaskAction):
                raise TypeError(f"mask policy action {action!r} is not a MaskAction")
            if kind is PiiKind.APPROVER:
                raise ValueError(
                    "mask policy cannot cover 'approver': no detector produces it, "
                    "so the rule could never fire"
                )
            if kind in seen:
                raise ValueError(f"mask policy lists {kind.value!r} twice")
            seen.append(kind)

    def action_for(self, kind: PiiKind) -> MaskAction:
        """The action for one class: its override, or the default."""
        if not isinstance(kind, PiiKind):
            raise TypeError("kind must be a PiiKind")
        for listed_kind, action in self.per_kind:
            if listed_kind is kind:
                return action
        return self.default

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> MaskPolicy:
        """Parse a policy mapping: {"default": "mask"|"block",
        "per_kind": {"email": "mask", "api_key": "block", ...}}.

        Wrong shapes fail closed (TypeError); unknown kind or action
        strings fail closed (ValueError); unknown top-level keys are
        ignored so policy files stay forward-compatible.
        """
        if not isinstance(data, Mapping):
            raise TypeError("mask policy must be a JSON object")
        default_raw = data.get("default", "mask")
        if not isinstance(default_raw, str):
            raise TypeError("mask policy 'default' must be a string")
        default = MaskAction.parse(default_raw)
        per_kind_raw = data.get("per_kind", {})
        if not isinstance(per_kind_raw, Mapping):
            raise TypeError("mask policy 'per_kind' must be an object")
        by_value = {kind.value: kind for kind in PiiKind}
        entries: list[tuple[PiiKind, MaskAction]] = []
        for name, action_raw in per_kind_raw.items():
            if not isinstance(name, str) or not isinstance(action_raw, str):
                raise TypeError(
                    "mask policy 'per_kind' must map string kind names to string actions"
                )
            if name not in by_value:
                raise ValueError(
                    f"mask policy unknown PII kind {name!r}: expected one of "
                    + ", ".join(sorted(by_value))
                )
            kind = by_value[name]
            if kind is PiiKind.APPROVER:
                raise ValueError(
                    "mask policy cannot cover 'approver': no detector produces it, "
                    "so the rule could never fire"
                )
            entries.append((kind, MaskAction.parse(action_raw)))
        return cls(per_kind=tuple(entries), default=default)


class MaskBlockedError(Exception):
    """A prompt was blocked: it contains a block-policy PII class.

    Carries the blocked kinds only, never the matched values.
    """

    def __init__(self, kinds: tuple[PiiKind, ...]) -> None:
        self.kinds = kinds
        names = ", ".join(sorted(kind.value for kind in kinds))
        super().__init__(f"masked prompt blocked: detected {names} (mask policy: block)")


class MaskSessionClosedError(Exception):
    """The pipeline's session ended: no further mask/unmask is possible."""

    def __init__(self) -> None:
        super().__init__("mask pipeline session is closed: call end_session only once")


@dataclass(frozen=True)
class MaskedPrompt:
    """A masked outbound prompt: masked text + what was applied.

    ``masked_text`` carries placeholders only — no raw detected value
    survives in it. ``applied`` names the kind and token per span.
    """

    masked_text: str
    applied: tuple[TokenApplied, ...] = ()

    @property
    def token_kinds(self) -> tuple[str, ...]:
        """Distinct PII kinds masked in this prompt, sorted."""
        return tuple(sorted({a.kind.value for a in self.applied}))


@dataclass(frozen=True)
class MaskEvent:
    """One pipeline audit event: what happened, never the content.

    ``token_kinds`` / ``token_count`` describe how much PII was
    handled; values never appear here (or anywhere the pipeline
    serializes). ``kind`` is one of "masked" / "blocked" / "unmasked" /
    "session_ended".
    """

    kind: str
    timestamp: str
    token_kinds: tuple[str, ...] = ()
    token_count: int = 0

    def to_dict(self) -> JsonDict:
        """Serialize for audit ingestion: kinds and counts only."""
        return {
            "kind": self.kind,
            "timestamp": self.timestamp,
            "token_kinds": list(self.token_kinds),
            "token_count": self.token_count,
        }


class MaskPipeline:
    """Session-scoped mask-then-unmask for one external model call path.

    Owns its ``PiiTokenizer``: tokens minted here resolve here only,
    never against the gateway's tool-call tokens. One instance is one
    session — ``end_session`` wipes the reverse dictionary and closes
    the pipeline; a new session needs a new pipeline.
    """

    def __init__(
        self,
        tokenizer: PiiTokenizer | None = None,
        policy: MaskPolicy | None = None,
    ) -> None:
        self._tokenizer = tokenizer if tokenizer is not None else PiiTokenizer()
        self._policy = policy if policy is not None else MaskPolicy()
        self._events: list[MaskEvent] = []
        self._closed = False

    @property
    def policy(self) -> MaskPolicy:
        """The mask-vs-block policy this pipeline enforces."""
        return self._policy

    @property
    def is_closed(self) -> bool:
        """True after ``end_session``: the reverse dictionary is wiped."""
        return self._closed

    def events(self) -> tuple[MaskEvent, ...]:
        """Audit events so far: kinds and counts only, never values."""
        return tuple(self._events)

    def events_json(self) -> list[JsonDict]:
        """Serialize the audit events for ingestion."""
        return [e.to_dict() for e in self._events]

    def _record(self, kind: str, token_kinds: tuple[str, ...], token_count: int) -> None:
        self._events.append(
            MaskEvent(
                kind=kind,
                timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
                token_kinds=token_kinds,
                token_count=token_count,
            )
        )

    def mask_prompt(self, prompt: str) -> MaskedPrompt:
        """Mask an outbound prompt; block-policy classes raise first.

        Detection runs BEFORE any minting: a prompt blocked on a
        class leaves no token for that value in the reverse dictionary,
        so a later response echoing the placeholder cannot recover it.
        Detection is run twice (once to decide, once to mask) — the
        honest price of block-before-mint; detectors are regex over
        the prompt, not a model call.
        """
        if not isinstance(prompt, str):
            raise TypeError("prompt must be a string")
        if self._closed:
            raise MaskSessionClosedError()
        kinds = self._tokenizer.detect_kinds(prompt)
        blocked = tuple(k for k in kinds if self._policy.action_for(k) is MaskAction.BLOCK)
        if blocked:
            blocked_names = tuple(sorted(k.value for k in blocked))
            self._record("blocked", blocked_names, len(blocked))
            raise MaskBlockedError(blocked)
        masked_text, applied = self._tokenizer.tokenize_text(prompt)
        applied_kinds = tuple(sorted({a.kind.value for a in applied}))
        self._record("masked", applied_kinds, len(applied))
        return MaskedPrompt(masked_text=masked_text, applied=applied)

    def unmask_response(self, response: str) -> tuple[str, int]:
        """Resolve minted placeholders in a COMPLETE response only.

        Only tokens this pipeline minted in this session resolve;
        anything else passes through untouched. Never call this on a
        partial stream: use ``new_stream`` / ``finish`` for streamed
        responses, so no placeholder is unmasked mid-stream.
        """
        if not isinstance(response, str):
            raise TypeError("response must be a string")
        if self._closed:
            raise MaskSessionClosedError()
        text, resolved = self._tokenizer.detokenize_text(response)
        self._record("unmasked", (), resolved)
        return text, resolved

    def new_stream(self) -> StreamingResponse:
        """Open a streamed response: chunks stay masked until ``finish``."""
        if self._closed:
            raise MaskSessionClosedError()
        return StreamingResponse(self)

    def end_session(self) -> None:
        """Wipe the reverse dictionary and close the pipeline.

        Idempotent: a harness ``finally`` block may call it twice.
        After this, placeholders minted in this session resolve
        nowhere — a new session needs a new pipeline.
        """
        if self._closed:
            return
        self._tokenizer.clear()
        self._closed = True
        self._record("session_ended", (), 0)


class StreamingResponse:
    """One streamed model response: masked while flowing, unmasked once.

    ``feed`` returns each chunk unchanged — placeholders and all — so
    the harness can forward it without ever seeing raw PII mid-stream.
    ``finish`` joins the buffered chunks and unmasks exactly once, at
    completion. There is deliberately no per-chunk unmask method: a
    placeholder is never unmasked before the response is complete.
    """

    def __init__(self, pipeline: MaskPipeline) -> None:
        self._pipeline = pipeline
        self._chunks: list[str] = []
        self._finished = False

    @property
    def is_finished(self) -> bool:
        """True after ``finish``: no more chunks may be fed."""
        return self._finished

    def feed(self, chunk: str) -> str:
        """Buffer one chunk and return it unchanged (still masked)."""
        if not isinstance(chunk, str):
            raise TypeError("chunk must be a string")
        if self._finished:
            raise ValueError("stream already finished: feed no more chunks")
        if self._pipeline.is_closed:
            raise MaskSessionClosedError()
        self._chunks.append(chunk)
        return chunk

    def finish(self) -> tuple[str, int]:
        """Unmask the complete buffered response, exactly once.

        The stream is marked finished only after the unmask succeeds:
        if the session closed mid-stream, the finish raises and the
        stream stays unfinished, so the failure stays loud instead of
        masquerading as a completed (still masked) response.
        """
        if self._finished:
            raise ValueError("stream already finished")
        result = self._pipeline.unmask_response("".join(self._chunks))
        self._finished = True
        return result
