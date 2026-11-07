"""Central MCP gateway — trust levels + pre-model tokenization (rat #66).

The gateway is the single choke point between an agent and MCP servers.
It enforces three properties from the source
(Perplexity "MCP Sensitive Data Integration Best Practices", catalog B.6):

1. Trust-level enforcement in the request path: a call whose declared
   caller trust is lower than the target tool's trust is DENIED before it
   reaches the server. A low-trust tool can never trigger a high-trust read.
2. PII tokenization before any model call: tool results are tokenized
   before they are returned, and tokens are resolved back only when the
   agent passes them into a later tool call.
3. Audit events, never content: the audit log records the fact of access
   (tool, levels, token kinds and counts), never values.

Deliberate boundaries (not hidden):
- The gateway enforces policy over the caller's DECLARED trust level. MCP
  tools/call carries no caller identity, so the gateway cannot authenticate
  who is calling; the agent harness declares it. An undeclared caller is
  LOW (least privilege, never root). Identity authentication (OAuth / JWT /
  mTLS per the source) is a deployment concern outside this stdlib library.
- Layer-1 PII detection is regex only (structured PII: email, phone, SSN,
  card numbers, API-key shapes). Names and addresses need the layer-2 NLP
  detector, which is a pluggable ``Detector`` seam — ship regex-only, gap
  documented, never claimed as complete.
- The token -> value mapping lives in memory only, is never serialized,
  and must be cleared between sessions (``PiiTokenizer.clear``).
- The gateway withholds the request envelope: ``last_exchange`` returns
  no envelope, only the response id, so the detokenized arguments never
  leak through the flight-recorder seam. A consumer needing delivery
  verification (the fuzzer) therefore cannot run through a gateway — its
  delivery check degrades to UNKNOWN, visibly, never DELIVERED.
- Tokenization covers dict keys as well as values, and tuples as well as
  lists: a result keyed by an identifier is tokenized like any other
  string, and detokenization resolves tokens in keys symmetrically.
- The fuzzer does NOT run through the gateway: tokenized responses would
  break reflection classification. The gateway is the agent path; the
  fuzzer is the audit path.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol, cast

from .fuzzer import Transport
from .transport import JsonDict

__all__ = [
    "AuditEvent",
    "AuditKind",
    "Detector",
    "Gateway",
    "GatewayAuditLog",
    "GatewayPolicy",
    "PiiKind",
    "PiiMatch",
    "PiiTokenizer",
    "RegexDetector",
    "TokenApplied",
    "TrustDeniedError",
    "TrustLevel",
]


class TrustLevel(str, Enum):
    """Trust tier of a tool (source tiers 1/2/3, high to low)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Ordering: HIGH outranks MEDIUM outranks LOW."""
        return {"low": 1, "medium": 2, "high": 3}[self.value]

    @classmethod
    def parse(cls, value: str) -> TrustLevel:
        """Parse a policy-file level string; ValueError names the bad value."""
        try:
            return cls(value)
        except ValueError:
            raise ValueError(
                f"unknown trust level {value!r}: expected one of low, medium, high"
            ) from None


class PiiKind(str, Enum):
    """Structured PII kinds the regex layer detects."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"


@dataclass(frozen=True)
class PiiMatch:
    """One detector hit: kind + span inside the scanned text."""

    kind: PiiKind
    start: int
    end: int


class Detector(Protocol):
    """Layer-2 seam: any PII detector plugs in here (e.g. Presidio NLP)."""

    def detect(self, text: str) -> list[PiiMatch]: ...


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum: a 15/16/19-digit run is a card number only if it passes.

    Without this, any 16-digit order or reference number would tokenize as
    a card (over-tokenization breaks agent utility for no security gain).
    """
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class RegexDetector:
    """Layer-1 PII detection: regex over structured formats.

    Phone numbers: a bare 10-digit run IS treated as a phone number
    (fail-closed for a security gateway; documented, test-pinned). The
    ``(?<!\\d)`` / ``(?!\\d)`` guards keep a fragment of a longer digit
    run from matching.
    """

    # (kind, pattern, needs_luhn)
    _PATTERNS: tuple[tuple[PiiKind, str, bool], ...] = (
        (PiiKind.API_KEY, r"sk-[A-Za-z0-9_-]{16,}", False),
        (PiiKind.API_KEY, r"AKIA[0-9A-Z]{16}", False),
        # gh[p]_ avoids the literal token prefix: the repo's secret-scan
        # flags any line containing it, and this is a pattern, not a secret.
        (PiiKind.API_KEY, r"gh[p]_[A-Za-z0-9]{20,}", False),
        (PiiKind.CREDIT_CARD, r"\b(?:\d{4}[- .]?){3}\d{4}\b", True),
        (PiiKind.CREDIT_CARD, r"\b\d{4}[- .]?\d{6}[- .]?\d{5}\b", True),
        (PiiKind.CREDIT_CARD, r"\b(?:\d{4}[- .]?){4}\d{3}\b", True),
        (PiiKind.SSN, r"\b\d{3}-\d{2}-\d{4}\b", False),
        (PiiKind.EMAIL, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", False),
        (
            PiiKind.PHONE,
            r"(?<!\d)(?:\+\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)",
            False,
        ),
    )

    def __init__(self) -> None:
        self._compiled: tuple[tuple[PiiKind, re.Pattern[str], bool], ...] = tuple(
            (kind, re.compile(pattern), needs_luhn) for kind, pattern, needs_luhn in self._PATTERNS
        )

    def detect(self, text: str) -> list[PiiMatch]:
        matches: list[PiiMatch] = []
        for kind, pattern, needs_luhn in self._compiled:
            for found in pattern.finditer(text):
                if needs_luhn:
                    digits = re.sub(r"\D", "", found.group(0))
                    if not _luhn_ok(digits):
                        continue
                matches.append(PiiMatch(kind=kind, start=found.start(), end=found.end()))
        # Longest-first at the same start; drop anything overlapping a kept
        # match so one span is never tokenized twice (e.g. a card number's
        # digits must not also match as a phone fragment).
        matches.sort(key=lambda hit: (hit.start, -(hit.end - hit.start)))
        kept: list[PiiMatch] = []
        for hit in matches:
            if any(hit.start < k.end and k.start < hit.end for k in kept):
                continue
            kept.append(hit)
        kept.sort(key=lambda hit: hit.start)
        return kept


@dataclass(frozen=True)
class TokenApplied:
    """One tokenization: the PII kind and the token string minted for it."""

    kind: PiiKind
    token: str


class PiiTokenizer:
    """Tokenize PII out of tool results; resolve tokens back into calls.

    Tokens are deterministic per value within a session (same value ->
    same token, so the agent can correlate across records without seeing
    the value). The mapping lives in memory only and is never serialized.
    """

    def __init__(self, detectors: tuple[Detector, ...] | None = None) -> None:
        self._detectors = detectors if detectors is not None else (RegexDetector(),)
        self._by_value: dict[tuple[PiiKind, str], str] = {}
        self._values: dict[str, str] = {}  # token -> value (memory only)
        self._counters: dict[PiiKind, int] = {}

    @property
    def token_count(self) -> int:
        """Minted tokens held in memory (== distinct PII values seen)."""
        return len(self._values)

    def clear(self) -> None:
        """Wipe the token mapping (call between sessions).

        The per-kind counters are NOT reset: tokens are monotonic across
        sessions, so a stale token from a previous session can never
        silently rebind to a different person's value.
        """
        self._by_value.clear()
        self._values.clear()

    def _mint(self, kind: PiiKind, value: str) -> str:
        key = (kind, value)
        token = self._by_value.get(key)
        if token is None:
            n = self._counters.get(kind, 0) + 1
            self._counters[kind] = n
            token = f"[{kind.value.upper()}_{n}]"
            self._by_value[key] = token
            self._values[token] = value
        return token

    def tokenize_text(self, text: str) -> tuple[str, tuple[TokenApplied, ...]]:
        """Replace PII spans with tokens; returns (text, applied tokens)."""
        matches: list[PiiMatch] = []
        for detector in self._detectors:
            matches.extend(detector.detect(text))
        matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
        kept: list[PiiMatch] = []
        for m in matches:
            if any(m.start < k.end and k.start < m.end for k in kept):
                continue
            kept.append(m)
        if not kept:
            return text, ()
        out: list[str] = []
        applied: list[TokenApplied] = []
        pos = 0
        for m in kept:
            out.append(text[pos : m.start])
            token = self._mint(m.kind, text[m.start : m.end])
            out.append(token)
            applied.append(TokenApplied(kind=m.kind, token=token))
            pos = m.end
        out.append(text[pos:])
        return "".join(out), tuple(applied)

    def detokenize_text(self, text: str) -> tuple[str, int]:
        """Resolve minted tokens back to values; returns (text, resolved).

        Only tokens this tokenizer minted are resolved: token-shaped text
        the gateway never minted passes through untouched. Resolution is
        a single pass: a value substituted in is never re-scanned, so a
        minted value that itself contains token-shaped text cannot
        cascade into a second resolution. The replacement is a function,
        so backslashes in a value can never raise ``re.error``.
        """
        if not self._values:
            return text, 0
        pattern = re.compile(
            "(?:"
            + "|".join(re.escape(token) for token in sorted(self._values, key=len, reverse=True))
            + r")(?!\d)"
        )
        resolved = 0

        def _replace(match: re.Match[str]) -> str:
            nonlocal resolved
            resolved += 1
            return self._values[match.group(0)]

        return pattern.sub(_replace, text), resolved

    def tokenize_value(self, value: object) -> tuple[object, tuple[TokenApplied, ...]]:
        """Recurse into JSON-shaped data, tokenizing every string.

        Dict keys are tokenized the same as values: a result keyed by an
        identifier (a contacts lookup, a per-user map) must not leak PII
        through the key while the value is tokenized. Tuples recurse like
        lists (JSON transport never produces them, but the promise is
        "every string", not "every string except in tuples").
        """
        if isinstance(value, str):
            return self.tokenize_text(value)
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            applied: list[TokenApplied] = []
            for k, v in value.items():
                new_k, a_k = self.tokenize_text(k) if isinstance(k, str) else (k, ())
                new_v, a = self.tokenize_value(v)
                out[new_k] = new_v
                applied.extend(a_k)
                applied.extend(a)
            return out, tuple(applied)
        if isinstance(value, list):
            items: list[object] = []
            applied = []
            for v in value:
                new_v, a = self.tokenize_value(v)
                items.append(new_v)
                applied.extend(a)
            return items, tuple(applied)
        if isinstance(value, tuple):
            items = []
            applied = []
            for v in value:
                new_v, a = self.tokenize_value(v)
                items.append(new_v)
                applied.extend(a)
            return tuple(items), tuple(applied)
        return value, ()

    def detokenize_value(self, value: object) -> tuple[object, int]:
        """Recurse into JSON-shaped data, resolving minted tokens.

        Symmetric with :meth:`tokenize_value`: tokens in dict keys and
        tuples resolve the same as tokens in values.
        """
        if isinstance(value, str):
            return self.detokenize_text(value)
        if isinstance(value, dict):
            out = {}
            total = 0
            for k, v in value.items():
                new_k, n_k = self.detokenize_text(k) if isinstance(k, str) else (k, 0)
                new_v, n = self.detokenize_value(v)
                out[new_k] = new_v
                total += n_k + n
            return out, total
        if isinstance(value, list):
            items = []
            total = 0
            for v in value:
                new_v, n = self.detokenize_value(v)
                items.append(new_v)
                total += n
            return items, total
        if isinstance(value, tuple):
            items = []
            total = 0
            for v in value:
                new_v, n = self.detokenize_value(v)
                items.append(new_v)
                total += n
            return tuple(items), total
        return value, 0


class AuditKind(str, Enum):
    """Gateway audit event kinds — facts of access, never content."""

    CALL_ALLOWED = "call_allowed"
    CALL_DENIED = "call_denied"
    PII_TOKENIZED = "pii_tokenized"
    TOKEN_RESOLVED = "token_resolved"  # nosec B105 - audit event kind, not a credential


@dataclass(frozen=True)
class AuditEvent:
    """One audit event: what happened, to which tool, at which levels.

    ``token_kinds`` / ``token_count`` describe how much PII was handled;
    values never appear here (or anywhere in the audit log).
    """

    seq: int
    timestamp: str
    kind: AuditKind
    tool_name: str
    caller_trust: TrustLevel
    target_trust: TrustLevel
    token_kinds: tuple[str, ...] = ()
    token_count: int = 0
    request_id: int | str | None = None

    def to_dict(self) -> JsonDict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "kind": self.kind.value,
            "tool": self.tool_name,
            "caller_trust": self.caller_trust.value,
            "target_trust": self.target_trust.value,
            "token_kinds": list(self.token_kinds),
            "token_count": self.token_count,
            "request_id": self.request_id,
        }


class GatewayAuditLog:
    """Append-only audit log (in-memory; serialize with ``to_json``)."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._seq = 0

    def __len__(self) -> int:
        return len(self._events)

    def record(
        self,
        kind: AuditKind,
        tool_name: str,
        caller_trust: TrustLevel,
        target_trust: TrustLevel,
        token_kinds: tuple[str, ...] = (),
        token_count: int = 0,
        request_id: int | str | None = None,
    ) -> AuditEvent:
        self._seq += 1
        event = AuditEvent(
            seq=self._seq,
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            kind=kind,
            tool_name=tool_name,
            caller_trust=caller_trust,
            target_trust=target_trust,
            token_kinds=token_kinds,
            token_count=token_count,
            request_id=request_id,
        )
        self._events.append(event)
        return event

    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def to_json(self) -> list[JsonDict]:
        return [e.to_dict() for e in self._events]


@dataclass(frozen=True)
class GatewayPolicy:
    """Per-tool trust assignment + the default for unlisted tools.

    The default is LOW: an unlisted tool can never trigger a higher-trust
    read. Trust is never guessed upward — a data-bearing tool the policy
    omits stays LOW until the operator classifies it.
    """

    tools: Mapping[str, TrustLevel] = field(default_factory=dict)
    default_trust: TrustLevel = TrustLevel.LOW

    def trust_of(self, tool_name: str) -> TrustLevel:
        if not isinstance(tool_name, str):
            raise TypeError("tool_name must be a string")
        return self.tools.get(tool_name, self.default_trust)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> GatewayPolicy:
        """Parse a policy file mapping: {"tools": {name: level}, ...}.

        Wrong shapes fail closed (TypeError); unknown level strings fail
        closed (ValueError); unknown top-level keys are ignored so policy
        files stay forward-compatible.
        """
        if not isinstance(data, dict):
            raise TypeError("gateway policy must be a JSON object")
        tools_data = data.get("tools", {})
        if not isinstance(tools_data, dict):
            raise TypeError("gateway policy 'tools' must be an object")
        tools: dict[str, TrustLevel] = {}
        for name, level in tools_data.items():
            if not isinstance(name, str) or not isinstance(level, str):
                raise TypeError("gateway policy tools must map string names to string levels")
            try:
                tools[name] = TrustLevel.parse(level)
            except ValueError as e:
                raise ValueError(f"gateway policy tool {name!r}: {e}") from None
        default_raw = data.get("default_trust", "low")
        if not isinstance(default_raw, str):
            raise TypeError("gateway policy 'default_trust' must be a string")
        return cls(tools=tools, default_trust=TrustLevel.parse(default_raw))


class TrustDeniedError(Exception):
    """A low-trust caller tried to invoke a higher-trust tool.

    Carries levels and the tool name only — never arguments or content.
    """

    def __init__(self, tool_name: str, caller_trust: TrustLevel, target_trust: TrustLevel) -> None:
        self.tool_name = tool_name
        self.caller_trust = caller_trust
        self.target_trust = target_trust
        super().__init__(
            f"trust denied: caller {caller_trust.value} may not invoke "
            f"{target_trust.value} tool '{tool_name}'"
        )


class Gateway:
    """The central choke point: wraps any Transport (same protocol the
    FuzzEngine uses), enforces trust levels, and tokenizes PII before the
    model ever sees a tool result.

    Implements the ``Transport`` protocol (``call_tool`` +
    ``last_exchange``) with one deliberate deviation: ``last_exchange``
    withholds the request envelope (it would carry the detokenized
    arguments) and returns only the response id. A consumer needing
    delivery verification (the fuzzer) therefore cannot run through a
    gateway — its delivery check degrades to UNKNOWN, visibly, never
    DELIVERED.
    """

    def __init__(
        self,
        transport: Transport,
        policy: GatewayPolicy,
        tokenizer: PiiTokenizer | None = None,
    ) -> None:
        self._transport = transport
        self._policy = policy
        self._tokenizer = tokenizer if tokenizer is not None else PiiTokenizer()
        self._audit = GatewayAuditLog()
        self._last_response_id: int | str | None = None

    @property
    def policy(self) -> GatewayPolicy:
        return self._policy

    @property
    def audit_log(self) -> GatewayAuditLog:
        return self._audit

    @property
    def tokenizer(self) -> PiiTokenizer:
        return self._tokenizer

    def annotate_tools(self, tools: list[JsonDict]) -> list[JsonDict]:
        """Tool list copies with the gateway-assigned trust level attached
        (``mcp_guard_trust_level``) so the harness can label its next call."""
        annotated: list[JsonDict] = []
        for tool in tools:
            name = tool.get("name", "unknown")
            if not isinstance(name, str):
                name = "unknown"
            copy = dict(tool)
            copy["mcp_guard_trust_level"] = self._policy.trust_of(name).value
            annotated.append(copy)
        return annotated

    def call_tool(
        self,
        tool_name: str,
        arguments: JsonDict,
        caller_trust: TrustLevel = TrustLevel.LOW,
    ) -> JsonDict:
        """One gated tool call.

        Denies (before any send) when the caller's trust is below the
        target tool's trust. Otherwise resolves minted tokens in the
        arguments, calls the server, and tokenizes the result before
        returning it — the model only ever sees tokens, never raw PII.
        """
        if not isinstance(caller_trust, TrustLevel):
            raise TypeError("caller_trust must be a TrustLevel")
        self._last_response_id = None
        target = self._policy.trust_of(tool_name)
        if caller_trust.rank < target.rank:
            self._audit.record(AuditKind.CALL_DENIED, tool_name, caller_trust, target)
            raise TrustDeniedError(tool_name, caller_trust, target)
        detokenized_args, resolved = self._tokenizer.detokenize_value(arguments)
        if resolved:
            self._audit.record(
                AuditKind.TOKEN_RESOLVED,
                tool_name,
                caller_trust,
                target,
                token_count=resolved,
            )
        result = self._transport.call_tool(tool_name, cast("JsonDict", detokenized_args))
        tokenized_result, applied = self._tokenizer.tokenize_value(result)
        if applied:
            kinds = tuple(sorted({a.kind.value for a in applied}))
            self._audit.record(
                AuditKind.PII_TOKENIZED,
                tool_name,
                caller_trust,
                target,
                token_kinds=kinds,
                token_count=len(applied),
            )
        _, response_id = self._transport.last_exchange()
        request_id: int | str | None = None
        if isinstance(response_id, (int, str)):
            request_id = response_id
            self._last_response_id = response_id
        self._audit.record(
            AuditKind.CALL_ALLOWED,
            tool_name,
            caller_trust,
            target,
            request_id=request_id,
        )
        return cast("JsonDict", tokenized_result)

    def last_exchange(self) -> tuple[JsonDict | None, Any]:
        """Flight recorder, redacted by design: no envelope, only the
        response id. The inner transport's envelope would carry the
        detokenized arguments (raw PII), so the gateway never hands it
        out. A denied or failed call invalidates the record (None), so a
        stale id can never stand in for a call that was never sent."""
        return None, self._last_response_id
