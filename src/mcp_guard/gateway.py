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
4. Rule of two (rat #69): a call to a HIGH-trust tool that mutates state
   on untrusted input escalates — it is DENIED before any send unless a
   second approval is presented, and the approval is audited.
5. Trust-context-aware inbound scanning (rat #72): every tool result is
   scanned at the ``tool`` trust tier before it reaches the model
   (indirect injection enters through tool output, not user text).
   Audit-only by default — the decision is recorded, nothing is refused;
   a policy that opts into ``enforce`` mode refuses ``block`` decisions
   and escalates ``hitl`` decisions (a second approval attached to the
   call lets a ``hitl`` result through, reusing the rule-of-two approval
   shape). Scan audit events carry tier, score, routing, and matched
   rule ids only — never content.

Deliberate boundaries (not hidden):
- The gateway enforces policy over the caller's DECLARED trust level. MCP
  tools/call carries no caller identity, so the gateway cannot authenticate
  who is calling; the agent harness declares it. An undeclared caller is
  LOW (least privilege, never root). Identity authentication (OAuth / JWT /
  mTLS per the source) is a deployment concern outside this stdlib library.
  Identity PROPAGATION (rat #70) is in-library: a harness that supplies
  an authenticated ``IdentityContext`` gets scope enforcement on every
  call plus attribution in the audit log; the gateway never mints
  identity itself.
- Layer-1 PII detection is regex only (structured PII: email, phone, SSN,
  card numbers, API-key shapes). Names and addresses need the layer-2 NLP
  detector, which is a pluggable ``Detector`` seam — ship regex-only, gap
  documented, never claimed as complete.
- The token -> value mapping lives in memory only, is never serialized,
  and must be cleared between sessions (``PiiTokenizer.clear``).
- Rule of two is evaluated on the caller's DECLARED input trust (MCP
  carries no provenance channel) and on the policy's mutating-tools set:
  a tool the policy omits is not known-mutating, and an undeclared
  input is UNTRUSTED. Only HIGH-trust tools are "sensitive" for the
  rule; a MEDIUM tool that mutates on untrusted input does not escalate
  unless the operator classifies it HIGH. The second approver is
  recorded by name but cannot be authenticated (same declared-identity
  boundary as caller trust).
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

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol, cast

from .escalation import (
    EscalationRequiredError,
    InputTrust,
    SecondApproval,
    evaluate_rule_of_two,
)
from .fuzzer import Transport
from .identity import (
    CredentialError,
    IdentityContext,
    ScopeDeniedError,
    ScopeExpiredError,
)
from .transport import JsonDict
from .trust_scanner import (
    InboundScanBlockedError,
    InboundScanEscalationError,
    InboundScanner,
    InboundScanPolicy,
    RoutingDecision,
    SemanticScorer,
)

__all__ = [
    "AuditEvent",
    "AuditKind",
    "CredentialError",
    "Detector",
    "Gateway",
    "GatewayAuditLog",
    "GatewayPolicy",
    "IdentityContext",
    "InboundScanBlockedError",
    "InboundScanEscalationError",
    "InboundScanPolicy",
    "InboundScanner",
    "PiiKind",
    "PiiMatch",
    "PiiTokenizer",
    "RegexDetector",
    "RoutingDecision",
    "ScopeDeniedError",
    "ScopeExpiredError",
    "TokenApplied",
    "TrustDeniedError",
    "TrustLevel",
    "luhn_ok",
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
        """Parse a policy-file level string.

        ValueError names the valid levels only (rat #69, round-4
        fix-forward): the rejected value is never echoed, it is
        caller-supplied free text and the CLI prints this error.
        """
        try:
            return cls(value)
        except ValueError:
            raise ValueError("unknown trust level: expected one of low, medium, high") from None


class PiiKind(str, Enum):
    """Structured PII kinds the regex layer detects."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"
    # Not a detected class: the whole-value pseudonym minted for a
    # free-text field (the second approver, rat #69). No detector
    # produces it; PiiTokenizer.pseudonymize mints it directly.
    APPROVER = "approver"


@dataclass(frozen=True)
class PiiMatch:
    """One detector hit: kind + span inside the scanned text."""

    kind: PiiKind
    start: int
    end: int


class Detector(Protocol):
    """Layer-2 seam: any PII detector plugs in here (e.g. Presidio NLP)."""

    def detect(self, text: str) -> list[PiiMatch]: ...


def luhn_ok(digits: str) -> bool:
    """Luhn checksum: a 15/16/19-digit run is a card number only if it passes.

    Without this, any 16-digit order or reference number would tokenize as
    a card (over-tokenization breaks agent utility for no security gain).

    Public (not private) because the memory gate (rat #71) needs the same
    check over bare 13-19 digit runs: one shared implementation, so a fix
    to the algorithm reaches both callers instead of drifting across two
    copies.
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
    run from matching. Israeli mobiles match in both forms (bare 05x
    via the generic pattern, +972-5x via its own pattern, rat #69).
    A bare 9-digit run is NOT treated as a national ID: the source
    (pii-scrubber Tier 1) conditions that pattern on column context the
    free-text detector lacks, so matching it here would flag every
    9-digit order number.
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
        # Email local part bounded to 64 chars (RFC 5321) and domain to
        # 253: an unbounded run before the "@" is quadratic on long
        # letter runs (rat #69 fix-forward: a 1M-char overflow payload
        # hung RegexDetector.detect, found by test_twyman_delivery).
        (PiiKind.EMAIL, r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}", False),
        # Israeli mobile, +972 form (rat #69, pii-scrubber Tier 1): the
        # bare 05x form already matches the phone pattern below; the
        # +972 form does not (the country code breaks the 3-3-4 shape).
        (PiiKind.PHONE, r"\+972[-.\s]?5\d[-.\s]?\d{3}[-.\s]?\d{4}", False),
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
        # Fast pre-filter (rat #69): a pattern cannot match without its
        # required character class, so skip whole families on texts that
        # cannot contain them instead of running every regex over
        # megabyte overflow payloads. Each check is a pure optimization:
        # it can only skip patterns that could not match.
        has_at = "@" in text
        has_digit = any(ch.isdigit() for ch in text)
        # Built from parts: the repo's secret-scan flags the literal token
        # prefix, and this is a detector pre-filter, not a secret.
        has_key_prefix = "sk-" in text or "AKIA" in text or "gh" + "p_" in text
        matches: list[PiiMatch] = []
        for kind, pattern, needs_luhn in self._compiled:
            if kind is PiiKind.EMAIL and not has_at:
                continue
            if kind in (PiiKind.PHONE, PiiKind.SSN, PiiKind.CREDIT_CARD) and not has_digit:
                continue
            if kind is PiiKind.API_KEY and not has_key_prefix:
                continue
            for found in pattern.finditer(text):
                if needs_luhn:
                    digits = re.sub(r"\D", "", found.group(0))
                    if not luhn_ok(digits):
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

    ``token_prefix`` namespaces the minting authority inside the token
    string itself (rat #74): a tokenizer constructed with prefix
    ``"MASK1_"`` mints ``[MASK1_EMAIL_1]``, while the gateway's
    default (empty prefix) mints ``[EMAIL_1]``. Two tokenizers with
    different prefixes can never mint the same string for different
    values, so a token minted by one authority can never resolve
    against another's map — the separation is checkable from the token
    alone, not from which object happens to hold the map.
    """

    def __init__(
        self,
        detectors: tuple[Detector, ...] | None = None,
        token_prefix: str = "",
    ) -> None:
        if not isinstance(token_prefix, str):
            raise TypeError("token_prefix must be a string")
        if token_prefix and not token_prefix.replace("_", "").isalnum():
            raise ValueError("token_prefix must contain only letters, digits, and underscores")
        self._detectors = detectors if detectors is not None else (RegexDetector(),)
        self._token_prefix = token_prefix
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
            token = f"[{self._token_prefix}{kind.value.upper()}_{n}]"
            self._by_value[key] = token
            self._values[token] = value
        return token

    def revoke(self, applied: tuple[TokenApplied, ...]) -> None:
        """Withdraw minted tokens from the reverse dictionary.

        The counters are NOT decremented: a revoked token number is
        never minted again, so the same string can never rebind to a
        different value. The mask pipeline (rat #74) uses this for
        block-before-mint in a single pass: tokenize, and if a blocked
        class is present, revoke what was just minted and raise — so a
        blocked value leaves no token a later response could recover,
        without running detection twice (a stateful detector could
        disagree between a probe pass and the mint pass).
        """
        if not isinstance(applied, tuple):
            raise TypeError("applied must be a tuple of TokenApplied")
        for item in applied:
            value = self._values.pop(item.token, None)
            if value is not None:
                self._by_value.pop((item.kind, value), None)

    def pseudonymize(self, value: str) -> str:
        """Mint a per-session pseudonym for a WHOLE free-text value (rat #69).

        Unlike tokenize_text, which only replaces detected-class spans,
        this replaces the entire value with one ``[APPROVER_n]`` token,
        so a plain name records as a token, never verbatim. The reverse
        mapping is deliberately NOT stored: the token can never be
        resolved back to the value (the audit log is emitted, never fed
        back into a call), so the name cannot leak through
        detokenization. Same value -> same token within a session;
        counters are monotonic across sessions (see clear()), so a stale
        token can never silently rebind to a different value.
        """
        key = (PiiKind.APPROVER, value)
        token = self._by_value.get(key)
        if token is None:
            n = self._counters.get(PiiKind.APPROVER, 0) + 1
            self._counters[PiiKind.APPROVER] = n
            token = f"[{self._token_prefix}APPROVER_{n}]"
            self._by_value[key] = token
        return token

    def _kept_matches(self, text: str) -> list[PiiMatch]:
        """Detector hits after overlap resolution (longest-first).

        One span is never counted twice (e.g. a card number's digits
        must not also match as a phone fragment).
        """
        matches: list[PiiMatch] = []
        for detector in self._detectors:
            matches.extend(detector.detect(text))
        matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
        kept: list[PiiMatch] = []
        for m in matches:
            if any(m.start < k.end and k.start < m.end for k in kept):
                continue
            kept.append(m)
        return kept

    def tokenize_text(self, text: str) -> tuple[str, tuple[TokenApplied, ...]]:
        """Replace PII spans with tokens; returns (text, applied tokens)."""
        kept = self._kept_matches(text)
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
    ESCALATION_REQUIRED = "escalation_required"
    ESCALATION_APPROVED = "escalation_approved"
    PII_TOKENIZED = "pii_tokenized"
    TOKEN_RESOLVED = "token_resolved"  # nosec B105 - audit event kind, not a credential
    IDENTITY_DENIED = "identity_denied"
    IDENTITY_EXPIRED = "identity_expired"
    CREDENTIAL_REFUSED = "credential_refused"
    INBOUND_SCAN = "inbound_scan"


@dataclass(frozen=True)
class AuditEvent:
    """One audit event: what happened, to which tool, at which levels.

    ``token_kinds`` / ``token_count`` describe how much PII was handled;
    values never appear here (or anywhere in the audit log). ``tool_name``
    is tokenized through the session tokenizer before recording (rat
    #69): a well-formed name has no detected spans and records
    unchanged; a PII-bearing name records with its spans tokenized.
    A string ``request_id`` (server-echoed) is tokenized the same way;
    an int id records unchanged. ``approver``
    names the second approver on an ESCALATION_APPROVED event only, and
    records as a per-session ``[APPROVER_n]`` token (rat #69): the whole
    field is pseudonymized, never verbatim, and the token can never be
    resolved back to the value. The approval reason is never recorded
    (operator free text could carry content). ``identity`` (rat #70)
    names the acting user on an identity-bound gateway, as the one-way
    ``user-<hash>`` audit token — the raw user id never reaches the log.
    ``scan_tier`` / ``scan_score`` / ``scan_routing`` / ``scan_rules``
    (rat #72) carry an inbound-scan decision on an INBOUND_SCAN event:
    tier, score, routing, and matched rule ids only — never content.
    ``scan_semantic_score`` / ``scan_semantic_review`` (rat #73) carry
    the gated semantic review for that scan: the LLM-leg score when it
    ran (None when it did not) and why ("unavailable" / "below-band" /
    "above-band" / "in-band" / "cached" / "failed"). ``scan_semantic_calls``
    / ``scan_semantic_cache_hit`` make the acceptance band observable:
    calls is 0 or 1 per scan (no call outside the band), and the
    cache-hit rate over the audit log is the fraction of in-band scans
    with review "cached".
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
    approver: str | None = None
    identity: str | None = None
    scan_tier: str | None = None
    scan_score: float | None = None
    scan_routing: str | None = None
    scan_rules: tuple[str, ...] = ()
    scan_semantic_score: float | None = None
    scan_semantic_review: str | None = None
    scan_semantic_calls: int | None = None
    scan_semantic_cache_hit: bool | None = None

    def to_dict(self) -> JsonDict:
        data: JsonDict = {
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
        if self.approver is not None:
            data["approver"] = self.approver
        if self.identity is not None:
            data["identity"] = self.identity
        if self.scan_tier is not None:
            data["scan_tier"] = self.scan_tier
        if self.scan_score is not None:
            data["scan_score"] = self.scan_score
        if self.scan_routing is not None:
            data["scan_routing"] = self.scan_routing
        if self.scan_rules:
            data["scan_rules"] = list(self.scan_rules)
        if self.scan_semantic_score is not None:
            data["scan_semantic_score"] = self.scan_semantic_score
        if self.scan_semantic_review is not None:
            data["scan_semantic_review"] = self.scan_semantic_review
        if self.scan_semantic_calls is not None:
            data["scan_semantic_calls"] = self.scan_semantic_calls
        if self.scan_semantic_cache_hit is not None:
            data["scan_semantic_cache_hit"] = self.scan_semantic_cache_hit
        return data


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
        approver: str | None = None,
        identity: str | None = None,
        scan_tier: str | None = None,
        scan_score: float | None = None,
        scan_routing: str | None = None,
        scan_rules: tuple[str, ...] = (),
        scan_semantic_score: float | None = None,
        scan_semantic_review: str | None = None,
        scan_semantic_calls: int | None = None,
        scan_semantic_cache_hit: bool | None = None,
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
            approver=approver,
            identity=identity,
            scan_tier=scan_tier,
            scan_score=scan_score,
            scan_routing=scan_routing,
            scan_rules=scan_rules,
            scan_semantic_score=scan_semantic_score,
            scan_semantic_review=scan_semantic_review,
            scan_semantic_calls=scan_semantic_calls,
            scan_semantic_cache_hit=scan_semantic_cache_hit,
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
    omits stays LOW until the operator classifies it. The same boundary
    applies to ``mutating_tools`` (rat #69): a tool the policy omits is
    not known-mutating until the operator classifies it — but a listed
    entry that can never escalate (effective trust not HIGH) is rejected
    by ``__post_init__`` on every construction path instead of silently
    doing nothing.

    ``inbound_scan`` (rat #72) is the trust-context-aware inbound
    scanner policy: audit-only by default (scan every tool result, record
    the decision, refuse nothing); ``enforce`` refuses ``block`` results
    and escalates ``hitl`` results.
    """

    tools: Mapping[str, TrustLevel] = field(default_factory=dict)
    mutating_tools: frozenset[str] = field(default_factory=frozenset)
    default_trust: TrustLevel = TrustLevel.LOW
    inbound_scan: InboundScanPolicy = field(default_factory=InboundScanPolicy)

    def __post_init__(self) -> None:
        """Reject dead mutating_tools entries on EVERY construction path
        (rat #69, round-3 fix-forward): a listed entry whose effective
        trust is not HIGH can never escalate, so accepting it would let
        the operator believe they have two-person control where none
        exists. Effective trust honors the declared default via
        trust_of (already registered); from_mapping parses first, then
        this runs — direct construction is checked the same way.

        The tools map and default are type-checked unconditionally
        (rat #69, round-4 fix-forward): a malformed value must fail
        here as TypeError, never surface later as AttributeError from
        inside trust_of — even when mutating_tools is empty. The tools
        container itself is checked first (round-6 fix-forward): a
        non-mapping tools value would otherwise raise AttributeError
        from .items() instead of the typed error.
        """
        if not isinstance(self.tools, Mapping):
            raise TypeError(f"gateway policy tools {self.tools!r} is not a mapping")
        if not isinstance(self.default_trust, TrustLevel):
            raise TypeError(
                f"gateway policy default trust {self.default_trust!r} is not a TrustLevel"
            )
        for name, level in self.tools.items():
            if not isinstance(level, TrustLevel):
                raise TypeError(
                    f"gateway policy tool {name!r} has a non-TrustLevel "
                    f"trust value {level!r}: policy tools must map to TrustLevel"
                )
        for name in sorted(self.mutating_tools):
            if self.trust_of(name) is not TrustLevel.HIGH:
                raise ValueError(
                    f"gateway policy mutating tool {name!r} is not HIGH trust "
                    f"(effective trust is {self.trust_of(name).value}): "
                    "it can never escalate"
                )

    def trust_of(self, tool_name: str) -> TrustLevel:
        if not isinstance(tool_name, str):
            raise TypeError("tool_name must be a string")
        return self.tools.get(tool_name, self.default_trust)

    def is_mutating(self, tool_name: str) -> bool:
        if not isinstance(tool_name, str):
            raise TypeError("tool_name must be a string")
        return tool_name in self.mutating_tools

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> GatewayPolicy:
        """Parse a policy file mapping: {"tools": {name: level}, ...}.

        Wrong shapes fail closed (TypeError); unknown level strings fail
        closed (ValueError); unknown top-level keys are ignored so policy
        files stay forward-compatible. A ``mutating_tools`` entry whose
        effective trust is not HIGH is rejected (ValueError, enforced in
        ``__post_init__`` on every construction path): it could
        never escalate, so accepting it would let the operator believe
        they have two-person control where none exists. Entries are
        stripped of surrounding whitespace; empty entries are rejected.
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
        mutating_data = data.get("mutating_tools", [])
        if not isinstance(mutating_data, list) or any(
            not isinstance(name, str) for name in mutating_data
        ):
            raise TypeError("gateway policy 'mutating_tools' must be a list of strings")
        default_raw = data.get("default_trust", "low")
        if not isinstance(default_raw, str):
            raise TypeError("gateway policy 'default_trust' must be a string")
        default_trust = TrustLevel.parse(default_raw)
        # Inbound-scan policy (rat #72): absent means audit-only with the
        # issue's thresholds; a present mapping is parsed by the policy
        # class itself (wrong shapes fail closed there).
        scan_data = data.get("inbound_scan", {})
        if not isinstance(scan_data, Mapping):
            raise TypeError("gateway policy 'inbound_scan' must be an object")
        inbound_scan = InboundScanPolicy.from_mapping(scan_data)
        # Entries are stripped: " delete_record" never matches a tool
        # name and would silently disable escalation for that tool.
        mutating = frozenset(name.strip() for name in mutating_data)
        if any(not name for name in mutating):
            raise ValueError("gateway policy 'mutating_tools' entries must be non-empty")
        # Dead-entry rejection runs in __post_init__ (rat #69): the
        # dataclass constructor enforces it on every construction path,
        # not just the file-load path.
        return cls(
            tools=tools,
            mutating_tools=mutating,
            default_trust=default_trust,
            inbound_scan=inbound_scan,
        )


class TrustDeniedError(Exception):
    """A low-trust caller tried to invoke a higher-trust tool.

    Carries levels and the tool name only — never arguments or content.
    The tool name is the tokenized-for-log name (rat #69): a well-formed
    name is unchanged, a PII-bearing name has its spans tokenized.
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
        identity: IdentityContext | None = None,
        scanner: InboundScanner | None = None,
        semantic_scorer: SemanticScorer | None = None,
    ) -> None:
        self._transport = transport
        self._policy = policy
        self._tokenizer = tokenizer if tokenizer is not None else PiiTokenizer()
        self._audit = GatewayAuditLog()
        self._last_response_id: int | str | None = None
        # Inbound scanner (rat #72): always present — a gateway with no
        # scanner would silently stop scanning tool results, so the
        # default is constructed from the policy (audit-only unless the
        # policy opts into enforce). A caller-supplied scanner (tests,
        # custom rule sets) replaces it. The semantic scorer (rat #73)
        # follows the same fail-closed rule: an explicit scorer wins,
        # otherwise the policy's ``inbound_scan.semantic_scorer``
        # (None by default, so the shipped default stays
        # deterministic-only). A supplied scanner OWNS its scorer: a
        # caller that supplies both a scanner and a scorer (by argument
        # or by policy) gets a ValueError, never a silently discarded
        # scorer — a dropped semantic leg is a dropped security control.
        scan_policy = policy.inbound_scan
        effective_scorer = (
            semantic_scorer if semantic_scorer is not None else scan_policy.semantic_scorer
        )
        if scanner is not None and effective_scorer is not None:
            raise ValueError(
                "gateway cannot take both a scanner and a semantic scorer: "
                "pass the scorer inside the scanner, or let the gateway "
                "build the scanner from the policy"
            )
        self._scanner = (
            scanner
            if scanner is not None
            else InboundScanner(
                hitl_threshold=scan_policy.hitl_threshold,
                block_threshold=scan_policy.block_threshold,
                audit_only=scan_policy.mode == "audit",
                semantic_scorer=effective_scorer,
            )
        )
        # Identity propagation (rat #70): when bound, every call is
        # checked against the user's permission scope before the trust
        # check, and every audit event carries the one-way audit token
        # so the action is attributable to the scope. Unbound, the
        # gateway keeps its legacy declared-trust behavior unchanged.
        # Binding re-validates the handle against its vault right now:
        # a revocation issued between context construction and gateway
        # bind is refused here, before any call, instead of on the
        # first call.
        self._identity = identity
        if identity is not None:
            identity.check_handle()
        self._identity_token = identity.audit_token if identity is not None else None

    @property
    def policy(self) -> GatewayPolicy:
        return self._policy

    @property
    def identity(self) -> IdentityContext | None:
        return self._identity

    @property
    def audit_log(self) -> GatewayAuditLog:
        return self._audit

    @property
    def tokenizer(self) -> PiiTokenizer:
        return self._tokenizer

    @property
    def scanner(self) -> InboundScanner:
        return self._scanner

    def annotate_tools(self, tools: list[JsonDict]) -> list[JsonDict]:
        """Tool list copies with the gateway-assigned trust level attached
        (``mcp_guard_trust_level``) so the harness can label its next call.

        On an identity-bound gateway only in-scope tools are listed: an
        identity must not even discover a tool it cannot call.
        """
        annotated: list[JsonDict] = []
        for tool in tools:
            name = tool.get("name", "unknown")
            if not isinstance(name, str):
                name = "unknown"
            if self._identity is not None and not self._identity.scope.allows_tool(name):
                continue
            copy = dict(tool)
            copy["mcp_guard_trust_level"] = self._policy.trust_of(name).value
            annotated.append(copy)
        return annotated

    def call_tool(
        self,
        tool_name: str,
        arguments: JsonDict,
        caller_trust: TrustLevel = TrustLevel.LOW,
        input_trust: InputTrust = InputTrust.UNTRUSTED,
        approval: SecondApproval | None = None,
    ) -> JsonDict:
        """One gated tool call.

        Identity propagation (rat #70) runs FIRST, before the trust
        check: on an identity-bound gateway the call must be inside the
        user's permission scope (unexpired scope and credential, live
        handle, tool in the scope's grant) or it is denied before any
        send — an expired or revoked identity gets no trust verdict.
        Then denies (before any send) when the caller's trust is below
        the target tool's trust. Then evaluates the rule of two on every
        gateway call (rat #69):
        a HIGH-trust tool that mutates state on untrusted input escalates
        and is denied before any send unless a second approval is
        presented. Otherwise resolves minted tokens in the arguments,
        calls the server, and tokenizes the result before returning it —
        the model only ever sees tokens, never raw PII. The tool name
        recorded in the audit log (and in denial messages) is tokenized
        first (rat #69): a well-formed name records unchanged; the real
        name still drives trust lookup, escalation, and the server call.
        Every audit event on an identity-bound gateway carries the
        one-way audit token, so the action is attributable to the scope.

        Inbound scanning (rat #72) runs on the RAW result, before
        tokenization (a token must never mask an exfil pattern), at the
        ``tool`` trust tier: tool output is where indirect injection
        enters. In audit mode the decision is recorded and the result
        returns unchanged. In enforce mode a ``block`` decision raises
        ``InboundScanBlockedError`` (the result never reaches the model)
        and a ``hitl`` decision raises ``InboundScanEscalationError``
        unless a second approval is attached to the call — the same
        ``approval`` the rule of two uses, one second sign-off per call,
        recorded as a per-session ``[APPROVER_n]`` token on the scan
        event when it lets a ``hitl`` result through.
        """
        self._last_response_id = None
        if not isinstance(caller_trust, TrustLevel):
            raise TypeError("caller_trust must be a TrustLevel")
        target = self._policy.trust_of(tool_name)
        # The tool name is caller-supplied text recorded in the audit log
        # and embedded in denial messages (rat #69, round-3 fix-forward):
        # tokenize it once, before the first record, so a PII-bearing
        # name can never reach the log or the CLI's denied line. A
        # well-formed name has no detected spans and records unchanged.
        # The REAL name still drives trust lookup, escalation, and the
        # transport call below.
        log_tool_name, _ = self._tokenizer.tokenize_text(tool_name)
        if self._identity is not None:
            try:
                self._identity.check_call(tool_name)
            except ScopeExpiredError:
                self._audit.record(
                    AuditKind.IDENTITY_EXPIRED,
                    log_tool_name,
                    caller_trust,
                    target,
                    identity=self._identity_token,
                )
                raise
            except ScopeDeniedError:
                self._audit.record(
                    AuditKind.IDENTITY_DENIED,
                    log_tool_name,
                    caller_trust,
                    target,
                    identity=self._identity_token,
                )
                raise
            except CredentialError:
                self._audit.record(
                    AuditKind.CREDENTIAL_REFUSED,
                    log_tool_name,
                    caller_trust,
                    target,
                    identity=self._identity_token,
                )
                raise
        if caller_trust.rank < target.rank:
            self._audit.record(
                AuditKind.CALL_DENIED,
                log_tool_name,
                caller_trust,
                target,
                identity=self._identity_token,
            )
            raise TrustDeniedError(log_tool_name, caller_trust, target)
        # Type validation for input_trust / approval runs AFTER the trust
        # check (rat #69 fix-forward): a malformed call on a denied tool
        # is audited as call_denied instead of vanishing without a trace.
        if not isinstance(input_trust, InputTrust):
            raise TypeError("input_trust must be an InputTrust")
        if approval is not None and not isinstance(approval, SecondApproval):
            raise TypeError("approval must be a SecondApproval or None")
        escalation = evaluate_rule_of_two(
            target is TrustLevel.HIGH, input_trust, self._policy.is_mutating(tool_name)
        )
        if escalation.triggered:
            if approval is None:
                self._audit.record(
                    AuditKind.ESCALATION_REQUIRED,
                    log_tool_name,
                    caller_trust,
                    target,
                    identity=self._identity_token,
                )
                raise EscalationRequiredError(log_tool_name, escalation)
            # The approver is caller-supplied free text (rat #69): the
            # WHOLE field is pseudonymized with a per-session token before
            # recording, so the approver never reaches the audit log or
            # the CLI's gateway_closed line verbatim — not as a plain
            # name, not as detected-class PII in the field. The token is
            # stable within the session and can never be resolved back
            # to the value (see PiiTokenizer.pseudonymize).
            approver_token = self._tokenizer.pseudonymize(approval.approver)
            self._audit.record(
                AuditKind.ESCALATION_APPROVED,
                log_tool_name,
                caller_trust,
                target,
                approver=approver_token,
                identity=self._identity_token,
            )
        detokenized_args, resolved = self._tokenizer.detokenize_value(arguments)
        if resolved:
            self._audit.record(
                AuditKind.TOKEN_RESOLVED,
                log_tool_name,
                caller_trust,
                target,
                token_count=resolved,
                identity=self._identity_token,
            )
        result = self._transport.call_tool(tool_name, cast("JsonDict", detokenized_args))
        # Inbound scan (rat #72): the RAW result, before tokenization,
        # as its canonical JSON text, at the tool tier. The scan decision
        # is always audited (tier / score / routing / rule ids — never
        # content). In enforce mode a block refuses the return outright
        # and a hitl without a second approval escalates; a hitl WITH an
        # approval proceeds and the approver records as a per-session
        # token, the same way the rule of two records its approvals.
        scan = self._scanner.scan_message(
            {
                "role": "tool",
                "content": json.dumps(result, ensure_ascii=False, sort_keys=True, default=str),
            }
        )
        enforce = self._policy.inbound_scan.mode == "enforce"
        if scan.routing_decision is RoutingDecision.BLOCK and enforce:
            self._audit.record(
                AuditKind.INBOUND_SCAN,
                log_tool_name,
                caller_trust,
                target,
                scan_tier=scan.tier.value,
                scan_score=scan.score,
                scan_routing=scan.routing_decision.value,
                scan_rules=scan.matched_rules,
                scan_semantic_score=scan.semantic_score,
                scan_semantic_review=scan.semantic_review,
                scan_semantic_calls=scan.semantic_calls,
                scan_semantic_cache_hit=scan.semantic_cache_hit,
                identity=self._identity_token,
            )
            raise InboundScanBlockedError(scan)
        if scan.routing_decision is RoutingDecision.HITL and enforce and approval is None:
            self._audit.record(
                AuditKind.INBOUND_SCAN,
                log_tool_name,
                caller_trust,
                target,
                scan_tier=scan.tier.value,
                scan_score=scan.score,
                scan_routing=scan.routing_decision.value,
                scan_rules=scan.matched_rules,
                scan_semantic_score=scan.semantic_score,
                scan_semantic_review=scan.semantic_review,
                scan_semantic_calls=scan.semantic_calls,
                scan_semantic_cache_hit=scan.semantic_cache_hit,
                identity=self._identity_token,
            )
            raise InboundScanEscalationError(scan)
        scan_approver = (
            self._tokenizer.pseudonymize(approval.approver)
            if approval is not None and scan.routing_decision is RoutingDecision.HITL
            else None
        )
        self._audit.record(
            AuditKind.INBOUND_SCAN,
            log_tool_name,
            caller_trust,
            target,
            scan_tier=scan.tier.value,
            scan_score=scan.score,
            scan_routing=scan.routing_decision.value,
            scan_rules=scan.matched_rules,
            scan_semantic_score=scan.semantic_score,
            scan_semantic_review=scan.semantic_review,
            scan_semantic_calls=scan.semantic_calls,
            scan_semantic_cache_hit=scan.semantic_cache_hit,
            approver=scan_approver,
            identity=self._identity_token,
        )
        tokenized_result, applied = self._tokenizer.tokenize_value(result)
        if applied:
            kinds = tuple(sorted({a.kind.value for a in applied}))
            self._audit.record(
                AuditKind.PII_TOKENIZED,
                log_tool_name,
                caller_trust,
                target,
                token_kinds=kinds,
                token_count=len(applied),
                identity=self._identity_token,
            )
        _, response_id = self._transport.last_exchange()
        request_id: int | str | None = None
        if isinstance(response_id, (int, str)):
            request_id = response_id
            self._last_response_id = response_id
        # The response id is server-echoed text (rat #69, round-3
        # fix-forward): a string id is tokenized before it reaches the
        # audit log, the same way the report scrubs request ids. An int
        # id passes through unchanged; the raw id is kept only in
        # _last_response_id for last_exchange correlation.
        log_request_id: int | str | None = request_id
        if isinstance(log_request_id, str):
            log_request_id, _ = self._tokenizer.tokenize_text(log_request_id)
        self._audit.record(
            AuditKind.CALL_ALLOWED,
            log_tool_name,
            caller_trust,
            target,
            request_id=log_request_id,
            identity=self._identity_token,
        )
        return cast("JsonDict", tokenized_result)

    def last_exchange(self) -> tuple[JsonDict | None, Any]:
        """Flight recorder, redacted by design: no envelope, only the
        response id. The inner transport's envelope would carry the
        detokenized arguments (raw PII), so the gateway never hands it
        out. A denied or failed call invalidates the record (None), so a
        stale id can never stand in for a call that was never sent."""
        return None, self._last_response_id
