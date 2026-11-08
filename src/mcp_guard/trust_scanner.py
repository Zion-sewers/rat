"""Trust-context-aware inbound scanner (rat #72).

Source: Nicole Koenigstein, *AI Agents: The Definitive Guide* (O'Reilly),
ch.12 — mined 2026-09-27, evidence secondary-only. The chapter's defense
argument: prompt injection rarely enters as user text; it propagates
model -> orchestration -> tool -> memory (indirect prompt injection), so
a scanner must score content *differently depending on its source* and
cover all message roles.

What this module does, per message ``{role, content,
metadata.trust_level}``:

1. Resolve a :class:`TrustTier` — explicit ``metadata.trust_level`` wins;
   otherwise role ``tool`` -> ``tool``, role ``developer`` -> ``developer``,
   everything else -> ``untrusted``.
2. Normalize before matching: NFKC canonicalization, then strip
   Unicode Cf/Cc characters (zero-width spaces, control characters) for
   matching — and enumerate them as first-class findings, so
   invisible-prompt obfuscation is part of the risk model instead of a
   bypass. Matching runs over TWO normalized views (invisible chars as
   spaces, and removed) so neither word-joining nor word-splitting
   obfuscation hides a lexical pattern.
3. Score two categories with hand-coded regex rule families derived from
   the repo's own payload shapes (``payloads.py`` prompt/indirect
   injection) and the fuzzer's exfil-channel classifier: injection and
   exfiltration. Same content, different weight per tier: the ``tool``
   tier multiplies both categories by 1.4 (indirect-injection surface);
   the ``developer`` tier multiplies exfiltration by 0.25 (legitimate
   ops talk about secrets).
4. Route: score >= block threshold -> ``block``; >= HITL threshold ->
   ``hitl``; else ``allow``. Defaults 0.80 / 0.40 (the issue's numbers),
   configurable per scanner.

Deliberate boundaries (not hidden):
- The scanner is pure: it returns a routing decision, it never enforces
  one. Enforcement lives in the gateway (``Gateway.call_tool`` scans
  every tool result; audit-only by default, block/HITL enforced only
  when the policy opts in). A scanner decision with no gateway behind
  it changes nothing — the live consumer is the gateway, not this module.
- Multipliers and thresholds are the book's numbers, unmeasured on live
  traffic: there is no precision/recall claim here. Rule weights are
  policy defaults chosen so the issue's three fixtures land in their
  named bands; they are pinned by tests, not by measurement. An operator
  that wants measured calibration must run the scanner in audit-only
  mode first and fit thresholds to its own traffic.
- Normalization covers NFKC + Cf/Cc. Homoglyphs and mixed-script
  obfuscation are NOT covered: a Cyrillic look-alike of a Latin keyword
  still evades matching, and no finding is raised for it. Likewise,
  invisible characters BETWEEN the letters of a keyword are defeated
  lexically only through the compact view (see
  :func:`normalize_for_matching`); the spaced view keeps word boundaries.
  Tab / newline / carriage return are Cf/Cc-adjacent controls but
  legitimate whitespace: they are neither stripped nor reported.
- Invisible-character findings are always reported, but they do not
  move the score by themselves: a message of pure zero-width characters
  routes ``allow`` WITH findings. The score comes from lexical matching
  on the normalized views — the findings exist so the audit trail shows
  the obfuscation attempt, not so an invisible character alone blocks a
  message.
- Role strings are caller-declared, like every other trust input in
  this repo (gateway caller trust, input trust, memory provenance).
  A caller that lies about the role gets the tier for the lie. The
  control stops accidental mislabeling, it does not authenticate the
  source — exactly the gateway's declared-identity boundary.
- The scanner never sees PII tokenization: the gateway scans the RAW
  tool result before tokenizing it, so a token can never mask an exfil
  pattern. Scan results carry rule ids, tier, and score only — never
  content — so they are safe for the audit log.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Literal

__all__ = [
    "InboundScanBlockedError",
    "InboundScanEscalationError",
    "InboundScanPolicy",
    "InboundScanner",
    "InvisibleCharFinding",
    "RoutingDecision",
    "ScanResult",
    "ScanRule",
    "TrustContext",
    "TrustTier",
    "normalize_for_matching",
]

# Multipliers per tier, from the issue (book numbers, unmeasured):
# tool multiplies injection AND exfiltration by 1.4; developer multiplies
# exfiltration by 0.25; untrusted is the 1.0 baseline for both.
_TIER_MULTIPLIERS: dict[str, tuple[float, float]] = {
    "untrusted": (1.0, 1.0),
    "tool": (1.4, 1.4),
    "developer": (1.0, 0.25),
}

# Unicode general categories enumerated as invisible-char findings:
# Cf = format characters (zero-width space U+200B, zero-width joiner,
# byte-order mark U+FEFF, soft hyphen U+00AD, ...), Cc = control
# characters (NUL, DEL, C1 controls). NFKC alone does not remove these,
# so matching normalizes them away. Tab / newline / carriage return are
# Cc but legitimate whitespace: they are kept as-is and never reported.
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Cc"})
_KEPT_WHITESPACE = frozenset({"\t", "\n", "\r"})


class TrustTier(str, Enum):
    """Per-message trust tier: how much the scanner trusts the source."""

    UNTRUSTED = "untrusted"
    TOOL = "tool"
    DEVELOPER = "developer"

    @classmethod
    def parse(cls, value: str) -> TrustTier:
        """Parse a metadata trust-level string; fail closed on anything else.

        The rejected value is never echoed: it is caller-supplied free
        text, and the scanner's caller may print this error.
        """
        if not isinstance(value, str):
            raise ValueError(  # noqa: TRY004 - parse failures are ValueError by contract, like TrustLevel.parse; the CLI catches ValueError
                "unknown trust tier: expected one of untrusted, tool, developer"
            )
        try:
            return cls(value.strip().lower())
        except ValueError:
            raise ValueError(
                "unknown trust tier: expected one of untrusted, tool, developer"
            ) from None


class RoutingDecision(str, Enum):
    """Three-way routing for one scanned message."""

    ALLOW = "allow"
    HITL = "hitl"
    BLOCK = "block"


Category = Literal["injection", "exfiltration"]


@dataclass(frozen=True)
class InvisibleCharFinding:
    """One hidden/control character found in the raw message text.

    ``position`` is the offset in the NFKC-normalized text. The character
    itself is never stored: a single invisible codepoint carries no
    content, and the codepoint + category is the whole finding.
    """

    codepoint: str
    category: str
    position: int

    def to_dict(self) -> dict[str, object]:
        return {
            "codepoint": self.codepoint,
            "category": self.category,
            "position": self.position,
        }


@dataclass(frozen=True)
class TrustContext:
    """The resolved tier for one message + how it was derived."""

    tier: TrustTier
    source: Literal["metadata", "role", "default"]

    @classmethod
    def resolve(cls, message: Mapping[str, object]) -> TrustContext:
        """Resolve the tier: explicit metadata wins, then role, then default.

        ``metadata.trust_level`` must be a known tier string (unknown
        values fail closed with ValueError). A non-string role fails
        closed with TypeError: the role is caller-declared, but a wrong
        type is a programming error, never a silent downgrade to
        untrusted. A missing or unknown role defaults to untrusted, per
        the issue ("everything else defaults to untrusted").
        """
        metadata = message.get("metadata")
        if isinstance(metadata, Mapping):
            raw_level = metadata.get("trust_level")
            if raw_level is not None:
                if not isinstance(raw_level, str):
                    raise ValueError(
                        "unknown trust tier: expected one of untrusted, tool, developer"
                    )
                return cls(tier=TrustTier.parse(raw_level), source="metadata")
        role = message.get("role")
        if role is None:
            return cls(tier=TrustTier.UNTRUSTED, source="default")
        if not isinstance(role, str):
            raise TypeError("message role must be a string")
        normalized_role = role.strip().lower()
        if normalized_role == "tool":
            return cls(tier=TrustTier.TOOL, source="role")
        if normalized_role == "developer":
            return cls(tier=TrustTier.DEVELOPER, source="role")
        return cls(tier=TrustTier.UNTRUSTED, source="default")


def normalize_for_matching(
    text: str,
) -> tuple[str, str, tuple[InvisibleCharFinding, ...]]:
    """NFKC-canonicalize, normalize Cf/Cc away, enumerate what was removed.

    Fullwidth and compatibility characters (e.g. fullwidth "IGNORE") match
    after NFKC, so that obfuscation class needs no finding. The findings
    cover only what NFKC leaves behind: format + control characters
    (tab / newline / carriage return excepted — legitimate whitespace).

    Returns ``(spaced, compact, findings)``: two views for matching plus
    the findings in raw order. ``spaced`` replaces each invisible char
    with a space, keeping word boundaries ("Ignore<ZW>all" still reads as
    two words); ``compact`` removes them, rejoining split keywords
    ("pass<ZW>word" still reads as "password"). Rules run over BOTH
    views — a match in either view counts — so neither obfuscation shape
    hides a lexical pattern. Positions are offsets in the
    NFKC-normalized text.
    """
    canonical = unicodedata.normalize("NFKC", text)
    findings: list[InvisibleCharFinding] = []
    spaced: list[str] = []
    compact: list[str] = []
    for position, char in enumerate(canonical):
        category = unicodedata.category(char)
        if category in _INVISIBLE_CATEGORIES and char not in _KEPT_WHITESPACE:
            findings.append(
                InvisibleCharFinding(
                    codepoint=f"U+{ord(char):04X}",
                    category=category,
                    position=position,
                )
            )
            spaced.append(" ")
        else:
            spaced.append(char)
            compact.append(char)
    return "".join(spaced), "".join(compact), tuple(findings)


@dataclass(frozen=True)
class ScanRule:
    """One hand-coded detection rule: regex over normalized text + weight.

    Weights are policy defaults, not measurements: they are chosen so the
    issue's acceptance fixtures land in their named bands (see the
    calibration note in gates.md / the fixture tests), and they are pinned
    by those tests. Category scores sum matched weights uncapped; the
    final score clamps at 1.0 after tier multipliers, so a developer-tier
    message can still reach HITL when several exfiltration rules fire.
    """

    rule_id: str
    category: Category
    pattern: re.Pattern[str]
    weight: float


def _rule(rule_id: str, category: Category, pattern: str, weight: float) -> ScanRule:
    return ScanRule(
        rule_id=rule_id,
        category=category,
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        weight=weight,
    )


# Rule families, derived from the repo's own payload shapes
# (payloads.py prompt/indirect injection) and the fuzzer's exfil-channel
# classifier. Every pattern is bounded (no nested quantifiers, no
# unbounded alternation): a 1M-char input scans in linear time.
DEFAULT_RULES: tuple[ScanRule, ...] = (
    # -- injection -------------------------------------------------------
    _rule(
        "injection-instruction-override",
        "injection",
        r"\b(?:ignore|disregard)\b.{0,40}?\b(?:previous|prior|above)\s+instructions?\b"
        r"|\byou are now\b",
        0.9,
    ),
    _rule(
        "injection-fake-system-tag",
        "injection",
        r"<\s*/?\s*system\s*>|\bsystem\s*:",
        0.7,
    ),
    _rule(
        "injection-role-injection",
        "injection",
        r"""['"]role['"]\s*:\s*['"]system['"]""",
        0.6,
    ),
    _rule(
        "injection-system-prompt-extraction",
        "injection",
        r"\brepeat\s+everything\s+above\b"
        r"|\breveal\s+(?:all\s+)?(?:previous|prior|system)\b"
        r"|\boutput\s+all\s+previous\b",
        0.6,
    ),
    _rule(
        "injection-code-exec-markdown",
        "injection",
        r"```\s*(?:python|bash|sh|shell|powershell)\b.{0,200}?\b(?:os\.system|subprocess|eval|exec)\s*\(",
        0.3,
    ),
    # -- exfiltration ----------------------------------------------------
    _rule(
        "exfiltration-send-to-external-url",
        "exfiltration",
        r"\bsend\b.{0,80}?\b(?:https?://|www\.|[a-z0-9-]+\.[a-z]{2,})\b",
        1.0,
    ),
    _rule(
        "exfiltration-conversation-harvest",
        "exfiltration",
        r"(?:\bconversation\b.{0,60}?\b(?:send|share|forward|upload|post)\b"
        r"|\b(?:send|share|forward|upload|post)\b.{0,60}?\bconversation\b)",
        0.8,
    ),
    _rule(
        "exfiltration-markdown-image-exfil",
        "exfiltration",
        r"!\[[^\]]*\]\(\s*https?://",
        0.9,
    ),
    _rule(
        "exfiltration-secret-disclosure-request",
        "exfiltration",
        r"\b(?:reveal|share|disclose|show|tell|give|send)\b.{0,60}?"
        r"\b(?:passwords?|secrets?|api[-_ ]?keys?|tokens?|credentials?|private[-_ ]?keys?)\b",
        0.5,
    ),
)


@dataclass(frozen=True)
class ScanResult:
    """The scanner's verdict for one message: score, tier, rules, findings.

    ``injection_score`` / ``exfiltration_score`` are the pre-multiplier
    category sums (uncapped); ``score`` is the tier-adjusted total
    clamped to [0, 1]. ``audit_only`` records the mode the scanner ran
    in: in audit-only (shadow) mode the routing decision is advisory —
    the caller enforces nothing from it.
    """

    score: float
    tier: TrustTier
    matched_rules: tuple[str, ...]
    invisible_char_findings: tuple[InvisibleCharFinding, ...]
    routing_decision: RoutingDecision
    audit_only: bool
    injection_score: float = 0.0
    exfiltration_score: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """The issue's acceptance shape (+ the audit-only flag)."""
        return {
            "score": self.score,
            "tier": self.tier.value,
            "matched_rules": list(self.matched_rules),
            "invisible_char_findings": [f.to_dict() for f in self.invisible_char_findings],
            "routing_decision": self.routing_decision.value,
            "audit_only": self.audit_only,
        }


@dataclass(frozen=True)
class InboundScanPolicy:
    """Scanner deployment policy: mode + routing thresholds.

    Mode ``audit`` (default): the scanner runs on every scanned message
    and its decision is recorded, but nothing is ever refused — shadow
    deployment. Mode ``enforce``: the gateway refuses ``block`` decisions
    and escalates ``hitl`` decisions. Thresholds must satisfy
    0 < hitl < block <= 1; anything else fails closed at construction.
    """

    mode: Literal["audit", "enforce"] = "audit"
    hitl_threshold: float = 0.40
    block_threshold: float = 0.80

    def __post_init__(self) -> None:
        if self.mode not in ("audit", "enforce"):
            raise ValueError("inbound scan mode must be one of audit, enforce")
        for name, value in (
            ("hitl_threshold", self.hitl_threshold),
            ("block_threshold", self.block_threshold),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"inbound scan {name} must be a number")
            if not 0 < value <= 1:
                raise ValueError(f"inbound scan {name} must be in (0, 1]")
        if not self.hitl_threshold < self.block_threshold:
            raise ValueError("inbound scan hitl_threshold must be below block_threshold")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> InboundScanPolicy:
        """Parse a policy-file ``inbound_scan`` mapping.

        Wrong shapes fail closed (TypeError); unknown mode strings fail
        closed (ValueError, value never echoed); unknown keys are ignored
        so policy files stay forward-compatible. Defaults are audit mode
        with the issue's 0.40 / 0.80 thresholds.
        """
        if not isinstance(data, Mapping):
            raise TypeError("gateway policy 'inbound_scan' must be an object")
        mode_raw = data.get("mode", "audit")
        if not isinstance(mode_raw, str):
            raise TypeError("gateway policy 'inbound_scan.mode' must be a string")
        if mode_raw not in ("audit", "enforce"):
            raise ValueError("gateway policy 'inbound_scan.mode' must be one of audit, enforce")
        mode: Literal["audit", "enforce"] = "audit" if mode_raw == "audit" else "enforce"
        thresholds: dict[str, float] = {}
        for name, default in (("hitl_threshold", 0.40), ("block_threshold", 0.80)):
            raw = data.get(name, default)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise TypeError(f"gateway policy 'inbound_scan.{name}' must be a number")
            thresholds[name] = float(raw)
        return cls(
            mode=mode,
            hitl_threshold=thresholds["hitl_threshold"],
            block_threshold=thresholds["block_threshold"],
        )


class InboundScanBlockedError(Exception):
    """A scanned message routed ``block`` in enforce mode: refused outright.

    Carries tier, score, and matched rule ids only — never content.
    The gateway raises this instead of returning the result to the model.
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__(
            f"inbound scan blocked: tier={result.tier.value} "
            f"score={result.score:.2f} rules={','.join(result.matched_rules)}"
        )


class InboundScanEscalationError(Exception):
    """A scanned message routed ``hitl`` in enforce mode without approval.

    Carries tier, score, and matched rule ids only — never content.
    The caller re-issues the call with a second approval attached.
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__(
            f"inbound scan needs a second approval: tier={result.tier.value} "
            f"score={result.score:.2f} rules={','.join(result.matched_rules)}"
        )


class InboundScanner:
    """Score one message per its trust tier; route allow / hitl / block."""

    def __init__(
        self,
        rules: tuple[ScanRule, ...] = DEFAULT_RULES,
        hitl_threshold: float = 0.40,
        block_threshold: float = 0.80,
        audit_only: bool = True,
    ) -> None:
        policy = InboundScanPolicy(
            mode="audit" if audit_only else "enforce",
            hitl_threshold=hitl_threshold,
            block_threshold=block_threshold,
        )
        self._rules = rules
        self._hitl_threshold = policy.hitl_threshold
        self._block_threshold = policy.block_threshold
        self._audit_only = audit_only

    @property
    def audit_only(self) -> bool:
        return self._audit_only

    def scan_message(self, message: Mapping[str, object]) -> ScanResult:
        """Score one message; never raises on message content.

        Type errors fail closed (non-string content/role); unknown
        ``metadata.trust_level`` values fail closed (ValueError from
        :meth:`TrustTier.parse`). A message with no role and no metadata
        scans as untrusted.
        """
        content = message.get("content")
        if not isinstance(content, str):
            raise TypeError("message content must be a string")
        context = TrustContext.resolve(message)
        spaced, compact, findings = normalize_for_matching(content)
        matched: list[str] = []
        injection_score = 0.0
        exfiltration_score = 0.0
        for rule in self._rules:
            if rule.pattern.search(spaced) or rule.pattern.search(compact):
                matched.append(rule.rule_id)
                if rule.category == "injection":
                    injection_score += rule.weight
                else:
                    exfiltration_score += rule.weight
        injection_mult, exfiltration_mult = _TIER_MULTIPLIERS[context.tier.value]
        score = min(
            1.0,
            injection_score * injection_mult + exfiltration_score * exfiltration_mult,
        )
        if score >= self._block_threshold:
            routing = RoutingDecision.BLOCK
        elif score >= self._hitl_threshold:
            routing = RoutingDecision.HITL
        else:
            routing = RoutingDecision.ALLOW
        return ScanResult(
            score=score,
            tier=context.tier,
            matched_rules=tuple(matched),
            invisible_char_findings=findings,
            routing_decision=routing,
            audit_only=self._audit_only,
            injection_score=injection_score,
            exfiltration_score=exfiltration_score,
        )
