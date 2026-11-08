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
3. Score four categories with hand-coded regex rule families derived from
   the repo's own payload shapes (``payloads.py`` prompt/indirect
   injection) and the fuzzer's exfil-channel classifier: injection,
   exfiltration, format, and invisible-chars. Each category is capped
   (rat #73: injection 0.70, exfiltration 0.60, format 0.25,
   invisible-chars 0.50) so one loud signal class can never dominate
   the verdict, and dense multi-signal prompts earn a stacking bonus
   (>=3 exfiltration cues +0.30, >=4 injection cues +0.20). Same
   content, different weight per tier: the ``tool`` tier multiplies
   both injection and exfiltration by 1.4 (indirect-injection surface);
   the ``developer`` tier multiplies exfiltration by 0.25 (legitimate
   ops talk about secrets). Format and invisible-chars are unweighted
   by tier. An injected semantic scorer (rat #73) runs only when the
   lexical score lands in the uncertainty band [0.20, 0.80]; it can
   only escalate, never clear a lexical signal, and its result is
   cached (512 entries, keyed by content hash) with fail-soft fallback
   to the deterministic score.
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
- Invisible-character findings are always reported, and since rat #73
  they also move the score: each finding contributes 0.05 to the
  invisible-chars category, capped at 0.50. A message of pure
  zero-width characters still routes ``allow`` (two findings score
  0.10), but dense obfuscation (10+ characters) reaches HITL. The
  findings exist so the audit trail shows the obfuscation attempt,
  and the capped category score is what prices it.
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

import hashlib
import logging
import re
import unicodedata
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol

logger = logging.getLogger(__name__)

__all__ = [
    "CATEGORY_CAPS",
    "SEMANTIC_BAND",
    "SEMANTIC_CACHE_SIZE",
    "STACKING_BONUS",
    "InboundScanBlockedError",
    "InboundScanEscalationError",
    "InboundScanPolicy",
    "InboundScanner",
    "InvisibleCharFinding",
    "RoutingDecision",
    "ScanResult",
    "ScanRule",
    "SemanticReview",
    "SemanticScorer",
    "TrustContext",
    "TrustTier",
    "normalize_for_matching",
]

# Category caps (rat #73, the issue's numbers, unmeasured book numbers
# like the #72 multipliers): per-category score is min(raw, cap), so one
# loud signal class can never dominate the verdict. With these caps a
# single saturated category at the untrusted tier reaches at most 0.70
# (injection) — HITL, never BLOCK — by itself.
CATEGORY_CAPS: dict[str, float] = {
    "injection": 0.70,
    "exfiltration": 0.60,
    "format": 0.25,
    "invisible-chars": 0.50,
}

# Stacking bonus (rat #73, the issue's numbers): compositional escalation.
# >=3 exfiltration cues add +0.30, >=4 injection cues add +0.20. A cue is
# one matched rule in the category. The bonus is added to the total AFTER
# capping and tier multipliers: dense weak cues are a separate escalation
# signal, not just the sum of parts.
STACKING_BONUS: dict[str, tuple[int, float]] = {
    "exfiltration": (3, 0.30),
    "injection": (4, 0.20),
}

# Gated semantic review (rat #73): the semantic scorer runs ONLY when the
# lexical score lands in this band, inclusive. Below it the deterministic
# score stands (clear allow); above it the deterministic score stands
# (clear block). This is what keeps the runtime defense practical rather
# than expensive by default.
SEMANTIC_BAND: tuple[float, float] = (0.20, 0.80)

# Semantic cache bound (rat #73, the issue's number): 512 entries, FIFO
# eviction. Keys are SHA-256 hashes of the normalized text, never content.
SEMANTIC_CACHE_SIZE: int = 512

# Invisible-character category weight (rat #73): each Cf/Cc finding
# contributes this much to the invisible-chars raw score (capped at 0.50).
# Two stray zero-width characters score 0.10 (still ALLOW, the #72 pin);
# dense obfuscation (10+ characters) reaches the 0.50 cap and HITL.
INVISIBLE_CHAR_WEIGHT: float = 0.05

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


Category = Literal["injection", "exfiltration", "format", "invisible-chars"]

SemanticReview = Literal["unavailable", "below-band", "above-band", "in-band", "cached", "failed"]


class SemanticScorer(Protocol):
    """The LLM semantic leg of the deterministic-first pattern (rat #73).

    A scorer judges one normalized message text and returns a risk score
    in [0, 1]. The scanner calls it ONLY when the lexical score lands in
    :data:`SEMANTIC_BAND`, caches the result, and falls back to the
    deterministic score if the scorer raises or returns out of range.
    There is no live scorer in this repo: ``jev/router.py`` routes but
    never judges (ADR-0009), and no model-call transport exists. A
    deployment wires its own scorer here; with none configured the
    deterministic score stands and ``semantic_review`` is "unavailable".
    The protocol takes the compact normalized text (invisible characters
    removed) so the scorer sees what the rules matched on.
    """

    def score(self, text: str) -> float: ...


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
    by those tests. Category scores sum matched weights, then cap per
    ``CATEGORY_CAPS`` (rat #73); the final score clamps at 1.0 after tier
    multipliers and the stacking bonus, so a developer-tier message can
    still reach HITL when several exfiltration rules fire.
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
    # -- format ----------------------------------------------------------
    # Structural/format anomalies: the shape of the message, not its
    # words. Capped at 0.25 by construction, so a format false positive
    # (e.g. a long innocent token that looks like base64) can never
    # route above ALLOW on its own.
    _rule(
        "format-hidden-html-comment",
        "format",
        r"<!--.*?-->",
        0.25,
    ),
    _rule(
        "format-base64-blob",
        "format",
        r"[A-Za-z0-9+/]{40,}={0,2}",
        0.25,
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
    the caller enforces nothing from it. ``category_scores`` holds the
    CAPPED per-category scores (``min(raw, cap)`` per rat #73) for every
    category with a nonzero raw score, before tier multipliers.
    ``stacking_bonus`` is the compositional bonus added to the total
    after capping (>=3 exfiltration cues +0.30, >=4 injection cues
    +0.20). ``semantic_score`` is the LLM-leg score when the semantic
    review ran (None when it did not); ``semantic_review`` says why:
    "unavailable" (no scorer configured), "below-band" / "above-band"
    (lexical score outside [0.20, 0.80], deterministic score stands),
    "in-band" (scorer ran), "cached" (served from the bounded cache),
    "failed" (scorer raised or returned out of range: fail-soft to the
    deterministic score). ``semantic_calls`` is the call counter for
    this scan (0 or 1): the acceptance "no calls for scores <0.20 or
    >0.80" is observable per scan, and the cache-hit rate over the
    audit log is the fraction of in-band scans with ``cached`` review.
    """

    score: float
    tier: TrustTier
    matched_rules: tuple[str, ...]
    invisible_char_findings: tuple[InvisibleCharFinding, ...]
    routing_decision: RoutingDecision
    audit_only: bool
    injection_score: float = 0.0
    exfiltration_score: float = 0.0
    category_scores: tuple[tuple[str, float], ...] = ()
    stacking_bonus: float = 0.0
    semantic_score: float | None = None
    semantic_review: SemanticReview = "unavailable"
    semantic_cache_hit: bool = False
    semantic_calls: int = 0

    def to_dict(self) -> dict[str, object]:
        """The issue's acceptance shape (+ the audit-only flag)."""
        return {
            "score": self.score,
            "tier": self.tier.value,
            "matched_rules": list(self.matched_rules),
            "invisible_char_findings": [f.to_dict() for f in self.invisible_char_findings],
            "routing_decision": self.routing_decision.value,
            "audit_only": self.audit_only,
            "category_scores": dict(self.category_scores),
            "stacking_bonus": self.stacking_bonus,
            "semantic_score": self.semantic_score,
            "semantic_review": self.semantic_review,
            "semantic_cache_hit": self.semantic_cache_hit,
            "semantic_calls": self.semantic_calls,
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
    """Score one message per its trust tier; route allow / hitl / block.

    Compositional scoring (rat #73): each signal family is capped
    (``CATEGORY_CAPS``), dense multi-signal prompts earn a stacking
    bonus, and an injected semantic scorer runs only inside the
    uncertainty band [0.20, 0.80] with a bounded cache and fail-soft
    fallback to the deterministic score.
    """

    def __init__(
        self,
        rules: tuple[ScanRule, ...] = DEFAULT_RULES,
        hitl_threshold: float = 0.40,
        block_threshold: float = 0.80,
        audit_only: bool = True,
        semantic_scorer: SemanticScorer | None = None,
        semantic_cache_size: int = SEMANTIC_CACHE_SIZE,
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
        self._semantic_scorer = semantic_scorer
        if isinstance(semantic_cache_size, bool) or not isinstance(semantic_cache_size, int):
            raise TypeError("semantic cache size must be an integer")
        if semantic_cache_size < 1:
            raise ValueError("semantic cache size must be at least 1")
        self._semantic_cache_size = semantic_cache_size
        # Bounded cache: SHA-256 of the compact normalized text -> score.
        # Scores only, never content (same no-content rule as the audit log).
        self._semantic_cache: OrderedDict[str, float] = OrderedDict()

    @property
    def audit_only(self) -> bool:
        return self._audit_only

    @property
    def semantic_scorer(self) -> SemanticScorer | None:
        return self._semantic_scorer

    def _semantic_review(
        self, lexical_score: float, compact: str
    ) -> tuple[float | None, SemanticReview, bool, int]:
        """Gated semantic review for one lexical score.

        Returns ``(semantic_score, review, cache_hit, calls)``. No scorer
        configured -> (None, "unavailable", False, 0). Lexical score
        outside the band -> deterministic score stands, no call. Inside
        the band the scorer runs once per distinct text (cache hit serves
        repeat texts without a call); a raise or an out-of-range return
        logs and falls back to the deterministic score ("failed").
        """
        if self._semantic_scorer is None:
            return None, "unavailable", False, 0
        low, high = SEMANTIC_BAND
        if lexical_score < low:
            return None, "below-band", False, 0
        if lexical_score > high:
            return None, "above-band", False, 0
        cache_key = hashlib.sha256(compact.encode("utf-8")).hexdigest()
        cached = self._semantic_cache.get(cache_key)
        if cached is not None:
            self._semantic_cache.move_to_end(cache_key)
            return cached, "cached", True, 0
        try:
            value = self._semantic_scorer.score(compact)
        except Exception:
            logger.warning(
                "semantic scorer failed; falling back to the deterministic score",
                exc_info=True,
            )
            return None, "failed", False, 1
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            logger.warning(
                "semantic scorer returned a non-number; falling back to the deterministic score"
            )
            return None, "failed", False, 1
        semantic = float(value)
        if not 0.0 <= semantic <= 1.0:
            logger.warning(
                "semantic scorer returned an out-of-range score; falling back to the deterministic score"
            )
            return None, "failed", False, 1
        self._semantic_cache[cache_key] = semantic
        while len(self._semantic_cache) > self._semantic_cache_size:
            self._semantic_cache.popitem(last=False)
        return semantic, "in-band", False, 1

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
        raw: dict[str, float] = {category: 0.0 for category in CATEGORY_CAPS}
        cues: dict[str, int] = {category: 0 for category in CATEGORY_CAPS}
        for rule in self._rules:
            if rule.pattern.search(spaced) or rule.pattern.search(compact):
                matched.append(rule.rule_id)
                raw[rule.category] += rule.weight
                cues[rule.category] += 1
        # Invisible characters are a scored category (rat #73): each
        # finding contributes INVISIBLE_CHAR_WEIGHT, capped at 0.50.
        raw["invisible-chars"] = INVISIBLE_CHAR_WEIGHT * len(findings)
        cues["invisible-chars"] = len(findings)
        capped = {
            category: min(raw[category], CATEGORY_CAPS[category]) for category in CATEGORY_CAPS
        }
        injection_mult, exfiltration_mult = _TIER_MULTIPLIERS[context.tier.value]
        multipliers = {
            "injection": injection_mult,
            "exfiltration": exfiltration_mult,
            "format": 1.0,
            "invisible-chars": 1.0,
        }
        lexical_score = sum(capped[category] * multipliers[category] for category in CATEGORY_CAPS)
        stacking_bonus = 0.0
        for category, (needed, bonus) in STACKING_BONUS.items():
            if cues[category] >= needed:
                stacking_bonus += bonus
        lexical_score = min(1.0, lexical_score + stacking_bonus)
        semantic_score, semantic_review, cache_hit, calls = self._semantic_review(
            lexical_score, compact
        )
        # The semantic review can only escalate, never clear a lexical
        # signal: final = max(lexical, semantic) in-band. Deterministic-
        # first means the LLM leg never downgrades what the rules found.
        score = lexical_score
        if semantic_score is not None:
            score = min(1.0, max(lexical_score, semantic_score))
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
            injection_score=raw["injection"],
            exfiltration_score=raw["exfiltration"],
            category_scores=tuple(
                (category, capped[category]) for category in CATEGORY_CAPS if raw[category] > 0
            ),
            stacking_bonus=stacking_bonus,
            semantic_score=semantic_score,
            semantic_review=semantic_review,
            semantic_cache_hit=cache_hit,
            semantic_calls=calls,
        )
