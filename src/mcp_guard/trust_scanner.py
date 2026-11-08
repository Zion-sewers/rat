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
   exfiltration, format, and invisible-chars. Each category's
   contribution is capped (rat #73: injection 0.70, exfiltration 0.60,
   format 0.25, invisible-chars 0.50): the raw score plus the stacking
   bonus is multiplied by the tier multiplier and then capped, so one
   loud signal class can never contribute more than its cap at ANY tier
   — a single saturated category reaches at most 0.70 (injection),
   HITL, never BLOCK, by itself. Dense multi-signal prompts earn a
   stacking bonus (>=3 exfiltration cues +0.30, >=4 injection cues
   +0.20) folded into the category score BEFORE the cap, so the bonus
   lifts sub-cap dense prompts without ever breaking the cap. Same
   content, different weight per tier: the ``tool`` tier multiplies
   both injection and exfiltration by 1.4 (indirect-injection surface);
   the ``developer`` tier multiplies exfiltration by 0.25 (legitimate
   ops talk about secrets). Format and invisible-chars are unweighted
   by tier. An injected semantic scorer (rat #73) runs only when the
   lexical score lands in the uncertainty band [0.20, 0.80]; in the
   band its score REPLACES the lexical score (the judge decides
   uncertain cases — it can clear a lexical false positive as well as
   escalate), used unweighted and capped at 0.70, the largest category
   cap: the verdict is a verdict on the message, not on a signal
   family, so no lexical category's multiplier applies to it. The
   tier decides WHETHER the judge runs (the band is measured on the
   tier-adjusted lexical score), never what the verdict is worth once
   it runs. The judge can therefore never BLOCK (max 0.70 < 0.80) —
   that is a deliberate limitation of the deterministic-first pattern
   as implemented, stated plainly. Its result is cached
   (512 entries, LRU, keyed by content hash) with fail-soft fallback
   to the deterministic score. The band is measured on the final
   lexical score (post-cap, post-bonus, post-multiplier): the band
   gauges the deterministic verdict's uncertainty, not the raw rules.
   Scores are quantized to 4 decimals before routing, so threshold
   comparisons are decimal-exact, not float-exact (0.70 + 4 x 0.025
   is 0.80, BLOCK, not a float dust below it).
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
  they also move the score: each finding contributes 0.025 to the
  invisible-chars category, capped at 0.50. A message of pure
  zero-width characters still routes ``allow`` (two findings score
  0.05), eight stray characters (a plausible copy-paste artifact)
  score 0.20, while deliberate obfuscation (16+ characters) reaches
  HITL. The findings exist so the audit trail shows the obfuscation
  attempt, and the capped category score is what prices it.
- Evidence kinds (rat #73 fix-forward, the independence criterion):
  categories are evidence KINDS, not disjoint byte spans. Lexical
  content (injection, exfiltration) and concealment (format,
  invisible-chars) are different kinds of evidence about the same
  message, so both may claim the same bytes by design: a hidden HTML
  comment around an instruction is two facts (the instruction, and
  the concealment), and a zero-width character that both enables a
  lexical match and adds an invisible-chars finding is priced twice
  for the same reason. Two lexical rules matching the same bytes also
  both count (cue = one matched rule, documented as design). What the
  caps guarantee is per-category contribution, never per-byte
  independence — and the guarantee is structural, not documentary:
  the scanner refuses to construct unless the largest cap sits below
  the block threshold (``max(caps) < block_threshold``, enforced in
  ``__init__`` and therefore in the tuning harness and the policy
  file, both of which build a scanner), so no accepted configuration
  can void it; a deployment that wants a lower block threshold must
  lower the caps with it.
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
import math
import re
import unicodedata
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol

from .semantic import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT_S,
    OllamaSemanticScorer,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CATEGORY_CAPS",
    "SEMANTIC_BAND",
    "SEMANTIC_CACHE_SIZE",
    "SEMANTIC_CAP",
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
# like the #72 multipliers): per-category CONTRIBUTION is min((raw +
# bonus) * mult, cap), so one loud signal class can never contribute more
# than its cap at ANY tier. A single saturated category reaches at most
# 0.70 (injection) — HITL, never BLOCK — by itself, at the shipped
# thresholds (block 0.80 > largest cap 0.70; see the evidence-kinds
# note in the module docstring for the precondition). "Saturated" means
# one rule at 3x its cap (single-signal saturation); no shipped rule
# reaches 3x any cap (largest: send-to-external 1.0 vs the 0.60
# exfiltration cap, 1.67x), so the 3x fixture uses synthetic rules —
# a multi-cue prompt reaching BLOCK via the stacking bonus is a separate
# mechanism, not a saturated category.
CATEGORY_CAPS: dict[str, float] = {
    "injection": 0.70,
    "exfiltration": 0.60,
    "format": 0.25,
    "invisible-chars": 0.50,
}

# Stacking bonus (rat #73, the issue's numbers): compositional escalation.
# >=3 exfiltration cues add +0.30, >=4 injection cues add +0.20. A cue is
# one matched rule in the category. The bonus is folded into the category
# score BEFORE the cap and the tier multiplier: dense weak cues lift a
# sub-cap category toward its cap, but the bonus can never break the cap
# — a single category's total contribution stays bounded by its cap.
# Routing-real at the shipped weights (rat #73 fix-forward, round 2):
# the shipped exfiltration weights are retuned so a realistic three-cue
# combination is routing-real at the developer tier, where the 0.25
# discount creates headroom — conversation-harvest 0.8 +
# markdown-image 0.45 + secret-disclosure 0.30 = 1.55 raw scores 0.3875
# (ALLOW) without the bonus and (1.55 + 0.30) x 0.25 = 0.4625 (HITL)
# with it, so the bonus is the sole cause of that crossing. At the
# untrusted/tool tiers every three-cue combination already saturates
# its cap without the bonus, so the bonus cannot move a routing there
# — that is structural in the issue's numbers (caps barely above the
# HITL threshold), not a bug in the mechanism. The weak-rules
# sole-cause fixture (0.10 cues) stays as the mechanism proof, labeled
# synthetic. Overlapping rules count separately (cue = one matched
# rule): one sentence matching two rules earns two cues, by design.
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

# Semantic cache bound (rat #73, the issue's number): 512 entries, LRU
# eviction (a hit refreshes recency). Keys are SHA-256 hashes of the
# normalized text, never content.
SEMANTIC_CACHE_SIZE: int = 512

# Semantic cap (rat #73 fix-forward): no single signal class may
# contribute more than the largest category cap — the semantic leg is a
# signal class too, so its (unweighted) score is capped here. The judge
# can therefore never BLOCK (0.70 < 0.80), by design.
SEMANTIC_CAP: float = max(CATEGORY_CAPS.values())

# Invisible-character category weight (rat #73 fix-forward): each Cf/Cc
# finding contributes this much to the invisible-chars raw score (capped
# at 0.50). The issue fixes only the cap; the per-finding weight is the
# implementer's choice. 0.025 keeps plausible copy-paste artifacts out
# of HITL (8 stray zero-width characters score 0.20, still ALLOW) while
# deliberate obfuscation (16 characters) reaches HITL and 20 hit the cap.
INVISIBLE_CHAR_WEIGHT: float = 0.025

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
    :data:`SEMANTIC_BAND`, caches the RAW score (no tier adjustment
    exists to leak: the verdict is used unweighted, so a cached score
    is the same at every tier), and falls back to the deterministic
    score if the scorer raises or returns out of range. In the band the
    scorer's verdict REPLACES the lexical score (the judge decides
    uncertain cases — it can clear a lexical false positive as well as
    escalate), capped at :data:`SEMANTIC_CAP` and nothing else: the
    verdict is a verdict on the message, not on a signal family, so no
    lexical category's multiplier applies to it, and the judge can
    never BLOCK (0.70 < 0.80). The tier decides WHETHER the judge runs
    (the band is measured on the tier-adjusted lexical score), never
    what the verdict is worth once it runs.

    The shipped scorer is :class:`mcp_guard.semantic.OllamaSemanticScorer`
    (local Ollama model, off by default); a deployment may wire its own
    here. With none configured the deterministic score stands and
    ``semantic_review`` is "unavailable". The protocol takes the compact
    normalized text (invisible characters removed) so the scorer sees
    what the rules matched on.

    Deployment contract (the scanner enforces none of this): the scorer
    receives the RAW message text — secrets and PII intact, since the
    gateway deliberately scans before PII tokenization — so a scorer
    must run against a model the deployment trusts with that text
    (local by default), and the scorer itself must bound its own latency
    (timeout): the scanner calls it synchronously with no timeout, and
    fail-soft covers exceptions, not a hanging scorer — a hanging custom
    scorer stalls one gateway call with no watchdog, and a failed call
    is NOT cached, so every in-band repeat re-calls a down server (the
    shipped scorer's timeout is the only backstop; there is no circuit
    breaker). A scorer that raises :exc:`BaseException`
    (KeyboardInterrupt, SystemExit) is NOT caught: a process signal is
    not a scorer failure, and it propagates.
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

    A rule may instead carry a ``matcher`` predicate, used when the
    regex form of the detection is not linear-time (the base64 rule);
    when present the matcher is authoritative and ``pattern`` is only
    the candidate-run shape.

    Weights are policy defaults, not measurements: they are chosen so the
    issue's acceptance fixtures land in their named bands (see the
    calibration note in gates.md / the fixture tests), and they are pinned
    by those tests. A rule's category must be one of ``CATEGORY_CAPS``
    (anything else fails closed at construction — an unknown category
    would otherwise crash scoring with a KeyError) and its weight must
    be a finite non-negative number (a negative weight would subtract
    from its category and break the [0, 1] score contract; the cap, not
    the weight, bounds the contribution).
    Category scores sum matched weights plus the stacking bonus, are
    tier-multiplied, and then cap per ``CATEGORY_CAPS`` (rat #73); the
    final score is the sum of the capped contributions, clamped at 1.0.
    """

    rule_id: str
    category: Category
    pattern: re.Pattern[str]
    weight: float
    # Optional predicate matcher: when present it is authoritative and
    # the pattern is only the candidate-run shape. Exists for the
    # base64 rule, whose regex form was quadratic on long hex-only
    # runs (rat #73 fix-forward, round 3) — the predicate is a linear
    # run scan instead. A rule copied without its matcher (the
    # harness's _with_overrides, the bonus-sweep tests) must carry it
    # along, or the copy silently reverts to the pattern.
    matcher: Callable[[str], bool] | None = None

    def __post_init__(self) -> None:
        if self.category not in CATEGORY_CAPS:
            raise ValueError(f"unknown rule category: {self.category!r}")
        if isinstance(self.weight, bool) or not isinstance(self.weight, (int, float)):
            raise TypeError("rule weight must be a number")
        if not math.isfinite(self.weight):
            raise ValueError("rule weight must be finite")
        if self.weight < 0:
            raise ValueError("rule weight must be non-negative")
        if self.matcher is not None and not callable(self.matcher):
            raise TypeError("rule matcher must be callable")


def _rule(
    rule_id: str,
    category: Category,
    pattern: str,
    weight: float,
    matcher: Callable[[str], bool] | None = None,
) -> ScanRule:
    return ScanRule(
        rule_id=rule_id,
        category=category,
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        weight=weight,
        matcher=matcher,
    )


# Linear base64-blob detection (rat #73 fix-forward, round 3): the
# regex form of this rule was quadratic on long hex-only runs — the
# engine backtracked at every start position, stalling the gateway's
# synchronous scan path (~17s for a 10k-char hex run). The predicate
# is now a single linear pass: split the text into maximal
# [A-Za-z0-9+/=] runs and test each run. A run matches when either
# (a) a 40+ base64 stretch sits immediately before a '=' (a padded
# blob — a hex digest never carries '='), or (b) a non-hex character
# (g-z, G-Z, +, /, or '=' itself) has 39+ base64 characters
# immediately after it. The boundary is positional: a 46-character
# token escapes only when its first non-hex character sits at index 7
# or later (fewer than 39 characters follow it).
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]+")
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _matches_base64_blob(text: str) -> bool:
    """Whether ``text`` holds a long base64 blob (linear in len(text))."""
    for run_match in _BASE64_RUN_RE.finditer(text):
        segments = run_match.group(0).split("=")
        for index, segment in enumerate(segments):
            # (a) a 40+ base64 stretch immediately before a '='.
            if index < len(segments) - 1 and len(segment) >= 40:
                return True
            # (b) an '=' with 39+ base64 characters after it: the '='
            # itself is the non-hex character the old regex required.
            if index > 0 and len(segment) >= 39:
                return True
            # (b) a non-hex character inside the stretch with 39+
            # base64 characters after it. Only the FIRST non-hex
            # character can satisfy this — later ones have fewer
            # characters after them — so one check per segment.
            for position, char in enumerate(segment):
                if char not in _HEX_CHARS:
                    if len(segment) - position - 1 >= 39:
                        return True
                    break
    return False


# Rule families, derived from the repo's own payload shapes
# (payloads.py prompt/indirect injection) and the fuzzer's exfil-channel
# classifier. Every pattern is bounded (no nested quantifiers, no
# unbounded alternation), and the base64 rule matches with the linear
# run scan above instead of a regex: a 1M-char input scans in linear
# time.
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
        # Candidate-run shape only — the authoritative predicate is
        # _matches_base64_blob (a linear run scan; the regex form of
        # this rule was quadratic on long hex-only runs). A long
        # base64 run matches when either padded (a hex digest never
        # carries '=') or containing a non-hex character with 39+
        # base64 characters after it, so SHA-256 digests and other
        # hex-only runs do not match. Realistic JWTs DO match
        # (verified): a 64-character payload segment clears the
        # 39-after-a-non-hex bar — a known false positive, bounded by
        # the 0.25 format cap, so a JWT alone routes ALLOW. A JWT that
        # moves is caught by the exfiltration rules (URL,
        # markdown-image) instead. Long padded blobs still match.
        r"[A-Za-z0-9+/=]{40,}",
        0.25,
        matcher=_matches_base64_blob,
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
        # 0.45 (rat #73 fix-forward, round 2): retuned down from 0.9 so
        # the stacking bonus is routing-real — with harvest 0.8 and
        # secret-disclosure 0.30, a realistic three-cue combination
        # (1.55 raw) sits below HITL at the developer tier pre-bonus
        # and crosses only with the bonus. Alone it still HITLs at
        # every tier (0.45 untrusted; 0.45 x 1.4 capped at 0.60 tool).
        0.45,
    ),
    _rule(
        "exfiltration-secret-disclosure-request",
        "exfiltration",
        r"\b(?:reveal|share|disclose|show|tell|give|send)\b.{0,60}?"
        r"\b(?:passwords?|secrets?|api[-_ ]?keys?|tokens?|credentials?|private[-_ ]?keys?)\b",
        # 0.30 (rat #73 fix-forward, round 2): retuned down from 0.5
        # for the same routing-real bonus (see above). Alone it still
        # HITLs at the tool tier (0.30 x 1.4 = 0.42); at the developer
        # tier a legitimate secret request allows at 0.075.
        0.30,
    ),
)


@dataclass(frozen=True)
class ScanResult:
    """The scanner's verdict for one message: score, tier, rules, findings.

    Two conventions live in this struct, named explicitly so no consumer
    mixes them: ``injection_score`` / ``exfiltration_score`` are the RAW
    pre-multiplier category sums (uncapped, bonus excluded); ``score``
    is the tier-adjusted total clamped to [0, 1]. ``audit_only`` records
    the mode the scanner ran in: in audit-only (shadow) mode the routing
    decision is advisory — the caller enforces nothing from it.
    ``category_scores`` holds the CAPPED per-category CONTRIBUTIONS
    (``min((raw + bonus) * mult, cap)`` per rat #73 fix-forward) for
    every category with a nonzero raw score. ``stacking_bonus`` is the
    total earned bonus (pre-cap value) folded into the category scores
    before the cap (>=3 exfiltration cues +0.30, >=4 injection cues
    +0.20).
    ``semantic_score`` is the RAW LLM-leg score when the semantic review
    ran (None when it did not) — the verdict is used unweighted, capped
    at :data:`SEMANTIC_CAP`, so this field is what the scorer actually
    said and ``score`` is the capped copy of it in-band. ``semantic_review``
    says why: "unavailable" (no scorer configured),
    "below-band" / "above-band" (lexical score outside [0.20, 0.80],
    deterministic score stands), "in-band" (scorer ran and its verdict
    replaced the lexical score), "cached" (served from the bounded
    cache), "failed" (scorer raised or returned out of range: fail-soft
    to the deterministic score). ``semantic_calls`` is the call counter
    for this scan (0 or 1): the acceptance "no calls for scores <0.20 or
    >0.80" is observable per scan, and the cache-hit rate over the
    audit log is the fraction of in-band scans (review "in-band" plus
    review "cached") with ``cached`` review. ``stacking_bonus_by_category``
    names the earned bonus per category (only categories that earned
    one); ``bonus_clipped_by_category`` names how much of (raw + bonus)
    x multiplier each cap removed (only categories the cap bit on), so
    the audit log can reconstruct the bonus and the cap's effect.
    Scores are quantized to 4 decimals before routing, so ``score`` is
    decimal-exact at threshold comparisons.
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
    stacking_bonus_by_category: tuple[tuple[str, float], ...] = ()
    bonus_clipped_by_category: tuple[tuple[str, float], ...] = ()
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
            "injection_score": self.injection_score,
            "exfiltration_score": self.exfiltration_score,
            "category_scores": dict(self.category_scores),
            "stacking_bonus": self.stacking_bonus,
            "stacking_bonus_by_category": dict(self.stacking_bonus_by_category),
            "bonus_clipped_by_category": dict(self.bonus_clipped_by_category),
            "semantic_score": self.semantic_score,
            "semantic_review": self.semantic_review,
            "semantic_cache_hit": self.semantic_cache_hit,
            "semantic_calls": self.semantic_calls,
        }


def _validate_thresholds(hitl_threshold: float, block_threshold: float) -> None:
    """Shared threshold validation for the policy and the scanner.

    Thresholds must satisfy 0 < hitl < block <= 1; anything else fails
    closed. One helper so the scanner does not construct a throwaway
    policy solely to validate its thresholds.
    """
    for name, value in (
        ("hitl_threshold", hitl_threshold),
        ("block_threshold", block_threshold),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"inbound scan {name} must be a number")
        if not 0 < value <= 1:
            raise ValueError(f"inbound scan {name} must be in (0, 1]")
    if not hitl_threshold < block_threshold:
        raise ValueError("inbound scan hitl_threshold must be below block_threshold")


@dataclass(frozen=True)
class InboundScanPolicy:
    """Scanner deployment policy: mode + routing thresholds + semantic scorer.

    Mode ``audit`` (default): the scanner runs on every scanned message
    and its decision is recorded, but nothing is ever refused — shadow
    deployment. Mode ``enforce``: the gateway refuses ``block`` decisions
    and escalates ``hitl`` decisions. Thresholds must satisfy
    0 < hitl < block <= 1; anything else fails closed at construction.
    ``semantic_scorer`` (default None) is the opt-in LLM leg: when set,
    the gateway wires it into the default scanner; the shipped default
    stays deterministic-only. In a policy file it comes from
    ``inbound_scan.semantic_scorer`` — {"type": "ollama", "model": ...,
    "base_url": ..., "timeout_s": ...} — and only "ollama" is a known
    type; anything else fails closed.
    """

    mode: Literal["audit", "enforce"] = "audit"
    hitl_threshold: float = 0.40
    block_threshold: float = 0.80
    semantic_scorer: SemanticScorer | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("audit", "enforce"):
            raise ValueError("inbound scan mode must be one of audit, enforce")
        _validate_thresholds(self.hitl_threshold, self.block_threshold)

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
        scorer = cls._parse_semantic_scorer(data.get("semantic_scorer"))
        return cls(
            mode=mode,
            hitl_threshold=thresholds["hitl_threshold"],
            block_threshold=thresholds["block_threshold"],
            semantic_scorer=scorer,
        )

    @staticmethod
    def _parse_semantic_scorer(raw: object) -> SemanticScorer | None:
        """Parse ``inbound_scan.semantic_scorer`` (or None for absent).

        Only "ollama" is a known type; unknown types, wrong shapes, and
        out-of-range values fail closed. The scorer's own constructor
        validates the model name, base URL, and timeout. ``type``
        defaults to "ollama" when omitted.
        """
        if raw is None:
            return None
        if not isinstance(raw, Mapping):
            raise TypeError("gateway policy 'inbound_scan.semantic_scorer' must be an object")
        scorer_type = raw.get("type", "ollama")
        if not isinstance(scorer_type, str):
            raise TypeError("gateway policy 'inbound_scan.semantic_scorer.type' must be a string")
        if scorer_type != "ollama":
            raise ValueError("gateway policy 'inbound_scan.semantic_scorer.type' must be 'ollama'")
        model = raw.get("model", DEFAULT_MODEL)
        if not isinstance(model, str):
            raise TypeError("gateway policy 'inbound_scan.semantic_scorer.model' must be a string")
        base_url = raw.get("base_url", DEFAULT_BASE_URL)
        if not isinstance(base_url, str):
            raise TypeError(
                "gateway policy 'inbound_scan.semantic_scorer.base_url' must be a string"
            )
        timeout_s = raw.get("timeout_s", DEFAULT_TIMEOUT_S)
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
            raise TypeError(
                "gateway policy 'inbound_scan.semantic_scorer.timeout_s' must be a number"
            )
        return OllamaSemanticScorer(model=model, base_url=base_url, timeout_s=float(timeout_s))


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

    Compositional scoring (rat #73): each signal family contributes at
    most its cap (``CATEGORY_CAPS``) at any tier — the raw score plus
    the stacking bonus is tier-multiplied and then capped — dense
    multi-signal prompts earn a stacking bonus folded into the category
    score before the cap, and an injected semantic scorer runs only
    inside the uncertainty band [0.20, 0.80] with a bounded cache and
    fail-soft fallback to the deterministic score. ``caps`` /
    ``stacking_bonus`` override the module constants (the weight-tuning
    harness's knobs); unknown keys or out-of-range values fail closed.
    A cap at or above the block threshold fails closed too: the
    single-category-never-BLOCKs guarantee is enforced at construction
    (``max(caps) < block_threshold``), so no accepted configuration
    can void it.
    """

    def __init__(
        self,
        rules: tuple[ScanRule, ...] = DEFAULT_RULES,
        hitl_threshold: float = 0.40,
        block_threshold: float = 0.80,
        audit_only: bool = True,
        semantic_scorer: SemanticScorer | None = None,
        semantic_cache_size: int = SEMANTIC_CACHE_SIZE,
        caps: Mapping[str, float] | None = None,
        stacking_bonus: Mapping[str, tuple[int, float]] | None = None,
    ) -> None:
        _validate_thresholds(hitl_threshold, block_threshold)
        # Defensive copy: a generator would score once, then silently
        # score 0.0 on every later scan; None raises here, not at scan
        # time. Items must be ScanRules — anything else fails closed
        # at construction, not with an AttributeError mid-scan.
        self._rules = tuple(rules)
        if not all(isinstance(rule, ScanRule) for rule in self._rules):
            raise TypeError("rules must be ScanRules")
        self._hitl_threshold = float(hitl_threshold)
        self._block_threshold = float(block_threshold)
        self._audit_only = audit_only
        self._semantic_scorer = semantic_scorer
        if isinstance(semantic_cache_size, bool) or not isinstance(semantic_cache_size, int):
            raise TypeError("semantic cache size must be an integer")
        if semantic_cache_size < 1:
            raise ValueError("semantic cache size must be at least 1")
        self._semantic_cache_size = semantic_cache_size
        # Bounded cache: SHA-256 of the compact normalized text -> RAW
        # scorer score. Scores only, never content (same no-content rule
        # as the audit log). The cache is per scanner instance and the
        # scorer is fixed at construction with no setter, so a key
        # without scorer identity cannot leak one scorer's verdict into
        # another scanner — the isolation is by construction, not by
        # the key. The verdict is used unweighted, so a cached score is
        # the same at every tier.
        self._semantic_cache: OrderedDict[str, float] = OrderedDict()
        self._caps = self._validate_caps(caps)
        self._stacking = self._validate_stacking(stacking_bonus)
        # The single-category-never-BLOCKs guarantee is structural:
        # the largest cap must sit below the block threshold, or a
        # single saturated category could BLOCK by itself — and the
        # semantic cap, derived from the same values, could BLOCK too.
        # Caps and thresholds are validated independently above, so
        # the cross-check lives here: any combination that voids the
        # guarantee fails closed at construction, including through
        # the tuning harness and the policy file (both build a scanner).
        if max(self._caps.values()) >= self._block_threshold:
            raise ValueError(
                "inbound scan caps must sit below block_threshold "
                f"(largest cap {max(self._caps.values())} >= block "
                f"{self._block_threshold}): a single saturated category "
                "would BLOCK by itself"
            )
        # No single signal class may contribute more than the largest
        # category cap — the semantic leg is a signal class too.
        self._semantic_cap = max(self._caps.values())

    @staticmethod
    def _validate_caps(
        caps: Mapping[str, float] | None,
    ) -> dict[str, float]:
        if caps is not None and not isinstance(caps, Mapping):
            raise TypeError("caps must be a mapping")
        merged = dict(CATEGORY_CAPS)
        if caps is None:
            return merged
        for category, value in caps.items():
            if category not in CATEGORY_CAPS:
                raise ValueError(f"unknown cap category: {category!r}")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"cap for {category!r} must be a number")
            if not 0.0 < float(value) <= 1.0:
                raise ValueError(f"cap for {category!r} must be in (0, 1]")
            merged[category] = float(value)
        return merged

    @staticmethod
    def _validate_stacking(
        stacking_bonus: Mapping[str, tuple[int, float]] | None,
    ) -> dict[str, tuple[int, float]]:
        if stacking_bonus is not None and not isinstance(stacking_bonus, Mapping):
            raise TypeError("stacking_bonus must be a mapping")
        merged = dict(STACKING_BONUS)
        if stacking_bonus is None:
            return merged
        for category, pair in stacking_bonus.items():
            if category not in STACKING_BONUS:
                raise ValueError(f"unknown stacking category: {category!r}")
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise TypeError(
                    f"stacking bonus for {category!r} must be a (threshold, bonus) pair"
                )
            needed, value = pair
            if isinstance(needed, bool) or not isinstance(needed, int) or needed < 1:
                raise ValueError(f"stacking threshold for {category!r} must be an integer >= 1")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"stacking bonus for {category!r} must be a number")
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"stacking bonus for {category!r} must be in [0, 1]")
            merged[category] = (needed, float(value))
        return merged

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

        Returns ``(semantic_score, review, cache_hit, calls)`` where the
        score is the RAW scorer verdict (used unweighted in
        :meth:`scan_message`, so the cache never leaks one tier's
        treatment into another — there is no tier treatment to leak).
        No scorer configured -> (None, "unavailable", False, 0).
        Lexical score outside the band -> deterministic score stands,
        no call. Inside the band the scorer runs once per distinct text
        (cache hit serves repeat texts without a call); a raise or an
        out-of-range return logs and falls back to the deterministic
        score ("failed"). A scorer raising :exc:`BaseException` is NOT
        caught here: a process signal is not a scorer failure, and it
        propagates.
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
            # The compact view only adds signal when it differs from the
            # spaced view (non-ASCII / invisible characters present):
            # for plain ASCII text the two views are identical and the
            # second search is pure duplication — skipping it keeps
            # 1M-char scans linear and fast (rat #73 fix-forward, impl
            # advisory A9: the rule loop, not normalization, dominated).
            # A rule with a matcher predicate uses it (the base64 rule:
            # its regex form was quadratic); otherwise the regex. The
            # matcher runs over the same two views as the regex.
            if rule.matcher is not None:
                matched_rule = rule.matcher(spaced) or (compact != spaced and rule.matcher(compact))
            else:
                matched_rule = rule.pattern.search(spaced) is not None or (
                    compact != spaced and rule.pattern.search(compact) is not None
                )
            if matched_rule:
                matched.append(rule.rule_id)
                raw[rule.category] += rule.weight
                cues[rule.category] += 1
        # Invisible characters are a scored category (rat #73): each
        # finding contributes INVISIBLE_CHAR_WEIGHT, capped at 0.50.
        # A caller-supplied rule in the category keeps its own score:
        # the findings weight ACCUMULATES onto the rule sum instead of
        # overwriting it (a public extension point must not silently
        # drop its input).
        raw["invisible-chars"] += INVISIBLE_CHAR_WEIGHT * len(findings)
        cues["invisible-chars"] += len(findings)
        # Stacking bonus, folded into the category BEFORE the cap: dense
        # weak cues lift a sub-cap category toward its cap, but the bonus
        # can never break the cap — a single category's total
        # contribution stays bounded by its cap.
        bonus: dict[str, float] = {}
        for category, (needed, value) in self._stacking.items():
            bonus[category] = value if cues[category] >= needed else 0.0
        stacking_bonus = sum(bonus.values())
        injection_mult, exfiltration_mult = _TIER_MULTIPLIERS[context.tier.value]
        multipliers = {
            "injection": injection_mult,
            "exfiltration": exfiltration_mult,
            "format": 1.0,
            "invisible-chars": 1.0,
        }
        # Cap AFTER the multiplier: the cap bounds the category's
        # contribution to the verdict at ANY tier. A single saturated
        # category reaches at most its cap (max 0.70 < 0.80 block) —
        # HITL, never BLOCK — by itself, at the shipped thresholds.
        # Contributions are quantized to 4 decimals so threshold
        # comparisons are decimal-exact, not float-exact.
        contributions = {
            category: round(
                min(
                    (raw[category] + bonus.get(category, 0.0)) * multipliers[category],
                    self._caps[category],
                ),
                4,
            )
            for category in self._caps
        }
        # What each cap removed, per category, for the audit log.
        bonus_clipped = {
            category: round(
                max(
                    0.0,
                    (raw[category] + bonus.get(category, 0.0)) * multipliers[category]
                    - self._caps[category],
                ),
                4,
            )
            for category in self._caps
        }
        lexical_score = round(min(1.0, sum(contributions.values())), 4)
        semantic_score, semantic_review, cache_hit, calls = self._semantic_review(
            lexical_score, compact
        )
        # In the band the semantic verdict REPLACES the lexical score:
        # the judge decides uncertain cases, so it can clear a lexical
        # false positive as well as escalate. The verdict is a verdict
        # on the message, not on a signal family: it is used unweighted
        # (no dominant-category multiplier — the tier decides whether
        # the judge runs, never what the verdict is worth) and capped
        # at the largest category cap, so the judge can never BLOCK.
        score = lexical_score
        if semantic_score is not None:
            score = round(min(self._semantic_cap, semantic_score), 4)
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
                (category, contributions[category]) for category in self._caps if raw[category] > 0
            ),
            stacking_bonus=stacking_bonus,
            stacking_bonus_by_category=tuple(
                (category, bonus[category]) for category in bonus if bonus[category] > 0
            ),
            bonus_clipped_by_category=tuple(
                (category, clipped) for category, clipped in bonus_clipped.items() if clipped > 0
            ),
            semantic_score=semantic_score,
            semantic_review=semantic_review,
            semantic_cache_hit=cache_hit,
            semantic_calls=calls,
        )
