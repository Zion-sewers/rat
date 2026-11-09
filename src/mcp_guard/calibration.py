"""Calibration-aware escalation for guardrail decisions (rat #77).

Source: ch.11 "Evaluating Specialized LLM Systems", Guardrail SLM
section incl. the ShieldGemma runtime-governance use case. Evidence
tag: adaptation — the chapter contributes the disposition discipline
(confidence-gated allow/block/escalate, calibration as an eval target,
reasoning alignment, evidence-explanation consistency, operational
KPIs); every number and weight below is this unit's calibration,
pinned by the tests, never a paper number and never a measurement on
live traffic.

The problem this module answers: a guardrail that only classifies
"violation / no violation" is half a system. In production the
confidence score determines the disposition — high-confidence
violation auto-blocks, low-confidence or borderline escalates to
human review, never auto-blocks on weak confidence. Without measuring
that disposition layer, false positives and false negatives hide
behind a good classification accuracy number.

What lives here, all stdlib-only pure functions:

1. Confidence-gated disposition: :func:`confidence_for` derives a
   confidence in [0, 1] from the scan's own evidence (matched rules,
   category spread, semantic-leg agreement), and
   :func:`gate_disposition` turns (score, confidence) into a
   :class:`Disposition`. The load-bearing invariant, test-pinned: a
   high score with weak confidence ESCALATES, it never BLOCKs.
2. Calibration eval: :func:`evaluate_calibration` over labeled
   :class:`CalibrationCase` values — expected calibration error and
   Brier score of the score as P(violation), AND of the confidence
   as P(the disposition is correct), escalation precision /
   recall, allow-miss rate, human-reviewer agreement rate, latency
   mean/p95, jailbreak resistance, containment effectiveness.
   :func:`threshold_sensitivity` sweeps the block threshold and the
   confidence floor so both are eval targets, not hand-tuned
   constants. :func:`evaluate_scanner_calibration` runs the real
   scanner over labeled messages and measures the disposition the
   scanner actually emitted.
3. Policy-grounded reasoning alignment: :class:`GuardrailReasoning`
   (verdict + steps + policy refs + cited spans) and
   :func:`check_reasoning` — a cited span must occur in the input, a
   policy ref must be a known policy id, and reasoning must be
   non-empty. A correct verdict with a fabricated justification is a
   defect, reported as one. The producer is the semantic leg: the
   Ollama scorer's ``judge`` method returns structured reasoning for
   in-band scans, and the scanner attaches it to the result.
4. Operational KPIs + drift: latency and agreement live in the
   calibration report; :func:`compare_calibration` diffs a current
   report against a baseline and flags drift. The operator entry
   point is ``mcp-guard calibration --cases cases.jsonl``: it runs
   the real scanner over a labeled-cases file (timing each scan),
   prints the report + threshold sweep, and diffs a baseline when
   one is given. An example labeled set ships at
   ``docs/examples/calibration-cases.jsonl``.

Complementary to #69 (rule of two): #69 is the policy — sensitive +
untrusted + mutating needs a second approval. This module is the
calibration-and-measurement discipline that makes that policy
trustworthy. The scanner's shipped routing (score -> ALLOW / HITL /
BLOCK) is unchanged, but enforcement now consults the calibrated
disposition: in enforce mode a routing-BLOCK on weak confidence
escalates for a second approval instead of auto-blocking, and the
block-confidence floor is settable from the policy file
(``"calibration": {"min_block_confidence": ...}``). In audit-only
mode the disagreement is recorded on the audit event, never enforced.

Deliberate boundaries (not hidden):
- The confidence weights are priors, not measurements. A wrong prior
  shows up as bad confidence ECE/Brier in
  :func:`evaluate_calibration` instead of being asserted as truth —
  the confidence metrics are the check on the weights.
- ECE / Brier are computed twice: once on the SCORE as the predicted
  P(violation), once on the CONFIDENCE as P(the disposition is
  correct). Confidence gates the disposition; the confidence-ECE is
  what validates the gate.
- :func:`check_reasoning` verifies what is checkable
  deterministically (span grounded in the input, policy ref known,
  reasoning present). It cannot verify that the reasoning is
  semantically sound — that needs a judge, and the shipped judge
  (the Ollama scorer) is itself the reasoning's author, so its
  verdict and its justification share one model. The
  semantic-consistency gap is a stated boundary.
- Span grounding is exact substring matching on the input as given.
  Normalization (case, whitespace, invisible characters) is the
  caller's job: a span that differs from the input only by case or
  spacing is reported hallucinated, and the report says so.
- The reasoning attached to a scan carries input spans, so it is
  never written to the audit log or the ``to_dict`` shape: content
  stays out of the log, as everywhere else in the gateway.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

__all__ = [
    "CalibratedDecision",
    "CalibrationCase",
    "CalibrationPolicy",
    "CalibrationReport",
    "Disposition",
    "DriftReport",
    "GuardrailReasoning",
    "ReasoningAlignment",
    "ReasoningAlignmentSummary",
    "ScanEvidence",
    "ScannerCalibrationCase",
    "ScoredDecision",
    "ThresholdSensitivity",
    "check_reasoning",
    "compare_calibration",
    "confidence_for",
    "evaluate_calibration",
    "evaluate_reasoning",
    "evaluate_scanner_calibration",
    "gate_disposition",
    "threshold_sensitivity",
]


class Disposition(str, Enum):
    """Confidence-gated disposition for one guardrail decision."""

    ALLOW = "allow"
    ESCALATE = "escalate"
    BLOCK = "block"


def _validate_unit(name: str, value: float) -> float:
    """Validate a [0, 1] number; bools and non-numbers fail closed."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"calibration {name} must be a number")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"calibration {name} must be in [0, 1]")
    return number


def _validate_thresholds(hitl_threshold: float, block_threshold: float) -> None:
    """Thresholds must satisfy 0 < hitl < block <= 1; else fail closed."""
    for name, value in (
        ("hitl_threshold", hitl_threshold),
        ("block_threshold", block_threshold),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"calibration {name} must be a number")
        if not 0 < float(value) <= 1:
            raise ValueError(f"calibration {name} must be in (0, 1]")
    if not hitl_threshold < block_threshold:
        raise ValueError("calibration hitl_threshold must be below block_threshold")


@dataclass(frozen=True)
class CalibrationPolicy:
    """The confidence-gated disposition policy: thresholds + confidence floor.

    ``hitl_threshold`` / ``block_threshold`` are the score cutoffs
    (shipped scanner defaults 0.40 / 0.80). ``min_block_confidence``
    is the confidence floor for auto-block: a score at or above the
    block threshold with confidence below this floor escalates to
    human review instead of blocking. The floor is itself an eval
    target — see :func:`threshold_sensitivity` — not a hand-tuned
    constant smuggled in as a default.
    """

    hitl_threshold: float = 0.40
    block_threshold: float = 0.80
    min_block_confidence: float = 0.80

    def __post_init__(self) -> None:
        _validate_thresholds(self.hitl_threshold, self.block_threshold)
        _validate_unit("min_block_confidence", self.min_block_confidence)
        if self.min_block_confidence <= 0.0:
            raise ValueError("calibration min_block_confidence must be above 0")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> CalibrationPolicy:
        """Parse a policy-file ``calibration`` mapping; fail closed.

        Unknown keys are ignored so policy files stay
        forward-compatible; wrong shapes fail closed (TypeError),
        out-of-range values fail closed (ValueError). Defaults are
        the shipped scanner thresholds with a 0.80 block-confidence
        floor.
        """
        if not isinstance(data, Mapping):
            raise TypeError("calibration policy must be an object")
        thresholds: dict[str, float] = {}
        for name, default in (
            ("hitl_threshold", 0.40),
            ("block_threshold", 0.80),
            ("min_block_confidence", 0.80),
        ):
            raw = data.get(name, default)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise TypeError(f"calibration policy '{name}' must be a number")
            thresholds[name] = float(raw)
        return cls(
            hitl_threshold=thresholds["hitl_threshold"],
            block_threshold=thresholds["block_threshold"],
            min_block_confidence=thresholds["min_block_confidence"],
        )


@dataclass(frozen=True)
class ScanEvidence:
    """The evidence one scan offers for its own confidence.

    ``lexical_score`` is the deterministic score before any semantic
    replacement; ``score`` is the final routed score. ``semantic_score``
    is the raw LLM-leg verdict when it ran (None when it did not) and
    ``semantic_review`` says why ("unavailable" / "below-band" /
    "above-band" / "in-band" / "cached" / "failed"). Counts are
    non-negative by construction.
    """

    score: float
    lexical_score: float
    matched_rule_count: int
    category_count: int
    semantic_score: float | None = None
    semantic_review: str = "unavailable"

    def __post_init__(self) -> None:
        _validate_unit("score", self.score)
        _validate_unit("lexical_score", self.lexical_score)
        if self.semantic_score is not None:
            _validate_unit("semantic_score", self.semantic_score)
        if self.semantic_review in ("in-band", "cached") and self.semantic_score is None:
            raise ValueError(
                "calibration semantic_score is required when the semantic review ran"
            )
        for name, value in (
            ("matched_rule_count", self.matched_rule_count),
            ("category_count", self.category_count),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TypeError(f"calibration {name} must be a non-negative integer")


# Confidence weights: this unit's calibration (adaptation), pinned by
# the tests — see the module docstring. A lone single-rule hit starts
# at 0.40 (below the 0.80 block floor: one signal never auto-blocks);
# each extra distinct category adds 0.15 (capped at +0.30) and each
# extra matched rule adds 0.05 (capped at +0.20), so a dense
# multi-category hit reaches 0.90 and can block. Semantic agreement
# moves the number by at most 0.20 either way. A scan with no
# matched rule and no scored category returns 0.90 — the absence of
# any signal is the strongest benign evidence the deterministic
# scanner can offer. The same 0.90 is also the honest limit of the
# prior: a jailbreak that evades every rule scores a high-confidence
# ALLOW, because the confidence measures the evidence the scanner
# saw, not the absence of attacks — which is why the confidence
# itself is measured (confidence ECE/Brier in the report), not
# merely asserted.
_BASE_CONFIDENCE = 0.40
_PER_EXTRA_CATEGORY = 0.15
_MAX_CATEGORY_BONUS = 0.30
_PER_EXTRA_RULE = 0.05
_MAX_RULE_BONUS = 0.20
_SEMANTIC_AGREE_BONUS = 0.10
_SEMANTIC_AGREE_WINDOW = 0.20
_SEMANTIC_DISAGREE_PENALTY = -0.20
_SEMANTIC_DISAGREE_WINDOW = 0.40
_SEMANTIC_FAILED_PENALTY = -0.10


def confidence_for(evidence: ScanEvidence) -> float:
    """Derive a confidence in [0, 1] from one scan's own evidence.

    Deterministic and evidence-only: more distinct categories and
    more matched rules raise confidence; a semantic leg that agrees
    with the lexical score (within 0.20) raises it, one that
    disagrees (by 0.40 or more) lowers it, and a failed semantic call
    lowers it slightly — the missing second opinion is itself
    evidence of uncertainty. A scan with no matched rule and no
    scored category at all returns 0.90: the absence of any signal is
    the strongest benign evidence the deterministic scanner can offer
    (unless the semantic leg ran or failed — then the formula below
    decides). A scan whose only signal is invisible characters takes
    the formula path, not the shortcut: findings add score with zero
    matched rules, so a score-bearing scan never reports 0.90 on the
    strength of having no rule hits. The result is quantized to 4
    decimals, like the scanner's scores.
    """
    if evidence.matched_rule_count == 0 and evidence.category_count == 0:
        # No signal at all — but only when the semantic leg did not
        # speak or fail: a failed call lowers confidence (see below),
        # and an in-band/cached verdict is evidence of its own.
        if evidence.semantic_review not in ("in-band", "cached", "failed"):
            return 0.90
    value = _BASE_CONFIDENCE
    value += min(
        _MAX_CATEGORY_BONUS,
        _PER_EXTRA_CATEGORY * max(0, evidence.category_count - 1),
    )
    value += min(
        _MAX_RULE_BONUS,
        _PER_EXTRA_RULE * max(0, evidence.matched_rule_count - 1),
    )
    if evidence.semantic_review in ("in-band", "cached") and evidence.semantic_score is not None:
        gap = abs(evidence.lexical_score - evidence.semantic_score)
        if gap <= _SEMANTIC_AGREE_WINDOW:
            value += _SEMANTIC_AGREE_BONUS
        elif gap >= _SEMANTIC_DISAGREE_WINDOW:
            value += _SEMANTIC_DISAGREE_PENALTY
    elif evidence.semantic_review == "failed":
        value += _SEMANTIC_FAILED_PENALTY
    return round(min(0.95, max(0.05, value)), 4)


@dataclass(frozen=True)
class CalibratedDecision:
    """One confidence-gated disposition: what + why."""

    disposition: Disposition
    score: float
    confidence: float
    reasons: tuple[str, ...] = ()


def gate_disposition(
    score: float, confidence: float, policy: CalibrationPolicy | None = None
) -> CalibratedDecision:
    """Gate one (score, confidence) pair into ALLOW / ESCALATE / BLOCK.

    BLOCK requires BOTH a score at or above the block threshold AND
    confidence at or above the block-confidence floor — a high score
    with weak confidence escalates instead. That is the invariant
    this module exists for: never auto-block on weak confidence.
    ESCALATE covers every score at or above the hitl threshold that
    does not block. Anything below the hitl threshold allows.
    """
    active = policy if policy is not None else CalibrationPolicy()
    score = _validate_unit("score", score)
    confidence = _validate_unit("confidence", confidence)
    if score >= active.block_threshold and confidence >= active.min_block_confidence:
        return CalibratedDecision(
            disposition=Disposition.BLOCK,
            score=score,
            confidence=confidence,
            reasons=(
                f"score {score:.2f} at or above block threshold {active.block_threshold:.2f}",
                (
                    f"confidence {confidence:.2f} at or above block floor "
                    f"{active.min_block_confidence:.2f}"
                ),
            ),
        )
    if score >= active.hitl_threshold:
        if score >= active.block_threshold:
            reason = (
                f"score {score:.2f} at or above block threshold "
                f"{active.block_threshold:.2f} but confidence {confidence:.2f} "
                f"below block floor {active.min_block_confidence:.2f}: "
                "escalate, never auto-block on weak confidence"
            )
        else:
            reason = f"score {score:.2f} at or above hitl threshold {active.hitl_threshold:.2f}"
        return CalibratedDecision(
            disposition=Disposition.ESCALATE,
            score=score,
            confidence=confidence,
            reasons=(reason,),
        )
    return CalibratedDecision(
        disposition=Disposition.ALLOW,
        score=score,
        confidence=confidence,
        reasons=(f"score {score:.2f} below hitl threshold {active.hitl_threshold:.2f}",),
    )


@dataclass(frozen=True)
class GuardrailReasoning:
    """A guardrail decision's structured output: verdict + reasoning.

    ``verdict`` is the Yes/No (True = violation). ``steps`` is the
    step-by-step reasoning against the policy definition.
    ``policy_refs`` names the policy rules the reasoning invokes;
    ``cited_spans`` quotes the input spans the reasoning rests on.
    All three collections must hold strings: a non-string element
    fails closed at construction, so a malformed reasoning can never
    reach the checker.
    """

    verdict: bool
    steps: tuple[str, ...] = ()
    policy_refs: tuple[str, ...] = ()
    cited_spans: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, bool):
            raise TypeError("reasoning verdict must be a bool")
        for name, values in (
            ("steps", self.steps),
            ("policy_refs", self.policy_refs),
            ("cited_spans", self.cited_spans),
        ):
            if not isinstance(values, tuple):
                raise TypeError(f"reasoning {name} must be a tuple of strings")
            if not all(isinstance(value, str) for value in values):
                raise TypeError(f"reasoning {name} must be a tuple of strings")


@dataclass(frozen=True)
class ReasoningAlignment:
    """What :func:`check_reasoning` found, per decision.

    ``hallucinated_spans`` are cited spans that do not occur in the
    input; ``unknown_policy_refs`` are policy refs outside the known
    policy set. ``is_defect`` is True when the reasoning is missing,
    cites ungrouded spans, or invokes unknown policy — including a
    correct verdict with a fabricated justification.
    """

    has_reasoning: bool
    hallucinated_spans: tuple[str, ...] = ()
    unknown_policy_refs: tuple[str, ...] = ()
    cited_count: int = 0
    is_defect: bool = False


def check_reasoning(
    reasoning: GuardrailReasoning,
    input_text: str,
    known_policy_ids: tuple[str, ...] | frozenset[str],
) -> ReasoningAlignment:
    """Check one guardrail reasoning against its input and policy set.

    Evidence-explanation consistency (mechanism 3): every cited span
    must occur verbatim in the input text. Policy-reference
    correctness (mechanism 2): every policy ref must be a known
    policy id. Explanation consistency (mechanism 2): reasoning must
    be non-empty — a verdict with no steps is a defect, not a
    verdict. Span matching is exact substring matching on the input
    as given; normalization is the caller's job.
    """
    if not isinstance(input_text, str):
        raise TypeError("reasoning input_text must be a string")
    if isinstance(known_policy_ids, str) or not isinstance(
        known_policy_ids, (tuple, frozenset)
    ):
        raise TypeError("reasoning known_policy_ids must be a tuple or frozenset of strings")
    if not all(isinstance(ref, str) for ref in known_policy_ids):
        raise TypeError("reasoning known_policy_ids must be a tuple or frozenset of strings")
    known = frozenset(known_policy_ids)
    # An empty or whitespace-only span is not evidence present in the
    # input: "" is a substring of every string, so the naive check
    # would bless a citation of nothing.
    hallucinated = tuple(
        span for span in reasoning.cited_spans if not span.strip() or span not in input_text
    )
    unknown = tuple(ref for ref in reasoning.policy_refs if ref not in known)
    # Reasoning must have content, not just entries: a step that is
    # empty or whitespace-only is no reasoning at all.
    has_reasoning = any(step.strip() for step in reasoning.steps)
    return ReasoningAlignment(
        has_reasoning=has_reasoning,
        hallucinated_spans=hallucinated,
        unknown_policy_refs=unknown,
        cited_count=len(reasoning.cited_spans),
        is_defect=(not has_reasoning) or bool(hallucinated) or bool(unknown),
    )


@dataclass(frozen=True)
class ReasoningAlignmentSummary:
    """Aggregate reasoning alignment over many decisions."""

    cases: int
    defects: int
    defect_rate: float | None
    hallucinated_spans: int
    cited_spans: int
    hallucination_frequency: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "cases": self.cases,
            "defects": self.defects,
            "defect_rate": self.defect_rate,
            "hallucinated_spans": self.hallucinated_spans,
            "cited_spans": self.cited_spans,
            "hallucination_frequency": self.hallucination_frequency,
        }


def evaluate_reasoning(results: tuple[ReasoningAlignment, ...]) -> ReasoningAlignmentSummary:
    """Aggregate per-decision reasoning alignments into rates.

    ``hallucination_frequency`` is hallucinated spans over all cited
    spans (None when nothing was cited anywhere); ``defect_rate`` is
    defective decisions over all decisions (None when there are none).
    """
    total_cited = sum(result.cited_count for result in results)
    total_hallucinated = sum(len(result.hallucinated_spans) for result in results)
    defects = sum(1 for result in results if result.is_defect)
    return ReasoningAlignmentSummary(
        cases=len(results),
        defects=defects,
        defect_rate=(defects / len(results)) if results else None,
        hallucinated_spans=total_hallucinated,
        cited_spans=total_cited,
        hallucination_frequency=(total_hallucinated / total_cited) if total_cited else None,
    )


@dataclass(frozen=True)
class CalibrationCase:
    """One labeled case for the calibration eval.

    ``score`` is the guardrail's predicted P(violation);
    ``confidence`` is the confidence in the disposition;
    ``label_violation`` is the ground-truth label.
    ``human_disposition`` is the reviewer's disposition when a human
    reviewed the case (None when unreviewed). ``latency_ms`` is the
    moderation latency when measured. ``is_jailbreak`` marks jailbreak
    attempts for the jailbreak-resistance KPI. ``reasoning`` carries
    the structured output when the guardrail produced one, with
    ``reasoning_input`` the input text it reasoned about and
    ``known_policy_ids`` the policy set its refs are checked against.
    ``disposition`` carries the disposition the system under test
    actually emitted (None: gate it from score + confidence under
    the eval policy). A supplied disposition is trusted as the system
    under test — the harness must measure the shipped layer, not
    re-derive it under a possibly different policy.
    """

    score: float
    confidence: float
    label_violation: bool
    human_disposition: Disposition | None = None
    latency_ms: float | None = None
    is_jailbreak: bool = False
    reasoning: GuardrailReasoning | None = None
    reasoning_input: str = ""
    known_policy_ids: tuple[str, ...] = ()
    disposition: Disposition | None = None

    def __post_init__(self) -> None:
        _validate_unit("score", self.score)
        _validate_unit("confidence", self.confidence)
        if not isinstance(self.label_violation, bool):
            raise TypeError("calibration label_violation must be a bool")
        if self.latency_ms is not None:
            if isinstance(self.latency_ms, bool) or not isinstance(self.latency_ms, (int, float)):
                raise TypeError("calibration latency_ms must be a number")
            if not math.isfinite(float(self.latency_ms)) or float(self.latency_ms) < 0:
                raise ValueError("calibration latency_ms must be finite and non-negative")
        if not isinstance(self.is_jailbreak, bool):
            raise TypeError("calibration is_jailbreak must be a bool")
        if not isinstance(self.reasoning_input, str):
            raise TypeError("calibration reasoning_input must be a string")
        if self.disposition is not None and not isinstance(self.disposition, Disposition):
            raise TypeError("calibration disposition must be a Disposition or None")


def _percentile(values: tuple[float, ...], fraction: float) -> float:
    """Nearest-rank percentile over a non-empty sorted tuple."""
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


@dataclass(frozen=True)
class CalibrationReport:
    """The calibration eval over one labeled set (mechanisms 1 + 4).

    ``ece`` is the expected calibration error of the score as
    P(violation) over ``bins`` equal-width bins; ``brier`` is the
    mean squared error of score vs label. ``escalation_precision``
    is true violations among escalated cases over all escalated
    cases; ``escalation_recall`` is true violations escalated over
    all true violations that were NOT auto-blocked (the violations
    the disposition layer had to catch by escalation rather than by
    blocking). ``allow_miss_rate`` is violations allowed over all
    violations — the false negatives the accuracy number hides.
    ``human_agreement_rate`` is dispositions matching the human
    reviewer over reviewed cases. ``jailbreak_resistance`` is
    jailbreak cases contained (blocked or escalated) over all
    jailbreak cases; ``containment_effectiveness`` is violations
    contained over all violations. ``confidence_ece`` /
    ``confidence_brier`` measure the CONFIDENCE itself: a disposition
    is correct when a violation is contained (blocked or escalated)
    or a benign case is allowed, so the confidence bins compare mean
    confidence against the decision-correct rate — the weights behind
    the confidence are priors, and these two numbers are the check on
    them. ``latency_ms_mean`` / ``p95``
    cover measured cases only. Any rate is None when its denominator
    is zero — a missing denominator is reported, never zero-filled.
    """

    cases: int
    bins: int
    ece: float
    brier: float
    confidence_ece: float
    confidence_brier: float
    allow_count: int
    escalate_count: int
    block_count: int
    escalation_precision: float | None
    escalation_recall: float | None
    allow_miss_rate: float | None
    human_agreement_rate: float | None
    latency_ms_mean: float | None
    latency_ms_p95: float | None
    jailbreak_resistance: float | None
    containment_effectiveness: float | None
    reasoning: ReasoningAlignmentSummary

    def to_dict(self) -> dict[str, object]:
        return {
            "cases": self.cases,
            "bins": self.bins,
            "ece": self.ece,
            "brier": self.brier,
            "confidence_ece": self.confidence_ece,
            "confidence_brier": self.confidence_brier,
            "allow_count": self.allow_count,
            "escalate_count": self.escalate_count,
            "block_count": self.block_count,
            "escalation_precision": self.escalation_precision,
            "escalation_recall": self.escalation_recall,
            "allow_miss_rate": self.allow_miss_rate,
            "human_agreement_rate": self.human_agreement_rate,
            "latency_ms_mean": self.latency_ms_mean,
            "latency_ms_p95": self.latency_ms_p95,
            "jailbreak_resistance": self.jailbreak_resistance,
            "containment_effectiveness": self.containment_effectiveness,
            "reasoning": self.reasoning.to_dict(),
        }


def evaluate_calibration(
    cases: tuple[CalibrationCase, ...] | list[CalibrationCase],
    policy: CalibrationPolicy | None = None,
    bins: int = 10,
) -> CalibrationReport:
    """Evaluate the disposition layer over labeled cases.

    The threshold is an eval target here, not a constant: the caller
    passes the policy under test, and :func:`threshold_sensitivity`
    repeats this eval across candidate thresholds. A case that carries
    its own ``disposition`` (the scanner harness path) is measured as
    emitted — the policy is not re-applied to it. An empty case list
    fails closed — a calibration report over zero cases would be a
    vacuous number.
    """
    active = policy if policy is not None else CalibrationPolicy()
    if isinstance(bins, bool) or not isinstance(bins, int) or bins < 1:
        raise ValueError("calibration bins must be an integer >= 1")
    ordered = tuple(cases)
    if not ordered:
        raise ValueError("calibration needs at least one case")
    decisions = tuple(
        case.disposition
        if case.disposition is not None
        else gate_disposition(case.score, case.confidence, active).disposition
        for case in ordered
    )
    n = len(ordered)
    # ECE: equal-width bins over the score; predicted = mean score in
    # the bin, observed = violation rate in the bin, weighted by bin
    # size. Brier: mean (score - label)^2 over all cases.
    ece = 0.0
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        in_bin = tuple(
            case
            for case in ordered
            if (low <= case.score < high) or (index == bins - 1 and case.score == 1.0)
        )
        if not in_bin:
            continue
        predicted = sum(case.score for case in in_bin) / len(in_bin)
        observed = sum(1 for case in in_bin if case.label_violation) / len(in_bin)
        ece += abs(predicted - observed) * (len(in_bin) / n)
    brier = sum((case.score - (1.0 if case.label_violation else 0.0)) ** 2 for case in ordered) / n
    # Confidence calibration: a disposition is correct when a violation
    # is contained (blocked or escalated) or a benign case is allowed.
    # The confidence bins compare mean confidence against the
    # decision-correct rate — the same ECE/Brier shape, over the
    # confidence instead of the score.
    correct = tuple(
        (case.label_violation and d is not Disposition.ALLOW)
        or (not case.label_violation and d is Disposition.ALLOW)
        for case, d in zip(ordered, decisions)
    )
    confidence_ece = 0.0
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        in_bin = tuple(
            (case, ok)
            for case, ok in zip(ordered, correct)
            if (low <= case.confidence < high)
            or (index == bins - 1 and case.confidence == 1.0)
        )
        if not in_bin:
            continue
        predicted = sum(case.confidence for case, _ok in in_bin) / len(in_bin)
        observed = sum(1 for _case, ok in in_bin if ok) / len(in_bin)
        confidence_ece += abs(predicted - observed) * (len(in_bin) / n)
    confidence_brier = (
        sum(
            (case.confidence - (1.0 if ok else 0.0)) ** 2
            for case, ok in zip(ordered, correct)
        )
        / n
    )
    allow_count = sum(1 for d in decisions if d is Disposition.ALLOW)
    escalate_count = sum(1 for d in decisions if d is Disposition.ESCALATE)
    block_count = sum(1 for d in decisions if d is Disposition.BLOCK)
    escalated = tuple(case for case, d in zip(ordered, decisions) if d is Disposition.ESCALATE)
    escalated_violations = sum(1 for case in escalated if case.label_violation)
    escalation_precision = (escalated_violations / len(escalated)) if escalated else None
    not_blocked_violations = tuple(
        case
        for case, d in zip(ordered, decisions)
        if case.label_violation and d is not Disposition.BLOCK
    )
    escalation_recall = (
        (escalated_violations / len(not_blocked_violations)) if not_blocked_violations else None
    )
    violations = tuple(case for case in ordered if case.label_violation)
    allowed_violations = sum(
        1 for case, d in zip(ordered, decisions) if case.label_violation and d is Disposition.ALLOW
    )
    allow_miss_rate = (allowed_violations / len(violations)) if violations else None
    contained_violations = sum(
        1
        for case, d in zip(ordered, decisions)
        if case.label_violation and d is not Disposition.ALLOW
    )
    containment = (contained_violations / len(violations)) if violations else None
    reviewed = tuple(
        (case, d) for case, d in zip(ordered, decisions) if case.human_disposition is not None
    )
    agreement = (
        (sum(1 for _case, d in reviewed if d == _case.human_disposition) / len(reviewed))
        if reviewed
        else None
    )
    latencies = tuple(case.latency_ms for case in ordered if case.latency_ms is not None)
    latency_mean = (sum(latencies) / len(latencies)) if latencies else None
    latency_p95 = _percentile(tuple(float(v) for v in latencies), 0.95) if latencies else None
    jailbreaks = tuple(case for case in ordered if case.is_jailbreak)
    jailbreak_contained = sum(
        1
        for case, d in zip(ordered, decisions)
        if case.is_jailbreak and d is not Disposition.ALLOW
    )
    jailbreak_resistance = (jailbreak_contained / len(jailbreaks)) if jailbreaks else None
    return CalibrationReport(
        cases=n,
        bins=bins,
        ece=round(ece, 4),
        brier=round(brier, 4),
        confidence_ece=round(confidence_ece, 4),
        confidence_brier=round(confidence_brier, 4),
        allow_count=allow_count,
        escalate_count=escalate_count,
        block_count=block_count,
        escalation_precision=escalation_precision,
        escalation_recall=escalation_recall,
        allow_miss_rate=allow_miss_rate,
        human_agreement_rate=agreement,
        latency_ms_mean=latency_mean,
        latency_ms_p95=latency_p95,
        jailbreak_resistance=jailbreak_resistance,
        containment_effectiveness=containment,
        reasoning=evaluate_reasoning(
            tuple(
                check_reasoning(case.reasoning, case.reasoning_input, case.known_policy_ids)
                for case in ordered
                if case.reasoning is not None
            )
        ),
    )


@dataclass(frozen=True)
class ThresholdSensitivity:
    """One row of the threshold sweep: dispositions + escalation P/R."""

    block_threshold: float
    min_block_confidence: float
    allow_count: int
    escalate_count: int
    block_count: int
    escalation_precision: float | None
    escalation_recall: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "block_threshold": self.block_threshold,
            "min_block_confidence": self.min_block_confidence,
            "allow_count": self.allow_count,
            "escalate_count": self.escalate_count,
            "block_count": self.block_count,
            "escalation_precision": self.escalation_precision,
            "escalation_recall": self.escalation_recall,
        }


def threshold_sensitivity(
    cases: tuple[CalibrationCase, ...] | list[CalibrationCase],
    block_thresholds: tuple[float, ...] | list[float],
    policy: CalibrationPolicy | None = None,
    min_block_confidences: tuple[float, ...] | list[float] | None = None,
) -> tuple[ThresholdSensitivity, ...]:
    """Sweep the block threshold (and optionally the confidence floor).

    Each candidate threshold re-runs the disposition + escalation
    P/R over the same labeled cases, so the operator picks the
    threshold from measured trade-offs (more blocks vs more
    escalations, precision vs recall) instead of hand-tuning a
    constant. A candidate at or below the hitl threshold fails
    closed — it would void the hitl < block ordering. The floor is
    swept the same way when ``min_block_confidences`` is given: the
    floor is the load-bearing gate, so it is an eval target too, not
    a constant the sweep holds fixed. Cases that carry their own
    emitted disposition are re-gated here — a sweep that trusted the
    recorded disposition would return the same row for every
    candidate. An empty candidate list fails closed, like an empty
    case list.
    """
    active = policy if policy is not None else CalibrationPolicy()
    ordered = tuple(cases)
    if not ordered:
        raise ValueError("calibration needs at least one case")
    thresholds = tuple(block_thresholds)
    if not thresholds:
        raise ValueError("calibration needs at least one block threshold")
    floors = (
        tuple(min_block_confidences)
        if min_block_confidences is not None
        else (active.min_block_confidence,)
    )
    if not floors:
        raise ValueError("calibration needs at least one block-confidence floor")
    # The sweep re-gates every case under each candidate: strip any
    # recorded disposition first, or every row would be identical.
    ungated = tuple(replace(case, disposition=None) for case in ordered)
    rows: list[ThresholdSensitivity] = []
    for threshold in thresholds:
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise TypeError("calibration block threshold must be a number")
        for floor in floors:
            if isinstance(floor, bool) or not isinstance(floor, (int, float)):
                raise TypeError("calibration block-confidence floor must be a number")
            candidate = CalibrationPolicy(
                hitl_threshold=active.hitl_threshold,
                block_threshold=float(threshold),
                min_block_confidence=float(floor),
            )
            report = evaluate_calibration(ungated, candidate)
            rows.append(
                ThresholdSensitivity(
                    block_threshold=float(threshold),
                    min_block_confidence=float(floor),
                    allow_count=report.allow_count,
                    escalate_count=report.escalate_count,
                    block_count=report.block_count,
                    escalation_precision=report.escalation_precision,
                    escalation_recall=report.escalation_recall,
                )
            )
    return tuple(rows)


@dataclass(frozen=True)
class DriftReport:
    """Baseline-vs-current calibration drift (mechanism 4).

    ``drifted`` is True when the ECE moved by more than
    ``ece_delta``, human agreement fell by more than
    ``agreement_delta``, or escalation precision fell by more than
    ``agreement_delta`` — all three deltas are this unit's
    calibration (adaptation), 0.05 each, and the report carries the
    raw changes so the operator can re-decide them from the numbers.
    A precision change of None (no escalations in either report)
    never flags drift on its own.
    """

    ece_change: float
    escalation_precision_change: float | None
    human_agreement_change: float | None
    drifted: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "ece_change": self.ece_change,
            "escalation_precision_change": self.escalation_precision_change,
            "human_agreement_change": self.human_agreement_change,
            "drifted": self.drifted,
        }


def compare_calibration(
    baseline: CalibrationReport,
    current: CalibrationReport,
    ece_delta: float = 0.05,
    agreement_delta: float = 0.05,
) -> DriftReport:
    """Diff two calibration reports; flag policy drift over time."""
    for name, delta in (("ece_delta", ece_delta), ("agreement_delta", agreement_delta)):
        if isinstance(delta, bool) or not isinstance(delta, (int, float)):
            raise TypeError(f"calibration {name} must be a number")
        if not 0.0 <= float(delta) <= 1.0:
            raise ValueError(f"calibration {name} must be in [0, 1]")
    precision_change = (
        (current.escalation_precision - baseline.escalation_precision)
        if current.escalation_precision is not None and baseline.escalation_precision is not None
        else None
    )
    agreement_change = (
        (current.human_agreement_rate - baseline.human_agreement_rate)
        if current.human_agreement_rate is not None and baseline.human_agreement_rate is not None
        else None
    )
    ece_change = round(current.ece - baseline.ece, 4)
    drifted = (
        abs(ece_change) > ece_delta
        or (agreement_change is not None and agreement_change < -agreement_delta)
        or (precision_change is not None and precision_change < -agreement_delta)
    )
    return DriftReport(
        ece_change=ece_change,
        escalation_precision_change=precision_change,
        human_agreement_change=agreement_change,
        drifted=drifted,
    )


class ScoredDecision(Protocol):
    """Structural shape of a scored guardrail decision.

    Any object carrying these fields — e.g. the scanner's
    :class:`mcp_guard.trust_scanner.ScanResult` — can be evaluated
    by :func:`evaluate_scanner_calibration` without importing the
    scanner here (no import cycle: the scanner imports this module).
    ``reasoning`` is the structured output when the decision's
    producer emitted one (None when no reasoning producer ran).
    """

    score: float
    confidence: float
    calibrated_disposition: Disposition
    reasoning: GuardrailReasoning | None


class ScanFn(Protocol):
    """A callable that scores one message into a :class:`ScoredDecision`."""

    def __call__(self, message: Mapping[str, object]) -> ScoredDecision: ...


@dataclass(frozen=True)
class ScannerCalibrationCase:
    """One labeled message for the scanner eval harness."""

    message: Mapping[str, object]
    label_violation: bool
    human_disposition: Disposition | None = None
    latency_ms: float | None = None
    is_jailbreak: bool = False
    reasoning: GuardrailReasoning | None = None
    reasoning_input: str = ""
    known_policy_ids: tuple[str, ...] = ()


def evaluate_scanner_calibration(
    scan_fn: ScanFn,
    cases: tuple[ScannerCalibrationCase, ...] | list[ScannerCalibrationCase],
    bins: int = 10,
    known_policy_ids: tuple[str, ...] = (),
) -> CalibrationReport:
    """Run a real scanner over labeled messages; report calibration.

    The harness that makes the eval honest: it scores through the
    supplied callable (e.g. ``InboundScanner().scan_message``) instead
    of trusting pre-computed numbers, so the report measures the
    shipped disposition layer, not a spreadsheet of it. The
    disposition recorded is the one the scanner emitted
    (``decision.calibrated_disposition``) — the harness never
    re-gates under its own policy, so a scanner built with a
    non-default confidence floor is measured as configured. The
    reasoning leg uses the reasoning the scanner's producer emitted
    when one ran; a case may still carry its own
    :class:`GuardrailReasoning` instead. ``known_policy_ids`` is the
    deployment's policy set the refs are checked against (the CLI
    passes the scanner's rule ids); with the default empty set every
    cited ref is unknown, by design — the checker must not invent a
    policy set.
    """
    ordered = tuple(cases)
    if not ordered:
        raise ValueError("calibration needs at least one case")
    labeled: list[CalibrationCase] = []
    for case in ordered:
        decision = scan_fn(case.message)
        content = case.message.get("content")
        labeled.append(
            CalibrationCase(
                score=decision.score,
                confidence=decision.confidence,
                label_violation=case.label_violation,
                human_disposition=case.human_disposition,
                latency_ms=case.latency_ms,
                is_jailbreak=case.is_jailbreak,
                reasoning=(
                    decision.reasoning if decision.reasoning is not None else case.reasoning
                ),
                reasoning_input=(
                    case.reasoning_input
                    if case.reasoning_input
                    else (content if isinstance(content, str) else "")
                ),
                known_policy_ids=(
                    case.known_policy_ids if case.known_policy_ids else known_policy_ids
                ),
                disposition=decision.calibrated_disposition,
            )
        )
    return evaluate_calibration(tuple(labeled), None, bins)
