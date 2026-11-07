"""Rule-of-two escalation + output PII scrubbing (rat #69).

Source: claude-setup security-compliance-office persona + pii-scrubber
skill (catalog A.3): "Rule of Two for sensitive tool + untrusted input +
state mutation" and "PII pseudonymization before reports, commits, evals,
or model calls."

Two enforcement points, both fail-closed:

1. Rule of two, evaluated inside ``Gateway.call_tool`` on EVERY tool
   call: a call triggers escalation exactly when all three factors hold
   (sensitive tool + untrusted input + state mutation). An escalated call
   without a second approval is DENIED before any send — detection
   without blocking is not protection. With a second approval it
   proceeds and the approval is audited.
2. Output scrubbing, at the report emit boundary (``FuzzReport``
   formatters): every emitted string is passed through the rat #66
   ``PiiTokenizer`` first, so no raw structured PII reaches any report
   format. Scrubbing is emit-only: in-memory results stay raw so
   ``verify_counts`` keeps recomputing from unmodified data.

Deliberate boundaries (not hidden):
- Sensitive means HIGH trust: the policy's own sensitive tier. A MEDIUM
  tool that mutates on untrusted input does NOT escalate; an operator
  that wants it escalated classifies the tool HIGH.
- Input trust is caller-DECLARED (MCP carries no provenance channel);
  the default is UNTRUSTED, so escalation requires an explicit false
  claim, never an omission.
- The gateway cannot authenticate the second approver (same
  declared-identity boundary as caller trust). ``SecondApproval`` proves
  a second sign-off object was presented and records its approver; it
  does not prove who the approver is.
- A tool the policy omits is not known-mutating (same boundary as
  trust: the policy must classify; omission stays LOW / non-mutating
  until classified).
- The scrubber is the layer-1 regex detector: structured PII only
  (email, phone incl. +972 Israeli mobiles, SSN, Luhn cards, API-key
  shapes). Names need the layer-2 NLP ``Detector`` seam, which stays
  open. A bare 9-digit run is NOT treated as a national ID: the source
  conditions that pattern on column context (``id_number`` / ``tz`` /
  ``teudat``) the free-text detector lacks.
- Rat never commits or uploads evals, so the issue's "before reports,
  commits, evals, model calls" maps to rat as: reports (formatters) +
  model calls (gateway tokenization, rat #66). Commits/evals are out of
  rat's scope.
- The scrubber mapping lives in memory only (one fresh tokenizer per
  emit) and is never serialized: tokens are deterministic within one
  report, like the source's sha-based pseudonyms, and values are never
  recoverable from the emitted report.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .gateway import PiiTokenizer

__all__ = [
    "Escalation",
    "EscalationRequiredError",
    "InputTrust",
    "SecondApproval",
    "evaluate_rule_of_two",
    "scrub_for_output",
]


class InputTrust(str, Enum):
    """Provenance of a tool call's arguments, as declared by the caller."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"

    @classmethod
    def parse(cls, value: str) -> InputTrust:
        """Parse a request/policy input-trust string; ValueError names it."""
        try:
            return cls(value)
        except ValueError:
            raise ValueError(
                f"unknown input trust {value!r}: expected one of trusted, untrusted"
            ) from None


@dataclass(frozen=True)
class SecondApproval:
    """The second principal's sign-off for an escalated call.

    Both fields are required and non-empty: an approval with no approver
    or no reason is not a second pair of eyes, it is a skipped check.
    """

    approver: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.approver, str) or not self.approver.strip():
            raise ValueError("second approval needs a non-empty approver")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("second approval needs a non-empty reason")


@dataclass(frozen=True)
class Escalation:
    """The rule-of-two decision for one call: the three factors + verdict."""

    triggered: bool
    reasons: tuple[str, ...] = ()
    sensitive: bool = False
    untrusted_input: bool = False
    mutating: bool = False


def evaluate_rule_of_two(
    target_trust: object,
    input_trust: InputTrust,
    is_mutating: bool,
) -> Escalation:
    """Pure rule-of-two evaluation: sensitive + untrusted + mutating.

    ``target_trust`` is a ``TrustLevel``; compared by value so this
    module stays importable without a gateway cycle at type level.
    Triggered iff all three factors hold. The reasons name the factors
    that fired (never arguments or content).
    """
    from .gateway import TrustLevel

    sensitive = target_trust is TrustLevel.HIGH
    untrusted = input_trust is InputTrust.UNTRUSTED
    reasons: list[str] = []
    if sensitive:
        reasons.append("sensitive tool (high trust)")
    if untrusted:
        reasons.append("untrusted input")
    if is_mutating:
        reasons.append("state mutation")
    triggered = sensitive and untrusted and is_mutating
    return Escalation(
        triggered=triggered,
        reasons=tuple(reasons),
        sensitive=sensitive,
        untrusted_input=untrusted,
        mutating=is_mutating,
    )


class EscalationRequiredError(Exception):
    """An escalated call was attempted without a second approval.

    Carries the tool name and the fired reasons only — never arguments
    or content. The call was never sent.
    """

    def __init__(self, tool_name: str, escalation: Escalation) -> None:
        self.tool_name = tool_name
        self.escalation = escalation
        super().__init__(
            f"escalation required: '{tool_name}' needs a second approval "
            f"({'; '.join(escalation.reasons)})"
        )


def scrub_for_output(value: object, tokenizer: PiiTokenizer) -> object:
    """Pseudonymize structured PII out of JSON-shaped data for output.

    Thin wrapper over ``PiiTokenizer.tokenize_value``: every string is
    scanned, PII spans become deterministic per-value tokens, and the
    mapping stays in the tokenizer's memory only (never serialized).
    Non-string values pass through untouched.
    """
    scrubbed, _applied = tokenizer.tokenize_value(value)
    return scrubbed
