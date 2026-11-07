"""Rule-of-two escalation + output PII scrubbing (rat #69).

Source: claude-setup security-compliance-office persona + pii-scrubber
skill (catalog A.3): "Rule of Two for sensitive tool + untrusted input +
state mutation" and "PII pseudonymization before reports, commits, evals,
or model calls."

Two enforcement points:

1. Rule of two, evaluated inside ``Gateway.call_tool`` on every
   GATEWAY tool call: a call triggers escalation exactly when all
   three factors hold (sensitive tool + untrusted input + state
   mutation). An escalated call without a second approval is DENIED
   before any send — detection
   without blocking is not protection. With a second approval it
   proceeds and the approval is audited.
2. Output scrubbing, at the report emit boundary (``FuzzReport``
   formatters): every emitted string is passed through the rat #66
   ``PiiTokenizer`` first, so no raw structured PII of the detected
   classes reaches any report (names and bare 9-digit national IDs
   excepted). Scrubbing is emit-only: in-memory
   results stay raw so ``verify_counts`` keeps recomputing from
   unmodified data. Scope: the gateway path only for the rule of two.
   The fuzzer is the audit path and does NOT run through the gateway
   (tokenized responses would break reflection classification), so
   fuzz probes are exempt from the rule — stated as a boundary in
   the spec, not hidden.

Deliberate boundaries (not hidden):
- Sensitive means HIGH trust: the policy's own sensitive tier. A MEDIUM
  tool that mutates on untrusted input does NOT escalate; an operator
  that wants it escalated classifies the tool HIGH. There is no
  separate mutation-sensitivity knob: raising a MEDIUM mutator to HIGH
  also denies LOW callers outright instead of escalating them.
- Input trust is caller-DECLARED (MCP carries no provenance channel);
  the default is UNTRUSTED, so escalation requires an explicit false
  claim, never an omission.
- The gateway cannot authenticate the second approver (same
  declared-identity boundary as caller trust). ``SecondApproval`` proves
  a second sign-off object was presented and records its approver; it
  does not prove who the approver is. The approver value is replaced
  with a per-session ``[APPROVER_n]`` token before recording, so the
  approver never reaches the audit log verbatim — not as a plain name,
  not as detected-class PII in the field — and the token can never be
  resolved back to the value. Residual risk, stated plainly:
  a caller that can forge ``caller_trust`` can equally forge
  ``approval`` and ``input_trust`` in the same request. The control
  stops accidental or omitted second sign-off and creates an audit
  trail; it does not enforce two distinct humans. The harness owns
  obtaining approval from a distinct principal out of band and must
  never attach caller-supplied approval.
- A tool the policy omits is not known-mutating (same boundary as
  trust: the policy must classify; omission stays LOW / non-mutating
  until classified). Malformed policy shapes fail closed; omission
  silently disables escalation for that tool — the gateway cannot tell
  a HIGH read-only tool from a HIGH mutating tool the operator forgot
  to list. A ``mutating_tools`` entry that can never escalate (its
  effective trust is not HIGH) is rejected at policy load instead.
- The scrubber is the layer-1 regex detector: structured PII only
  (email, phone incl. +972 Israeli mobiles, SSN, Luhn cards, API-key
  shapes). Names need the layer-2 NLP ``Detector`` seam, which stays
  open. A bare 9-digit run is NOT treated as a national ID: the source
  conditions that pattern on column context (``id_number`` / ``tz`` /
  ``teudat``) the free-text detector lacks. So "no raw PII reaches a
  report" holds for the detected classes only — names and bare 9-digit
  IDs excepted.
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
        """Parse a request/policy input-trust string.

        Case-insensitive: "Trusted" and "trusted" are the same claim.
        A non-string raises ValueError, never AttributeError: a direct
        caller passing the wrong type gets a diagnosable rejection. The
        rejected value is never echoed (rat #69, round-4 fix-forward):
        it is caller-supplied free text, and the CLI prints this error
        to stdout — only the valid levels are named.
        """
        if not isinstance(value, str):
            raise ValueError(  # noqa: TRY004 - parse failures are ValueError by contract, like TrustLevel.parse; the CLI catches ValueError
                "unknown input trust: expected one of trusted, untrusted"
            )
        try:
            return cls(value.strip().lower())
        except ValueError:
            raise ValueError("unknown input trust: expected one of trusted, untrusted") from None


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
    sensitive: bool,
    input_trust: InputTrust,
    is_mutating: bool,
) -> Escalation:
    """Pure rule-of-two evaluation: sensitive + untrusted + mutating.

    ``sensitive`` is a plain bool (the caller maps its trust tier to it)
    so this module has no dependency on the gateway's ``TrustLevel``.
    Mistyped inputs raise TypeError instead of silently evaluating to
    "no escalation": a security predicate must never fail open on a
    wrong type. In particular a plain string ``"untrusted"`` is NOT
    accepted as the ``InputTrust.UNTRUSTED`` member — the caller must
    pass the enum (``Gateway.call_tool`` enforces this first).
    """
    if not isinstance(sensitive, bool):
        raise TypeError("sensitive must be a bool")
    if not isinstance(input_trust, InputTrust):
        raise TypeError("input_trust must be an InputTrust")
    if not isinstance(is_mutating, bool):
        raise TypeError("is_mutating must be a bool")
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
    or content. The call was never sent. The tool name is the
    tokenized-for-log name (rat #69): a well-formed name is unchanged,
    a PII-bearing name has its spans tokenized.
    """

    def __init__(self, tool_name: str, escalation: Escalation) -> None:
        self.tool_name = tool_name
        self.escalation = escalation
        super().__init__(
            f"escalation required: '{tool_name}' needs a second approval "
            f"({'; '.join(escalation.reasons)}); attach "
            '{"approval": {"approver": <name>, "reason": <why>}} to the request'
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
