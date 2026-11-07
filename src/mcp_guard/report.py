"""Report formatters — table, JSON, SARIF.

Every emitted report carries a ``_provenance`` block (Finding A: citation and
provenance are the load-bearing trust feature): scanner identity, version, run
id, UTC timestamp, target server id, and payload-ruleset version, so a
downstream agent or human can answer "where did this number come from?" without
trusting the channel the report arrived on.

All summary numbers are recomputed from the raw results list by
``verify_counts()`` (Finding B: never let the LLM do math, never show false
precision). The formatters refuse to emit a report whose summary disagrees with
its results — numbers are derived in code, never narrated.
"""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TextIO

from .delivery import DeliveryStatus
from .fuzzer import FuzzResult, ResultCategory
from .payloads import PAYLOAD_SET_VERSION

# Twyman's law (mcp-guard#65): a perfect pass rate is the surprising result
# that must trigger an instrumentation audit before the verdict is accepted.
SURPRISING_SAFE_RATE = 1.0


@dataclass(frozen=True)
class TwymanAudit:
    """Run-level Twyman check: is this pass rate surprising enough to
    withhold the verdict until the instrumentation is audited?"""

    triggered: bool
    reasons: tuple[str, ...] = ()
    safe_rate: float = 0.0
    delivered: int = 0
    total: int = 0


def twyman_audit(
    results: list[FuzzResult],
    allow_empty_error_responses: bool = False,
    allow_identical_error_responses: bool = False,
) -> TwymanAudit:
    """Audit a run's pass rate against its delivery evidence (mcp-guard#65).

    Triggers (any withholds CLEAN):
    - T1: every probe SAFE while any delivery is unconfirmed. The
      interesting-looking success may be an instrumentation miss — the fault
      never landed, so "tolerated" was never tested. Through the engine this
      is enforced per-probe by demotion to INCONCLUSIVE before
      classification, so the report-level T1 fires only on hand-built
      reports; the outcome is the same either way.
    - T2: every probe SAFE and the server never produced one byte of
      response text. A validator that rejects 29 distinct attacks per
      parameter without ever saying why is either a black hole or a broken
      response channel; either way the verdict waits for an audit.
      `allow_empty_error_responses` is the operator's explicit override for
      a known terse validator (see `--allow-empty-error-responses`): the
      override is recorded in the report, never silent.
    - T3: every probe SAFE and the server answered every distinct attack
      with the same non-empty text. A middleware stub that short-circuits
      validation returns one canned rejection for everything; a strict
      validator legitimately does the same, so T3 withholds the verdict and
      the operator asserts after a server-log check instead of the run
      passing silently. `allow_identical_error_responses` is that explicit
      override (see `--allow-identical-error-responses`), recorded in the
      report, never silent. T3 needs at least two probes: one probe cannot
      be "identical" to anything.
    A run with varied error text and full delivery does NOT trigger: that is
    the profile of a real validator, not a surprising result.
    """
    total = len(results)
    if total == 0:
        return TwymanAudit(triggered=False, total=0)
    safe = [r for r in results if r.category is ResultCategory.SAFE]
    safe_rate = len(safe) / total
    delivered = sum(1 for r in results if r.delivery is DeliveryStatus.DELIVERED)
    reasons: list[str] = []
    if safe_rate == SURPRISING_SAFE_RATE and delivered < total:
        reasons.append(
            f"100% SAFE ({total} probes) with only {delivered}/{total} "
            "confirmed deliveries: the fault may never have landed"
        )
    if (
        safe_rate == SURPRISING_SAFE_RATE
        and not allow_empty_error_responses
        and all(r.response_preview == "" for r in results)
    ):
        reasons.append(
            f"100% SAFE ({total} probes) with zero bytes of response text: "
            "no evidence the server processed distinct inputs"
        )
    if (
        safe_rate == SURPRISING_SAFE_RATE
        and total >= 2
        and not allow_identical_error_responses
        and all(r.response_preview != "" for r in results)
        and len({r.response_preview for r in results}) == 1
    ):
        reasons.append(
            f"100% SAFE ({total} probes) with identical response text on "
            "every probe: no evidence the server distinguished distinct inputs"
        )
    return TwymanAudit(
        triggered=bool(reasons),
        reasons=tuple(reasons),
        safe_rate=safe_rate,
        delivered=delivered,
        total=total,
    )


def scanner_version() -> str:
    """Best-effort installed version; never lies, never empty."""
    try:
        from importlib.metadata import version

        return version("mcp-guard")
    except Exception:  # noqa: BLE001 — metadata absent in a bare checkout
        return "0.0.0+unknown"


@dataclass
class FuzzReport:
    server_command: str
    tools_fuzzed: int
    total_payloads: int
    results: list[FuzzResult]
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    run_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    # Operator override for T2 (mcp-guard#65): a known terse validator whose
    # error responses legitimately carry no text. Recorded in the report so
    # the override is visible, never silent.
    allow_empty_error_responses: bool = False
    # Operator override for T3 (mcp-guard#65): a known strict validator
    # whose error responses legitimately repeat the same short text for
    # every payload. Recorded in the report, never silent.
    allow_identical_error_responses: bool = False

    @property
    def crashes(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.CRASH]

    @property
    def findings(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.FINDING]

    @property
    def safe(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.SAFE]

    @property
    def errors(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.ERROR]

    @property
    def inconclusive(self) -> list[FuzzResult]:
        return [r for r in self.results if r.category == ResultCategory.INCONCLUSIVE]

    def delivery_summary(self) -> dict[str, int]:
        """Fault-delivery counts (mcp-guard#65), recomputed from results."""
        summary = {"delivered": 0, "undelivered": 0, "unknown": 0}
        for r in self.results:
            summary[r.delivery.value] += 1
        return summary

    def audit(self) -> TwymanAudit:
        return twyman_audit(
            self.results,
            self.allow_empty_error_responses,
            self.allow_identical_error_responses,
        )

    def request_ids(self) -> list[Any]:
        """Ordered request ids for the run (mcp-guard#65): the audit
        procedure matches server-side dispatches against these. SAFE probes
        are excluded from the per-probe JSON array by design, so the summary
        carries their ids here instead — otherwise an all-SAFE hold would
        have no per-probe identifiers at all. None entries (uncorrelatable
        probes) are dropped."""
        return [r.request_id for r in self.results if r.request_id is not None]

    @property
    def verdict(self) -> str:
        """Run verdict. Precedence: crashes, then unconfirmed delivery,
        then errored probes, then findings, then the Twyman audit, then
        clean. The audit branch applies only to all-SAFE runs (all three
        triggers require a 100% pass rate), so it is unreachable once any
        finding exists. An ERROR probe produced no verdict about its tool, so any
        error withholds CLEAN just as an inconclusive probe does — and it
        sits above findings, so one INFO finding cannot flip an
        error-dominated run back to a passing exit code. Findings are
        still listed in full in every format; only the label yields. A run
        that fired no probes has no confirmed delivery at all, so it is
        INCONCLUSIVE, never CLEAN: a vacuous pass is still a pass without
        evidence."""
        if not self.results:
            return "INCONCLUSIVE"
        if self.crashes:
            return "VULNERABLE"
        if self.inconclusive:
            return "INCONCLUSIVE"
        if self.errors:
            return "INCONCLUSIVE"
        if self.findings:
            return "FINDINGS"
        if self.audit().triggered:
            return "INCONCLUSIVE"
        return "CLEAN"

    @property
    def verdict_reason(self) -> str:
        if not self.results:
            return "no probes fired — no fault delivery confirmed"
        if self.crashes:
            return f"{len(self.crashes)} crashes detected"
        if self.inconclusive:
            return (
                f"{len(self.inconclusive)} probes without confirmed fault "
                "delivery — verdict withheld"
            )
        if self.errors:
            return (
                f"{len(self.errors)} probes errored without a verdict "
                "about the tool — verdict withheld"
            )
        if self.findings:
            return f"{len(self.findings)} findings require investigation"
        audit = self.audit()
        if audit.triggered:
            return "Twyman audit: " + "; ".join(audit.reasons)
        return "all payloads handled safely"

    def _category_counts(self) -> dict[str, int]:
        counts = {"crash": 0, "finding": 0, "safe": 0, "error": 0, "inconclusive": 0}
        for r in self.results:
            counts[r.category.value] += 1
        return counts

    def _severity_counts(self) -> dict[str, int]:
        """Severity histogram over verdicts only (FINDING + CRASH).

        INCONCLUSIVE and ERROR probes carry a severity from their payload,
        but that severity describes the attack, not a verdict — counting it
        would present unconfirmed probes as findings."""
        counts: dict[str, int] = {}
        for r in self.results:
            if r.category in (ResultCategory.FINDING, ResultCategory.CRASH):
                counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts

    def verify_counts(self) -> None:
        """Recompute every summary number from the raw results (Finding B).

        Raises ValueError if any caller-supplied or derived number disagrees
        with the results list. A report must never emit numbers that cannot be
        re-derived deterministically in code.
        """
        counts = self._category_counts()
        problems: list[str] = []
        if self.total_payloads != len(self.results):
            problems.append(
                f"total_payloads={self.total_payloads} != len(results)={len(self.results)}"
            )
        if len(self.crashes) != counts["crash"]:
            problems.append("crash count drifted from results")
        if len(self.findings) != counts["finding"]:
            problems.append("finding count drifted from results")
        if len(self.safe) != counts["safe"]:
            problems.append("safe count drifted from results")
        if len(self.inconclusive) != counts["inconclusive"]:
            problems.append("inconclusive count drifted from results")
        if len(self.errors) != counts["error"]:
            problems.append("error count drifted from results")
        delivery = self.delivery_summary()
        if sum(delivery.values()) != len(self.results):
            problems.append("delivery counts drifted from results")
        distinct_tools = {r.tool_name for r in self.results}
        if self.results and self.tools_fuzzed != len(distinct_tools):
            problems.append(
                f"tools_fuzzed={self.tools_fuzzed} != distinct tools in results={len(distinct_tools)}"
            )
        if problems:
            raise ValueError("report summary inconsistent with results: " + "; ".join(problems))

    def _provenance(self) -> dict[str, str]:
        """Machine-readable provenance block (Finding A). Never empty."""
        return {
            "scanner": "mcp-guard",
            "scanner_version": scanner_version(),
            "run_id": self.run_id,
            "run_at": self.run_at,
            "data_source": self.server_command,
            "payload_ruleset_version": PAYLOAD_SET_VERSION,
            "report_schema": "1",
        }

    def t2_suppressed(self) -> bool:
        """Did the operator's override actually suppress a T2 trigger?

        True only when the flag is set AND the run is exactly the shape T2
        fires on (100% SAFE, zero response bytes). The table note uses this
        so the override is claimed only where it did something — not on a
        FINDINGS run where T2 could never fire."""
        if not self.allow_empty_error_responses or not self.results:
            return False
        return all(r.category is ResultCategory.SAFE for r in self.results) and all(
            r.response_preview == "" for r in self.results
        )

    def t3_suppressed(self) -> bool:
        """Did the operator's override actually suppress a T3 trigger?

        True only when the flag is set AND the run is exactly the shape T3
        fires on (100% SAFE, at least two probes, one identical non-empty
        response text)."""
        if not self.allow_identical_error_responses or len(self.results) < 2:
            return False
        return (
            all(r.category is ResultCategory.SAFE for r in self.results)
            and all(r.response_preview != "" for r in self.results)
            and len({r.response_preview for r in self.results}) == 1
        )

    def to_table(self, out: TextIO | None = None) -> None:
        self.verify_counts()
        out = out or sys.stdout
        out.write(f"\n{'=' * 72}\n")
        out.write(f"  mcp-guard fuzz report: {self.server_command}\n")
        out.write(f"{'=' * 72}\n\n")
        out.write(f"  Tools fuzzed:  {self.tools_fuzzed}\n")
        out.write(f"  Payloads sent: {self.total_payloads}\n")
        out.write(f"  Crashes:       {len(self.crashes)}\n")
        out.write(f"  Findings:      {len(self.findings)}\n")
        out.write(f"  Safe:          {len(self.safe)}\n")
        out.write(f"  Errors:        {len(self.errors)}\n")
        out.write(f"  Inconclusive:  {len(self.inconclusive)}\n")
        delivery = self.delivery_summary()
        out.write(
            f"  Delivery:      {delivery['delivered']} delivered, "
            f"{delivery['undelivered']} undelivered, {delivery['unknown']} unknown\n\n"
        )

        audit = self.audit()
        if audit.triggered:
            out.write("  TWYMAN AUDIT — surprising pass rate, verdict withheld:\n")
            for reason in audit.reasons:
                out.write(f"    - {reason}\n")
            out.write("\n")
        if self.t2_suppressed():
            out.write(
                "  Twyman audit: empty-error-response check overridden by "
                "operator (--allow-empty-error-responses)\n\n"
            )
        if self.t3_suppressed():
            out.write(
                "  Twyman audit: identical-error-response check overridden by "
                "operator (--allow-identical-error-responses)\n\n"
            )

        if self.inconclusive:
            out.write(f"  {'INCONCLUSIVE':^68}\n")
            out.write(f"  {'-' * 68}\n")
            for r in self.inconclusive[:10]:
                out.write(f"  [{r.severity.upper()}] {r.tool_name} :: {r.rule_id}\n")
                out.write(f"         {r.detail}\n")
            remaining_inc = len(self.inconclusive) - 10
            if remaining_inc > 0:
                out.write(f"  ... and {remaining_inc} more inconclusive probes\n")
            out.write("\n")

        if self.errors:
            out.write(f"  {'ERRORS':^68}\n")
            out.write(f"  {'-' * 68}\n")
            for r in self.errors[:10]:
                out.write(f"  [{r.severity.upper()}] {r.tool_name} :: {r.rule_id}\n")
                out.write(f"         {r.detail}\n")
            remaining_err = len(self.errors) - 10
            if remaining_err > 0:
                out.write(f"  ... and {remaining_err} more errored probes\n")
            out.write("\n")

        if self.crashes:
            out.write(f"  {'CRASHES':^68}\n")
            out.write(f"  {'-' * 68}\n")
            for r in self.crashes:
                out.write(f"  [{r.severity.upper()}] {r.tool_name} :: {r.rule_id}\n")
                out.write(f"         payload: {str(r.payload_value)[:60]}\n")
                out.write(f"         {r.detail}\n\n")

        if self.findings:
            out.write(f"  {'FINDINGS':^68}\n")
            out.write(f"  {'-' * 68}\n")
            for r in self.findings[:20]:
                out.write(f"  [{r.severity.upper()}] {r.tool_name} :: {r.rule_id}\n")
                out.write(f"         payload: {str(r.payload_value)[:60]}\n")
                if r.response_preview:
                    out.write(f"         response: {r.response_preview[:60]}\n")
                out.write("")

        remaining = len(self.findings) - 20
        if remaining > 0:
            out.write(f"  ... and {remaining} more findings\n")

        out.write(f"\n{'=' * 72}\n")
        if self.verdict == "VULNERABLE":
            out.write("  VERDICT: VULNERABLE — crashes detected\n")
        elif self.verdict == "INCONCLUSIVE":
            out.write(f"  VERDICT: INCONCLUSIVE — {self.verdict_reason}\n")
        elif self.findings:
            out.write(f"  VERDICT: {len(self.findings)} findings require investigation\n")
        else:
            out.write("  VERDICT: CLEAN — all payloads handled safely\n")
        out.write(f"{'=' * 72}\n")
        prov = self._provenance()
        out.write(
            f"  provenance: {prov['scanner']} {prov['scanner_version']} | "
            f"run {prov['run_id'][:12]} at {prov['run_at']} | "
            f"ruleset v{prov['payload_ruleset_version']}\n\n"
        )

    def to_json(self, out: TextIO | None = None) -> None:
        self.verify_counts()
        out = out or sys.stdout
        audit = self.audit()
        data = {
            "_provenance": self._provenance(),
            "server": self.server_command,
            "summary": {
                "tools_fuzzed": self.tools_fuzzed,
                "total_payloads": self.total_payloads,
                "crashes": len(self.crashes),
                "findings": len(self.findings),
                "safe": len(self.safe),
                "errors": len(self.errors),
                "inconclusive": len(self.inconclusive),
                "by_severity": self._severity_counts(),
                "delivery": self.delivery_summary(),
                "twyman_audit": {
                    "triggered": audit.triggered,
                    "reasons": list(audit.reasons),
                    "safe_rate": audit.safe_rate,
                    "allow_empty_error_responses": self.allow_empty_error_responses,
                    "t2_suppressed": self.t2_suppressed(),
                    "allow_identical_error_responses": (self.allow_identical_error_responses),
                    "t3_suppressed": self.t3_suppressed(),
                },
                "request_ids": self.request_ids(),
                "verdict": self.verdict,
            },
            "results": [
                {
                    "tool": r.tool_name,
                    "probe": r.probe_name,
                    "payload": repr(r.payload_value),
                    "category": r.category.value,
                    "rule_id": r.rule_id,
                    "severity": r.severity,
                    "detail": r.detail,
                    "response_preview": r.response_preview,
                    "delivery": r.delivery.value,
                    "delivery_detail": r.delivery_detail,
                    "request_id": r.request_id,
                    "response_id": r.response_id,
                }
                for r in self.results
                if r.category != ResultCategory.SAFE
            ],
        }
        out.write(json.dumps(data, indent=2, ensure_ascii=False))

    def to_sarif(self, out: TextIO | None = None) -> None:
        self.verify_counts()
        out = out or sys.stdout
        rules_map: dict[str, int] = {}
        rules_list: list[dict[str, Any]] = []
        results_sarif: list[dict[str, Any]] = []

        for r in self.results:
            if r.category == ResultCategory.SAFE:
                continue
            if r.category == ResultCategory.INCONCLUSIVE:
                # Not a finding, but a SARIF-only consumer must still see
                # which probe has no verdict and why: note-level result
                # under a dedicated rule, never a warning.
                if "fault-delivery-unconfirmed" not in rules_map:
                    idx = len(rules_list) + 1
                    rules_map["fault-delivery-unconfirmed"] = idx
                    rules_list.append(
                        {
                            "id": "fault-delivery-unconfirmed",
                            "shortDescription": {"text": "Fault delivery unconfirmed — no verdict"},
                        }
                    )
                results_sarif.append(
                    {
                        "ruleId": "fault-delivery-unconfirmed",
                        "ruleIndex": rules_map["fault-delivery-unconfirmed"] - 1,
                        "level": "note",
                        "message": {
                            "text": (
                                f"{r.rule_id}: {r.detail}"
                                + (
                                    f" (request id {r.request_id})"
                                    if r.request_id is not None
                                    else ""
                                )
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f"mcp://{r.tool_name}"}
                                }
                            }
                        ],
                    }
                )
                continue
            if r.category == ResultCategory.ERROR:
                # An errored probe is not a finding: it produced no verdict
                # about the tool. It gets its own rule so a SARIF consumer
                # never reads "no verdict" probes as findings.
                if "probe-error" not in rules_map:
                    idx = len(rules_list) + 1
                    rules_map["probe-error"] = idx
                    rules_list.append(
                        {
                            "id": "probe-error",
                            "shortDescription": {"text": "Probe errored — no verdict"},
                        }
                    )
                results_sarif.append(
                    {
                        "ruleId": "probe-error",
                        "ruleIndex": rules_map["probe-error"] - 1,
                        "level": "warning",
                        "message": {
                            "text": (
                                f"{r.rule_id}: {r.detail}"
                                + (
                                    f" (request id {r.request_id})"
                                    if r.request_id is not None
                                    else ""
                                )
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f"mcp://{r.tool_name}"}
                                }
                            }
                        ],
                    }
                )
                continue
            if r.rule_id not in rules_map:
                idx = len(rules_list) + 1
                rules_map[r.rule_id] = idx
                rules_list.append({"id": r.rule_id, "shortDescription": {"text": r.rule_id}})

            sarif_level = "error" if r.category == ResultCategory.CRASH else "warning"
            results_sarif.append(
                {
                    "ruleId": r.rule_id,
                    "ruleIndex": rules_map[r.rule_id] - 1,
                    "level": sarif_level,
                    "message": {"text": r.detail},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": f"mcp://{r.tool_name}"}}}
                    ],
                }
            )

        prov = self._provenance()
        audit = self.audit()
        delivery = self.delivery_summary()
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-guard",
                            "version": prov["scanner_version"],
                            "rules": rules_list,
                        }
                    },
                    "properties": {
                        "mcp-guard.run_id": prov["run_id"],
                        "mcp-guard.run_at": prov["run_at"],
                        "mcp-guard.data_source": prov["data_source"],
                        "mcp-guard.payload_ruleset_version": prov["payload_ruleset_version"],
                        "mcp-guard.verdict": self.verdict,
                        "mcp-guard.inconclusive": str(len(self.inconclusive)),
                        "mcp-guard.errors": str(len(self.errors)),
                        "mcp-guard.twyman_audit_triggered": str(audit.triggered),
                        "mcp-guard.allow_empty_error_responses": str(
                            self.allow_empty_error_responses
                        ),
                        # Fault-delivery evidence (mcp-guard#65): a SARIF-only
                        # consumer must be able to check a CLEAN verdict
                        # without the JSON file — the delivery counts, the
                        # audit reasons, and the pass rate live here too.
                        "mcp-guard.delivery_delivered": str(delivery["delivered"]),
                        "mcp-guard.delivery_undelivered": str(delivery["undelivered"]),
                        "mcp-guard.delivery_unknown": str(delivery["unknown"]),
                        "mcp-guard.twyman_audit_reasons": "; ".join(audit.reasons),
                        "mcp-guard.safe_rate": str(audit.safe_rate),
                        "mcp-guard.total_probes": str(audit.total),
                        "mcp-guard.twyman_audit_t2_suppressed": str(self.t2_suppressed()),
                        "mcp-guard.allow_identical_error_responses": str(
                            self.allow_identical_error_responses
                        ),
                        "mcp-guard.twyman_audit_t3_suppressed": str(self.t3_suppressed()),
                    },
                    "results": results_sarif,
                }
            ],
        }
        out.write(json.dumps(sarif, indent=2, ensure_ascii=False))
