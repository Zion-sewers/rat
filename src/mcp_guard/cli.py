"""CLI entry point for mcp-guard adversarial fuzzer."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .calibration import (
    CalibrationCase,
    CalibrationPolicy,
    CalibrationReport,
    Disposition,
    GuardrailReasoning,
    ReasoningAlignmentSummary,
    ScannerCalibrationCase,
    compare_calibration,
    evaluate_calibration,
    threshold_sensitivity,
)
from .concealment import (
    ConcealmentBlockedError,
    ConcealmentScanner,
    PipelineManifest,
    SideTaskDeniedError,
    StagedFile,
)
from .delegation import (
    CommandVerifier,
    ConcealmentVerifier,
    ContractRejectedError,
    DelegationContract,
    DelegationError,
    DelegationResult,
    DelegationRunner,
    DelegationState,
    FrontmatterParseError,
    LoopGuard,
    LoopRefusedError,
    SeniorVerifier,
    TaskKind,
    sanitize_delegation_id,
)
from .escalation import EscalationRequiredError, InputTrust, SecondApproval, scrub_for_output
from .fuzzer import FuzzEngine
from .gateway import AuditKind, GatewayPolicy, PiiTokenizer, TrustDeniedError, TrustLevel
from .identity import IdentityContext, IdentityError, IdentityVault, PermissionScope
from .intake import IntakeFailure, IntakePolicy, normalize_input
from .lifecycle import (
    Lifecycle,
    LifecycleError,
    LifecycleKind,
    ServerNotEnabledError,
    ServerRegistry,
    ServerSpec,
    TeardownFailedError,
)
from .report import FuzzReport
from .scanner import Scanner
from .transport import JsonDict, StdioTransport
from .trust_scanner import DEFAULT_RULES, InboundScanner

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool, quiet: bool) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser (extracted so tests can pin the delegate
    defaults against the delegation module's constants)."""
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Adversarial fuzzer for MCP servers — break before they break you.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Suppress all non-error output")
    sub = parser.add_subparsers(dest="command")

    # fuzz subcommand
    fuzz_parser = sub.add_parser("fuzz", help="Fuzz an MCP server via stdio transport")
    fuzz_parser.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    fuzz_parser.add_argument("--delay-ms", type=int, default=0, help="Delay between payloads (ms)")
    fuzz_parser.add_argument(
        "--timeout", type=float, default=10.0, help="Per-tool-call timeout (seconds)"
    )
    fuzz_parser.add_argument(
        "--allow-empty-error-responses",
        action="store_true",
        help=(
            "Twyman audit override: accept a 100%% SAFE run whose error responses "
            "carry no text (known terse validator). Recorded in the report; "
            "without it such a run is INCONCLUSIVE."
        ),
    )
    fuzz_parser.add_argument(
        "--allow-identical-error-responses",
        action="store_true",
        help=(
            "Twyman audit override: accept a 100%% SAFE run whose error responses "
            "are all the same short text (known strict validator). Recorded "
            "in the report; without it such a run is INCONCLUSIVE."
        ),
    )
    fuzz_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    # scan subcommand (static analysis)
    scan_parser = sub.add_parser("scan", help="Static security scan of MCP tool schemas")
    scan_parser.add_argument("--format", choices=["table", "json"], default="table")
    scan_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    # gateway subcommand (rat #66): proxy MCP calls through the trust /
    # tokenization gateway. Speaks JSON lines on stdout: first line is the
    # annotated tool list, then one line per request, then a gateway_closed
    # line carrying the full audit log. Requests on stdin are JSON objects:
    # {"tool": ..., "arguments": {...}, "caller_trust": "low"|"medium"|"high",
    # "input_trust": "trusted"|"untrusted" (default untrusted),
    # "metadata": {...} (optional operator-declared intake fields, rat #76),
    # "approval": {"approver": ..., "reason": ...} (second approval for
    # rule-of-two escalations, rat #69, and for inbound-scan HITL results
    # when the policy opts into enforce mode, rat #72)}.
    # Lifecycle (rat #68): the session is one task. With --servers, the
    # session starts with NOTHING enabled; stdin control lines
    # {"task": "begin", "servers": [...]} / {"task": "end"} narrowly enable
    # servers per task and tear them down (verified) afterwards. Without
    # --servers, the single server after -- is the session's task.
    gateway_parser = sub.add_parser(
        "gateway", help="Proxy MCP calls through the trust/tokenization gateway"
    )
    gateway_parser.add_argument(
        "--policy",
        required=True,
        help=(
            'JSON policy file: {"tools": {name: level}, "default_trust": level, '
            '"inbound_scan": {"mode": "audit"|"enforce", "hitl_threshold": 0.40, '
            '"block_threshold": 0.80, "semantic_scorer": {"type": "ollama", '
            '"model": "qwen2.5:7b", "base_url": "http://localhost:11434", '
            '"timeout_s": 10}}} — the inbound scanner (rat #72) runs '
            "audit-only unless the policy opts into enforce mode; the "
            '"semantic_scorer key (rat #73) opts into the LLM leg, off by '
            "default — a gateway given both a scanner and a scorer refuses "
            "to construct rather than silently dropping the scorer; a "
            "custom scanner cannot combine with a policy-file scorer — "
            "build the scanner with the scorer first, or let the gateway "
            "build it from the policy. The 'intake' section (rat #76) "
            "supplies the schema-gate budgets (head 1536 + tail 512 + "
            '"[TRUNCATED]" by default); absent it the schema gate runs '
            "with shipped defaults — gate on, no required metadata, "
            "identity not required — until the operator declares "
            "required_metadata or require_identity in the policy"
        ),
    )
    gateway_parser.add_argument(
        "--identity",
        help=(
            "JSON permission-scope file for identity propagation (rat #70): "
            '{"user_id": ..., "servers": [...], "tools": [...], '
            '"expires_at": ...}. Every call is checked against the scope '
            "and audited under the scope's one-way token; the file is "
            "issued by the deployment's identity provider, this CLI only "
            "enforces it — a locally authored file is self-asserted, not "
            "authenticated. For a single-server session the scope's "
            '"servers" list must include "default" (the registry name of '
            "the single server after --)."
        ),
    )
    gateway_parser.add_argument(
        "--servers",
        help=(
            'JSON registry file: {"servers": {name: [command...]}}. '
            "Enables multi-server tasks via stdin control lines; "
            "cannot be combined with a server command after --."
        ),
    )
    gateway_parser.add_argument(
        "--contract",
        help=(
            "Agent Markdown file carrying a delegation contract in "
            "frontmatter (rat #75): the contract's tool allowlist is "
            "the declared task graph for the concealment side-task "
            "check — a call outside it is off-graph, recorded, and "
            "denied before send when the policy opts into enforce "
            "mode. Without it the side-task check is unavailable."
        ),
    )
    gateway_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    # delegate subcommand (rat #67): run one delegation under a frontmatter
    # contract. The task prompt is scrubbed before it reaches the junior
    # command, and the result stays PENDING_VERIFICATION unless a senior
    # verifier command approves it (exit 0). Without --verify-command the
    # CLI exits 2: the delegation ran, but nobody senior has approved it.
    delegate_parser = sub.add_parser(
        "delegate", help="Run one delegation under a frontmatter contract"
    )
    delegate_parser.add_argument(
        "--contract",
        help="Agent Markdown file carrying the delegation contract in frontmatter "
        "(required unless --resolve-pending or --discard-pending is used)",
    )
    delegate_parser.add_argument(
        "--task",
        choices=[kind.value for kind in TaskKind],
        help="Task kind (routing matrix: trigger, effort, verification step; "
        "required unless --resolve-pending or --discard-pending is used)",
    )
    delegate_parser.add_argument(
        "--prompt-file",
        help="File holding the task prompt (scrubbed before the junior sees it; "
        "required unless --resolve-pending or --discard-pending is used)",
    )
    delegate_parser.add_argument(
        "--resolve-pending",
        metavar="ID",
        help="Resolve a pending delegation by id instead of starting a new one: "
        "runs the senior verifier against the stored pending record and lands "
        "or discards the staged work. Needs --verify-command; --contract, "
        "--task, --prompt-file, and the junior command are not used.",
    )
    delegate_parser.add_argument(
        "--discard-pending",
        metavar="ID",
        help="Discard a pending delegation by id instead of starting a new one: "
        "deletes the pending record and removes the staged worktree without "
        "verification and without landing anything. The discharge path for "
        "pending records resolve cannot discharge (report-kind steps above "
        "all). --contract, --task, --prompt-file, and the junior command "
        "are not used.",
    )
    delegate_parser.add_argument(
        "--identity",
        help=(
            "JSON permission-scope file for identity propagation (rat #70): "
            '{"user_id": ..., "servers": [...], "tools": [...], '
            '"expires_at": ...}. Admission control for the delegation: '
            "every tool the contract declares must be inside the scope, "
            "or the delegation is refused before the junior starts, and "
            "the delegation is audited under the scope's one-way token. "
            "The file is issued by the deployment's identity provider, "
            "this CLI only enforces it — a locally authored file is "
            "self-asserted, not authenticated. Without --identity the "
            "junior's permission ceiling is the contract alone."
        ),
    )
    delegate_parser.add_argument(
        "--verify-command",
        help="Senior verifier command (exit 0 approves); without it the result stays pending",
    )
    delegate_parser.add_argument(
        "--pipeline-manifest",
        help=(
            "JSON pipeline-manifest file for the concealment pre-gate "
            '(rat #75): {"stages": [{"name": ..., "reads": [...], '
            '"writes": [...]}], "declared_inputs": [...]}. The '
            "staged files are checked against it before the senior "
            "verifier runs — an unreferenced or downstream-only file "
            "rejects the result. Needs --verify-command: the "
            "concealment check is a pre-gate, never the senior."
        ),
    )
    delegate_parser.add_argument(
        "--repo-dir",
        help="Repository the delegation runs against (default: the current directory)",
    )
    delegate_parser.add_argument(
        "--no-repo-dir",
        action="store_true",
        help="Run without a repo directory: diff-based verification steps are "
        "skipped and the senior verifier is the only gate",
    )
    delegate_parser.add_argument(
        "--lock-dir",
        help="Directory for lock files and the audit log (default: ~/.mcp-guard/<repo-hash>, outside the repo)",
    )
    delegate_parser.add_argument(
        "--max-delegations",
        type=int,
        default=5,
        help="Max delegation attempts in the rate-limit window",
    )
    delegate_parser.add_argument(
        "--window-seconds",
        type=int,
        default=60,
        help="Rate-limit window (seconds)",
    )
    delegate_parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Junior command timeout (seconds)",
    )
    delegate_parser.add_argument(
        "--delegation-id",
        help="Delegation id (default: derived from the contract filename, task, and path hash)",
    )
    delegate_parser.add_argument(
        "--allow-env",
        action="append",
        help="Extra parent environment variable the junior may inherit (repeatable)",
    )
    delegate_parser.add_argument("junior_command", nargs=argparse.REMAINDER)

    # concealment subcommand (rat #75): audit a staging directory
    # against the concealment catalog — redundant-code wrapping over
    # .py files (needs --privileged-tools to name the privileged tools)
    # and augmentation-embedding over the staged file list vs the
    # pipeline manifest. Prints one JSON object; exit 0 clean, 1
    # findings, 2 input error (a script keying on the exit code must
    # be able to tell a finding from a broken input). The staged
    # directory is the staged deliverable set, not a source tree: every
    # file in it is expected to be pipeline data or a deliverable the
    # manifest accounts for. The gateway and the delegation pre-gate
    # are the live paths; this subcommand is the direct audit surface.
    concealment_parser = sub.add_parser(
        "concealment", help="Audit a staging directory against the concealment catalog"
    )
    concealment_parser.add_argument(
        "--staged-dir",
        required=True,
        help="Directory whose files are the staged deliverable set (not a source tree)",
    )
    concealment_parser.add_argument(
        "--manifest",
        required=True,
        help='JSON pipeline-manifest file: {"stages": [...], "declared_inputs": [...]}',
    )
    concealment_parser.add_argument(
        "--privileged-tools",
        help="Comma-separated privileged tool names for the redundant-code check; "
        "without it that check is skipped and only the augmentation check runs",
    )

    # intake subcommand (rat #76): normalize one intake request offline
    # against the intake policy — the direct audit surface for the
    # schema gate. The request file is {"tool": ..., "arguments": {...},
    # "metadata": {...}}; --policy is a gateway policy file whose
    # "intake" section supplies the budgets (absent: shipped defaults —
    # schema gate on, no required metadata, identity not required, head
    # 1536 + tail 512 + "[TRUNCATED]"). The ok-path prints the
    # normalized request, content included — do not pipe stdout into
    # logs. Prints one JSON object; exit 0 ok, 1 structured fallback, 2
    # input error (an unreadable file, invalid JSON, or a malformed
    # policy — a normalization that could not read its input must not
    # report ok, and must not look like a fallback either). The gateway
    # is the live path; this subcommand is the offline proof surface.
    intake_parser = sub.add_parser(
        "intake",
        help="Normalize one intake request offline against the intake policy",
        description="Normalize one intake request offline against the intake policy. "
        "The ok-path prints the normalized request, content included — "
        "do not pipe stdout into logs.",
    )
    intake_parser.add_argument(
        "--file",
        required=True,
        help='JSON request file: {"tool": ..., "arguments": {...}, "metadata": {...}}',
    )
    intake_parser.add_argument(
        "--policy",
        help="Gateway policy file whose 'intake' section supplies the budgets "
        "(absent: shipped defaults — schema gate on, no required metadata, "
        "identity not required, head 1536 + tail 512)",
    )
    intake_parser.add_argument(
        "--identity-bound",
        action="store_true",
        help="Pretend an identity is bound to the gateway, so a policy with "
        "'require_identity' can return ok offline (absent: unbound, so such "
        "a policy always falls back — the offline surface cannot mint identity)",
    )
    calibration_parser = sub.add_parser(
        "calibration",
        help="Evaluate the calibration-aware escalation over a labeled-cases file",
        description="Run the real inbound scanner over a labeled-cases "
        "file (JSONL) and print the calibration report: ECE/Brier of "
        "score and of confidence, escalation precision/recall, "
        "human-agreement rate, latency, jailbreak resistance, "
        "containment, reasoning alignment, plus a block-threshold and "
        "confidence-floor sweep. An example file ships at "
        "docs/examples/calibration-cases.jsonl.",
    )
    calibration_parser.add_argument(
        "--cases",
        required=True,
        help='JSONL cases file: one JSON object per line: {"message": '
        '{"role": ..., "content": ...}, "label_violation": true|false, '
        '"human_disposition": "allow"|"escalate"|"block", '
        '"is_jailbreak": true|false, "reasoning": {...}}',
    )
    calibration_parser.add_argument(
        "--policy",
        help="Gateway policy file whose 'inbound_scan' section supplies "
        "the thresholds and whose 'calibration' section supplies the "
        "block-confidence floor (absent: shipped defaults 0.40 / 0.80 / 0.80)",
    )
    calibration_parser.add_argument(
        "--thresholds",
        help="Comma-separated block thresholds to sweep (absent: 0.70,0.80,0.90)",
    )
    calibration_parser.add_argument(
        "--floors",
        help="Comma-separated block-confidence floors to sweep (absent: the policy floor only)",
    )
    calibration_parser.add_argument(
        "--baseline",
        help="A previous calibration output file (this command's JSON) "
        "to diff against for drift detection",
    )
    calibration_parser.add_argument(
        "--known-policy-ids",
        help="Comma-separated policy ids the reasoning refs are checked "
        "against (absent: the scanner's rule ids)",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose, args.quiet)

    if args.command == "fuzz":
        _run_fuzz(args)
    elif args.command == "scan":
        _run_scan(args)
    elif args.command == "gateway":
        _run_gateway(args)
    elif args.command == "delegate":
        _run_delegate(args)
    elif args.command == "concealment":
        _run_concealment(args)
    elif args.command == "intake":
        _run_intake(args)
    elif args.command == "calibration":
        _run_calibration(args)
    else:
        parser.print_help()


def _run_fuzz(args: argparse.Namespace) -> None:
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        logger.error("Error: specify MCP server command after --")
        logger.info("Usage: mcp-guard fuzz -- npx @modelcontextprotocol/server-memory")
        sys.exit(1)

    logger.info("Starting MCP server: %s", " ".join(cmd))
    try:
        with StdioTransport(cmd, timeout=args.timeout) as transport:
            logger.info("Connected. Enumerating tools...")
            tools = transport.list_tools()
            if not tools:
                logger.warning("No tools found on this server.")
                return

            logger.info("Found %d tools. Generating payloads...", len(tools))
            all_results = []
            engine = FuzzEngine(transport=transport, delay_ms=args.delay_ms)
            for tool in tools:
                name = tool.get("name", "unknown")
                logger.info("Fuzzing: %s...", name)
                results = engine.fuzz_tool(tool)
                all_results.extend(results)

            report = FuzzReport(
                server_command=" ".join(cmd),
                tools_fuzzed=len(tools),
                total_payloads=len(all_results),
                results=all_results,
                allow_empty_error_responses=args.allow_empty_error_responses,
                allow_identical_error_responses=args.allow_identical_error_responses,
            )

            if args.format == "json":
                report.to_json()
            elif args.format == "sarif":
                report.to_sarif()
            else:
                report.to_table()

            crashes = len(report.crashes)
            if crashes:
                logger.warning("VERDICT: VULNERABLE — %d crashes detected", crashes)
                sys.exit(2)
            elif report.verdict == "INCONCLUSIVE":
                # Twyman's law (mcp-guard#65): an inconclusive run is not a
                # clean run. Exit 1, same as any other error: CI must fail
                # rather than pass a verdict the instrumentation cannot back.
                # The branch keys on the verdict itself (single source of
                # truth) so errored probes withhold CLEAN exactly like
                # inconclusive probes and triggered audits do.
                logger.warning("VERDICT: INCONCLUSIVE — %s", report.verdict_reason)
                sys.exit(1)
            elif report.findings:
                logger.warning("VERDICT: %d findings require investigation", len(report.findings))
            else:
                logger.info("VERDICT: CLEAN — all payloads handled safely")
    except ConnectionError as e:
        logger.error("Connection error: %s", e)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        logger.error("Error: %s", e)
        sys.exit(1)


class _GatewaySession:
    """Mutable stdin-session state for the gateway subcommand.

    Holds the lifecycle, the live task (at most one at a time in a
    session), and the default server for single-server sessions.
    """

    def __init__(
        self,
        lifecycle: Lifecycle,
        default_server: str | None,
        identity: IdentityContext | None = None,
    ) -> None:
        self.lifecycle = lifecycle
        self.default_server = default_server
        self.identity = identity
        self.task_id: str | None = None
        self.task_counter = 0


def _scrub_text(text: str) -> str:
    """Tokenize detected-class PII spans out of one stdout string (rat #69).

    Fresh per-call tokenizer: display tokens, not session-correlated
    audit tokens (the audit log uses the session tokenizer in the
    gateway). A string with no detected spans prints unchanged.
    """
    scrubbed, _ = PiiTokenizer().tokenize_text(text)
    return scrubbed


def _handle_gateway_begin(session: _GatewaySession, request: JsonDict) -> None:
    """Handle a {"task": "begin", ...} control line."""
    if session.task_id is not None:
        print(json.dumps({"error": "a task is already live; end it before beginning another"}))
        return
    servers = request.get("servers")
    if not isinstance(servers, list) or any(not isinstance(name, str) for name in servers):
        print(json.dumps({"error": "begin needs a 'servers' list of names"}))
        return
    task_id = request.get("task_id")
    if task_id is None:
        session.task_counter += 1
        # Auto-minted ids use their own prefix so they can never collide
        # with a user-supplied id.
        task_id = f"auto-task-{session.task_counter}"
    if not isinstance(task_id, str):
        print(json.dumps({"error": "begin 'task_id' must be a string"}))
        return
    try:
        handle = session.lifecycle.begin_task(task_id, servers, session.identity)
    except (IdentityError, LifecycleError, OSError, TimeoutError, RuntimeError) as e:
        print(json.dumps({"error": _scrub_text(str(e))}))
        return
    session.task_id = task_id
    try:
        tools = {name: session.lifecycle.list_tools(task_id, name) for name in handle.servers}
    except (LifecycleError, OSError, TimeoutError, RuntimeError) as e:
        # The task began but its tools cannot be listed (server died or
        # answered with an error between initialize and tools/list): roll
        # the task back instead of leaving begun servers behind. If the
        # rollback teardown itself fails, the task stays live so the
        # operator can retry {"task": "end"}.
        try:
            session.lifecycle.end_task(task_id)
        except TeardownFailedError as te:
            print(
                json.dumps(
                    {
                        "error": _scrub_text(str(e)),
                        "teardown": scrub_for_output(te.report.to_dict(), PiiTokenizer()),
                    }
                )
            )
            return
        session.task_id = None
        print(json.dumps({"error": _scrub_text(str(e))}))
        return
    # The annotated list is server-controlled free text (rat #69,
    # round-5 fix-forward): names and descriptions are scrubbed at this
    # print site, never in annotate_tools — the harness still needs the
    # real names to call the tools by. The task id is caller-supplied
    # free text too (round-6 fix-forward), so it is scrubbed as well.
    print(
        json.dumps(
            {
                "task": "begun",
                "task_id": _scrub_text(task_id),
                "tools": scrub_for_output(tools, PiiTokenizer()),
            }
        )
    )


def _handle_gateway_end(session: _GatewaySession) -> None:
    """Handle a {"task": "end"} control line."""
    if session.task_id is None:
        print(json.dumps({"error": "no live task to end"}))
        return
    task_id = session.task_id
    try:
        report = session.lifecycle.end_task(task_id)
    except TeardownFailedError as e:
        print(
            json.dumps(
                {
                    "task": "end_failed",
                    "task_id": _scrub_text(task_id),
                    "error": _scrub_text(str(e)),
                    "teardown": scrub_for_output(e.report.to_dict(), PiiTokenizer()),
                }
            )
        )
        return
    session.task_id = None
    print(
        json.dumps(
            {
                "task": "ended",
                "task_id": _scrub_text(task_id),
                "teardown": scrub_for_output(report.to_dict(), PiiTokenizer()),
            }
        )
    )


def _handle_gateway_line(session: _GatewaySession, line: str) -> None:
    """Route one stdin JSON request through the lifecycle's gateway.

    Control lines ({"task": "begin"/"end"}) manage the session's task;
    call lines route one gated tool call. Malformed requests print an
    {"error": ...} line and never kill the session; a denied call prints
    {"denied": true, ...} with the audit delta, never the raw request;
    an intake failure prints {"fallback": true, "error_code": ...} with
    the audit delta and the structured fallback in "result" (rat #76,
    round-2 fix-forward: a fallback is not a result, so the line carries
    an explicit top-level marker instead of a bare success line). The
    tool name is tokenized before any print (rat #69): a PII-bearing
    name prints with its spans tokenized on every line, and rejected
    enum values are never echoed back.
    """
    lc_before = len(session.lifecycle.audit_log)
    try:
        request = json.loads(line)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"invalid JSON: {e}"}))
        return
    if not isinstance(request, dict):
        print(json.dumps({"error": "gateway request must be a JSON object"}))
        return
    task_cmd = request.get("task")
    if task_cmd is not None:
        if task_cmd == "begin":
            _handle_gateway_begin(session, request)
        elif task_cmd == "end":
            _handle_gateway_end(session)
        else:
            print(json.dumps({"error": "unknown task command"}))
        return
    server = request.get("server")
    if server is None:
        server = session.default_server
    if server is None:
        print(json.dumps({"error": "call needs a 'server' (no default server)"}))
        return
    if not isinstance(server, str):
        print(json.dumps({"error": "call 'server' must be a string"}))
        return
    task_id = session.task_id
    if task_id is None:
        print(json.dumps({"error": 'no live task: send {"task": "begin", ...} first'}))
        return
    tool = request.get("tool")
    if not isinstance(tool, str):
        print(json.dumps({"error": "gateway request needs a string 'tool'"}))
        return
    if not tool.strip():
        # A blank tool name is malformed input, not a call: the gateway
        # would raise ValueError from the tool-call record, which no
        # handler below catches — an error line here keeps the session
        # alive (round-1 fix-forward).
        print(json.dumps({"error": "gateway request needs a non-empty 'tool'"}))
        return
    # The tool name is caller-supplied text echoed on every stdout line
    # below (rat #69, round-4 fix-forward): tokenize it once, before any
    # print, so a PII-bearing name can never reach stdout. A well-formed
    # name has no detected spans and prints unchanged; the REAL name
    # still drives the gateway call below. Fresh per-line tokenizer:
    # error-line tokens are diagnostics, not session-correlated audit
    # tokens (the audit log uses the session tokenizer in the gateway).
    _log_tokenizer = PiiTokenizer()
    log_tool, _ = _log_tokenizer.tokenize_text(tool)
    arguments = request.get("arguments", {})
    if not isinstance(arguments, dict):
        print(
            json.dumps({"error": "gateway request 'arguments' must be an object", "tool": log_tool})
        )
        return
    caller_raw = request.get("caller_trust", "low")
    if not isinstance(caller_raw, str):
        print(
            json.dumps(
                {"error": "gateway request 'caller_trust' must be a string", "tool": log_tool}
            )
        )
        return
    try:
        caller_trust = TrustLevel.parse(caller_raw)
    except ValueError as e:
        print(json.dumps({"error": str(e), "tool": log_tool}))
        return
    input_raw = request.get("input_trust", "untrusted")
    if not isinstance(input_raw, str):
        print(
            json.dumps(
                {"error": "gateway request 'input_trust' must be a string", "tool": log_tool}
            )
        )
        return
    try:
        input_trust = InputTrust.parse(input_raw)
    except ValueError as e:
        print(json.dumps({"error": str(e), "tool": log_tool}))
        return
    # "approval" must be an object (a string approval is a malformed
    # request, not a denial). A metadata object (rat #76) carries
    # operator-declared pipeline-critical fields (e.g. "locale") for
    # the intake policy to check; its shape is intake's rule, not the
    # shell's — a non-object metadata reaches the gateway, which
    # records the INTAKE fail and returns the structured fallback like
    # every other malformed input (round-2 fix-forward: the shell must
    # not own a second verdict path for the same input).
    approval: SecondApproval | None = None
    approval_raw = request.get("approval")
    if approval_raw is not None:
        if not isinstance(approval_raw, dict):
            print(
                json.dumps(
                    {"error": "gateway request 'approval' must be an object", "tool": log_tool}
                )
            )
            return
        approver = approval_raw.get("approver")
        reason = approval_raw.get("reason")
        if not isinstance(approver, str) or not isinstance(reason, str):
            print(
                json.dumps(
                    {
                        "error": "gateway 'approval' needs string 'approver' and 'reason'",
                        "tool": log_tool,
                    }
                )
            )
            return
        try:
            approval = SecondApproval(approver=approver, reason=reason)
        except ValueError as e:
            print(json.dumps({"error": str(e), "tool": log_tool}))
            return
    metadata_raw = request.get("metadata")
    # The stdin JSON is untyped, so the value reaches the gateway as
    # ``object`` and the cast below is the bridge into the typed
    # ``call_tool`` signature. The shape verdict belongs to intake, not
    # to this shell: a non-object metadata is an INTAKE_INVALID_ARGUMENTS
    # fallback from the gateway (with its INTAKE event), never an error
    # line from here.
    metadata: Mapping[str, object] | None = cast("Mapping[str, object] | None", metadata_raw)
    try:
        gw_before = len(session.lifecycle.gateway_audit_log(task_id, server))
    except ServerNotEnabledError as e:
        # The probe is a read view, so it deliberately records no denial
        # — but this line IS a call attempt, not a read: the denial is a
        # real access attempt and must be audited exactly as the denial
        # call_tool would have recorded, or the production consumer's
        # audit log stays silent about denied calls.
        session.lifecycle.audit_log.record(
            LifecycleKind.SERVER_DENIED, task_id, "not enabled for task", server=server
        )
        print(
            json.dumps(
                {
                    "tool": log_tool,
                    "denied": True,
                    "reason": _log_tokenizer.tokenize_text(str(e))[0],
                    "lifecycle_audit": scrub_for_output(
                        session.lifecycle.audit_log.to_json()[lc_before:], PiiTokenizer()
                    ),
                }
            )
        )
        return
    except LifecycleError as e:
        print(
            json.dumps(
                {
                    "tool": log_tool,
                    "denied": True,
                    "reason": _log_tokenizer.tokenize_text(str(e))[0],
                    "lifecycle_audit": scrub_for_output(
                        session.lifecycle.audit_log.to_json()[lc_before:], PiiTokenizer()
                    ),
                }
            )
        )
        return
    try:
        result = session.lifecycle.call_tool(
            task_id, server, tool, arguments, caller_trust, input_trust, approval, metadata
        )
    except (
        TrustDeniedError,
        EscalationRequiredError,
        IdentityError,
        ConcealmentBlockedError,
        SideTaskDeniedError,
    ) as e:
        # Identity denials (rat #70) print the same denied line as trust
        # denials, with the audit delta carrying the identity_denied /
        # identity_expired / credential_refused event: a refused call is
        # a per-request denial, never a dead session. Concealment
        # denials (rat #75, round-1 fix-forward) print the same line:
        # the gateway records the CONCEALMENT_SCAN event before raising,
        # so the audit delta carries the trip — an enforce-mode trip
        # must deny one call, not end the session.
        print(
            json.dumps(
                {
                    "tool": log_tool,
                    "denied": True,
                    "reason": _log_tokenizer.tokenize_text(str(e))[0],
                    "audit": session.lifecycle.gateway_audit_log(task_id, server).to_json()[
                        gw_before:
                    ],
                }
            )
        )
        return
    except LifecycleError as e:
        print(
            json.dumps(
                {
                    "tool": log_tool,
                    "denied": True,
                    "reason": _log_tokenizer.tokenize_text(str(e))[0],
                    "lifecycle_audit": scrub_for_output(
                        session.lifecycle.audit_log.to_json()[lc_before:], PiiTokenizer()
                    ),
                }
            )
        )
        return
    except (OSError, TimeoutError, RuntimeError) as e:
        # A transport-level call failure (server error envelope, dead
        # server, hung call, broken pipe on the write path) is an error
        # line for that request, never a dead session: the operator's
        # next lines still run and EOF still tears the task down with
        # verified teardown.
        print(json.dumps({"tool": log_tool, "error": _log_tokenizer.tokenize_text(str(e))[0]}))
        return
    audit_delta = session.lifecycle.gateway_audit_log(task_id, server).to_json()[gw_before:]
    audit_events = session.lifecycle.gateway_audit_log(task_id, server).events()[gw_before:]
    intake_fail = next(
        (
            event
            for event in audit_events
            if event.kind is AuditKind.INTAKE and event.intake_outcome == "fail"
        ),
        None,
    )
    if intake_fail is not None:
        # Round-2 fix-forward (rat #76, architecture B1): a fallback is
        # not a result. The line carries an explicit top-level marker
        # plus the stable error code, so a consumer need not parse the
        # result body to tell a fallback from a tool result; the
        # fallback payload stays in "result" so the harness can still
        # read the structured fallback itself.
        print(
            json.dumps(
                {
                    "tool": log_tool,
                    "fallback": True,
                    "error_code": intake_fail.intake_error_code,
                    "result": result,
                    "audit": audit_delta,
                }
            )
        )
        return
    print(
        json.dumps(
            {
                "tool": log_tool,
                "result": result,
                "audit": audit_delta,
            }
        )
    )


def _load_identity_context(path: str) -> IdentityContext:
    """Load a permission-scope file and mint an ephemeral bound context.

    The scope file is trusted deployment-issued input: the deployment's
    identity provider issues it, this CLI only enforces it — a locally
    authored file is self-asserted, not authenticated. The vault mints
    an ephemeral in-process handle bound to the scope; the vault itself
    is never persisted by the CLI, so there is no cross-process
    revocation source in the shipped CLI session (revocation is
    enforced live in-library for a harness holding the vault). A
    malformed or expired scope file exits 1, like a malformed policy
    file: the session never starts unscoped by accident.
    """
    try:
        scope_data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Cannot load identity scope %s: %s", path, e)
        sys.exit(1)
    try:
        scope = PermissionScope.from_mapping(scope_data)
        return IdentityVault().issue_context(scope)
    except (TypeError, ValueError, IdentityError) as e:
        logger.error("Invalid identity scope: %s", e)
        sys.exit(1)


def _load_pipeline_manifest(path: str, exit_code: int = 1) -> PipelineManifest:
    """Load a pipeline-manifest file for the concealment pre-gate.

    A malformed manifest exits 1, like a malformed policy file: the
    session never runs a concealment check against a manifest it could
    not parse — a half-parsed manifest would silently pass staged
    files the operator meant to be checked. The concealment
    subcommand passes exit code 2 so a script can tell a broken input
    from a finding (round-1 fix-forward).
    """
    try:
        manifest_data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Cannot load pipeline manifest %s: %s", path, e)
        sys.exit(exit_code)
    try:
        return PipelineManifest.from_mapping(manifest_data)
    except (TypeError, ValueError) as e:
        logger.error("Invalid pipeline manifest: %s", e)
        sys.exit(exit_code)


def _run_gateway(args: argparse.Namespace) -> None:
    try:
        policy_data = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Cannot load gateway policy %s: %s", args.policy, e)
        sys.exit(1)
    try:
        policy = GatewayPolicy.from_mapping(policy_data)
    except (TypeError, ValueError) as e:
        logger.error("Invalid gateway policy: %s", e)
        sys.exit(1)

    # Identity propagation (rat #70): the scope file is issued by the
    # deployment's identity provider; this CLI only enforces it.
    identity: IdentityContext | None = None
    if args.identity:
        identity = _load_identity_context(args.identity)

    # Concealment side-task check (rat #75): the contract's tool
    # allowlist is the declared task graph. A malformed contract exits
    # 1, like a malformed policy file: the session never starts with a
    # silently unbound side-task check.
    contract: DelegationContract | None = None
    if args.contract:
        try:
            contract_text = Path(args.contract).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            logger.error("Cannot read contract file: %s", e)
            sys.exit(1)
        try:
            contract = DelegationContract.from_text(contract_text)
        except (FrontmatterParseError, ContractRejectedError) as e:
            logger.error("Invalid delegation contract: %s", e)
            sys.exit(1)

    cmd = [a for a in args.server_command if a != "--"]
    if args.servers:
        if cmd:
            logger.error("Cannot combine --servers with a server command after --")
            sys.exit(1)
        try:
            registry_data = json.loads(Path(args.servers).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Cannot load servers file %s: %s", args.servers, e)
            sys.exit(1)
        try:
            registry = ServerRegistry.from_mapping(registry_data)
        except (TypeError, ValueError) as e:
            logger.error("Invalid servers file: %s", e)
            sys.exit(1)
        default_server = None
    else:
        if not cmd:
            logger.error("Error: specify MCP server command after --")
            sys.exit(1)
        registry = ServerRegistry(servers={"default": ServerSpec("default", tuple(cmd))})
        default_server = "default"

    try:
        lifecycle = Lifecycle(registry, policy, contract=contract)
        session = _GatewaySession(lifecycle, default_server, identity)
        # A single-server session that fails before its first line (begin
        # or tools/list) still closes with a gateway_closed line carrying
        # the error and the rolled-back teardown report, instead of dying
        # with an empty stdout: the operator always gets a
        # machine-readable close, and a begun server is always torn down
        # (verified) before the process exits 1.
        startup_error: str | None = None
        startup_teardown: JsonDict | None = None
        startup_teardown_failed = False
        if default_server is not None:
            try:
                lifecycle.begin_task("session", (default_server,), identity)
            except (IdentityError, LifecycleError, OSError, TimeoutError, RuntimeError) as e:
                startup_error = _scrub_text(str(e))
            else:
                session.task_id = "session"
                try:
                    tools = lifecycle.list_tools("session", default_server)
                except (LifecycleError, OSError, TimeoutError, RuntimeError) as e:
                    startup_error = _scrub_text(str(e))
                    try:
                        startup_teardown = lifecycle.end_task("session").to_dict()
                    except TeardownFailedError as te:
                        startup_teardown = te.report.to_dict()
                        startup_teardown_failed = True
                    session.task_id = None
                else:
                    # Server-controlled names/descriptions (rat #69,
                    # round-5 fix-forward): scrubbed at this print site,
                    # never in annotate_tools — the harness still needs
                    # the real names to call the tools by.
                    print(json.dumps({"tools": scrub_for_output(tools, PiiTokenizer())}))
        else:
            print(json.dumps({"servers": list(registry.names)}))
        loop_done = False
        try:
            if startup_error is None:
                for line in sys.stdin:
                    if line.strip():
                        _handle_gateway_line(session, line.strip())
            loop_done = True
        finally:
            # An abnormal exit of the line loop (an unhandled error inside
            # a handler, a broken stdin) must never orphan begun servers:
            # end the live task here. The closing line below is printed
            # only on the normal path.
            if not loop_done and session.task_id is not None:
                try:
                    lifecycle.end_task(session.task_id)
                except TeardownFailedError as te:
                    logger.error(
                        "teardown failed on abnormal exit: %s",
                        te.report.to_dict(),
                    )
                session.task_id = None
        # Full gateway audit while the session task is still live: end_task
        # drops the task record, so this read must come first.
        gateway_audit: list[JsonDict] | None = None
        server_audits: dict[str, list[JsonDict]] | None = None
        if default_server is not None and session.task_id == "session":
            gateway_audit = lifecycle.gateway_audit_log("session", default_server).to_json()
        elif session.task_id is not None:
            server_audits = {
                name: lifecycle.gateway_audit_log(session.task_id, name).to_json()
                for name in lifecycle.enabled_servers(session.task_id)
            }
        # EOF ends any live task: teardown is verified, never assumed.
        # A startup failure already ended (and reported) its task above,
        # so its teardown carries over instead of being recomputed.
        teardown: JsonDict | None = startup_teardown
        teardown_failed = startup_teardown_failed
        if session.task_id is not None:
            try:
                teardown = lifecycle.end_task(session.task_id).to_dict()
            except TeardownFailedError as e:
                teardown = e.report.to_dict()
                teardown_failed = True
        # Teardown and lifecycle-audit blocks carry the caller-supplied
        # task id (round-6 fix-forward): scrubbed at this print site, the
        # same way the begun/ended lines scrub it. Gateway audits are
        # already tokenized at record time and stay as-is.
        closing: JsonDict = {
            "event": "gateway_closed",
            "teardown": scrub_for_output(teardown, PiiTokenizer()),
            "lifecycle_audit": scrub_for_output(lifecycle.audit_log.to_json(), PiiTokenizer()),
        }
        if startup_error is not None:
            closing["error"] = startup_error
        if gateway_audit is not None:
            closing["audit"] = gateway_audit
        if server_audits is not None:
            closing["server_audits"] = server_audits
        print(json.dumps(closing))
        if teardown_failed or startup_error is not None:
            sys.exit(1)
    except ConnectionError as e:
        logger.error("Connection error: %s", e)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        logger.error("Error: %s", e)
        sys.exit(1)


def _default_lock_dir(repo_dir: Path | None) -> Path:
    """The default guard-state directory: outside the junior's tree.

    Guard state (per-id locks + the audit log) must not live inside the
    repo the junior works in: it would show up in ``git status`` and be
    collected as junior changes, and a worktree run would stage it. The
    default is per-repo (a hash of the repo path) under ~/.mcp-guard, so
    two repos never share a rate-limit window; --lock-dir overrides it
    explicitly. This is NOT a security boundary: the junior inherits
    HOME and the contract-file path names the lock dir, so a junior
    that goes looking can still find and delete the audit log (see
    docs/spec.md Boundaries). This is a computed default, not an
    argparse literal: the registry does not track it (same as
    --repo-dir, which likewise has no default).
    """
    base = repo_dir if repo_dir is not None else Path.cwd()
    slug = hashlib.sha256(str(base.resolve()).encode("utf-8")).hexdigest()[:8]
    return Path.home() / ".mcp-guard" / slug


def _emit_delegate_result(
    result: DelegationResult, verifier: CommandVerifier | None, delegation_id: str
) -> None:
    """Print the machine-readable summary + bounded junior output, then
    exit by state: 0 approved, 2 still pending, 1 anything else."""
    summary = result.to_summary()
    print(json.dumps(summary))
    # The junior's own output goes to stderr, so stdout stays one
    # machine-readable JSON line; the operator still sees what the
    # junior did, which is what a rejection needs to be diagnosed.
    # Bounded (from the summary): a runaway junior must not flood the
    # operator's terminal or logs with an unbounded dump.
    if summary["junior_stdout"]:
        print(f"[junior stdout]\n{summary['junior_stdout']}", file=sys.stderr)
    if summary["junior_stderr"]:
        print(f"[junior stderr]\n{summary['junior_stderr']}", file=sys.stderr)
    # Same for the verifier: a missing binary and a rejection on
    # substance must not print the identical line.
    if isinstance(verifier, CommandVerifier) and verifier.last_stderr:
        print(f"[verifier stderr]\n{verifier.last_stderr}", file=sys.stderr)
    if result.state is DelegationState.PENDING_VERIFICATION:
        if result.worktree_path:
            logger.error(
                "Result is PENDING_VERIFICATION: no senior verifier approved it; "
                "do not act on it until one does. The junior's changes are "
                "staged in the worktree at %s; nothing has landed in the "
                "working tree. Resolve it later with: mcp-guard delegate "
                "--resolve-pending %s --verify-command <cmd>.",
                result.worktree_path,
                delegation_id,
            )
        else:
            logger.error(
                "Result is PENDING_VERIFICATION: no senior verifier approved it; "
                "do not act on it until one does. Note: the junior's changes are "
                "already in the working tree; approval gates acting on them, not "
                "their presence. Resolve it later with: mcp-guard delegate "
                "--resolve-pending %s --verify-command <cmd>.",
                delegation_id,
            )
        sys.exit(2)
    if result.state is DelegationState.COMPLETE:
        return
    logger.error("Delegation ended in state %s", result.state.value)
    sys.exit(1)


def _run_delegate(args: argparse.Namespace) -> None:
    if args.max_delegations < 1:
        logger.error("Error: --max-delegations must be >= 1")
        sys.exit(1)
    if args.window_seconds < 1:
        logger.error("Error: --window-seconds must be >= 1")
        sys.exit(1)
    if args.timeout <= 0 or not math.isfinite(args.timeout):
        logger.error("Error: --timeout must be > 0 and finite (nan/inf would disable the timeout)")
        sys.exit(1)
    if args.no_repo_dir and args.repo_dir:
        logger.error("Error: --repo-dir and --no-repo-dir conflict")
        sys.exit(1)

    repo_dir: Path | None = (
        None if args.no_repo_dir else (Path(args.repo_dir) if args.repo_dir else Path.cwd())
    )
    lock_dir = Path(args.lock_dir) if args.lock_dir else _default_lock_dir(repo_dir)

    if args.resolve_pending and args.discard_pending:
        logger.error("Error: --resolve-pending and --discard-pending conflict")
        sys.exit(1)

    if args.resolve_pending:
        # Discharge a pending delegation: no contract, prompt, or junior
        # command is involved — the pending record holds everything.
        # The id is rejected, not sanitized, on the resolve path: a
        # rewritten id could silently resolve a different delegation
        # than the one the operator typed.
        if sanitize_delegation_id(args.resolve_pending) != args.resolve_pending:
            logger.error(
                "Error: --resolve-pending id %r is not a valid delegation id",
                args.resolve_pending,
            )
            sys.exit(1)
        delegation_id = args.resolve_pending
        if not args.verify_command:
            logger.error("Error: --resolve-pending needs --verify-command")
            sys.exit(1)
        runner = DelegationRunner(
            lock_dir,
            guard=LoopGuard(
                lock_dir,
                max_delegations=args.max_delegations,
                window_seconds=args.window_seconds,
            ),
            junior_command=[],
            junior_timeout=args.timeout,
            extra_env_vars=frozenset(args.allow_env or []),
        )
        resolve_command_verifier = CommandVerifier(args.verify_command)
        resolve_verifier: SeniorVerifier = resolve_command_verifier
        if args.pipeline_manifest:
            # Concealment pre-gate (rat #75): staged files are checked
            # against the manifest before the senior verifier runs.
            resolve_verifier = ConcealmentVerifier(
                _load_pipeline_manifest(args.pipeline_manifest), inner=resolve_command_verifier
            )
        try:
            result = runner.resolve_pending(delegation_id, resolve_verifier, repo_dir=repo_dir)
        except (LoopRefusedError, DelegationError, OSError) as e:
            logger.error("Resolve refused: %s", e)
            sys.exit(1)
        _emit_delegate_result(result, resolve_command_verifier, delegation_id)
        return

    if args.discard_pending:
        # Discard a pending delegation without verification: the
        # discharge path for records resolve cannot discharge. The id
        # is rejected, not sanitized, like --resolve-pending: a
        # rewritten id could silently discard a different delegation
        # than the one the operator typed.
        if sanitize_delegation_id(args.discard_pending) != args.discard_pending:
            logger.error(
                "Error: --discard-pending id %r is not a valid delegation id",
                args.discard_pending,
            )
            sys.exit(1)
        runner = DelegationRunner(
            lock_dir,
            guard=LoopGuard(
                lock_dir,
                max_delegations=args.max_delegations,
                window_seconds=args.window_seconds,
            ),
            junior_command=[],
            junior_timeout=args.timeout,
            extra_env_vars=frozenset(args.allow_env or []),
        )
        # Only an explicitly supplied repo locates the removal; the
        # runner otherwise uses the repo stored in the record.
        discard_repo = Path(args.repo_dir) if args.repo_dir else None
        try:
            runner.discard_pending(args.discard_pending, repo_dir=discard_repo)
        except (LoopRefusedError, DelegationError, OSError) as e:
            logger.error("Discard refused: %s", e)
            sys.exit(1)
        logger.info("Discarded pending delegation %s", args.discard_pending)
        return

    if not args.contract or not args.task or not args.prompt_file:
        logger.error(
            "Error: --contract, --task and --prompt-file are required "
            "(or use --resolve-pending to discharge a pending delegation, "
            "or --discard-pending to drop one)"
        )
        sys.exit(1)

    try:
        contract_text = Path(args.contract).read_text(encoding="utf-8")
        prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        logger.error("Cannot read input file: %s", e)
        sys.exit(1)

    # Only the FIRST "--" is the argparse separator: a later "--" is a
    # legitimate junior argument (a git-style separator, a flag value)
    # and must reach the junior's argv unchanged.
    junior_args = list(args.junior_command)
    if junior_args[:1] == ["--"]:
        junior_args = junior_args[1:]
    cmd = junior_args
    if not cmd:
        logger.error("Error: specify junior command after --")
        sys.exit(1)

    command_verifier = CommandVerifier(args.verify_command) if args.verify_command else None
    verifier: SeniorVerifier | None = command_verifier
    if args.pipeline_manifest:
        # Concealment pre-gate (rat #75): staged files are checked
        # against the manifest before the senior verifier runs. The
        # pre-gate needs a senior to hand clean results to, so a
        # manifest without --verify-command is refused outright.
        if command_verifier is None:
            logger.error("Error: --pipeline-manifest needs --verify-command")
            sys.exit(1)
        verifier = ConcealmentVerifier(
            _load_pipeline_manifest(args.pipeline_manifest), inner=command_verifier
        )
    if args.delegation_id:
        delegation_id = sanitize_delegation_id(args.delegation_id)
    else:
        # Same filename in two directories must not collide: the
        # absolute contract path is hashed into the derived id.
        contract_path = str(Path(args.contract).resolve())
        digest = hashlib.sha256(contract_path.encode("utf-8")).hexdigest()[:8]
        delegation_id = sanitize_delegation_id(f"{Path(args.contract).stem}-{args.task}-{digest}")
    runner = DelegationRunner(
        lock_dir,
        guard=LoopGuard(
            lock_dir,
            max_delegations=args.max_delegations,
            window_seconds=args.window_seconds,
        ),
        junior_command=cmd,
        junior_timeout=args.timeout,
        extra_env_vars=frozenset(args.allow_env or []),
    )
    try:
        contract = DelegationContract.from_text(contract_text)
    except (FrontmatterParseError, ContractRejectedError) as e:
        logger.error("Delegation refused: %s", e)
        sys.exit(1)

    # Identity propagation (rat #70): admission control for the
    # delegation. With --identity, every tool the contract declares
    # must be inside the delegating user's scope, or the delegation is
    # refused BEFORE the junior starts — a junior must never run with
    # a wider tool ceiling than the user who delegated to it. The
    # delegation is then audited under the scope's one-way token.
    # Without --identity the junior's ceiling is the contract alone,
    # and nothing warns: the operator chose an unattributed run.
    identity: IdentityContext | None = None
    if args.identity:
        identity = _load_identity_context(args.identity)
        excess = sorted(tool for tool in contract.tools if not identity.scope.allows_tool(tool))
        if excess:
            logger.error(
                "Delegation refused: contract declares tools outside the identity scope: %s",
                ", ".join(excess),
            )
            sys.exit(1)
        logger.info(
            "Delegation %s bound to identity %s (contract tools inside scope)",
            delegation_id,
            identity.audit_token,
        )

    try:
        result = runner.delegate(
            contract=contract,
            delegation_id=delegation_id,
            task=TaskKind(args.task),
            prompt=prompt,
            repo_dir=repo_dir,
            verifier=verifier,
            identity_token=identity.audit_token if identity is not None else None,
        )
    except (LoopRefusedError, DelegationError) as e:
        logger.error("Delegation refused: %s", e)
        sys.exit(1)

    if (
        result.state is DelegationState.TIMEOUT
        and (lock_dir / f"{delegation_id}.pending.json").exists()
    ):
        # The timeout left a durable pending record (isolation none):
        # the operator can still get a senior verdict on the partial
        # work instead of discovering the record only from the docs.
        logger.error(
            "Result is TIMEOUT: the junior was killed, but its partial writes "
            "are recorded as a pending delegation; resolve it with: "
            "mcp-guard delegate --resolve-pending %s --verify-command <cmd>.",
            delegation_id,
        )

    _emit_delegate_result(result, command_verifier, delegation_id)


def _run_concealment(args: argparse.Namespace) -> None:
    """Audit a staging directory against the concealment catalog (rat #75).

    Redundant-code wrapping runs over every ``.py`` file (needs
    --privileged-tools to name the privileged tools; without it that
    check is skipped and the report says so). Augmentation-embedding
    runs over every file in the directory against the manifest. The
    side-task check has no direct surface here (it needs a live
    tool-call trace, so it runs only through the gateway) and the
    report says so. Hidden directories are audited like any other:
    only the named tooling directories (``.git``, ``.venv``,
    ``__pycache__``) are skipped — a blanket dot-prefix rule would
    treat a payload in ``.secret/`` as tooling and report the
    directory clean (round-2 fix-forward). Hidden FILES are audited
    too: a dotfile is a classic concealment spot and belongs in the
    audit (round-1 fix-forward). The staged directory is the staged
    deliverable set, not a source tree: every file in it is expected
    to be pipeline data or a deliverable the manifest accounts for.
    Prints one JSON object; exit 0 clean, 1 findings, 2 input
    error (a missing directory, an unreadable file, or a malformed
    manifest — an audit that could not read its input must not
    report clean, and must not look like a finding either).
    """
    staged_dir = Path(args.staged_dir)
    if not staged_dir.is_dir():
        logger.error("Error: --staged-dir %s is not a directory", args.staged_dir)
        sys.exit(2)
    manifest = _load_pipeline_manifest(args.manifest, exit_code=2)
    privileged = frozenset(
        name.strip() for name in (args.privileged_tools or "").split(",") if name.strip()
    )
    scanner = ConcealmentScanner()
    # Named tooling set only (round-2 fix-forward): a blanket
    # dot-prefix rule skipped every hidden directory, so a payload in
    # `.secret/` never entered the staged list and the audit reported
    # clean. A hidden directory's files are staged files like any
    # other; a future tooling name belongs in this set with a reason.
    skipped = {".git", ".venv", "__pycache__"}
    staged: list[StagedFile] = []
    skipped_dirs: set[str] = set()
    redundant: list[dict[str, object]] = []
    py_checked = 0
    try:
        all_files = sorted(path for path in staged_dir.rglob("*") if path.is_file())
    except OSError as e:
        logger.error("Cannot list --staged-dir %s: %s", staged_dir, e)
        sys.exit(2)
    files: list[Path] = []
    for path in all_files:
        parts = path.relative_to(staged_dir).parts
        hidden = next(
            (i for i, part in enumerate(parts[:-1]) if part in skipped),
            None,
        )
        if hidden is not None:
            skipped_dirs.add("/".join(parts[: hidden + 1]))
            continue
        files.append(path)
    for path in files:
        relative = path.relative_to(staged_dir).as_posix()
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as e:
            logger.error("Cannot read staged file %s: %s", relative, e)
            sys.exit(2)
        staged.append(StagedFile(path=relative, sha256=digest))
        if privileged and path.suffix == ".py":
            py_checked += 1
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                logger.error("Cannot read staged file %s: %s", relative, e)
                sys.exit(2)
            finding = scanner.scan_artifact(text, privileged)
            if finding is not None and finding.tripped:
                item = finding.to_dict()
                item["file"] = relative
                redundant.append(item)
    augmentation = scanner.scan_staging(tuple(staged), manifest)
    report: dict[str, object] = {
        "files_scanned": len(staged),
        "redundant_code": redundant,
        "redundant_code_checked": bool(privileged),
        "redundant_code_files_checked": py_checked,
        "side_task_checked": False,
        "skipped_dirs": sorted(skipped_dirs),
        "augmentation": augmentation.to_dict() if augmentation is not None else None,
    }
    print(json.dumps(report))
    if redundant or (augmentation is not None and augmentation.tripped):
        sys.exit(1)


def _run_intake(args: argparse.Namespace) -> None:
    """Normalize one intake request offline (rat #76).

    The request file is ``{"tool": ..., "arguments": {...},
    "metadata": {...}}``; ``--policy`` is a gateway policy file whose
    ``"intake"`` section supplies the budgets (absent: shipped
    defaults). A missing ``"tool"`` key is a malformed REQUEST, not a
    broken input file: it normalizes to an ``INTAKE_INVALID_TOOL``
    fallback (exit 1), the same verdict the gateway returns live. Only
    an unreadable file, invalid JSON, a non-object request, or a
    malformed policy exits 2. ``--identity-bound`` pretends an identity
    is bound, so a policy with ``require_identity`` can return ok
    offline; without it such a policy always falls back. The ok-path
    prints the normalized request, content included — do not pipe
    stdout into logs. Prints one JSON object; exit 0 ok,
    1 structured fallback, 2 input error.
    """
    try:
        request_data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Cannot load intake request %s: %s", args.file, e)
        sys.exit(2)
    if not isinstance(request_data, dict):
        logger.error("Intake request must be a JSON object")
        sys.exit(2)
    policy = IntakePolicy()
    if args.policy is not None:
        try:
            policy_data = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Cannot load gateway policy %s: %s", args.policy, e)
            sys.exit(2)
        try:
            policy = GatewayPolicy.from_mapping(policy_data).intake
        except (TypeError, ValueError) as e:
            logger.error("Invalid gateway policy: %s", e)
            sys.exit(2)
    metadata = request_data.get("metadata")
    outcome = normalize_input(
        request_data.get("tool"),
        request_data.get("arguments", {}),
        policy=policy,
        metadata=metadata,
        identity_bound=args.identity_bound,
    )
    if isinstance(outcome, IntakeFailure):
        print(
            json.dumps(
                {
                    "ok": False,
                    "fallback": {
                        "status": "fallback",
                        "error_code": outcome.error_code.value,
                        "policy_tag": outcome.policy_tag,
                    },
                    "detail": outcome.detail,
                }
            )
        )
        sys.exit(1)
    print(
        json.dumps(
            {
                "ok": True,
                "tool": outcome.tool_name,
                "arguments": outcome.arguments,
                "policy_tag": outcome.policy_tag,
                "truncated": outcome.truncated,
                "truncated_fields": list(outcome.truncated_fields),
            }
        )
    )


def _parse_calibration_reasoning(raw: object) -> GuardrailReasoning:
    """Parse one case's ``reasoning`` object; fail closed (rat #77)."""
    if not isinstance(raw, dict):
        raise TypeError("calibration case 'reasoning' must be an object")
    verdict = raw.get("verdict")
    if not isinstance(verdict, bool):
        raise TypeError("calibration reasoning 'verdict' must be a bool")
    lists: dict[str, tuple[str, ...]] = {}
    for name in ("steps", "policy_refs", "cited_spans"):
        items = raw.get(name, [])
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise TypeError(f"calibration reasoning '{name}' must be a list of strings")
        lists[name] = tuple(items)
    return GuardrailReasoning(
        verdict=verdict,
        steps=lists["steps"],
        policy_refs=lists["policy_refs"],
        cited_spans=lists["cited_spans"],
    )


def _parse_calibration_case(raw: object) -> ScannerCalibrationCase:
    """Parse one JSONL case object; fail closed (rat #77)."""
    if not isinstance(raw, dict):
        raise TypeError("calibration case must be a JSON object")
    message = raw.get("message")
    if not isinstance(message, dict):
        raise TypeError("calibration case 'message' must be an object")
    label = raw.get("label_violation")
    if not isinstance(label, bool):
        raise TypeError("calibration case 'label_violation' must be a bool")
    human = raw.get("human_disposition")
    disposition: Disposition | None = None
    if human is not None:
        if human not in ("allow", "escalate", "block"):
            raise ValueError(
                "calibration case 'human_disposition' must be allow, escalate, or block"
            )
        disposition = Disposition(human)
    is_jailbreak = raw.get("is_jailbreak", False)
    if not isinstance(is_jailbreak, bool):
        raise TypeError("calibration case 'is_jailbreak' must be a bool")
    reasoning = (
        _parse_calibration_reasoning(raw["reasoning"]) if raw.get("reasoning") is not None else None
    )
    reasoning_input = raw.get("reasoning_input", "")
    if not isinstance(reasoning_input, str):
        raise TypeError("calibration case 'reasoning_input' must be a string")
    known = raw.get("known_policy_ids", [])
    if (
        isinstance(known, str)
        or not isinstance(known, list)
        or not all(isinstance(item, str) for item in known)
    ):
        raise TypeError("calibration case 'known_policy_ids' must be a list of strings")
    return ScannerCalibrationCase(
        message=message,
        label_violation=label,
        human_disposition=disposition,
        is_jailbreak=is_jailbreak,
        reasoning=reasoning,
        reasoning_input=reasoning_input,
        known_policy_ids=tuple(known),
    )


def _parse_float_list(raw: str, flag: str) -> tuple[float, ...]:
    """Parse a comma-separated float list from a CLI flag; fail closed."""
    values: list[float] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"{flag} must be a comma-separated list of numbers")
        try:
            values.append(float(part))
        except ValueError as exc:
            raise ValueError(f"{flag} must be a comma-separated list of numbers") from exc
    if not values:
        raise ValueError(f"{flag} must list at least one number")
    return tuple(values)


def _calibration_number(data: dict[str, object], name: str) -> float:
    raw = data.get(name)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise TypeError(f"calibration baseline '{name}' must be a number")
    return float(raw)


def _calibration_optional_number(data: dict[str, object], name: str) -> float | None:
    raw = data.get(name)
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise TypeError(f"calibration baseline '{name}' must be a number or null")
    return float(raw)


def _calibration_int(data: dict[str, object], name: str) -> int:
    raw = data.get(name)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise TypeError(f"calibration baseline '{name}' must be an integer")
    return raw


def _calibration_report_from_dict(data: dict[str, object]) -> CalibrationReport:
    """Rebuild a report from a previous ``calibration`` JSON output.

    Only the numbers :func:`compare_calibration` reads are load-bearing
    for the drift diff, but the whole report is rebuilt and validated so
    a truncated or hand-edited baseline fails closed instead of diffing
    against invented numbers.
    """
    reasoning_data = data.get("reasoning")
    if not isinstance(reasoning_data, dict):
        raise TypeError("calibration baseline 'reasoning' must be an object")
    summary = ReasoningAlignmentSummary(
        cases=_calibration_int(reasoning_data, "cases"),
        defects=_calibration_int(reasoning_data, "defects"),
        defect_rate=_calibration_optional_number(reasoning_data, "defect_rate"),
        hallucinated_spans=_calibration_int(reasoning_data, "hallucinated_spans"),
        cited_spans=_calibration_int(reasoning_data, "cited_spans"),
        hallucination_frequency=_calibration_optional_number(
            reasoning_data, "hallucination_frequency"
        ),
    )
    return CalibrationReport(
        cases=_calibration_int(data, "cases"),
        bins=_calibration_int(data, "bins"),
        ece=_calibration_number(data, "ece"),
        brier=_calibration_number(data, "brier"),
        confidence_ece=_calibration_number(data, "confidence_ece"),
        confidence_brier=_calibration_number(data, "confidence_brier"),
        allow_count=_calibration_int(data, "allow_count"),
        escalate_count=_calibration_int(data, "escalate_count"),
        block_count=_calibration_int(data, "block_count"),
        escalation_precision=_calibration_optional_number(data, "escalation_precision"),
        escalation_recall=_calibration_optional_number(data, "escalation_recall"),
        allow_miss_rate=_calibration_optional_number(data, "allow_miss_rate"),
        human_agreement_rate=_calibration_optional_number(data, "human_agreement_rate"),
        latency_ms_mean=_calibration_optional_number(data, "latency_ms_mean"),
        latency_ms_p95=_calibration_optional_number(data, "latency_ms_p95"),
        jailbreak_resistance=_calibration_optional_number(data, "jailbreak_resistance"),
        containment_effectiveness=_calibration_optional_number(data, "containment_effectiveness"),
        reasoning=summary,
    )


def _run_calibration(args: argparse.Namespace) -> None:
    """Run the real scanner over a labeled-cases file; print the report (rat #77).

    One timed scan pass per case feeds both the report and the
    threshold sweep from the same labeled cases — the sweep re-gates
    the same (score, confidence) pairs under each candidate, so the
    numbers are one measurement, not two. Prints one JSON object
    (``cases`` = the report, ``threshold_sweep``, ``policy``,
    ``drift`` when ``--baseline`` is given); exit 0 on a report,
    exit 2 on any input error (unreadable/invalid cases file, policy,
    thresholds, floors, or baseline). A drifted baseline is reported
    in the JSON, never as an exit code: drift is a finding, not a
    broken input.
    """
    try:
        lines = Path(args.cases).read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.error("Cannot load calibration cases %s: %s", args.cases, e)
        sys.exit(2)
    cases: list[ScannerCalibrationCase] = []
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            raw: object = json.loads(line)
        except json.JSONDecodeError as e:
            logger.error("Calibration cases %s line %d: invalid JSON: %s", args.cases, lineno, e)
            sys.exit(2)
        try:
            cases.append(_parse_calibration_case(raw))
        except (TypeError, ValueError) as e:
            logger.error("Calibration cases %s line %d: %s", args.cases, lineno, e)
            sys.exit(2)
    if not cases:
        logger.error("Calibration cases %s: no cases", args.cases)
        sys.exit(2)
    policy = CalibrationPolicy()
    hitl_threshold = 0.40
    block_threshold = 0.80
    if args.policy is not None:
        try:
            policy_data = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Cannot load gateway policy %s: %s", args.policy, e)
            sys.exit(2)
        if not isinstance(policy_data, dict):
            logger.error("Gateway policy must be a JSON object")
            sys.exit(2)
        try:
            gateway_policy = GatewayPolicy.from_mapping(policy_data)
        except (TypeError, ValueError) as e:
            logger.error("Invalid gateway policy: %s", e)
            sys.exit(2)
        policy = gateway_policy.calibration
        hitl_threshold = gateway_policy.inbound_scan.hitl_threshold
        block_threshold = gateway_policy.inbound_scan.block_threshold
    try:
        thresholds = _parse_float_list(
            args.thresholds if args.thresholds is not None else "0.70,0.80,0.90",
            "--thresholds",
        )
        floors = _parse_float_list(args.floors, "--floors") if args.floors is not None else None
    except ValueError as e:
        logger.error("Invalid calibration sweep: %s", e)
        sys.exit(2)
    known_ids = (
        tuple(part.strip() for part in args.known_policy_ids.split(",") if part.strip())
        if args.known_policy_ids is not None
        else tuple(rule.rule_id for rule in DEFAULT_RULES)
    )
    scanner = InboundScanner(
        hitl_threshold=hitl_threshold,
        block_threshold=block_threshold,
        calibration_policy=policy,
    )
    labeled: list[CalibrationCase] = []
    for case in cases:
        started = time.perf_counter()
        decision = scanner.scan_message(case.message)
        latency_ms = (time.perf_counter() - started) * 1000.0
        content = case.message.get("content")
        labeled.append(
            CalibrationCase(
                score=decision.score,
                confidence=decision.confidence,
                label_violation=case.label_violation,
                human_disposition=case.human_disposition,
                latency_ms=latency_ms,
                is_jailbreak=case.is_jailbreak,
                reasoning=(
                    decision.reasoning if decision.reasoning is not None else case.reasoning
                ),
                reasoning_input=(
                    case.reasoning_input
                    if case.reasoning_input
                    else (content if isinstance(content, str) else "")
                ),
                known_policy_ids=(case.known_policy_ids if case.known_policy_ids else known_ids),
                disposition=decision.calibrated_disposition,
            )
        )
    try:
        report = evaluate_calibration(labeled, policy)
        sweep = threshold_sensitivity(labeled, thresholds, policy, floors)
    except (TypeError, ValueError) as e:
        logger.error("Calibration eval failed: %s", e)
        sys.exit(2)
    output: dict[str, object] = {
        "cases": report.to_dict(),
        "threshold_sweep": [row.to_dict() for row in sweep],
        "policy": {
            "hitl_threshold": policy.hitl_threshold,
            "block_threshold": policy.block_threshold,
            "min_block_confidence": policy.min_block_confidence,
        },
    }
    if args.baseline is not None:
        try:
            baseline_data: object = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Cannot load calibration baseline %s: %s", args.baseline, e)
            sys.exit(2)
        if not isinstance(baseline_data, dict):
            logger.error("Calibration baseline must be a JSON object")
            sys.exit(2)
        baseline_report_data = baseline_data.get("cases", baseline_data)
        if not isinstance(baseline_report_data, dict):
            logger.error("Calibration baseline has no calibration report")
            sys.exit(2)
        try:
            baseline = _calibration_report_from_dict(baseline_report_data)
            drift = compare_calibration(baseline, report)
        except (TypeError, ValueError, KeyError) as e:
            logger.error("Invalid calibration baseline %s: %s", args.baseline, e)
            sys.exit(2)
        output["drift"] = drift.to_dict()
    print(json.dumps(output))


def _run_scan(args: argparse.Namespace) -> None:
    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        logger.error("Error: specify MCP server command after --")
        sys.exit(1)

    try:
        with StdioTransport(cmd) as transport:
            tools = transport.list_tools()
            if not tools:
                logger.warning("No tools found.")
                return

            scanner = Scanner()
            logger.info("Static scan of %d tools:", len(tools))
            for tool in tools:
                name = tool.get("name", "unknown")
                results = scanner.scan_tool(tool)
                if results:
                    for r in results:
                        logger.info("  [%s] %s: %s", r.severity.value.upper(), name, r.message)
                else:
                    logger.info("  [PASS] %s", name)
    except Exception as e:  # noqa: BLE001
        logger.error("Error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
