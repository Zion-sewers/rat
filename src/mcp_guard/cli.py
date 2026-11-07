"""CLI entry point for mcp-guard adversarial fuzzer."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import sys
from pathlib import Path

from .delegation import (
    CommandVerifier,
    ContractRejectedError,
    DelegationContract,
    DelegationError,
    DelegationResult,
    DelegationRunner,
    DelegationState,
    FrontmatterParseError,
    LoopGuard,
    LoopRefusedError,
    TaskKind,
    sanitize_delegation_id,
)
from .fuzzer import FuzzEngine
from .gateway import Gateway, GatewayPolicy, TrustDeniedError, TrustLevel
from .report import FuzzReport
from .scanner import Scanner
from .transport import StdioTransport

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
    # {"tool": ..., "arguments": {...}, "caller_trust": "low"|"medium"|"high"}.
    gateway_parser = sub.add_parser(
        "gateway", help="Proxy MCP calls through the trust/tokenization gateway"
    )
    gateway_parser.add_argument(
        "--policy",
        required=True,
        help='JSON policy file: {"tools": {name: level}, "default_trust": level}',
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
        "--verify-command",
        help="Senior verifier command (exit 0 approves); without it the result stays pending",
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


def _handle_gateway_line(gateway: Gateway, line: str) -> None:
    """Route one stdin JSON request through the gateway; print one JSON line.

    Malformed requests print an {"error": ...} line and never kill the
    session; a denied call prints {"denied": true, ...} with the audit
    delta, never the raw request.
    """
    before = len(gateway.audit_log)
    try:
        request = json.loads(line)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"invalid JSON: {e}"}))
        return
    if not isinstance(request, dict):
        print(json.dumps({"error": "gateway request must be a JSON object"}))
        return
    tool = request.get("tool")
    if not isinstance(tool, str):
        print(json.dumps({"error": "gateway request needs a string 'tool'"}))
        return
    arguments = request.get("arguments", {})
    if not isinstance(arguments, dict):
        print(json.dumps({"error": "gateway request 'arguments' must be an object", "tool": tool}))
        return
    caller_raw = request.get("caller_trust", "low")
    if not isinstance(caller_raw, str):
        print(
            json.dumps({"error": "gateway request 'caller_trust' must be a string", "tool": tool})
        )
        return
    try:
        caller_trust = TrustLevel.parse(caller_raw)
    except ValueError as e:
        print(json.dumps({"error": str(e), "tool": tool}))
        return
    try:
        result = gateway.call_tool(tool, arguments, caller_trust)
    except TrustDeniedError as e:
        print(
            json.dumps(
                {
                    "tool": tool,
                    "denied": True,
                    "reason": str(e),
                    "audit": gateway.audit_log.to_json()[before:],
                }
            )
        )
        return
    print(
        json.dumps({"tool": tool, "result": result, "audit": gateway.audit_log.to_json()[before:]})
    )


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

    cmd = [a for a in args.server_command if a != "--"]
    if not cmd:
        logger.error("Error: specify MCP server command after --")
        sys.exit(1)

    try:
        with StdioTransport(cmd) as transport:
            gateway = Gateway(transport, policy)
            tools = transport.list_tools()
            print(json.dumps({"tools": gateway.annotate_tools(tools)}))
            for line in sys.stdin:
                if line.strip():
                    _handle_gateway_line(gateway, line.strip())
            print(json.dumps({"event": "gateway_closed", "audit": gateway.audit_log.to_json()}))
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
        resolve_verifier = CommandVerifier(args.verify_command)
        try:
            result = runner.resolve_pending(delegation_id, resolve_verifier, repo_dir=repo_dir)
        except (LoopRefusedError, DelegationError, OSError) as e:
            logger.error("Resolve refused: %s", e)
            sys.exit(1)
        _emit_delegate_result(result, resolve_verifier, delegation_id)
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

    verifier = CommandVerifier(args.verify_command) if args.verify_command else None
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
        result = runner.delegate(
            contract=contract,
            delegation_id=delegation_id,
            task=TaskKind(args.task),
            prompt=prompt,
            repo_dir=repo_dir,
            verifier=verifier,
        )
    except (FrontmatterParseError, ContractRejectedError, LoopRefusedError, DelegationError) as e:
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

    _emit_delegate_result(result, verifier, delegation_id)


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
