"""CLI entry point for mcp-guard adversarial fuzzer."""

from __future__ import annotations

import argparse
import json
import logging
import shlex
import sys
from pathlib import Path

from .delegation import (
    CommandVerifier,
    ContractRejectedError,
    DelegationError,
    DelegationRunner,
    DelegationState,
    FrontmatterParseError,
    LoopGuard,
    LoopRefusedError,
    TaskKind,
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


def main(argv: list[str] | None = None) -> None:
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
        required=True,
        help="Agent Markdown file carrying the delegation contract in frontmatter",
    )
    delegate_parser.add_argument(
        "--task",
        required=True,
        choices=[kind.value for kind in TaskKind],
        help="Task kind (routing matrix: trigger, effort, verification step)",
    )
    delegate_parser.add_argument(
        "--prompt-file",
        required=True,
        help="File holding the task prompt (scrubbed before the junior sees it)",
    )
    delegate_parser.add_argument(
        "--verify-command",
        help="Senior verifier command (exit 0 approves); without it the result stays pending",
    )
    delegate_parser.add_argument(
        "--lock-dir",
        default=".mcp-guard-delegation",
        help="Directory for lock files and the audit log",
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
    delegate_parser.add_argument("junior_command", nargs=argparse.REMAINDER)

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


def _run_delegate(args: argparse.Namespace) -> None:
    try:
        contract_text = Path(args.contract).read_text(encoding="utf-8")
        prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    except OSError as e:
        logger.error("Cannot read input file: %s", e)
        sys.exit(1)

    cmd = [a for a in args.junior_command if a != "--"]
    if not cmd:
        logger.error("Error: specify junior command after --")
        sys.exit(1)

    verifier = CommandVerifier(shlex.split(args.verify_command)) if args.verify_command else None
    lock_dir = Path(args.lock_dir)
    runner = DelegationRunner(
        lock_dir,
        junior_timeout=args.timeout,
        loop_guard=LoopGuard(
            lock_dir,
            max_delegations=args.max_delegations,
            window_seconds=args.window_seconds,
        ),
        verifier=verifier,
    )
    try:
        result = runner.delegate(
            contract_text=contract_text,
            task_kind=TaskKind(args.task),
            prompt=prompt,
            delegation_id=f"{Path(args.contract).stem}-{args.task}",
            junior_command=cmd,
            repo_dir=Path.cwd(),
        )
    except (FrontmatterParseError, ContractRejectedError, LoopRefusedError, DelegationError) as e:
        logger.error("Delegation refused: %s", e)
        sys.exit(1)

    print(json.dumps(result.to_summary()))
    if result.state is DelegationState.PENDING_VERIFICATION:
        logger.error(
            "Result is PENDING_VERIFICATION: no senior verifier approved it; "
            "do not act on it until one does."
        )
        sys.exit(2)
    if result.state is DelegationState.COMPLETE:
        return
    logger.error("Delegation ended in state %s", result.state.value)
    sys.exit(1)


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
