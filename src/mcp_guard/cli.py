"""CLI entry point for mcp-guard adversarial fuzzer."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .fuzzer import FuzzEngine
from .gateway import GatewayPolicy, TrustDeniedError, TrustLevel
from .lifecycle import (
    Lifecycle,
    LifecycleError,
    ServerRegistry,
    ServerSpec,
    TeardownFailedError,
)
from .report import FuzzReport
from .scanner import Scanner
from .transport import JsonDict, StdioTransport

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
        help='JSON policy file: {"tools": {name: level}, "default_trust": level}',
    )
    gateway_parser.add_argument(
        "--servers",
        help=(
            'JSON registry file: {"servers": {name: [command...]}}. '
            "Enables multi-server tasks via stdin control lines; "
            "cannot be combined with a server command after --."
        ),
    )
    gateway_parser.add_argument("server_command", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose, args.quiet)

    if args.command == "fuzz":
        _run_fuzz(args)
    elif args.command == "scan":
        _run_scan(args)
    elif args.command == "gateway":
        _run_gateway(args)
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

    def __init__(self, lifecycle: Lifecycle, default_server: str | None) -> None:
        self.lifecycle = lifecycle
        self.default_server = default_server
        self.task_id: str | None = None
        self.task_counter = 0


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
        handle = session.lifecycle.begin_task(task_id, servers)
    except (LifecycleError, OSError, TimeoutError, RuntimeError) as e:
        print(json.dumps({"error": str(e)}))
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
            print(json.dumps({"error": str(e), "teardown": te.report.to_dict()}))
            return
        session.task_id = None
        print(json.dumps({"error": str(e)}))
        return
    print(json.dumps({"task": "begun", "task_id": task_id, "tools": tools}))


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
                    "task_id": task_id,
                    "error": str(e),
                    "teardown": e.report.to_dict(),
                }
            )
        )
        return
    session.task_id = None
    print(json.dumps({"task": "ended", "task_id": task_id, "teardown": report.to_dict()}))


def _handle_gateway_line(session: _GatewaySession, line: str) -> None:
    """Route one stdin JSON request through the lifecycle's gateway.

    Control lines ({"task": "begin"/"end"}) manage the session's task;
    call lines route one gated tool call. Malformed requests print an
    {"error": ...} line and never kill the session; a denied call prints
    {"denied": true, ...} with the audit delta, never the raw request.
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
            print(json.dumps({"error": f"unknown task command {task_cmd!r}"}))
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
        gw_before = len(session.lifecycle.gateway_audit_log(task_id, server))
    except LifecycleError as e:
        print(
            json.dumps(
                {
                    "tool": tool,
                    "denied": True,
                    "reason": str(e),
                    "lifecycle_audit": session.lifecycle.audit_log.to_json()[lc_before:],
                }
            )
        )
        return
    try:
        result = session.lifecycle.call_tool(task_id, server, tool, arguments, caller_trust)
    except TrustDeniedError as e:
        print(
            json.dumps(
                {
                    "tool": tool,
                    "denied": True,
                    "reason": str(e),
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
                    "tool": tool,
                    "denied": True,
                    "reason": str(e),
                    "lifecycle_audit": session.lifecycle.audit_log.to_json()[lc_before:],
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
        print(json.dumps({"tool": tool, "error": str(e)}))
        return
    print(
        json.dumps(
            {
                "tool": tool,
                "result": result,
                "audit": session.lifecycle.gateway_audit_log(task_id, server).to_json()[gw_before:],
            }
        )
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
        lifecycle = Lifecycle(registry, policy)
        session = _GatewaySession(lifecycle, default_server)
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
                lifecycle.begin_task("session", (default_server,))
            except (LifecycleError, OSError, TimeoutError, RuntimeError) as e:
                startup_error = str(e)
            else:
                session.task_id = "session"
                try:
                    tools = lifecycle.list_tools("session", default_server)
                except (LifecycleError, OSError, TimeoutError, RuntimeError) as e:
                    startup_error = str(e)
                    try:
                        startup_teardown = lifecycle.end_task("session").to_dict()
                    except TeardownFailedError as te:
                        startup_teardown = te.report.to_dict()
                        startup_teardown_failed = True
                    session.task_id = None
                else:
                    print(json.dumps({"tools": tools}))
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
        closing: JsonDict = {
            "event": "gateway_closed",
            "teardown": teardown,
            "lifecycle_audit": lifecycle.audit_log.to_json(),
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
