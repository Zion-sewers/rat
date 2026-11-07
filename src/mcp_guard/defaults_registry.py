"""Defaults registry for mcp-guard (issue #96).

Every implicit default in the codebase — CLI defaults, dict fallbacks,
function-signature defaults, except-path fallbacks — is declared here with
its rationale. The registry IS the documentation; there is no separate prose
list that can drift.

Enforced by tests/test_defaults_registry.py, which scans src/mcp_guard via
AST and asserts:
  1. coverage: every default-like construct found in code is registered;
  2. no orphans: every registry entry still exists in code;
  3. value match: registered values match the code (flipping a default
     without updating its registry entry — rationale included — fails CI).

Key derivation (stable, no line numbers):
  cli:{receiver}:{flag}       e.g. cli:fuzz_parser:--format
  {module}:{scope}:{key}      e.g. fuzzer:FuzzEngine.fuzz_tool:name
  {module}:{scope}:param:{a}  e.g. transport:StdioTransport.__init__:param:timeout
  {module}:{scope}:except:{E} e.g. cli:_run_fuzz:except:ConnectionError
where scope is func or Class.method. Non-constant .get keys use ~unparsed-expr.
See the test module for the exact rules and deliberate scope decisions.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Default:
    """A single declared default."""

    id: str  # stable key (see module docstring)
    kind: str  # cli-default | dict-fallback | param-default | except-path
    value: str  # the default as written in code (repr for constants)
    rationale: str  # why this default exists; reviewed, never silent
    location: str  # file, for humans (not used for matching)


DEFAULTS: list[Default] = [
    # --- cli.py: argparse defaults -------------------------------------
    Default(
        id="cli:fuzz_parser:--format",
        kind="cli-default",
        value="'table'",
        rationale=(
            "Human-readable table is the operator-facing default; machine "
            "formats (json/sarif) are opt-in so casual runs don't dump "
            "unparsed JSON."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:fuzz_parser:--delay-ms",
        kind="cli-default",
        value="0",
        rationale=(
            "No artificial delay by default: maximum fuzzing throughput. "
            "Operators add delay only to avoid overwhelming fragile servers."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:fuzz_parser:--timeout",
        kind="cli-default",
        value="10.0",
        rationale=(
            "10s per tool call: generous enough for slow MCP servers, short "
            "enough that a hung server doesn't stall a whole campaign. Mirrors "
            "StdioTransport's default timeout."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:fuzz_parser:--allow-empty-error-responses",
        kind="cli-default",
        value="False",
        rationale=(
            "store_true: the Twyman audit fires on empty error responses by "
            "default. Only an operator who knows the server is a terse "
            "validator opts out, and the override is recorded in the report."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:fuzz_parser:--allow-identical-error-responses",
        kind="cli-default",
        value="False",
        rationale=(
            "store_true: the Twyman audit fires on identical error responses "
            "by default. Only an operator who knows the server is a strict "
            "validator opts out, and the override is recorded in the report."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:scan_parser:--format",
        kind="cli-default",
        value="'table'",
        rationale="Same as fuzz --format: human-readable unless asked otherwise.",
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:parser:--verbose",
        kind="cli-default",
        value="False",
        rationale=(
            "store_true: INFO logging by default; DEBUG is opt-in so normal "
            "runs aren't drowned in transport chatter."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:parser:--quiet",
        kind="cli-default",
        value="False",
        rationale=(
            "store_true: errors visible by default; --quiet suppresses "
            "everything below ERROR only when the operator asks."
        ),
        location="src/mcp_guard/cli.py",
    ),
    # --- cli.py: dict fallbacks ----------------------------------------
    Default(
        id="cli:_run_fuzz:name",
        kind="dict-fallback",
        value="'unknown'",
        rationale=(
            "A tool without a name still gets fuzzed; 'unknown' keeps logs "
            "greppable instead of crashing on schema-less servers."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_scan:name",
        kind="dict-fallback",
        value="'unknown'",
        rationale="Same as _run_fuzz: nameless tools are scanned, not skipped.",
        location="src/mcp_guard/cli.py",
    ),
    # --- cli.py: except paths ------------------------------------------
    Default(
        id="cli:_run_fuzz:except:ConnectionError",
        kind="except-path",
        value="ConnectionError",
        rationale=(
            "Transport failure is fatal to the run but not a crash: clean "
            "error message + exit 1, never an unhandled traceback."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_fuzz:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "Last-resort guard: any unexpected failure exits 1 with a logged "
            "error, never an unhandled traceback to the operator."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_scan:except:Exception",
        kind="except-path",
        value="Exception",
        rationale="Same as _run_fuzz: unexpected failure exits 1, logged.",
        location="src/mcp_guard/cli.py",
    ),
    # --- fuzzer.py ------------------------------------------------------
    Default(
        id="fuzzer:FuzzEngine.__init__:param:delay_ms",
        kind="param-default",
        value="0",
        rationale=(
            "Matches CLI --delay-ms default; programmatic users get full "
            "speed unless they ask for pacing."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine.fuzz_tool:name",
        kind="dict-fallback",
        value="'unknown'",
        rationale="Unnamed tools are still fuzzed; results stay attributable.",
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine.fuzz_tool:inputSchema",
        kind="dict-fallback",
        value="{}",
        rationale=(
            "Missing schema routes to the schema-less fuzzing path "
            "(_fuzz_no_schema), never a KeyError. Absence of schema is "
            "itself a finding surface."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine.fuzz_tool:properties",
        kind="dict-fallback",
        value="{}",
        rationale=(
            "Schema without properties behaves like no schema; avoids crashing on partial schemas."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine.fuzz_tool:required",
        kind="dict-fallback",
        value="[]",
        rationale=(
            "No required list means no required params; payloads still fire "
            "against every declared property."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine._fire_payload:except:ConnectionError",
        kind="except-path",
        value="ConnectionError",
        rationale=(
            "Connection lost mid-payload is the strongest crash signal: the "
            "server died handling attacker input. Recorded as CRASH, never "
            "as ERROR."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine._fire_payload:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "Unexpected local failure is an ERROR (our harness broke), never "
            "silently swallowed and never mislabeled as a server crash."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine._classify_response:isError",
        kind="dict-fallback",
        value="False",
        rationale=(
            "A response without isError is treated as success; the content "
            "classifiers then decide. Fail-open on the flag, fail-closed on "
            "the content."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine._classify_response:content",
        kind="dict-fallback",
        value="[]",
        rationale=(
            "Missing content means empty text for classifiers; a missing "
            "field is not itself a finding."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    Default(
        id="fuzzer:FuzzEngine._classify_response:text",
        kind="dict-fallback",
        value="''",
        rationale=(
            "Non-text blocks contribute nothing to reflection checks; empty "
            "string keeps the join total."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    # --- canary.py ------------------------------------------------------
    Default(
        id="canary:CanaryTrap.__init__:param:token_factory",
        kind="param-default",
        value="_default_token_factory",
        rationale=(
            "Deterministic default token factory keeps canary tests "
            "reproducible; operators inject their own factory for production "
            "uniqueness."
        ),
        location="src/mcp_guard/canary.py",
    ),
    Default(
        id="canary:CanaryTrap.smuggle_tool_result:content",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Result without content has nothing to mark; returned unchanged instead of crashing."
        ),
        location="src/mcp_guard/canary.py",
    ),
    Default(
        id="canary:CanaryTrap.smuggle_tool_result:type",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A block without a type is never treated as text; non-text "
            "blocks pass through unmarked."
        ),
        location="src/mcp_guard/canary.py",
    ),
    Default(
        id="canary:CanaryTrap.smuggle_tool_result:text",
        kind="dict-fallback",
        value="''",
        rationale=(
            "A text block without text still gets its canary bound to the "
            "block; empty string smuggles cleanly."
        ),
        location="src/mcp_guard/canary.py",
    ),
    # --- payloads.py ----------------------------------------------------
    Default(
        id="payloads:generate_type_confusion:param:param_type",
        kind="param-default",
        value="'string'",
        rationale=(
            "MCP schemas overwhelmingly use string params; the default "
            "targets the common case, callers override per schema."
        ),
        location="src/mcp_guard/payloads.py",
    ),
    Default(
        id="payloads:generate_all_for_param:type",
        kind="dict-fallback",
        value="'string'",
        rationale=(
            "A param without a declared type is treated as string — the "
            "most attackable surface — never skipped."
        ),
        location="src/mcp_guard/payloads.py",
    ),
    Default(
        id="payloads:generate_all_for_param:format",
        kind="dict-fallback",
        value="''",
        rationale=(
            "No format means no format-specific payloads; empty string is "
            "the neutral 'no constraint' marker."
        ),
        location="src/mcp_guard/payloads.py",
    ),
    # --- report.py ------------------------------------------------------
    Default(
        id="report:twyman_audit:param:allow_empty_error_responses",
        kind="param-default",
        value="False",
        rationale=(
            "The Twyman audit fires on empty error responses unless the "
            "operator explicitly overrides it for a known terse validator; "
            "the default keeps the audit fail-closed."
        ),
        location="src/mcp_guard/report.py",
    ),
    Default(
        id="report:twyman_audit:param:allow_identical_error_responses",
        kind="param-default",
        value="False",
        rationale=(
            "The Twyman audit fires on identical error responses unless the "
            "operator explicitly overrides it for a known strict validator; "
            "the default keeps the audit fail-closed."
        ),
        location="src/mcp_guard/report.py",
    ),
    Default(
        id="report:FuzzReport._severity_counts:~r.severity",
        kind="dict-fallback",
        value="0",
        rationale=(
            "First occurrence of a severity starts its count at zero; "
            "standard counter idiom, no severity pre-seeded."
        ),
        location="src/mcp_guard/report.py",
    ),
    Default(
        id="report:scanner_version:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "Version metadata absent in a bare checkout falls back to "
            "'unknown' instead of crashing the report."
        ),
        location="src/mcp_guard/report.py",
    ),
    # --- scanner.py -----------------------------------------------------
    Default(
        id="scanner:Scanner.scan_tool:name",
        kind="dict-fallback",
        value="''",
        rationale=(
            "Lowercased empty name matches nothing; a nameless tool still gets its schema scanned."
        ),
        location="src/mcp_guard/scanner.py",
    ),
    Default(
        id="scanner:Scanner.scan_tool:description",
        kind="dict-fallback",
        value="''",
        rationale=(
            "Missing description means no description-based checks fire; "
            "absence of description is not itself a finding."
        ),
        location="src/mcp_guard/scanner.py",
    ),
    Default(
        id="scanner:Scanner.scan_tool:inputSchema",
        kind="dict-fallback",
        value="{}",
        rationale=(
            "Missing schema routes to the dedicated _check_missing_schema; "
            "the empty dict is a signal, not a crash."
        ),
        location="src/mcp_guard/scanner.py",
    ),
    Default(
        id="scanner:Scanner.scan_tool:properties",
        kind="dict-fallback",
        value="{}",
        rationale=(
            "Schema without properties means no per-param checks; same "
            "graceful degradation as a missing schema."
        ),
        location="src/mcp_guard/scanner.py",
    ),
    Default(
        id="scanner:Scanner._check_shell_injection:description",
        kind="dict-fallback",
        value="''",
        rationale=(
            "A param without description gets no description-based "
            "shell-injection heuristics; the check still runs on name/type."
        ),
        location="src/mcp_guard/scanner.py",
    ),
    Default(
        id="scanner:Scanner._check_ssrf:description",
        kind="dict-fallback",
        value="''",
        rationale=(
            "Description heuristics are opt-in by presence, never assumed; "
            "missing description simply skips them."
        ),
        location="src/mcp_guard/scanner.py",
    ),
    Default(
        id="scanner:Scanner._check_ssrf:format",
        kind="dict-fallback",
        value="''",
        rationale=(
            "A param without format skips format-specific SSRF heuristics "
            "(e.g. uri-format special-casing)."
        ),
        location="src/mcp_guard/scanner.py",
    ),
    # --- transport.py ---------------------------------------------------
    Default(
        id="transport:StdioTransport.__init__:param:timeout",
        kind="param-default",
        value="10.0",
        rationale=(
            "Matches CLI --timeout default: 10s per JSON-RPC round trip, "
            "consistent across CLI and programmatic use."
        ),
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport.stop:except:subprocess.TimeoutExpired",
        kind="except-path",
        value="subprocess.TimeoutExpired",
        rationale=(
            "A server that won't terminate within 5s gets killed; the "
            "timeout is the escalation policy, not a failure."
        ),
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport._read_line:except:(OSError, ValueError)",
        kind="except-path",
        value="(OSError, ValueError)",
        rationale=(
            "Stream closed or torn down mid-read is an expected shutdown "
            "race, not an error: the read loop ends cleanly with None."
        ),
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport._read_response:except:json.JSONDecodeError",
        kind="except-path",
        value="json.JSONDecodeError",
        rationale=(
            "Non-JSON on stdout is a protocol violation by the server; "
            "surfaced as a structured ConnectionError, never a raw traceback."
        ),
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport._read_response:result",
        kind="dict-fallback",
        value="{}",
        rationale=(
            "A JSON-RPC response without a result field yields an empty "
            "dict; callers handle absence explicitly."
        ),
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport.list_tools:tools",
        kind="dict-fallback",
        value="[]",
        rationale=(
            "A server enumerating zero tools yields an empty list; the CLI "
            "then warns the operator instead of crashing."
        ),
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport.list_resources:resources",
        kind="dict-fallback",
        value="[]",
        rationale="Same graceful degradation as list_tools for resources.",
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport.list_prompts:prompts",
        kind="dict-fallback",
        value="[]",
        rationale="Same graceful degradation as list_tools for prompts.",
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport._read_response:id",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A response without an id leaves the flight recorder's response "
            "id as None: the fuzzer's delivery check then reports UNKNOWN "
            "(correlation unverifiable), never a false DELIVERED."
        ),
        location="src/mcp_guard/transport.py",
    ),
    # --- fuzzer.py: flight-recorder leniency (mcp-guard#65) --------------
    Default(
        id="fuzzer:FuzzEngine._flight_recorder:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "A third-party transport whose recorder raises (or returns a "
            "malformed value) degrades to UNKNOWN delivery, never aborts "
            "the run: a broken recorder is unverifiable delivery, and the "
            "probe becomes INCONCLUSIVE downstream."
        ),
        location="src/mcp_guard/fuzzer.py",
    ),
    # --- delivery.py: flight-recorder fallbacks (mcp-guard#65) -----------
    # Every .get here defaults to None on purpose: a missing field is
    # itself evidence of a broken envelope, and verify_send maps it to
    # UNDELIVERED/UNKNOWN rather than raising — the check must never crash
    # on the malformed input it exists to catch.
    Default(
        id="delivery:_json_equal:except:(TypeError, ValueError, RecursionError)",
        kind="except-path",
        value="(TypeError, ValueError, RecursionError)",
        rationale=(
            "Canonical JSON dumps fail only on non-serializable values, "
            "which cannot occur for JSON-native payloads, and on deeply "
            "nested values; the fallback to `==` keeps the comparison "
            "total instead of raising."
        ),
        location="src/mcp_guard/delivery.py",
    ),
    Default(
        id="delivery:verify_send:arguments",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Envelope without arguments cannot match the intended call: "
            "UNDELIVERED, not a KeyError inside the verification itself."
        ),
        location="src/mcp_guard/delivery.py",
    ),
    Default(
        id="delivery:verify_send:id",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Envelope without a request id cannot be correlated with the "
            "response; the check falls through to the id comparison, which "
            "treats a missing id as UNKNOWN."
        ),
        location="src/mcp_guard/delivery.py",
    ),
    Default(
        id="delivery:verify_send:jsonrpc",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Envelope without a JSON-RPC version is not a well-formed call: "
            "UNDELIVERED, so a stray dict from another protocol can never "
            "verify as a delivered fault."
        ),
        location="src/mcp_guard/delivery.py",
    ),
    Default(
        id="delivery:verify_send:method",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Envelope without a method is not a tools/call send: UNDELIVERED, "
            "so a handshake or list envelope can never masquerade as a fired payload."
        ),
        location="src/mcp_guard/delivery.py",
    ),
    Default(
        id="delivery:verify_send:name",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Envelope without a tool name cannot match the intended tool: "
            "UNDELIVERED, not a crash in the verifier."
        ),
        location="src/mcp_guard/delivery.py",
    ),
    Default(
        id="delivery:verify_send:params",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Envelope without params is not a well-formed call: UNDELIVERED. "
            "A missing params object is a broken envelope, not a delivered fault."
        ),
        location="src/mcp_guard/delivery.py",
    ),
]

BY_ID: dict[str, Default] = {d.id: d for d in DEFAULTS}

# Fail-fast duplicate-id guard. A plain raise (not assert) so the bandit
# security gate does not flag B101: this invariant must hold even under -O.
if len(BY_ID) != len(DEFAULTS):
    raise ValueError("duplicate default ids in registry")
