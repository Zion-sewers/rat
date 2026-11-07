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
    # --- gateway.py (rat #66) ------------------------------------------
    Default(
        id="gateway:Gateway.call_tool:param:caller_trust",
        kind="param-default",
        value="TrustLevel.LOW",
        rationale=(
            "Least privilege: an undeclared caller is LOW, never root. A "
            "low-trust caller can never trigger a high-trust read by "
            "omitting its level."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:Gateway.annotate_tools:name",
        kind="dict-fallback",
        value="'unknown'",
        rationale="Same as _run_fuzz/_run_scan: nameless tools are listed, not skipped.",
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:GatewayAuditLog.record:param:token_kinds",
        kind="param-default",
        value="()",
        rationale="Most audit events involve no PII: empty kinds is the normal case.",
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:GatewayAuditLog.record:param:token_count",
        kind="param-default",
        value="0",
        rationale="Same as token_kinds: zero tokens handled is the normal case.",
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:GatewayPolicy.from_mapping:tools",
        kind="dict-fallback",
        value="{}",
        rationale=(
            "A policy file may omit 'tools' (default-trust-only policy): "
            "every tool then takes the declared default trust."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:GatewayPolicy.from_mapping:default_trust",
        kind="dict-fallback",
        value="'low'",
        rationale=(
            "A policy file may omit 'default_trust': LOW is the fail-closed "
            "default, matching the GatewayPolicy dataclass default."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:GatewayPolicy.from_mapping:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "TrustLevel.parse failures are re-raised with the tool name for "
            "a diagnosable policy error, not swallowed."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:GatewayPolicy.trust_of:~tool_name",
        kind="dict-fallback",
        value="self.default_trust",
        rationale=(
            "Unlisted tools take the policy default (LOW unless declared): "
            "trust is never guessed upward."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:PiiTokenizer._mint:~key",
        kind="dict-fallback",
        value="None",
        rationale=(
            "First sight of a (kind, value) pair mints a fresh token; a "
            "known pair reuses its token so the agent can correlate."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:PiiTokenizer._mint:~kind",
        kind="dict-fallback",
        value="0",
        rationale=(
            "Token counters start at 1 per kind: first token is [KIND_1]. "
            "Counters are monotonic across clear(): a stale token from a "
            "previous session can never rebind to a different value."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    Default(
        id="gateway:TrustLevel.parse:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "An unknown level string is a policy error, not a crash: "
            "re-raised with the valid levels named."
        ),
        location="src/mcp_guard/gateway.py",
    ),
    # --- cli.py: gateway subcommand (rat #66) ---------------------------
    Default(
        id="cli:_handle_gateway_line:tool",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A request without 'tool' is malformed: error line, session "
            "continues. None is the missing-value marker, never a tool name."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:arguments",
        kind="dict-fallback",
        value="{}",
        rationale="A request without 'arguments' is a no-argument call.",
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:caller_trust",
        kind="dict-fallback",
        value="'low'",
        rationale=(
            "A request without 'caller_trust' is LOW (least privilege), "
            "matching Gateway.call_tool's default."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:except:json.JSONDecodeError",
        kind="except-path",
        value="json.JSONDecodeError",
        rationale=(
            "A malformed stdin line is an error line, never a dead session: "
            "the proxy loop keeps serving the next request."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "An unknown caller_trust level is an error line for that request, never a dead session."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:except:TrustDeniedError",
        kind="except-path",
        value="TrustDeniedError",
        rationale=(
            'A denied call is a normal gateway outcome: a {"denied": true} '
            "line with the audit delta, never an exception to the operator."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_gateway:except:(OSError, json.JSONDecodeError)",
        kind="except-path",
        value="(OSError, json.JSONDecodeError)",
        rationale=(
            "An unreadable or unparsable policy file fails closed before "
            "any server starts: exit 1, never a gateway with no policy."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_gateway:except:(TypeError, ValueError)",
        kind="except-path",
        value="(TypeError, ValueError)",
        rationale=(
            "A malformed policy (wrong shape or unknown level) fails closed "
            "before any server starts: exit 1, never a gateway with no policy."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_gateway:except:ConnectionError",
        kind="except-path",
        value="ConnectionError",
        rationale="Same as _run_fuzz: transport failure exits 1, logged.",
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_gateway:except:Exception",
        kind="except-path",
        value="Exception",
        rationale="Same as _run_fuzz: unexpected failure exits 1, logged.",
        location="src/mcp_guard/cli.py",
    ),
    # --- lifecycle.py (rat #68) --------------------------------------------
    Default(
        id="lifecycle:Lifecycle.call_tool:param:caller_trust",
        kind="param-default",
        value="TrustLevel.LOW",
        rationale=(
            "Same as Gateway.call_tool: an undeclared caller is LOW (least "
            "privilege, never root); trust is never guessed upward."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle._bound:~task_id",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Task lookup has no default: an unknown task id raises TaskError "
            "(fail-closed) instead of routing to a task that does not exist."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle._bound:~server_name",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Server lookup has no default: a server the task did not enable "
            "raises ServerNotEnabledError and audits SERVER_DENIED."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle._bound:param:record_denial",
        kind="param-default",
        value="True",
        rationale=(
            "A denied lookup audits SERVER_DENIED by default; read-only "
            "lookups (the audit log view) pass False so reading a log never "
            "appends a denial event of its own."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle.enabled_servers:~task_id",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Task lookup has no default: an unknown task id raises TaskError "
            "instead of reporting the servers of a task that does not exist."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle.end_task:~task_id",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Task lookup has no default: ending an unknown task raises "
            "TaskError instead of silently reporting a teardown that never ran."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle.begin_task:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "Any start failure rolls back already-started servers and "
            "re-raises: the blind catch exists only to run the rollback, "
            "never to swallow the failure."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle.end_task:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "A raising stop() counts as a failed teardown (recorded in the "
            "report, task stays live for retry), never a crash of the run."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:Lifecycle._rollback_stop:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "A rollback stop that raises (or leaves the server alive) is "
            "logged with the pid and never masks the begin failure: the "
            "blind catch exists only to run the rollback, the original "
            "error still wins."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    Default(
        id="lifecycle:ServerRegistry.from_mapping:servers",
        kind="dict-fallback",
        value="{}",
        rationale=(
            "Same as GatewayPolicy's tools default: a registry file without "
            "'servers' names zero servers, so begin_task refuses every name "
            "as unknown instead of enabling something unlisted."
        ),
        location="src/mcp_guard/lifecycle.py",
    ),
    # --- cli.py: gateway lifecycle (rat #68) --------------------------------
    Default(
        id="cli:_handle_gateway_begin:servers",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A begin line without 'servers' is an error line, never an "
            "implicit enable-all: narrow enablement needs the names."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_begin:task_id",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A missing task_id mints task-N in the body; None means absent, "
            "the real fallback lives there, not in a silent default id."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_begin:except:(LifecycleError, OSError, TimeoutError, RuntimeError)",
        kind="except-path",
        value="(LifecycleError, OSError, TimeoutError, RuntimeError)",
        rationale=(
            "A failed begin is an error line for that request, never a dead "
            "session: the operator can retry with different servers. The "
            "tuple covers lifecycle refusals and every transport-level "
            "begin failure (dead server, hung handshake, error envelope, "
            "spawn failure and broken pipe, which arrive as OSError)."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_begin:except:TeardownFailedError",
        kind="except-path",
        value="TeardownFailedError",
        rationale=(
            "When a begin fails after listing tools, the rollback teardown "
            "may itself fail: the error line carries the teardown report "
            "and the task stays live so the operator can retry the end."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_end:except:TeardownFailedError",
        kind="except-path",
        value="TeardownFailedError",
        rationale=(
            "A failed end is an end_failed line carrying the report; the "
            "task stays live so the operator can retry the teardown."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:server",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A call line without 'server' falls back to the session default "
            "server (single-server mode) or an error line (multi-server "
            "mode); None means absent, never an implicit server."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:task",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A request without 'task' is a call line, not a control line: "
            "the absence selects the call path, nothing else."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:except:LifecycleError",
        kind="except-path",
        value="LifecycleError",
        rationale=(
            "A lifecycle refusal (unknown task, server not enabled) is a "
            "denied line with the audit delta, never an exception to the operator."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:except:(OSError, TimeoutError, RuntimeError)",
        kind="except-path",
        value="(OSError, TimeoutError, RuntimeError)",
        rationale=(
            "A transport-level call failure (server error envelope, dead "
            "server, hung call, broken pipe on the write path, which "
            "arrives as OSError) is an error line for that request, never "
            "a dead session: the operator's next lines still run and EOF "
            "still tears the task down with verified teardown."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_gateway:except:TeardownFailedError",
        kind="except-path",
        value="TeardownFailedError",
        rationale=(
            "A failed teardown at EOF prints the closing line with the "
            "failed report and exits 1, never 0: a session that could not "
            "verify its servers dead must not read as clean."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_gateway:except:(LifecycleError, OSError, TimeoutError, RuntimeError)",
        kind="except-path",
        value="(LifecycleError, OSError, TimeoutError, RuntimeError)",
        rationale=(
            "A single-server session that fails before its first line "
            "(begin or tools/list) still prints the gateway_closed line "
            "carrying the error and the rolled-back teardown report, and "
            "exits 1 — the operator always gets a machine-readable close "
            "instead of an empty stdout."
        ),
        location="src/mcp_guard/cli.py",
    ),
]

BY_ID: dict[str, Default] = {d.id: d for d in DEFAULTS}

# Fail-fast duplicate-id guard. A plain raise (not assert) so the bandit
# security gate does not flag B101: this invariant must hold even under -O.
if len(BY_ID) != len(DEFAULTS):
    raise ValueError("duplicate default ids in registry")
