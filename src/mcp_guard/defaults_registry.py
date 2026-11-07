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
Plain module constants (e.g. _DEFAULT_MAX_TURNS, _DEFAULT_MAX_DEPTH) are
NOT tracked: the scan covers only the four construct kinds above, so a
constant that no signature, .get, except path, or argparse default reads
needs no entry.
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
        rationale=(
            "A missing 'resources' key yields an empty list; a malformed "
            "value fails closed as ConnectionError, same as list_tools."
        ),
        location="src/mcp_guard/transport.py",
    ),
    Default(
        id="transport:StdioTransport.list_prompts:prompts",
        kind="dict-fallback",
        value="[]",
        rationale=(
            "A missing 'prompts' key yields an empty list; a malformed "
            "value fails closed as ConnectionError, same as list_tools."
        ),
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
        id="gateway:Gateway.call_tool:param:input_trust",
        kind="param-default",
        value="InputTrust.UNTRUSTED",
        rationale=(
            "Fail-closed provenance: input whose origin the caller does not "
            "declare is UNTRUSTED, so a rule-of-two escalation needs an "
            "explicit trusted claim, never an omission."
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
        id="gateway:GatewayPolicy.from_mapping:mutating_tools",
        kind="dict-fallback",
        value="[]",
        rationale=(
            "A policy file may omit 'mutating_tools': no tool is "
            "known-mutating until the operator classifies it (same "
            "boundary as trust — omission is not an escalation). A listed "
            "entry that can never escalate (effective trust not HIGH) is "
            "rejected at load instead of silently doing nothing."
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
        id="gateway:GatewayPolicy.from_mapping:~name",
        kind="dict-fallback",
        value="default_trust",
        rationale=(
            "Dead-entry check (rat #69): a mutating_tools entry's effective "
            "trust is its listed trust, or the declared default when the "
            "tool is unlisted — the same default as trust_of, so an entry "
            "for a HIGH-default tool is live and any other dead entry is "
            "rejected at load instead of silently doing nothing."
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
    # --- escalation.py (rat #69) ------------------------------------------
    Default(
        id="escalation:InputTrust.parse:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "An unknown input-trust string is a caller error, not a crash: "
            "re-raised with the valid levels named."
        ),
        location="src/mcp_guard/escalation.py",
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
        id="cli:_handle_gateway_line:input_trust",
        kind="dict-fallback",
        value="'untrusted'",
        rationale=(
            "A request without 'input_trust' is UNTRUSTED, matching "
            "Gateway.call_tool's default: escalation needs an explicit "
            "trusted claim."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:approval",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A request without 'approval' carries no second approval: an "
            "escalated call is denied, a non-escalated call proceeds."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:approver",
        kind="dict-fallback",
        value="None",
        rationale=(
            "An approval object without 'approver' is malformed: error "
            "line, session continues. None is the missing-value marker, "
            "never an approver name."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:reason",
        kind="dict-fallback",
        value="None",
        rationale=(
            "An approval object without 'reason' is malformed: error line, "
            "session continues. None is the missing-value marker, never a "
            "reason."
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
        id="cli:_handle_gateway_line:except:(TrustDeniedError, EscalationRequiredError)",
        kind="except-path",
        value="(TrustDeniedError, EscalationRequiredError)",
        rationale=(
            "A denied or escalated-without-approval call is a normal "
            'gateway outcome: a {"denied": true} line with the audit '
            "delta, never an exception to the operator."
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
    # --- delegation.py (rat #67) -----------------------------------------
    Default(
        id="delegation:_lookup:except:KeyError",
        kind="except-path",
        value="KeyError",
        rationale=(
            "A missing key is an absence marker (None), not an error: the "
            "callers decide what absence means (default, rejection, or "
            "fail-closed refusal)."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationAuditLog.attempts_in_window:except:json.JSONDecodeError",
        kind="except-path",
        value="json.JSONDecodeError",
        rationale=(
            "A corrupt audit line is skipped for counting: one bad line must "
            "not hide the valid attempts around it, and must not wedge the "
            "rate-limit check."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationAuditLog.attempts_in_window:except:(ValueError, TypeError)",
        kind="except-path",
        value="(ValueError, TypeError)",
        rationale=(
            "An unparsable timestamp in an audit line is skipped for "
            "counting: same reasoning as the corrupt-line path. TypeError "
            "covers a non-string timestamp value."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationAuditLog.record:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "An audit write that fails is logged, never fatal: a failed "
            "write must not mask the delegation outcome it was recording. "
            "The cost is visible degradation (an unrecorded STARTED event "
            "is not counted by the rate limit)."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationAuditLog._read_recent_lines:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "An unreadable audit file counts zero attempts: the rate limit "
            "degrades rather than wedging the delegation. A missing file "
            "is a fresh count, not an error."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationContract.from_mapping:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "An unknown enum string in frontmatter is a validation "
            "error, not a crash: re-raised as ContractRejectedError "
            "naming the field."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:CommandVerifier.verify:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "A malformed verifier command (unbalanced quotes) REJECTS: a "
            "verification that cannot be parsed is not an approval."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationAuditLog.attempts_in_window:kind",
        kind="dict-fallback",
        value="None",
        rationale=(
            "An audit line without a kind field is not a delegation "
            "attempt: only DELEGATION_STARTED lines count toward the cap."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationAuditLog.attempts_in_window:started",
        kind="dict-fallback",
        value="None",
        rationale=(
            "An audit line without a started field has no timestamp to "
            "place in the window: it is skipped, never counted. A "
            "non-object JSON line is skipped earlier by the isinstance "
            "guard, so the timestamp parse never sees it."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationResult.__setattr__:_sealed",
        kind="dict-fallback",
        value="None",
        rationale=(
            "Before __post_init__ seals the result, _sealed is absent: "
            "construction-time field assignment is the only path that may "
            "set state, verification, or rejection_reason directly, and "
            "__post_init__ rejects a result constructed in a terminal "
            "state, so no caller can mint an approved result through the "
            "public API. The claim is scoped to that API: object.__setattr__ "
            "and _transition are private module escape hatches, and the "
            "boundary that matters is that the junior subprocess cannot "
            "touch the object at all."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._child_env:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "The guard refuses an unparsable depth marker before _child_env "
            "ever runs (see check_environment), so via delegate() this "
            "fallback is unreachable; it exists for direct _child_env "
            "callers, where a corrupt value must start the child at depth "
            "1 rather than wedge the delegation."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._run_junior:except:(OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired)",
        rationale=(
            "A worktree setup that fails (missing git binary, git "
            "refusing on a non-repo, or a hung git call) fails the "
            "delegation, never silently degrades to unisolated "
            "execution."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._run_junior:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "A contract-file write or junior spawn failure fails the "
            "delegation as a DelegationError: the run cannot start, so it "
            "must not proceed unguarded or unrecorded."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._child_env:~_DEPTH_ENV_VAR",
        kind="dict-fallback",
        value="'0'",
        rationale=(
            "A parent environment without a depth marker is top-level "
            "(depth 0): the child is marked 1, so a delegation inside a "
            "delegation is refused by the next guard."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:CommandVerifier.verify:except:(OSError, subprocess.TimeoutExpired, ValueError)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired, ValueError)",
        rationale=(
            "A verifier that cannot run (missing binary, timeout, bad "
            "quoting) REJECTS: a verification that did not happen is not "
            "an approval."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.delegate:except:LoopRefusedError",
        kind="except-path",
        value="LoopRefusedError",
        rationale=(
            "A loop refusal propagates unchanged: the guard already "
            "audited it, and the caller (CLI) turns it into exit 1."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.delegate:except:DelegationError",
        kind="except-path",
        value="DelegationError",
        rationale=(
            "A delegation that cannot run propagates unchanged: it is "
            "already the typed failure, not an unexpected crash."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.delegate:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "An environment failure (unwritable lock dir) fails the "
            "delegation as a DelegationError: the run cannot be guarded, "
            "so it must not proceed unguarded."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.delegate:except:(OSError, DelegationError)",
        kind="except-path",
        value="(OSError, DelegationError)",
        rationale=(
            "A copy-back failure (IO error, drift, or a main-tree "
            "conflict) leaves the result pending, never complete with "
            "unlanded files: the approval is persisted as a pending "
            "record and the failure propagates as a DelegationError "
            "naming the kept worktree."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.delegate:except:VerificationError",
        kind="except-path",
        value="VerificationError",
        rationale=(
            "A verdict that cannot apply (an approved verdict on a "
            "result whose worktree is still staged) discards the "
            "staging before propagating: a bug in verdict application "
            "must not leak a worktree."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._write_pending_file:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "A pending record that cannot be written is logged, never "
            "fatal: the pending obligation still survives as an audit "
            "event, and failing the delegation over its own bookkeeping "
            "would destroy the outcome it was recording."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.resolve_pending:except:(OSError, RuntimeError, ValueError, KeyError, TypeError)",
        kind="except-path",
        value="(OSError, RuntimeError, ValueError, KeyError, TypeError)",
        rationale=(
            "A missing, unreadable, or malformed pending record means "
            "there is nothing to resolve: a DelegationError naming the "
            "id, never a traceback or a guessed-at discharge. RuntimeError "
            "is included because Path.resolve on a symlink loop raises it."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.resolve_pending:except:(OSError, RuntimeError)",
        kind="except-path",
        value="(OSError, RuntimeError)",
        rationale=(
            "A staged worktree path that cannot be resolved (a symlink "
            "loop in a forged record) is corrupt input: refuse typed, "
            "never escape a RuntimeError out of resolve_pending."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.resolve_pending:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "A raising verifier is a rejection, never a crash: the "
            "staged work is discarded and the pending record deleted, "
            "exactly as on the in-run verifier path."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.resolve_pending:except:(OSError, DelegationError)",
        kind="except-path",
        value="(OSError, DelegationError)",
        rationale=(
            "A copy-back failure while resolving a pending delegation "
            "keeps the worktree and the pending record: the approval is "
            "durable, so the operator can retry the resolve after "
            "fixing the conflict instead of losing the verdict."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.discard_pending:except:(OSError, RuntimeError, ValueError, KeyError, TypeError)",
        kind="except-path",
        value="(OSError, RuntimeError, ValueError, KeyError, TypeError)",
        rationale=(
            "A missing, unreadable, or malformed pending record means "
            "there is nothing to discard: a DelegationError naming the "
            "id, never a traceback or a guessed-at deletion."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.discard_pending:except:(OSError, RuntimeError)",
        kind="except-path",
        value="(OSError, RuntimeError)",
        rationale=(
            "A staged worktree path that cannot be resolved (a symlink "
            "loop in a forged record) is corrupt input: refuse typed, "
            "never delete a path that cannot be identified."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._run_junior:except:(ProcessLookupError, PermissionError, OSError)",
        kind="except-path",
        value="(ProcessLookupError, PermissionError, OSError)",
        rationale=(
            "Killing the junior's process group on timeout is best-effort: "
            "when the group is already gone or cannot be signalled, fall "
            "back to terminating the direct child."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._run_junior:except:DelegationError",
        kind="except-path",
        value="DelegationError",
        rationale=(
            "A worktree setup that refuses (a pending delegation with "
            "the same id still has staged work) is a typed failure, "
            "audited as a failed delegation: the operator resolves the "
            "pending delegation first instead of destroying its work."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_step_precondition_failed:param:allow_missing_returncode",
        kind="param-default",
        value="False",
        rationale=(
            "A missing return code fails the step precondition by "
            "default: only a timeout record resolved later skips that "
            "one check, because the junior was killed and there is no "
            "exit code — the step conditions on the recorded artifacts "
            "still apply."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._run_junior:param:shape_kinds",
        kind="param-default",
        value="frozenset()",
        rationale=(
            "The secret-shape kinds default to none: _run_junior is also "
            "called by tests that do not run the delegate() shape check, "
            "and an empty kind set means no warning was found, not an "
            "unknown one."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._main_tree_snapshot:except:(OSError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired)",
        rationale=(
            "A main-tree snapshot that cannot be taken (missing git, hung "
            "git) yields no conflict baseline: copy-back proceeds with a "
            "warning instead of refusing every file, and the missing "
            "baseline is a documented residual, not a silent pass."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._worktree_registered_in_repo:except:(OSError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired)",
        rationale=(
            "A worktree listing that cannot be taken (missing git, hung "
            "git) proves nothing about the staging: the check returns "
            "False and the caller refuses, fail-closed."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._worktree_registered_in_repo:except:(OSError, RuntimeError)",
        kind="except-path",
        value="(OSError, RuntimeError)",
        rationale=(
            "A listed worktree path that cannot be resolved (a symlink "
            "loop in a corrupt git worktree entry) is skipped, never "
            "trusted as a match and never allowed to escape the check."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._snapshot_from_batch:except:(OSError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired)",
        rationale=(
            "HEAD blob contents that cannot be read (missing git, hung "
            "git) yield no conflict baseline, like an unlistable tree: "
            "copy-back proceeds with a warning instead of refusing every "
            "file, and the missing baseline is a documented residual."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._snapshot_from_batch:except:(ValueError, IndexError)",
        kind="except-path",
        value="(ValueError, IndexError)",
        rationale=(
            "A malformed cat-file --batch reply (unexpected header, short "
            "content) yields no conflict baseline rather than a crash: "
            "the snapshot is advisory bookkeeping for copy-back, and a "
            "missing baseline is the documented fallback."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._unlink_pending:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "A pending record that cannot be deleted (unwritable lock "
            "dir) is a typed failure, never a traceback out of "
            "resolve_pending: the delegation already reached a terminal "
            "outcome and the operator must know the record survived."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._refuse_on_conflict:~check_path",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A target absent from the HEAD snapshot was not tracked at "
            "HEAD: landing over it (or unlinking it) destroys operator "
            "work the delegation never staged, so it is refused unless "
            "the landing is a byte-identical no-op."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._write_pending_file:param:timed_out",
        kind="param-default",
        value="False",
        rationale=(
            "A pending record is written for a completed junior run by "
            "default: only the timeout path marks it timed_out, where no "
            "return code exists and resolve must not demand one."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.resolve_pending:junior_returncode",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A record without an exit code is only legitimate as a "
            "timeout record: resolve refuses it as forged unless "
            "timed_out is set, as the shape invariants require."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.resolve_pending:timed_out",
        kind="dict-fallback",
        value="False",
        rationale=(
            "A pending record written before the timed_out field existed "
            "describes a completed junior run, not a timeout: resolve "
            "demands a return code for it, as before."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_pid_alive:except:OverflowError",
        kind="except-path",
        value="OverflowError",
        rationale=(
            "A pid that does not fit in pid_t (a corrupt lock naming e.g. "
            "9999999999) names no process, but the lock is corrupt, not "
            "dead: fail closed (alive) like every other probe error, "
            "never crash the liveness check on corrupt input."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._status_snapshot:except:(OSError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired)",
        rationale=(
            "A git status that cannot run (missing binary, hung git) "
            "means no pre-run snapshot: the junior's changes are then "
            "all collected, never silently dropped."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._collect_changes:except:(OSError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired)",
        rationale=(
            "A git status that cannot run after the junior finishes is a "
            "loud DelegationError when the directory is a repo: silently "
            "reporting no changes would let a verifier approve an empty "
            "deliverable. Without a repo there is no tree to diff, and "
            "the empty result stands."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._collect_changes:except:(ValueError, OSError, RuntimeError)",
        kind="except-path",
        value="(ValueError, OSError, RuntimeError)",
        rationale=(
            "The lock directory is excluded from change collection "
            "only when it resolves inside the run directory: a lock "
            "dir elsewhere (or an unresolvable path, including a "
            "symlink loop, which raises RuntimeError) simply means no "
            "exclusion, never a failed delegation."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._remove_worktree:except:(OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired)",
        rationale=(
            "A worktree removal that fails (or a hung git call) is "
            "audited, then pruned and removed by hand: a failed "
            "cleanup must not leak a stale worktree registration, "
            "and must not fail a delegation whose deliverable already "
            "landed."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._remove_worktree:except:(OSError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired)",
        rationale=(
            "The fallback worktree prune is best-effort: a prune that "
            "cannot run (or hangs) must not stop the hand removal of "
            "the worktree directory that follows it."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._copy_back:except:(OSError, RuntimeError)",
        kind="except-path",
        value="(OSError, RuntimeError)",
        rationale=(
            "A worktree path or symlink target that cannot be resolved "
            "(a symlink loop raises RuntimeError) is corrupt input: "
            "copy-back refuses typed, or skips and audits the link, "
            "never escapes the exception out of the landing."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._copy_back:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "Recreating a symlink on copy-back is best-effort: where "
            "the platform refuses the link (Windows without the "
            "privilege), a regular copy of the target content lands "
            "instead of failing the delegation on a link it cannot make."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_file_sha256:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "A file that cannot be read has no trustworthy baseline "
            "hash: it hashes to empty, so change collection treats it "
            "as changed (fail-closed) rather than silently dropping it."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_git_file_matches_head:except:(OSError, subprocess.TimeoutExpired)",
        kind="except-path",
        value="(OSError, subprocess.TimeoutExpired)",
        rationale=(
            "A HEAD comparison that cannot run (missing git, hung git) "
            "proves nothing about the file: the check returns False "
            "and the caller refuses the landing, fail-closed."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner.delegate:except:Exception",
        kind="except-path",
        value="Exception",
        rationale=(
            "A senior verifier that raises (instead of returning a "
            "verdict) rejects the delegation with an audit event: a "
            "verification that crashed is not an approval, and the "
            "delegation must end rejected, never with a traceback."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:DelegationRunner._run_junior:except:subprocess.TimeoutExpired",
        kind="except-path",
        value="subprocess.TimeoutExpired",
        rationale=(
            "A junior that overruns its timeout ends in state TIMEOUT with "
            "an audit event: the delegation is over, never left hanging. "
            "The output produced before the kill is kept on the result: "
            "it is the diagnosis, not noise to discard."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_LockArbiter._acquire_posix:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "A lock file that cannot be opened, or whose flock cannot "
            "be taken, refuses fail-fast: the arbiter is what proves "
            "exclusion, so a lock that cannot be arbitrated cannot be "
            "held. Contention surfaces as BlockingIOError (an OSError) "
            "and refuses the same way, never waits."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_LockArbiter._acquire_windows:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "A lock file that cannot be opened after the named mutex "
            "was acquired releases the mutex and refuses: holding the "
            "mutex without a pid file would strand the id with no "
            "record of who holds it. Resolving the path can also fail "
            "and falls back to the absolute path."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_LockArbiter.inode:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "An fstat that cannot read the guarded file yields inode "
            "0: the inode verify is skipped there, not faked — "
            "refusing every delegation on a platform that reports no "
            "inode would wedge the lock for no safety gain."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:LoopGuard.acquire:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "The inode verify after arbiter acquisition cannot read "
            "the path (the previous holder released it mid-acquire): "
            "the acquirer releases and retries from the content "
            "check instead of proceeding on a file the path no "
            "longer names. The same key covers a pid write that "
            "fails after acquisition, which refuses fail-closed "
            "rather than holding an unrecorded lock."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:LoopGuard._read_lock_pid:except:(OSError, UnicodeDecodeError)",
        kind="except-path",
        value="(OSError, UnicodeDecodeError)",
        rationale=(
            "An unreadable lock file yields no pid: an empty file is "
            "retried briefly (a writer mid-create), and a still-empty or "
            "corrupt file is fail-closed (refused), never reclaimed. A "
            "lock that names no live pid cannot prove the delegation is over. "
            "A file that is not valid UTF-8 is unreadable the same way."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:LoopGuard._read_lock_pid:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "A lock file whose content is not an integer names no pid: "
            "same fail-closed handling as an unreadable file, the "
            "delegation is refused rather than the lock reclaimed."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:LoopGuard._lock_file_empty:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "A lock file whose size cannot be read is not empty: the "
            "creation-retry path only applies to a file proven empty, so "
            "an unreadable size fails closed like a corrupt lock."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:LoopGuard.acquire:except:LoopRefusedError",
        kind="except-path",
        value="LoopRefusedError",
        rationale=(
            "Contention on the global audit lock waits and retries: the "
            "check + STARTED record critical section is milliseconds, so "
            "a spurious refusal would reject a valid delegation. Only a "
            "timeout after the wait becomes a refusal, on its own "
            "AUDIT_LOCK layer (lock contention, not a rate refusal). The "
            "same key also covers the guard auditing a lock refusal and "
            "re-raising it."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:LoopGuard.check_environment:~_DEPTH_ENV_VAR",
        kind="dict-fallback",
        value="None",
        rationale=(
            "A missing depth marker means top-level: layer 1 refuses a "
            "marker that is present and at or over the max depth, or "
            "below zero (a negative marker is not a deeper budget, it "
            "is a forged one)."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_parse_frontmatter_block:~key",
        kind="dict-fallback",
        value="key",
        rationale=(
            "A camelCase alias maps to its snake_case field, and an "
            "unknown key keeps its own spelling so the parse error names "
            "the field the author actually wrote."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:LoopGuard.check_environment:except:ValueError",
        kind="except-path",
        value="ValueError",
        rationale=(
            "An unparsable depth marker is a loop refusal, not a crash: a "
            "marker that cannot be read cannot prove the delegation is "
            "top-level."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_unlink_retry:except:PermissionError",
        kind="except-path",
        value="PermissionError",
        rationale=(
            "On Windows a lock file cannot be unlinked while a concurrent "
            "reader holds it open (WinError 32): retry briefly instead of "
            "failing the delegation on a transient share violation. The "
            "final attempt raises: a lock that cannot be released must "
            "fail loudly, never silently strand a live delegation id."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_pid_alive:except:OSError",
        kind="except-path",
        value="OSError",
        rationale=(
            "Any doubt about pid liveness means alive (fail-closed): a lock "
            "is reclaimed only on a proven-dead pid."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_pid_alive:except:PermissionError",
        kind="except-path",
        value="PermissionError",
        rationale=(
            "A pid that exists but cannot be signalled is alive: permission "
            "to signal is not evidence of death."
        ),
        location="src/mcp_guard/delegation.py",
    ),
    Default(
        id="delegation:_pid_alive:except:ProcessLookupError",
        kind="except-path",
        value="ProcessLookupError",
        rationale="No such pid is the only proof of death; the lock may be reclaimed.",
        location="src/mcp_guard/delegation.py",
    ),
    # --- cli.py: delegate subcommand (rat #67) ---------------------------
    # NOTE: --lock-dir has no registry entry: it has no argparse default
    # (None = absent) and its default is computed in _run_delegate
    # (~/.mcp-guard/<repo-hash>), documented there. Same as --repo-dir.
    Default(
        id="cli:delegate_parser:--max-delegations",
        kind="cli-default",
        value="5",
        rationale=(
            "Five attempts per window is the loop-prevention cap: a runaway "
            "hook chain trips it fast, while a human-paced session never does."
        ),
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
        id="lifecycle:Lifecycle.call_tool:param:input_trust",
        kind="param-default",
        value="InputTrust.UNTRUSTED",
        rationale=(
            "Same as Gateway.call_tool: undeclared input provenance is "
            "UNTRUSTED, so escalation needs an explicit trusted claim."
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
        id="cli:delegate_parser:--timeout",
        kind="cli-default",
        value="120.0",
        rationale=(
            "Two minutes bounds one junior run: long enough for a real "
            "subtask, short enough that a hung junior cannot stall the "
            "operator's session."
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
        id="cli:delegate_parser:--no-repo-dir",
        kind="cli-default",
        value="False",
        rationale=(
            "A repo directory is the default: without one there is no tree "
            "to diff, so diff-based verification steps are skipped and the "
            "senior verifier is the only gate. The operator opts out "
            "explicitly with --no-repo-dir."
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
        id="cli:delegate_parser:--window-seconds",
        kind="cli-default",
        value="60",
        rationale=(
            "Sixty seconds is the rate-limit window: short enough to catch "
            "a feedback loop, long enough that sequential human-paced "
            "delegations are unaffected."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_handle_gateway_line:except:ServerNotEnabledError",
        kind="except-path",
        value="ServerNotEnabledError",
        rationale=(
            "The audit-log probe before a call is a read view, so it "
            "records no denial of its own — but the line IS a call "
            "attempt, so the denial is recorded explicitly on this path, "
            "or the production consumer's audit log stays silent about "
            "denied calls."
        ),
        location="src/mcp_guard/cli.py",
    ),
    Default(
        id="cli:_run_delegate:except:(OSError, UnicodeDecodeError)",
        kind="except-path",
        value="(OSError, UnicodeDecodeError)",
        rationale=(
            "An unreadable contract or prompt file fails closed before any "
            "delegation starts: exit 1, never a delegation with no contract. "
            "A non-UTF-8 file is unreadable the same way: a decode failure "
            "is an operator error line, never a traceback."
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
        id="cli:_run_delegate:except:(FrontmatterParseError, ContractRejectedError, LoopRefusedError, DelegationError)",
        kind="except-path",
        value="(FrontmatterParseError, ContractRejectedError, LoopRefusedError, DelegationError)",
        rationale=(
            "A refused delegation (no contract, loop layer, cannot run) is "
            "an operator error line and exit 1: the refusal is the outcome."
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
        id="cli:_run_delegate:except:(LoopRefusedError, DelegationError, OSError)",
        kind="except-path",
        value="(LoopRefusedError, DelegationError, OSError)",
        rationale=(
            "A refused resolve (no pending record, lock held, copy-back "
            "conflict, unwritable lock dir) is an operator error line and "
            "exit 1, like a refused delegation: the pending record and the "
            "staged worktree are kept for the operator to retry."
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
