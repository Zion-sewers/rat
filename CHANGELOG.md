# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Central MCP gateway (`mcp-guard gateway`, rat #66): trust-level enforcement in the request path (a low-trust caller can never trigger a high-trust read), pre-model PII tokenization with detokenization on later calls, and an audit log of events, never content (the one exception, added by rat #69: the approver name on an `escalation_approved` event, which records as a per-session `[APPROVER_n]` token, never verbatim and never resolvable back to the value)
- MCP least-privilege lifecycle (rat #68): servers off by default, narrow per-task enablement via `ServerRegistry`, and post-task teardown verified against the live process (`TeardownReport`; a surviving server fails the teardown instead of reporting clean). The `gateway` subcommand is the production consumer: the session is one task, and `--servers` enables multi-server tasks via stdin control lines
- Rule-of-two escalation + PII pseudonymization before any output (rat #69): on gateway calls, a HIGH-trust mutating tool on untrusted input escalates and is denied before any send without a second approval (`SecondApproval`, audited; the approver name records as a per-session `[APPROVER_n]` token, the whole field pseudonymized, never verbatim and never resolvable back to the value) — but the same caller can attach its own approval or declare its input trusted, so the control stops accidental omission and creates an audit trail, it does not enforce two distinct humans; the harness must obtain approval from a distinct principal out of band; the fuzzer is exempt from the rule (it does not run through the gateway). Fuzz reports (table/JSON/SARIF) are scrubbed at the emit boundary, before any preview truncation, emit-only and unconditional (no opt-out), so no raw structured PII of the detected classes reaches any report (names and bare 9-digit national IDs excepted); the detector also matches +972 Israeli mobiles and uses a bounded email pattern plus a per-family pre-filter (1M-char runs covered by regression tests with a 10s bound). Gateway CLI lines print the tokenized tool name, never the raw name — including the annotated tool list, scrubbed at its print site — and rejected trust values are never echoed back

## [0.1.0] - 2026-06-03

### Added
- Initial release of mcp-guard
- Stdio transport with JSON-RPC 2.0 handshake
- Schema-aware adversarial payload generation (5 probe types)
- Dynamic fuzzing engine with SAFE / FINDING / CRASH classification
- Static schema scanner with shell injection, SSRF, and missing-schema rules
- CLI with `fuzz` and `scan` subcommands
- Output formats: table, JSON, SARIF
- Zero runtime dependencies (Python 3.11+ stdlib only)
