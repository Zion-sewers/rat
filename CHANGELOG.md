# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Central MCP gateway (`mcp-guard gateway`, rat #66): trust-level enforcement in the request path (a low-trust caller can never trigger a high-trust read), pre-model PII tokenization with detokenization on later calls, and an audit log of events, never content
- MCP least-privilege lifecycle (rat #68): servers off by default, narrow per-task enablement via `ServerRegistry`, and post-task teardown verified against the live process (`TeardownReport`; a surviving server fails the teardown instead of reporting clean). The `gateway` subcommand is the production consumer: the session is one task, and `--servers` enables multi-server tasks via stdin control lines
- Rule-of-two escalation + PII pseudonymization before any output (rat #69): a HIGH-trust mutating tool on untrusted input escalates and is denied before any send without a second approval (`SecondApproval`, audited); fuzz reports (table/JSON/SARIF) are scrubbed at the emit boundary so no raw structured PII of the detected classes reaches any report (names and bare 9-digit national IDs excepted); the detector also matches +972 Israeli mobiles and uses bounded patterns plus a per-family pre-filter so detection stays fast on long inputs (200k-char runs covered by tests)

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
