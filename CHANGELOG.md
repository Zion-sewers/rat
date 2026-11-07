# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Central MCP gateway (`mcp-guard gateway`, rat #66): trust-level enforcement in the request path (a low-trust caller can never trigger a high-trust read), pre-model PII tokenization with detokenization on later calls, and an audit log of events, never content

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
