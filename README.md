# mcp-guard

**Break your MCP servers before attackers do.**

![mcp-guard](docs/hero.webp)

[![CI](https://github.com/Zion-sewers/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Zion-sewers/mcp-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Version](https://img.shields.io/badge/version-0.2.1-blue.svg)

Your MCP server exposes tools to any agent that connects. mcp-guard connects first, and attacks. It spawns your server over stdio, reads every tool's input schema, and fires schema-aware attack payloads at every parameter. Each response is classified: `SAFE`, `FINDING`, or `CRASH`.

Against Anthropic's official `server-memory`, a stock run produced **41 findings**, including critical shell-injection hits where `$(whoami)` returned a normal-looking empty response. Not a crash. A silent execution. That is the dangerous kind. Full receipts in [LEADERBOARD.md](LEADERBOARD.md).

## Watch it run

![mcp-guard fuzz demo](docs/demo.gif)

*Live capture: `mcp-guard fuzz` against a two-tool toy MCP server — 58 findings, 0 crashes, verdict in the table.*

## 60 seconds

```bash
git clone https://github.com/Zion-sewers/mcp-guard && cd mcp-guard
pip install -e .
mcp-guard fuzz -- npx @modelcontextprotocol/server-memory
```

Zero runtime dependencies. Reports in `table`, `json`, or `sarif` for CI.

## How it works

![attack flow](docs/attack-flow.svg)

Every probe packet travels the same pipeline, fuzz input to chaos proxy to policy check, and lands in exactly one verdict lane: `SAFE`, `FINDING`, `CRASH`, `ERROR`, or `INCONCLUSIVE`. The animation above runs one packet per verdict so you can watch each outcome. A probe whose fault delivery is unconfirmed is `INCONCLUSIVE`, never `SAFE`; exit codes are `0` clean/findings, `1` inconclusive or error, `2` crashes.

## What it does

- Six probe types: shell injection, SSRF, overflow, type confusion, prompt injection, indirect injection.
- Schema-aware payloads: it reads each tool's `inputSchema` and builds attacks that fit the declared types.
- Machine-readable output: `sarif` for code scanning dashboards, `json` for pipelines.
- Central gateway (`mcp-guard gateway --policy policy.json -- ...`): trust-level enforcement in the request path plus pre-model PII tokenization, with an audit log of events, never content.

Fires up to **29 payloads per string parameter** (37 for URI-typed parameters) and classifies every response.

### 6 Probe Types

| Probe | Example Payloads | Catches |
|:------|:-----------------|:--------|
| **Shell injection** | `$(whoami)` `` `cat /etc/passwd` `` `; rm -rf /` | Command execution surface |
| **SSRF** | `http://169.254.169.254/` `file:///etc/passwd` `dict://` | Cloud metadata, internal network |
| **Overflow** | 10KB → 1MB strings, 10K-key objects | Buffer overflows, OOM |
| **Type confusion** | Wrong types, null for required, arrays for scalars | Missing input validation |
| **Prompt injection** | DAN override, system prompt extraction, XML injection | Instruction override, prompt leak |
| **Indirect injection** | `mcpguard-indirect-canary` exfil ping, reflected system tag | Goal hijack via reflected tool output |

Payloads are schema-aware: URI params get SSRF probes, string params get injection plus overflow, no-schema tools get a 24-payload subset.

## Honest limits

- Stdio transport only. SSE and streamable HTTP are out of scope for v1.
- Findings are response-pattern classifications for investigation, not confirmed exploits.
- Not on PyPI yet. Install from source.

## Methodology

Payload counts follow a schema-aware model. See [LEADERBOARD.md](LEADERBOARD.md#methodology) for the full benchmarking methodology.

| Tool Input | Payloads per Parameter |
|------------|------------------------|
| String parameter | 29 |
| URI-typed string parameter | 37 |
| Integer / number parameter | 9 |
| No input schema | 24 |

## License

[MIT](LICENSE), Shoval Benjer

---

Part of [Zion](https://github.com/Zion-sewers) — public infrastructure for trust in agents. The eval layer for the long-horizon era.
