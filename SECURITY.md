# Security Policy

mcp-guard is a security tool itself: it fuzzes MCP servers for a living.
This policy states how we handle vulnerabilities in mcp-guard, which
threats the tool is built to detect in the servers it tests, and which
mitigations back those claims. Every claim below names the place it can
be checked: a file, a workflow, or the code.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | Yes                |
| < 0.2   | No                 |

mcp-guard follows semantic versioning. Only the latest minor release
series receives security patches. The supported series is derived from
`[project].version` in `pyproject.toml` (currently 0.2.1); if the table
and the file disagree, the file wins and the table is stale.

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in
mcp-guard itself, please report it **privately**:

- **Email:** security@shovalbenjer.com
- **GitHub Security Advisory:** use the "Private vulnerability reporting"
  feature on this repository

**Please do NOT open a public GitHub issue for security vulnerabilities.**

We will acknowledge your report within 72 hours and provide a detailed
response within 7 days.

### Coordinated disclosure: 90 days

- The reporter agrees not to disclose the vulnerability publicly for
  **90 days** from the report date, or until a patched release ships,
  whichever comes first.
- The maintainers commit to shipping a fix, or publishing a public
  status update explaining the delay, within that 90-day window.
- After the window closes, or once a patched release ships, public
  disclosure is welcome, with credit to the reporter unless they ask
  to stay anonymous.

### security.txt

The same contact is published in `security.txt` at the repository root:

- `Contact: mailto:security@shovalbenjer.com`
- `Policy: https://github.com/Zion-sewers/rat/blob/main/SECURITY.md`

If the contact in `security.txt` ever disagrees with this file, this
file wins and `security.txt` is stale.

## Known Threats

mcp-guard is designed to detect the following failure modes in MCP
servers it fuzzes. The list comes from the premortem in `docs/spec.md`
("PREMORTEM — 5 Failure Modes"); each entry says what the code actually
does today, including the limits.

1. **Server crashes**: A payload crashes the MCP server process and the
   transport is lost. `FuzzEngine` catches the lost connection
   (`ConnectionError`) and classifies the payload as `CRASH`
   (`src/mcp_guard/fuzzer.py`); crash-causing payloads are tracked in
   the report (`FuzzReport.crashes`, `src/mcp_guard/report.py`). There
   is **no automatic respawn**: after a crash the operator restarts
   the target server and re-runs. A crash is never silently retried.

2. **Rate limiting / server throttling**: Aggressive fuzzing can
   trigger rate limits or intentional slowdowns. `mcp-guard fuzz`
   accepts `--delay-ms` to pace payloads (`src/mcp_guard/cli.py`,
   default 0). A server that rejects a payload with `isError: true`
   is classified `SAFE` ("expected error"). There is **no dedicated
   429/rate-limit detection**: a server that stops answering within
   the timeout surfaces as `ERROR`, not `SAFE`. A timeout is not
   evidence of safety, and the tool does not present it as such.

3. **False positives from expected errors**: A tool correctly rejecting
   bad input must not be flagged as a finding. `FuzzEngine`
   classifies by observed evidence (`src/mcp_guard/fuzzer.py`):
   `isError` responses are `SAFE`; responses leaking internal detail
   (tracebacks, secrets) or reflecting the payload are `FINDING`;
   a payload with no observable effect is `FINDING` at `INFO`
   severity, deliberately **not** `SAFE` — the fuzzer never asserts
   safety it cannot verify by black-box probing alone.

4. **Non-deterministic results**: The same payload can produce
   different results across runs when the target server holds state.
   Payload order is deterministic by construction: the generators
   emit a fixed sequence for a given schema, and no randomness is
   introduced (`src/mcp_guard/payloads.py`,
   `src/mcp_guard/fuzzer.py`). There is **no `--seed` option** and no
   state reset between probe groups: the same schema yields the same
   payload sequence, and every payload's result is recorded in the
   report, so two runs can be diffed payload by payload.

5. **MCP protocol version drift**: The MCP protocol spec evolves and
   handshakes change. The client pins `protocolVersion` to
   `2024-11-05` (`src/mcp_guard/transport.py`). A malformed or
   non-JSON response raises `ConnectionError` and is classified
   `CRASH`; an MCP error response raises `RuntimeError`. Neither
   hangs the run, and neither is reported as a clean bill.

## Mitigation Strategies

### Supply-Chain Hardening

- **Zero runtime dependencies.** `pyproject.toml` declares
  `dependencies = []`; mcp-guard runs on Python 3.11+ stdlib only.
  The attack surface of the tool itself has no third-party code to
  compromise at runtime.
- `bandit` security scanner runs in CI on every PR. The `security`
  job in `.github/workflows/ci.yml` fails the build on findings, and
  the JSON report is uploaded as an artifact.
- **pip-audit** runs in the same CI `security` job
  (`pip-audit --desc`), failing the build on known-vulnerable
  dependencies.
- **SBOM.** CI generates a CycloneDX SBOM in JSON and XML for the
  installed environment (the `sbom` job in `ci.yml`); releases attach
  an SPDX SBOM for the built artifacts (see Release Security).
- **Dependabot** watches `github-actions` and `pip` weekly
  (`.github/dependabot.yml`); patch updates are grouped, and the
  auto-merge workflow merges a Dependabot PR only after CI passes
  and only when every bump in it is a patch bump
  (`.github/workflows/dependabot-auto-merge.yml`,
  `tools/dependabot_patch_check.py`). Minor and major bumps stay open
  for human review.

### CI/CD Security Gates

- **Matrix testing** across Python 3.11, 3.12, 3.13 on Ubuntu,
  Windows, and macOS (the `test` job in `ci.yml`).
- **Lint and types:** `ruff check` and `ruff format --check` on every
  PR; `mypy --strict` on `src/mcp_guard`.
- **Fuzz gate:** the `fuzz-gate` job runs
  `tests/test_premortem_gates.py`, a battery that exercises all five
  failure modes above, so a green fuzz gate uniquely means the modes
  were tested.
- **CodeQL** analyzes Python and GitHub Actions with the
  `security-extended` query suite on every push and PR and weekly on
  schedule (`.github/workflows/codeql.yml`); results are uploaded as
  SARIF to GitHub code scanning.
- **Secret scanning:** `secret-scan.yml` greps every push and PR for
  committed credentials (GitHub tokens, API keys, cloud keys, private
  keys) and fails the build on a match.
- **Coverage floor:** the test job enforces `--cov-fail-under=60` so
  coverage cannot silently regress.

### Release Security

- **Pre-release gate:** the `checks` job in
  `.github/workflows/release.yml` runs the full battery (pytest on
  3.11/3.12/3.13, ruff, mypy) on the tagged commit before anything
  can publish; a red or untested commit can never release.
- **Version guard:** the tag `vX.Y.Z` must equal `[project].version`
  in `pyproject.toml` (`tools/release_check_version.py`); a mismatch
  aborts the run before anything is published.
- **Trusted publishing:** PyPI publishing uses OIDC trusted
  publishing — no long-lived API tokens exist anywhere in the
  pipeline. Honest boundary: trusted publishing needs a one-time
  pending-publisher registration on pypi.org for the mcp-guard
  project; until it is registered, publishing fails loudly at the
  OIDC exchange and nothing is published silently.
- **Sigstore:** every release carries a build-provenance attestation
  over `dist/*` and the SBOM
  (`actions/attest-build-provenance` in `release.yml`).
- **SBOM:** releases attach an SPDX SBOM for the built artifacts
  (`anchore/sbom-action`).
- **Least privilege and pinning:** each release job declares only
  the permissions it needs (`id-token: write` and
  `attestations: write` exist only inside the release job), and every
  third-party action is pinned to a commit SHA.

## Scope Notes

- This policy covers mcp-guard itself (the scanner, its CI, and its
  releases). Findings the tool reports about *other* MCP servers are
  the user's to disclose to those servers' maintainers; mcp-guard
  does not report them anywhere.
- The project was renamed from `mcp-guard` to `rat` in the
  `Zion-sewers` organization; old `ShovalBenjer/mcp-guard` and
  `Zion-sewers/mcp-guard` URLs redirect to `Zion-sewers/rat`.
  Canonical links in this file use `Zion-sewers/rat`.
