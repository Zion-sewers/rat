"""RED: SECURITY.md must stay true to the live repo.

rat#41 asks for a comprehensive SECURITY.md: supported versions,
reporting process, security.txt reference, the 5 premortem failure
modes, and mitigation strategies. A security policy that invents
contacts, versions, or controls is worse than no policy: a reporter
who writes to a dead address, or a user who trusts a gate that does
not run, is actively misled. These tests fail CI on any doc/repo
divergence — every factual claim in SECURITY.md is checked against
the file, workflow, or code it names, in both directions where the
repo owns the value (version from pyproject, protocol pin from
transport.py, flags from cli.py). The honest boundaries are pinned
too: the doc must say what the tool does NOT do (no respawn, no
429 detection, no --seed), so a future edit cannot silently upgrade
a limit into a feature.
"""

from __future__ import annotations

import ast
import re
import tomllib
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURITY = REPO_ROOT / "SECURITY.md"
SECURITY_TXT = REPO_ROOT / "security.txt"
PYPROJECT = REPO_ROOT / "pyproject.toml"
SPEC = REPO_ROOT / "docs" / "spec.md"
SRC = REPO_ROOT / "src" / "mcp_guard"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

CONTACT = "security@shovalbenjer.com"
POLICY_URL = "https://github.com/Zion-sewers/rat/blob/main/SECURITY.md"


def _doc() -> str:
    return SECURITY.read_text(encoding="utf-8")


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _source(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


# --- Supported versions: table must follow pyproject, not memory --------
def test_supported_series_matches_pyproject_version() -> None:
    """The Yes row is the live major.minor series; older rows are No."""
    version = str(_pyproject()["project"]["version"])  # e.g. "0.2.1"
    major, minor, _ = version.split(".")
    supported = f"{major}.{minor}.x"
    rows = re.findall(r"\| ([^|]+?) +\| (Yes|No) +\|", _doc())
    assert rows, "no supported-versions rows found"
    by_series = {series.strip(): support for series, support in rows}
    assert by_series.get(supported) == "Yes", (
        f"pyproject is {version} but {supported} is not the Yes row: {rows}"
    )
    for series, support in rows:
        if series != supported:
            assert support == "No", f"stale row claims support: {series}"


# --- Contacts: one real address, shared by both files, nothing invented --
def test_single_contact_shared_by_security_md_and_security_txt() -> None:
    doc, txt = _doc(), SECURITY_TXT.read_text(encoding="utf-8")
    assert f"mailto:{CONTACT}" in txt, "security.txt contact differs"
    assert CONTACT in doc, "SECURITY.md must name the reporting contact"
    for text, name in ((doc, "SECURITY.md"), (txt, "security.txt")):
        assert "example.com" not in text, f"placeholder contact survives in {name}"
        found = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text))
        assert found == {CONTACT}, f"unexpected address in {name}: {found}"


def test_security_txt_policy_url_points_at_this_repo() -> None:
    txt = SECURITY_TXT.read_text(encoding="utf-8")
    assert f"Policy: {POLICY_URL}" in txt, "security.txt Policy URL is stale"
    urls = re.findall(r"https://github\.com/\S+", _doc())
    assert urls, "SECURITY.md names no GitHub URL"
    for url in urls:
        assert "Zion-sewers/rat" in url, f"non-canonical repo URL: {url}"


def test_security_txt_expiry_parses_and_is_future() -> None:
    match = re.search(r"^Expires: (\d{4}-\d{2}-\d{2})$", SECURITY_TXT.read_text(), re.MULTILINE)
    assert match, "security.txt needs an Expires date (YYYY-MM-DD)"
    year, month, day = (int(part) for part in match.group(1).split("-"))
    assert date(year, month, day) >= datetime.now(tz=UTC).date(), "security.txt Expires is past"


# --- Required sections ------------------------------------------------------
def test_ninety_day_coordinated_disclosure_present() -> None:
    doc = _doc()
    assert "90 days" in doc, "issue demands a 90-day coordinated disclosure policy"
    assert "90-day" in doc


def test_five_premortem_modes_present_and_match_spec() -> None:
    doc, spec = _doc(), SPEC.read_text(encoding="utf-8")
    modes = [
        "Server crashes",
        "Rate limiting",
        "False positives",
        "Non-deterministic",
        "protocol version drift",
    ]
    for mode in modes:
        assert mode in doc, f"premortem mode missing from SECURITY.md: {mode}"
        assert mode in spec, f"premortem mode missing from docs/spec.md: {mode}"


# --- Threat entries must match the code ------------------------------------
def test_protocol_pin_matches_transport() -> None:
    pin = re.search(r'"protocolVersion": "([^"]+)"', _source("transport.py"))
    assert pin, "no protocolVersion pin in transport.py"
    assert pin.group(1) in _doc(), "SECURITY.md does not state the pinned version"


def test_delay_flag_matches_cli() -> None:
    tree = ast.parse(_source("cli.py"))
    found: dict[str, object] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
        ):
            first = node.args[0]
            if isinstance(first, ast.Constant) and first.value == "--delay-ms":
                for kw in node.keywords:
                    if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                        found["default"] = kw.value.value
    assert found.get("default") == 0, "--delay-ms default is not 0"
    assert "--delay-ms" in _doc(), "SECURITY.md does not mention --delay-ms"


def test_classification_claims_match_fuzzer() -> None:
    fuzzer = _source("fuzzer.py")
    assert "isError" in fuzzer, "fuzzer has no isError branch"
    assert "ResultCategory.SAFE" in fuzzer, "no SAFE classification in fuzzer"
    assert "except ConnectionError" in fuzzer, "no crash path in fuzzer"
    assert "ResultCategory.CRASH" in fuzzer, "no CRASH classification in fuzzer"
    assert "ResultCategory.ERROR" in fuzzer, "no ERROR category for timeouts"
    assert "def crashes" in _source("report.py"), "report has no crashes accessor"


def test_honest_boundaries_pinned() -> None:
    """The doc must state the limits; a limit silently dropped is a lie."""
    doc = _doc()
    assert "no automatic respawn" in doc
    assert doc.count("respawn") == 1, "respawn must appear only as a stated limit"
    flat = " ".join(doc.split())
    assert "no dedicated 429/rate-limit detection" in flat
    assert "no `--seed` option" in doc
    assert doc.count("--seed") == 1, "--seed must appear only as a stated limit"


# --- Mitigations must name gates that actually run --------------------------
# Each entry: (needle that must exist in the workflow file,
#               marker that must exist in SECURITY.md).
WORKFLOW_TOOLS: dict[str, list[tuple[str, str]]] = {
    "ci.yml": [
        ("bandit", "`bandit` security scanner runs in CI on every PR."),
        ("pip-audit", "pip-audit"),
        ("cyclonedx", "CycloneDX"),
        ("test_premortem_gates.py", "test_premortem_gates.py"),
        ("mypy --strict", "mypy --strict"),
        ("ruff check", "ruff check"),
        ("--cov-fail-under", "--cov-fail-under"),
    ],
    "release.yml": [
        ("attest-build-provenance", "Sigstore"),
        ("gh-action-pypi-publish", "trusted publishing"),
        ("sbom-action", "SPDX SBOM"),
        ("release_check_version.py", "Version guard"),
    ],
    "codeql.yml": [("security-extended", "CodeQL")],
    "secret-scan.yml": [("ghp_", "Secret scanning")],
    "dependabot-auto-merge.yml": [
        ("dependabot_patch_check.py", "Dependabot"),
    ],
}


@pytest.mark.parametrize("workflow,tools", list(WORKFLOW_TOOLS.items()))
def test_named_gates_exist_in_workflows(workflow: str, tools: list[tuple[str, str]]) -> None:
    text = _workflow(workflow)
    doc = _doc()
    for workflow_needle, doc_marker in tools:
        assert workflow_needle in text, f"{workflow_needle} not found in {workflow}"
        assert doc_marker in doc, (
            f"SECURITY.md does not mention the {workflow} control {doc_marker}"
        )


def test_zero_runtime_dependencies() -> None:
    assert _pyproject()["project"]["dependencies"] == []
    assert "Zero runtime dependencies" in _doc()


def test_dependabot_covers_actions_and_pip() -> None:
    dependabot = (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert "github-actions" in dependabot
    assert '"pip"' in dependabot
    assert "Dependabot" in _doc()


def test_matrix_versions_in_ci_and_doc() -> None:
    ci = _workflow("ci.yml")
    doc = _doc()
    for version in ("3.11", "3.12", "3.13"):
        assert version in ci, f"Python {version} missing from CI matrix"
        assert version in doc, f"Python {version} missing from SECURITY.md matrix claim"
    for os_name in ("ubuntu", "windows", "macos"):
        assert os_name in ci, f"{os_name} missing from CI matrix"
