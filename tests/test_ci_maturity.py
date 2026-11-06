"""Enforce the acceptance criteria of mcp-guard#27 (mature CI workflow) in CI.

The workflow file is the deliverable; these tests pin every acceptance
criterion so a regression (e.g. a dropped security gate or a narrowed
matrix) fails the build instead of silently weakening CI. Pattern follows
tests/test_codeql_workflow.py (#44).
"""

from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
SECURITY_MD = Path(__file__).resolve().parent.parent / "SECURITY.md"


@pytest.fixture(scope="module")
def doc() -> dict:
    assert WORKFLOW.exists(), f"ci.yml missing: {WORKFLOW}"
    raw = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # YAML 1.1 quirk: a bare `on:` key parses as boolean True.
    if "on" not in raw and True in raw:
        raw["on"] = raw.pop(True)
    return raw


@pytest.fixture(scope="module")
def jobs(doc: dict) -> dict:
    return doc["jobs"]


def _steps(job: dict) -> list[dict]:
    return job["steps"]


def _run_lines(job: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in _steps(job))


def _uses(job: dict) -> list[str]:
    return [str(s.get("uses", "")) for s in _steps(job)]


# --- matrix testing -------------------------------------------------------


def test_workflow_file_exists() -> None:
    assert WORKFLOW.exists()


def test_python_matrix_versions(jobs: dict) -> None:
    versions = jobs["test"]["strategy"]["matrix"]["python-version"]
    for v in ("3.11", "3.12", "3.13"):
        assert v in versions, f"CI matrix must test Python {v}"


def test_os_matrix(jobs: dict) -> None:
    oss = jobs["test"]["strategy"]["matrix"]["os"]
    for os_name in ("ubuntu-latest", "windows-latest", "macos-latest"):
        assert os_name in oss, f"CI matrix must test {os_name}"


def test_fail_fast_disabled(jobs: dict) -> None:
    assert jobs["test"]["strategy"].get("fail-fast") is False, (
        "fail-fast must be false so one matrix job failure does not cancel the rest"
    )


def test_dependency_caching_enabled(jobs: dict) -> None:
    uses = _uses(jobs["test"])
    uv_step = next(s for s in _steps(jobs["test"]) if "setup-uv" in str(s.get("uses", "")))
    assert uv_step.get("with", {}).get("enable-cache") is True, (
        "setup-uv must enable dependency caching"
    )
    assert any(u.startswith("actions/checkout@") for u in uses)


# --- coverage -------------------------------------------------------------


def test_coverage_reporting(jobs: dict) -> None:
    run = _run_lines(jobs["test"])
    assert "--cov=src/mcp_guard" in run, "pytest must collect coverage of src/mcp_guard"
    assert "--cov-report=xml" in run, "pytest must emit XML coverage for Codecov"
    assert "--cov-fail-under=" in run, "coverage must have a fail-under ratchet floor"


def test_codecov_upload_step(jobs: dict) -> None:
    assert any("codecov/codecov-action@" in u for u in _uses(jobs["test"])), (
        "CI must upload coverage to Codecov"
    )


def test_concurrency_group(jobs: dict, doc: dict) -> None:
    concurrency = doc.get("concurrency", {})
    assert concurrency.get("cancel-in-progress") is True, (
        "superseded pushes must cancel their own runs instead of burning matrix jobs"
    )


# --- lint / types ----------------------------------------------------------


def test_mypy_strict_gate(jobs: dict) -> None:
    run = _run_lines(jobs["test"])
    assert "mypy --strict src/mcp_guard" in run, "CI must type-check with mypy --strict"


def test_ruff_lint_and_format_gates(jobs: dict) -> None:
    run = _run_lines(jobs["test"])
    assert "ruff check src/ tests/" in run, "CI must run ruff check on src/ and tests/"
    assert "ruff format --check src/ tests/" in run, (
        "CI must run ruff format --check on src/ and tests/"
    )


# --- security gates --------------------------------------------------------


def test_bandit_security_gate(jobs: dict) -> None:
    assert "security" in jobs, "CI must define a security job"
    run = _run_lines(jobs["security"])
    assert "bandit -r src/mcp_guard/" in run, "security job must scan src/mcp_guard/ with bandit"


def test_pip_audit_gate(jobs: dict) -> None:
    run = _run_lines(jobs["security"])
    assert "pip-audit" in run, "security job must audit dependencies with pip-audit"


def test_security_md_bandit_claim_is_wired() -> None:
    text = SECURITY_MD.read_text(encoding="utf-8")
    # Pin the exact documented claim, not just the word "bandit": the claim
    # ("bandit security scanner runs in CI on every PR") was documented-but-
    # unwired before #27; this test plus test_bandit_security_gate keeps the
    # document and the workflow from drifting apart again.
    assert "`bandit` security scanner runs in CI on every PR." in text, (
        "SECURITY.md must document the bandit gate with its exact claim"
    )


# --- SBOM ------------------------------------------------------------------


def test_sbom_job(jobs: dict) -> None:
    assert "sbom" in jobs, "CI must define an sbom job"
    run = _run_lines(jobs["sbom"])
    assert "cyclonedx" in run.lower(), "sbom job must generate a CycloneDX SBOM"
    # #36 requires BOTH serializations: JSON for pipelines, XML for scanners
    # that only accept the XML form. A dropped format must fail the pin.
    assert "sbom.cdx.json" in run, "sbom job must generate the CycloneDX JSON SBOM (#36)"
    assert "sbom.cdx.xml" in run, "sbom job must generate the CycloneDX XML SBOM (#36)"
    assert any("actions/upload-artifact@" in u for u in _uses(jobs["sbom"])), (
        "sbom job must upload the SBOM as an artifact"
    )
    upload = next(s for s in _steps(jobs["sbom"]) if "upload-artifact" in str(s.get("uses", "")))
    path = str(upload.get("with", {}).get("path", ""))
    assert "sbom.cdx.json" in path and "sbom.cdx.xml" in path, (
        "sbom upload must include both the JSON and the XML artifact (#36)"
    )


# --- fuzz gate --------------------------------------------------------------


def test_fuzz_gate_job(jobs: dict) -> None:
    assert "fuzz-gate" in jobs, "CI must define a fuzz-gate job"
    run = _run_lines(jobs["fuzz-gate"])
    assert "tests/test_premortem_gates.py" in run, (
        "fuzz gate must run the premortem battery mapping each of the 5 spec "
        "failure modes to an explicit assertion"
    )


def test_fuzz_gate_is_distinct_from_matrix(jobs: dict) -> None:
    run = _run_lines(jobs["test"])
    assert "--ignore=tests/test_premortem_gates.py" in run, (
        "the matrix test job must exclude the premortem battery so a green "
        "fuzz-gate uniquely means the 5 failure modes were exercised"
    )


def test_fuzz_gate_maps_each_premortem_mode() -> None:
    gate = Path(__file__).resolve().parent / "test_premortem_gates.py"
    text = gate.read_text(encoding="utf-8")
    for mode in (1, 2, 3, 4, 5):
        assert f"def test_mode{mode}_" in text, (
            f"premortem battery must contain an explicit test for failure mode {mode} "
            "(docs/spec.md premortem section) — dropping a mode must fail the pin"
        )


# --- benchmark gate -----------------------------------------------------------


def test_benchmark_gate_job(jobs: dict) -> None:
    assert "benchmark-gate" in jobs, "CI must define a benchmark-gate job"
    run = _run_lines(jobs["benchmark-gate"])
    assert "tests/test_leaderboard_methodology.py" in run, (
        "benchmark gate must reproduce the leaderboard methodology (enumerate, fuzz, classify)"
    )
