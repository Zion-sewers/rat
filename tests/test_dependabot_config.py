"""Adversarial tests for the Dependabot auto-merge configuration (mcp-guard#38).

Two fail-closed surfaces are pinned here:

1. `.github/dependabot.yml` must demand exactly what the issue asks:
   weekly cadence, patch-only groups, `ci(deps)` commit prefix, for both
   the github-actions and pip ecosystems. npm is intentionally absent: the
   repo has no npm manifest.
2. `tools/dependabot_patch_check.py` must merge only patch bumps. Every
   test pins a failure mode: a minor/major bump, a mixed group, a
   pre-release version, or an unparseable body must NEVER read as "patch".
"""

import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from dependabot_patch_check import all_patch, decide, is_patch_bump, parse_bumps

ROOT = os.path.join(os.path.dirname(__file__), "..")
DEPENDABOT = os.path.join(ROOT, ".github", "dependabot.yml")
AUTO_MERGE = os.path.join(ROOT, ".github", "workflows", "dependabot-auto-merge.yml")


# --- dependabot.yml --------------------------------------------------------


@pytest.fixture(scope="module")
def config() -> dict:
    assert os.path.exists(DEPENDABOT), "dependabot.yml missing"
    with open(DEPENDABOT, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _update(config: dict, ecosystem: str) -> dict:
    matches = [u for u in config["updates"] if u["package-ecosystem"] == ecosystem]
    assert len(matches) == 1, f"expected exactly one {ecosystem} update block"
    return matches[0]


def test_ecosystems_are_actions_and_pip_only(config: dict) -> None:
    ecosystems = {u["package-ecosystem"] for u in config["updates"]}
    assert ecosystems == {"github-actions", "pip"}


def test_weekly_schedule(config: dict) -> None:
    for ecosystem in ("github-actions", "pip"):
        assert _update(config, ecosystem)["schedule"]["interval"] == "weekly"


def test_patch_only_groups(config: dict) -> None:
    for ecosystem in ("github-actions", "pip"):
        groups = _update(config, ecosystem)["groups"]
        assert groups, f"{ecosystem}: at least one group required"
        for name, group in groups.items():
            assert group["update-types"] == ["patch"], f"{ecosystem}/{name}"


def test_commit_message_prefix(config: dict) -> None:
    for ecosystem in ("github-actions", "pip"):
        assert _update(config, ecosystem)["commit-message"]["prefix"] == "ci(deps)"


def test_no_npm_without_manifest(config: dict) -> None:
    assert not os.path.exists(os.path.join(ROOT, "package.json"))
    ecosystems = {u["package-ecosystem"] for u in config["updates"]}
    assert "npm" not in ecosystems


# --- bump parsing ----------------------------------------------------------


def test_parse_single_bump() -> None:
    body = "Bumps [mypy](https://github.com/python/mypy) from 2.4.0 to 2.4.1."
    assert parse_bumps(body) == [("2.4.0", "2.4.1")]


def test_parse_grouped_bumps() -> None:
    body = (
        "Bumps [ruff](https://example.com) from 0.16.10 to 0.16.11.\n"
        "Bumps [mypy](https://example.com) from 2.4.0 to 2.4.1."
    )
    assert parse_bumps(body) == [("0.16.10", "0.16.11"), ("2.4.0", "2.4.1")]


def test_parse_no_bump_lines_is_none() -> None:
    assert parse_bumps("Bumps the pip-patch group with 2 updates.") is None
    assert parse_bumps("") is None


def test_parse_ignores_changelog_mentions() -> None:
    body = "Bumps [ruff](https://example.com) from 0.16.10 to 0.16.11.\nfrom 1.0 to 2.0 in the changelog text."
    assert parse_bumps(body) == [("0.16.10", "0.16.11")]


# --- patch classification --------------------------------------------------


@pytest.mark.parametrize(
    ("old", "new"),
    [("2.4.0", "2.4.1"), ("1.14.2", "1.14.3"), ("0.16.10", "0.16.11"), ("4", "4.0.1")],
)
def test_patch_bumps(old: str, new: str) -> None:
    assert is_patch_bump(old, new)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("0.16.10", "0.17.3"),  # minor
        ("4", "7"),  # major, bare versions (actions/checkout 4 -> 7)
        ("2.4.1", "2.4.1"),  # no change
        ("2.4.1", "2.4.0"),  # downgrade, never a patch bump
        ("1.0.0-rc1", "1.0.0"),  # pre-release, unparseable
        ("1.0.0", "1.0.0-rc1"),  # pre-release target
        ("v1.2.3", "v1.3.0"),  # v-prefixed minor
    ],
)
def test_non_patch_bumps(old: str, new: str) -> None:
    assert not is_patch_bump(old, new)


def test_v_prefixed_patch_is_patch() -> None:
    assert is_patch_bump("v1.2.3", "v1.2.4")


def test_all_patch_requires_every_bump_patch() -> None:
    assert all_patch([("2.4.0", "2.4.1"), ("1.14.2", "1.14.3")])
    assert not all_patch([("2.4.0", "2.4.1"), ("0.16.10", "0.17.0")])
    assert not all_patch([])
    assert not all_patch(None)


# --- merge decision --------------------------------------------------------


def _pr(**overrides: object) -> dict:
    pr: dict = {
        "state": "open",
        "user": {"login": "dependabot[bot]"},
        "title": "chore(deps): bump mypy from 2.4.0 to 2.4.1",
        "body": "Bumps [mypy](https://github.com/python/mypy) from 2.4.0 to 2.4.1.",
    }
    pr.update(overrides)
    return pr


def test_decide_merge_patch() -> None:
    assert decide(_pr()) == "merge"


def test_decide_skip_non_dependabot_author() -> None:
    pr = _pr(user={"login": "some-human"})
    assert decide(pr).startswith("skip:")


def test_decide_skip_closed_pr() -> None:
    assert decide(_pr(state="closed")).startswith("skip:")


def test_decide_skip_minor_bump() -> None:
    pr = _pr(body="Bumps [ruff](https://example.com) from 0.16.10 to 0.17.3.")
    assert decide(pr).startswith("skip:")


def test_decide_skip_unparseable_body() -> None:
    assert decide(_pr(body="Bumps the pip-patch group with 2 updates.")).startswith("skip:")
    assert decide(_pr(body="")).startswith("skip:")


def test_decide_skip_mixed_group() -> None:
    body = (
        "Bumps [ruff](https://example.com) from 0.16.10 to 0.16.11.\n"
        "Bumps [mypy](https://example.com) from 2.4.0 to 2.5.0."
    )
    assert decide(_pr(body=body)).startswith("skip:")


# --- auto-merge workflow ---------------------------------------------------


@pytest.fixture(scope="module")
def workflow() -> dict:
    assert os.path.exists(AUTO_MERGE), "dependabot-auto-merge.yml missing"
    with open(AUTO_MERGE, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if "on" not in raw and True in raw:
        raw["on"] = raw.pop(True)
    return raw


def test_workflow_triggers_on_ci_completion(workflow: dict) -> None:
    on = workflow["on"]
    assert on["workflow_run"]["workflows"] == ["CI"]
    assert on["workflow_run"]["types"] == ["completed"]


def test_workflow_requires_ci_success(workflow: dict) -> None:
    job = workflow["jobs"]["auto-merge-patch"]
    assert "success" in str(job["if"])
    assert "workflow_run" in str(job["if"])


def test_workflow_never_runs_pr_code(workflow: dict) -> None:
    triggers = workflow["on"]
    assert "pull_request_target" not in triggers
    assert "pull_request" not in triggers
    with open(AUTO_MERGE, encoding="utf-8") as f:
        text = f.read()
    assert "ref: main" in text


def test_workflow_permissions_minimal(workflow: dict) -> None:
    assert workflow["permissions"]["pull-requests"] == "write"
    assert workflow["permissions"]["contents"] == "read"
