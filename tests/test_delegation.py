"""Adversarial tests for the delegation protocol (rat #67).

Every acceptance criterion from the issue is pinned by a failing-first
test: contract rejection, all three loop-prevention layers, secret
scrubbing before the handoff, and mandatory senior verification.
The fix-forward round 1 tests additionally pin: the contract is
forwarded to the junior (env + JSON file), the routing matrix drives
the runner (effort inheritance, step preconditions), loop layers are
composed (audited lock refusals, serialized rate-limit), worktree
changes are copied back, and the junior inherits a minimal env.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_guard.delegation import (
    DEPTH_ENV_VAR,
    ROUTING_MATRIX,
    CommandVerifier,
    ContractRejectedError,
    DelegationAuditKind,
    DelegationAuditLog,
    DelegationContract,
    DelegationError,
    DelegationResult,
    DelegationRunner,
    DelegationState,
    Effort,
    FrontmatterParseError,
    Isolation,
    LoopGuard,
    LoopLayer,
    LoopRefusedError,
    MemoryScope,
    PermissionMode,
    TaskKind,
    TriggerSurface,
    VerificationError,
    VerificationStep,
    VerificationVerdict,
    _is_test_file,
    _parse_porcelain_z,
    _pid_alive,
    _shape_kinds,
    _split_command,
    parse_frontmatter,
    route_for,
    sanitize_delegation_id,
)

AGENT = """---
name: mechanical-refactor
description: Delegates mechanical refactors to the junior.
tools:
  - Bash
  - Read
denied_tools:
  - Bash
model: small-local
effort: medium
isolation: worktree
permission_mode: auto
max_turns: 10
memory: project
---

You are a mechanical refactor coordinator.
"""

ECHO_JUNIOR = [
    sys.executable,
    "-c",
    "import sys; sys.stdout.write(sys.stdin.read())",
]


AGENT_NONE = AGENT.replace("isolation: worktree", "isolation: none")
AGENT_NO_EFFORT = AGENT_NONE.replace("effort: medium\n", "")


def _contract(text: str = AGENT_NONE) -> DelegationContract:
    return DelegationContract.from_text(text)


def _runner(tmp_path: Path, **kwargs: object) -> DelegationRunner:
    return DelegationRunner(tmp_path / "locks", junior_command=ECHO_JUNIOR, **kwargs)


def _delegate(
    tmp_path: Path,
    prompt: str = "Fix the lint.",
    contract_text: str = AGENT_NONE,
    task: TaskKind = TaskKind.LINT_FIX,
    delegation_id: str = "test-1",
    junior_command: list[str] | None = None,
    verifier: object = None,
    repo_dir: Path | None = None,
    env: dict[str, str] | None = None,
    **runner_kwargs: object,
) -> DelegationResult:
    """Run one delegation; runner kwargs (timeout, env allowlist) go to
    the constructor, delegate kwargs (verifier, repo, env) to delegate()."""
    command = junior_command if junior_command is not None else ECHO_JUNIOR
    runner = DelegationRunner(tmp_path / "locks", junior_command=command, **runner_kwargs)
    return runner.delegate(
        contract=_contract(contract_text),
        delegation_id=delegation_id,
        task=task,
        prompt=prompt,
        verifier=verifier,
        repo_dir=repo_dir,
        env=env,
    )


def _audit_events(tmp_path: Path) -> list[dict[str, object]]:
    path = tmp_path / "locks" / "audit.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


class _RecordingVerifier:
    """A verifier that records whether it was consulted at all."""

    def __init__(self, verdict: VerificationVerdict) -> None:
        self.verdict = verdict
        self.called = False

    def verify(self, result: DelegationResult) -> VerificationVerdict:
        self.called = True
        return self.verdict


def _git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


# --- Frontmatter parsing -----------------------------------------------------


def test_valid_contract_parses_all_fields() -> None:
    contract = _contract(AGENT)
    assert contract.name == "mechanical-refactor"
    assert contract.description.startswith("Delegates mechanical")
    assert contract.tools == ("bash", "read")
    assert contract.denied_tools == ("bash",)
    assert contract.model == "small-local"
    assert contract.effort is Effort.MEDIUM
    assert contract.isolation is Isolation.WORKTREE
    assert contract.permission_mode is PermissionMode.AUTO
    assert contract.max_turns == 10
    assert contract.memory is MemoryScope.PROJECT


def test_minimal_contract_gets_declared_defaults() -> None:
    contract = _contract("---\nname: reviewer\ndescription: Reviews diffs.\n---\nBody.\n")
    assert contract.tools == ()
    assert contract.denied_tools == ()
    assert contract.permission_mode is PermissionMode.DEFAULT
    # Round 5: the default isolation is worktree — the safe mode is the
    # default, and `isolation: none` is an explicit opt-in.
    assert contract.isolation is Isolation.WORKTREE
    assert contract.effort is None  # inherits the routed task kind's effort
    assert contract.max_turns == 25
    assert contract.memory is MemoryScope.NONE
    assert contract.model == "inherit"


def test_empty_model_falls_back_to_inherit() -> None:
    # An empty `model:` is not a model: a blank value is the same as an
    # absent one, and the junior must not receive an empty env var.
    text = "---\nname: reviewer\ndescription: Reviews diffs.\nmodel: \n---\nBody.\n"
    assert DelegationContract.from_text(text).model == "inherit"


def test_non_string_model_is_rejected() -> None:
    # from_mapping is the typed boundary for programmatic callers: a
    # model that is not a string cannot be forwarded as an env var, so
    # it is rejected instead of silently coerced.
    fields: dict[str, str | list[str]] = {
        "name": "reviewer",
        "description": "Reviews diffs.",
        "model": 42,  # type: ignore[dict-item]
    }
    with pytest.raises(ContractRejectedError, match="model must be a string"):
        DelegationContract.from_mapping(fields)


def test_background_true_is_rejected() -> None:
    # The runner is synchronous: a contract declaring background
    # execution cannot be enforced exactly, so it cannot proceed.
    text = "---\nname: reviewer\ndescription: Reviews diffs.\nbackground: true\n---\nBody.\n"
    with pytest.raises(ContractRejectedError, match="background"):
        DelegationContract.from_text(text)


def test_background_non_boolean_is_rejected() -> None:
    # "yes" must not silently coerce to False: a background value
    # that is not true/false is a contract error.
    text = "---\nname: reviewer\ndescription: Reviews diffs.\nbackground: yes\n---\nBody.\n"
    with pytest.raises(ContractRejectedError, match="background"):
        DelegationContract.from_text(text)


def test_background_false_is_accepted() -> None:
    text = "---\nname: reviewer\ndescription: Reviews diffs.\nbackground: false\n---\nBody.\n"
    assert DelegationContract.from_text(text).background is False


def test_bom_frontmatter_parses() -> None:
    # A UTF-8 byte-order mark is not a missing frontmatter block.
    text = "\ufeff---\nname: reviewer\ndescription: Reviews diffs.\n---\nBody.\n"
    assert DelegationContract.from_text(text).name == "reviewer"


def test_parse_frontmatter_returns_the_field_map() -> None:
    fields = parse_frontmatter(AGENT)
    assert fields["name"] == "mechanical-refactor"
    assert fields["tools"] == ["Bash", "Read"]
    assert fields["max_turns"] == "10"


def test_no_frontmatter_is_rejected_not_defaulted() -> None:
    with pytest.raises(FrontmatterParseError):
        _contract("Be careful with this file.\nNo contract here.\n")


def test_verbal_be_careful_is_not_a_contract() -> None:
    # The issue's acceptance criterion, verbatim: verbal 'be careful' is
    # NOT a contract. A prompt begging for care, with no frontmatter, must
    # still be rejected.
    with pytest.raises(FrontmatterParseError):
        _contract("Please be very careful, double-check everything.\n")


def test_unclosed_frontmatter_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        _contract("---\nname: x\ndescription: y\n")


def test_unknown_field_is_rejected_not_ignored() -> None:
    with pytest.raises(FrontmatterParseError, match="unknown frontmatter"):
        _contract("---\nname: x\ndescription: y\nsecret_backdoor: true\n---\n")


def test_missing_name_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        _contract("---\ndescription: No name.\n---\n")


def test_missing_description_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        _contract("---\nname: x\n---\n")


def test_uppercase_name_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        _contract("---\nname: CodexRefactor\ndescription: y\n---\n")


def test_invalid_enum_value_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        _contract("---\nname: x\ndescription: y\neffort: ludicrous\n---\n")


def test_nested_map_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        _contract("---\nname: x\ndescription: y\nnested:\n  key: value\n---\n")


def test_duplicate_field_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError, match="duplicate"):
        _contract("---\nname: x\nname: y\ndescription: z\n---\n")


def test_max_turns_zero_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        _contract("---\nname: x\ndescription: y\nmax_turns: 0\n---\n")


def test_max_turns_bool_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        _contract("---\nname: x\ndescription: y\nmax_turns: true\n---\n")


def test_max_turns_above_limit_is_rejected() -> None:
    # max_turns is bounded: an unbounded turn budget is a loop the
    # contract cannot bound, so 1001 is rejected and 1000 is the cap.
    with pytest.raises(ContractRejectedError, match="max_turns must be <= 1000"):
        _contract("---\nname: x\ndescription: y\nmax_turns: 1001\n---\n")
    assert _contract("---\nname: x\ndescription: y\nmax_turns: 1000\n---\n").max_turns == 1000


def test_inline_flow_list_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        _contract("---\nname: x\ndescription: y\ntools: [Bash, Read]\n---\n")


def test_bare_scalar_list_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        _contract("---\nname: x\ndescription: y\ntools: Bash\n---\n")


def test_unbalanced_quote_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        _contract('---\nname: "abc\ndescription: y\n---\n')


def test_camelcase_aliases_are_accepted() -> None:
    contract = _contract(
        "---\nname: x\ndescription: y\npermissionMode: plan\nmaxTurns: 7\n"
        "deniedTools:\n  - Bash\n---\n"
    )
    assert contract.permission_mode is PermissionMode.PLAN
    assert contract.max_turns == 7
    assert contract.denied_tools == ("bash",)


def test_contract_serializes_for_the_junior() -> None:
    contract = _contract(AGENT)
    body = contract.to_dict()
    assert body["name"] == "mechanical-refactor"
    assert body["tools"] == ["bash", "read"]
    assert body["effort"] == "medium"
    env = contract.to_env(Effort.LOW)
    assert env["MCP_GUARD_CONTRACT_EFFORT"] == "low"
    assert env["MCP_GUARD_CONTRACT_TOOLS"] == "bash,read"
    assert env["MCP_GUARD_CONTRACT_MAX_TURNS"] == "10"
    assert env["MCP_GUARD_CONTRACT_PERMISSION_MODE"] == "auto"


# --- Contract enforcement ----------------------------------------------------


def test_denylist_beats_allowlist() -> None:
    contract = _contract(AGENT)
    assert contract.is_tool_allowed("Bash") is False  # denied AND allowed
    assert contract.is_tool_allowed("Read") is True
    assert contract.is_tool_allowed("Write") is False  # not allowlisted


def test_tool_names_normalize_case_and_space() -> None:
    contract = _contract(AGENT)
    assert contract.is_tool_allowed("  bash ") is False
    assert contract.is_tool_allowed("READ") is True


def test_empty_allowlist_denies_everything() -> None:
    # Fail-closed: a contract that declares no tools delegates no tool use.
    contract = DelegationContract(name="open", description="Open contract.")
    assert contract.is_tool_allowed("Read") is False
    assert contract.is_tool_allowed("Bash") is False
    denied = DelegationContract(
        name="closed", description="Closed contract.", denied_tools=("bash",)
    )
    assert denied.is_tool_allowed("Bash") is False


def test_contract_is_forwarded_to_the_junior(tmp_path: Path) -> None:
    junior = [
        sys.executable,
        "-c",
        "import json, os, sys; sys.stdout.write(os.environ['MCP_GUARD_CONTRACT_FILE'])",
    ]
    result = _delegate(
        tmp_path,
        prompt="hi",
        contract_text=AGENT_NONE,
        junior_command=junior,
    )
    contract_file = Path(result.junior_stdout)
    assert contract_file.exists()
    body = json.loads(contract_file.read_text(encoding="utf-8"))
    assert body["name"] == "mechanical-refactor"
    assert body["tools"] == ["bash", "read"]
    assert body["permission_mode"] == "auto"
    assert body["max_turns"] == 10
    assert body["effort"] == "medium"


def test_contract_env_vars_reach_the_junior(tmp_path: Path) -> None:
    junior = [
        sys.executable,
        "-c",
        (
            "import os, sys; sys.stdout.write(os.environ['MCP_GUARD_CONTRACT_EFFORT']"
            " + '/' + os.environ['MCP_GUARD_CONTRACT_TOOLS'])"
        ),
    ]
    result = _delegate(tmp_path, prompt="hi", junior_command=junior)
    assert result.junior_stdout == "medium/bash,read"


def test_junior_env_is_minimal(tmp_path: Path) -> None:
    junior = [
        sys.executable,
        "-c",
        "import os, sys; sys.stdout.write(','.join(sorted(os.environ)))",
    ]
    parent_env = dict(os.environ)
    parent_env["LEAKED_TOKEN"] = "should-not-reach-the-junior"
    result = _delegate(
        tmp_path,
        prompt="hi",
        junior_command=junior,
        env=parent_env,
    )
    seen = result.junior_stdout.split(",")
    assert "LEAKED_TOKEN" not in seen
    assert "PATH" in seen  # the junior still needs to run
    assert "MCP_GUARD_CONTRACT_NAME" in seen
    assert "MCP_GUARD_DELEGATION_DEPTH" in seen


def test_allow_env_extends_the_child_env(tmp_path: Path) -> None:
    junior = [
        sys.executable,
        "-c",
        "import os, sys; sys.stdout.write(os.environ.get('MY_FLAG', 'missing'))",
    ]
    parent_env = dict(os.environ)
    parent_env["MY_FLAG"] = "hello"
    result = _delegate(
        tmp_path,
        prompt="hi",
        junior_command=junior,
        env=parent_env,
        extra_env_vars=frozenset({"MY_FLAG"}),
    )
    assert result.junior_stdout == "hello"


# --- Routing matrix ----------------------------------------------------------


def test_every_task_kind_has_exactly_one_route() -> None:
    assert set(ROUTING_MATRIX) == set(TaskKind)
    for kind in TaskKind:
        route = route_for(kind)
        assert route.task_kind is kind
        assert isinstance(route.trigger, TriggerSurface)
        assert isinstance(route.effort, Effort)
        assert isinstance(route.verification, VerificationStep)


def test_routing_matrix_matches_source_table() -> None:
    # The full source table (section 2b), every row pinned: a missing or
    # drifted row is a routing decision the docs no longer describe.
    expected = {
        TaskKind.LINT_FIX: (
            TriggerSurface.POST_TOOL_USE,
            Effort.LOW,
            VerificationStep.CHECK_EXIT_AND_DIFF,
        ),
        TaskKind.DOCSTRING: (
            TriggerSurface.POST_TOOL_USE,
            Effort.LOW,
            VerificationStep.READ_AND_APPROVE,
        ),
        TaskKind.TEST_SCAFFOLD: (
            TriggerSurface.STOP_HOOK,
            Effort.MEDIUM,
            VerificationStep.RUN_TESTS_RED,
        ),
        TaskKind.MECHANICAL_REFACTOR: (
            TriggerSurface.SUBAGENT,
            Effort.MEDIUM,
            VerificationStep.SEMANTIC_DIFF_CHECK,
        ),
        TaskKind.DIFF_REVIEW: (
            TriggerSurface.SKILL,
            Effort.MEDIUM,
            VerificationStep.HUMAN_REVIEWS,
        ),
        TaskKind.COVERAGE_GAP: (
            TriggerSurface.STOP_HOOK,
            Effort.HIGH,
            VerificationStep.RUN_COVERAGE_DELTA,
        ),
        TaskKind.COMMIT_MESSAGE: (
            TriggerSurface.POST_TOOL_USE,
            Effort.LOW,
            VerificationStep.HUMAN_EDITS,
        ),
        TaskKind.CHANGELOG: (
            TriggerSurface.SKILL,
            Effort.MEDIUM,
            VerificationStep.HUMAN_REVIEWS,
        ),
        TaskKind.DEPENDENCY_CHECK: (
            TriggerSurface.STOP_HOOK,
            Effort.LOW,
            VerificationStep.READ_RESULTS_ESCALATE,
        ),
        TaskKind.OVER_ENGINEERING: (
            TriggerSurface.SUBAGENT,
            Effort.MEDIUM,
            VerificationStep.READ_ONLY_REPORT,
        ),
    }
    assert set(expected) == set(TaskKind)
    for kind, (trigger, effort, step) in expected.items():
        route = route_for(kind)
        assert route.trigger is trigger, kind
        assert route.effort is effort, kind
        assert route.verification is step, kind


def test_effort_inherits_route_when_contract_is_silent(tmp_path: Path) -> None:
    result = _delegate(tmp_path, prompt="hi", contract_text=AGENT_NO_EFFORT)
    assert result.effective_effort is Effort.LOW  # LINT_FIX row
    assert result.verification_step is VerificationStep.CHECK_EXIT_AND_DIFF


def test_declared_effort_beats_the_route(tmp_path: Path) -> None:
    result = _delegate(tmp_path, prompt="hi", contract_text=AGENT_NONE)
    assert result.effective_effort is Effort.MEDIUM  # contract declares it


# --- Routed verification-step preconditions ----------------------------------


def test_run_tests_red_precondition_needs_a_test_file(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    junior = [
        sys.executable,
        "-c",
        "open('notes.txt', 'w').write('not a test')",
    ]
    result = _delegate(
        tmp_path,
        prompt="scaffold tests",
        task=TaskKind.TEST_SCAFFOLD,
        delegation_id="red-1",
        junior_command=junior,
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "run_tests_red" in result.rejection_reason
    assert verifier.called is False  # the step gates the outcome, not the verifier


def test_run_tests_red_passes_with_a_test_file(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    junior = [
        sys.executable,
        "-c",
        "open('test_scaffold.py', 'w').write('def test_x(): pass')",
    ]
    result = _delegate(
        tmp_path,
        prompt="scaffold tests",
        task=TaskKind.TEST_SCAFFOLD,
        delegation_id="red-2",
        junior_command=junior,
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert verifier.called is True


def test_run_tests_red_rejects_notes_file_matching_test_substring(
    tmp_path: Path,
) -> None:
    # Substring matching over the full path lets "latest_notes.txt" count
    # as a test file ("test_" is inside "latest_notes"): the match is on
    # the basename, so a notes file fails the step.
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    junior = [
        sys.executable,
        "-c",
        "open('latest_notes.txt', 'w').write('def test_x(): pass')",
    ]
    result = _delegate(
        tmp_path,
        prompt="scaffold tests",
        task=TaskKind.TEST_SCAFFOLD,
        delegation_id="red-3",
        junior_command=junior,
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "run_tests_red" in result.rejection_reason
    assert verifier.called is False


def test_diff_preconditions_skip_without_repo_dir(tmp_path: Path) -> None:
    # Without a repo directory there is no tree to diff: the diff-based
    # steps (semantic_diff_check, run_coverage_delta) must not reject
    # an empty change set — the verifier is the only gate, and the
    # routes stay reachable.
    for task, delegation_id in (
        (TaskKind.MECHANICAL_REFACTOR, "nodiff-1"),
        (TaskKind.COVERAGE_GAP, "nodiff-2"),
    ):
        verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
        result = _delegate(
            tmp_path,
            contract_text=AGENT_NONE,
            task=task,
            prompt="review this",
            delegation_id=delegation_id,
            verifier=verifier,
            repo_dir=None,
        )
        assert result.state is DelegationState.COMPLETE
        assert verifier.called is True


def test_run_tests_red_rejects_file_under_test_data_dir(tmp_path: Path) -> None:
    # A file under "test_data/" is not a test file either: its basename
    # carries no test marker.
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    junior = [
        sys.executable,
        "-c",
        (
            "import os; os.makedirs('test_data', exist_ok=True); "
            "open('test_data/notes.txt', 'w').write('def test_x(): pass')"
        ),
    ]
    result = _delegate(
        tmp_path,
        prompt="scaffold tests",
        task=TaskKind.TEST_SCAFFOLD,
        delegation_id="red-4",
        junior_command=junior,
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "run_tests_red" in result.rejection_reason
    assert verifier.called is False


def test_is_test_file_matches_basename_only() -> None:
    assert _is_test_file("test_scaffold.py") is True
    assert _is_test_file("tests/test_scaffold.py") is True
    assert _is_test_file("foo_test.py") is True
    assert _is_test_file("latest_notes.txt") is False
    assert _is_test_file("test_data/notes.txt") is False
    assert _is_test_file("contest_results.md") is False


def test_read_only_report_needs_junior_output(tmp_path: Path) -> None:
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    silent = [sys.executable, "-c", "pass"]
    result = _delegate(
        tmp_path,
        prompt="report only",
        task=TaskKind.OVER_ENGINEERING,
        delegation_id="ro-1",
        junior_command=silent,
        verifier=verifier,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "read_only_report" in result.rejection_reason
    assert verifier.called is False


def test_semantic_diff_needs_a_changed_file(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    result = _delegate(
        tmp_path,
        prompt="refactor",
        task=TaskKind.MECHANICAL_REFACTOR,
        delegation_id="diff-1",
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "semantic_diff_check" in result.rejection_reason
    assert verifier.called is False


def test_nonzero_junior_exit_fails_the_precondition(tmp_path: Path) -> None:
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    failing = [sys.executable, "-c", "import sys; sys.exit(3)"]
    result = _delegate(
        tmp_path,
        prompt="lint",
        task=TaskKind.LINT_FIX,
        delegation_id="rc-1",
        junior_command=failing,
        verifier=verifier,
    )
    assert result.state is DelegationState.REJECTED
    assert verifier.called is False


def test_check_exit_and_diff_needs_a_changed_file(tmp_path: Path) -> None:
    # The step is named check_exit_and_diff: exit 0 with no diff is a
    # vacuous pass, so the runner rejects without consulting the verifier.
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    result = _delegate(
        tmp_path,
        prompt="lint",
        task=TaskKind.LINT_FIX,
        delegation_id="diff-2",
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "check_exit_and_diff" in result.rejection_reason
    assert verifier.called is False


def test_check_exit_and_diff_passes_with_a_change(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    junior = [sys.executable, "-c", "open('fix.txt', 'w').write('fixed')"]
    result = _delegate(
        tmp_path,
        prompt="lint",
        task=TaskKind.LINT_FIX,
        delegation_id="diff-3",
        junior_command=junior,
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert verifier.called is True


def test_check_exit_and_diff_without_a_repo_leaves_it_to_the_verifier(
    tmp_path: Path,
) -> None:
    # No repo directory means no tree to diff: the step cannot be
    # checked mechanically, so the verifier is the only gate.
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    result = _delegate(
        tmp_path,
        prompt="lint",
        task=TaskKind.LINT_FIX,
        delegation_id="diff-4",
        verifier=verifier,
    )
    assert result.state is DelegationState.COMPLETE
    assert verifier.called is True


def test_read_results_escalate_needs_junior_output(tmp_path: Path) -> None:
    # The deliverable of a dependency check is the results text: a
    # silent junior has nothing to escalate, so the step fails.
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    silent = [sys.executable, "-c", "pass"]
    result = _delegate(
        tmp_path,
        prompt="check deps",
        task=TaskKind.DEPENDENCY_CHECK,
        delegation_id="rr-1",
        junior_command=silent,
        verifier=verifier,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "read_results_escalate" in result.rejection_reason
    assert verifier.called is False


# --- Loop prevention, layer 1: environment -----------------------------------


def test_nested_delegation_is_refused() -> None:
    guard = LoopGuard(Path("/tmp/never-used"))
    with pytest.raises(LoopRefusedError) as exc:
        guard.check_environment({DEPTH_ENV_VAR: "1"})
    assert exc.value.layer is LoopLayer.ENVIRONMENT


def test_unparsable_depth_marker_is_refused() -> None:
    guard = LoopGuard(Path("/tmp/never-used"))
    with pytest.raises(LoopRefusedError) as exc:
        guard.check_environment({DEPTH_ENV_VAR: "deep"})
    assert exc.value.layer is LoopLayer.ENVIRONMENT


def test_depth_zero_passes() -> None:
    LoopGuard(Path("/tmp/never-used")).check_environment({})
    LoopGuard(Path("/tmp/never-used")).check_environment({DEPTH_ENV_VAR: "0"})


def test_negative_depth_marker_is_refused() -> None:
    # A negative marker is not a deeper budget: -100 buys 101 nested
    # delegations before L1 fires, so it is refused like any depth
    # at or over the cap.
    guard = LoopGuard(Path("/tmp/never-used"))
    with pytest.raises(LoopRefusedError) as exc:
        guard.check_environment({DEPTH_ENV_VAR: "-100"})
    assert exc.value.layer is LoopLayer.ENVIRONMENT


def test_child_env_carries_depth_marker(tmp_path: Path) -> None:
    junior = [
        sys.executable,
        "-c",
        f"import os, sys; sys.stdout.write(os.environ[{DEPTH_ENV_VAR!r}])",
    ]
    result = _delegate(tmp_path, prompt="hi", delegation_id="depth-1", junior_command=junior)
    assert result.junior_stdout == "1"


# --- Loop prevention, layer 2: lock file -------------------------------------


def test_concurrent_same_id_is_refused(tmp_path: Path) -> None:
    guard = LoopGuard(tmp_path / "locks")
    audit = DelegationAuditLog(tmp_path / "audit.jsonl")
    errors: list[LoopRefusedError] = []

    def _second() -> None:
        try:
            with guard.guard("same-id", {}, audit):
                pass
        except LoopRefusedError as e:
            errors.append(e)

    with guard.guard("same-id", {}, audit):
        thread = threading.Thread(target=_second)
        thread.start()
        thread.join(timeout=5)
    assert len(errors) == 1
    assert errors[0].layer is LoopLayer.LOCK_FILE


def test_lock_released_after_delegation(tmp_path: Path) -> None:
    _delegate(tmp_path)
    assert not list((tmp_path / "locks").glob("*.lock"))


def test_stale_lock_with_dead_pid_is_reclaimed(tmp_path: Path) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    dead_pid = 999999  # no such process on any sane machine
    (lock_dir / "stale-1.delegation.lock").write_text(str(dead_pid), encoding="utf-8")
    guard = LoopGuard(lock_dir)
    audit = DelegationAuditLog(tmp_path / "locks" / "audit.jsonl")
    with guard.guard("stale-1", {}, audit):
        pass
    events = _audit_events(tmp_path)
    assert any(e["kind"] == DelegationAuditKind.LOCK_RECLAIMED.value for e in events)


def test_lock_with_live_pid_is_not_reclaimed(tmp_path: Path) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    (lock_dir / "live-1.delegation.lock").write_text(str(os.getpid()), encoding="utf-8")
    guard = LoopGuard(lock_dir)
    audit = DelegationAuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(LoopRefusedError) as exc, guard.guard("live-1", {}, audit):
        pass
    assert exc.value.layer is LoopLayer.LOCK_FILE


def test_invalid_delegation_id_is_refused(tmp_path: Path) -> None:
    guard = LoopGuard(tmp_path / "locks")
    audit = DelegationAuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(LoopRefusedError) as exc, guard.guard("../escape", {}, audit):
        pass
    assert exc.value.layer is LoopLayer.LOCK_FILE


def test_audit_global_delegation_id_is_refused(tmp_path: Path) -> None:
    # "audit-global" is the global audit lock's own id: a delegation
    # with the same id would deadlock the rate-limit critical section
    # against its own live pid, so the guard refuses it outright.
    guard = LoopGuard(tmp_path / "locks")
    audit = DelegationAuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(LoopRefusedError) as exc, guard.guard("audit-global", {}, audit):
        pass
    assert exc.value.layer is LoopLayer.AUDIT_LOCK


def test_corrupt_lock_is_refused_not_reclaimed(tmp_path: Path) -> None:
    # A lock whose owner cannot be proven dead stays locked: silently
    # unlinking it would let two delegations share one id.
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    lock_path = lock_dir / "bad-1.delegation.lock"
    lock_path.write_text("not-a-pid", encoding="utf-8")
    guard = LoopGuard(lock_dir)
    audit = DelegationAuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(LoopRefusedError) as exc, guard.guard("bad-1", {}, audit):
        pass
    assert exc.value.layer is LoopLayer.LOCK_FILE
    assert lock_path.exists(), "a corrupt lock must not be reclaimed"


def test_lock_refusal_is_audited(tmp_path: Path) -> None:
    guard = LoopGuard(tmp_path / "locks")
    audit = DelegationAuditLog(tmp_path / "locks" / "audit.jsonl")
    with (
        guard.guard("held-1", {}, audit),
        pytest.raises(LoopRefusedError),
        guard.guard("held-1", {}, audit),
    ):
        pass
    refused = [
        e for e in _audit_events(tmp_path) if e["kind"] == DelegationAuditKind.LOOP_REFUSED.value
    ]
    assert len(refused) == 1
    assert refused[0]["detail"]["layer"] == LoopLayer.LOCK_FILE.value


def test_unlink_retry_survives_transient_share_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows refuses to unlink a file a concurrent reader holds open
    # (WinError 32): the release path retries instead of failing the
    # delegation. Simulated here by failing the first two unlinks.
    from mcp_guard.delegation import _unlink_retry

    target = tmp_path / "x.lock"
    target.write_text("1", encoding="utf-8")
    calls = {"n": 0}
    real_unlink = Path.unlink

    def _flaky(self: Path, missing_ok: bool = False) -> None:
        calls["n"] += 1
        if calls["n"] <= 2:
            raise PermissionError("simulated WinError 32")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _flaky)
    _unlink_retry(target)
    assert not target.exists()
    assert calls["n"] == 3


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_lock_file_mode_is_0600(tmp_path: Path) -> None:
    guard = LoopGuard(tmp_path / "locks")
    audit = DelegationAuditLog(tmp_path / "locks" / "audit.jsonl")
    with guard.guard("mode-1", {}, audit):
        mode = (tmp_path / "locks" / "mode-1.delegation.lock").stat().st_mode & 0o777
        assert mode == 0o600


def test_pid_alive_dead_and_live() -> None:
    assert _pid_alive(999999) is False
    assert _pid_alive(os.getpid()) is True


def test_sanitize_delegation_id() -> None:
    assert sanitize_delegation_id("my agent.md") == "my-agent.md"
    assert sanitize_delegation_id("../escape") == "escape"
    fallback = sanitize_delegation_id("")
    assert fallback.startswith("delegation-") and len(fallback) == len("delegation-") + 12
    assert sanitize_delegation_id("valid-1.2_x") == "valid-1.2_x"


# --- Loop prevention, layer 3: audit rate-limit ------------------------------


def test_rate_limit_counts_across_runner_instances(tmp_path: Path) -> None:
    # Layer 3 is cross-process: two separate runners share the audit file,
    # so the cap must count both.
    guard = LoopGuard(tmp_path / "locks", max_delegations=2, window_seconds=60)
    for n in range(2):
        _runner(tmp_path, guard=guard).delegate(
            contract=_contract(),
            delegation_id=f"rate-{n}",
            task=TaskKind.LINT_FIX,
            prompt="hi",
        )
    with pytest.raises(LoopRefusedError) as exc:
        _runner(tmp_path, guard=guard).delegate(
            contract=_contract(),
            delegation_id="rate-2",
            task=TaskKind.LINT_FIX,
            prompt="hi",
        )
    assert exc.value.layer is LoopLayer.AUDIT_RATE_LIMIT


def test_rate_limit_is_a_real_bound_under_concurrency(tmp_path: Path) -> None:
    # B3: the check + STARTED record are atomic under the global audit
    # lock. Six concurrent delegations against a cap of 5 must land
    # exactly five starts; without serialization the burst overruns.
    guard = LoopGuard(tmp_path / "locks", max_delegations=5, window_seconds=60)
    outcomes: list[str] = []
    lock = threading.Lock()

    def _one(n: int) -> None:
        try:
            _runner(tmp_path, guard=guard).delegate(
                contract=_contract(),
                delegation_id=f"conc-{n}",
                task=TaskKind.LINT_FIX,
                prompt="hi",
            )
            outcome = "ok"
        except LoopRefusedError as e:
            outcome = e.layer.value
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=_one, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert outcomes.count("ok") == 5
    assert outcomes.count(LoopLayer.AUDIT_RATE_LIMIT.value) == 1


def test_old_attempts_outside_window_do_not_count(tmp_path: Path) -> None:
    audit_path = tmp_path / "locks" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    old = (datetime.now(UTC) - timedelta(seconds=3600)).isoformat()
    audit_path.write_text(
        json.dumps(
            {
                "started": old,
                "kind": DelegationAuditKind.DELEGATION_STARTED.value,
                "delegation_id": "old-1",
                "detail": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    audit = DelegationAuditLog(audit_path)
    assert audit.attempts_in_window(60, datetime.now(UTC)) == 0


def test_corrupt_audit_lines_do_not_hide_attempts(tmp_path: Path) -> None:
    audit_path = tmp_path / "locks" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    now = datetime.now(UTC).isoformat()
    audit_path.write_text(
        "not json at all\n"
        + json.dumps(
            {
                "started": now,
                "kind": DelegationAuditKind.DELEGATION_STARTED.value,
                "delegation_id": "good-1",
                "detail": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    audit = DelegationAuditLog(audit_path)
    assert audit.attempts_in_window(60, datetime.now(UTC)) == 1


def test_naive_timestamp_is_coerced_not_fatal(tmp_path: Path) -> None:
    audit_path = tmp_path / "locks" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    naive = datetime.now(UTC).replace(tzinfo=None).isoformat()
    audit_path.write_text(
        json.dumps(
            {
                "started": naive,
                "kind": DelegationAuditKind.DELEGATION_STARTED.value,
                "delegation_id": "naive-1",
                "detail": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    audit = DelegationAuditLog(audit_path)
    assert audit.attempts_in_window(60, datetime.now(UTC)) == 1


def test_future_dated_events_do_not_count(tmp_path: Path) -> None:
    audit_path = tmp_path / "locks" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    future = (datetime.now(UTC) + timedelta(seconds=3600)).isoformat()
    audit_path.write_text(
        json.dumps(
            {
                "started": future,
                "kind": DelegationAuditKind.DELEGATION_STARTED.value,
                "delegation_id": "future-1",
                "detail": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    audit = DelegationAuditLog(audit_path)
    assert audit.attempts_in_window(60, datetime.now(UTC)) == 0


def test_audit_tail_is_bounded(tmp_path: Path) -> None:
    # A 1 MB+ audit file must not make the rate-limit check read the
    # whole file: only the tail can hold in-window events.
    audit_path = tmp_path / "locks" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    junk = json.dumps(
        {
            "started": (datetime.now(UTC) - timedelta(seconds=3600)).isoformat(),
            "kind": DelegationAuditKind.DELEGATION_STARTED.value,
            "delegation_id": "junk",
            "detail": {},
        }
    )
    with audit_path.open("w", encoding="utf-8") as handle:
        for _ in range(12000):
            handle.write(junk + "\n")
        handle.write(
            json.dumps(
                {
                    "started": datetime.now(UTC).isoformat(),
                    "kind": DelegationAuditKind.DELEGATION_STARTED.value,
                    "delegation_id": "recent-1",
                    "detail": {},
                }
            )
            + "\n"
        )
    assert audit_path.stat().st_size > 1_048_576
    audit = DelegationAuditLog(audit_path)
    assert audit.attempts_in_window(60, datetime.now(UTC)) == 1


def test_audit_record_never_raises(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory", encoding="utf-8")
    audit = DelegationAuditLog(blocker / "audit.jsonl")
    audit.record(DelegationAuditKind.DELEGATION_STARTED, "x", {})


# --- Secret scrubbing ----------------------------------------------------------


def test_prompt_is_scrubbed_before_the_junior_sees_it(tmp_path: Path) -> None:
    prompt_text = "contact me at ada@example.com or call 555-123-4567"
    result = _delegate(tmp_path, prompt=prompt_text)
    assert "ada@example.com" not in result.junior_stdout
    assert "555-123-4567" not in result.junior_stdout
    started = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.DELEGATION_STARTED.value
    ]
    assert len(started) == 1
    detail = started[0]["detail"]
    assert detail["token_count"] == 2
    assert detail["token_kinds"] == "email,phone"
    # The hash is over the SCRUBBED prompt (what the junior saw), never
    # the raw prompt: hashing the raw text would leak it by dictionary.
    assert (
        detail["prompt_hash"]
        == hashlib.sha256(result.junior_stdout.encode("utf-8")).hexdigest()[:16]
    )


def test_audit_log_never_holds_prompt_values(tmp_path: Path) -> None:
    email = "ada@example.com"
    _delegate(tmp_path, prompt=f"reach {email}")
    audit_text = (tmp_path / "locks" / "audit.jsonl").read_text(encoding="utf-8")
    assert email not in audit_text
    started = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.DELEGATION_STARTED.value
    ]
    assert started[0]["detail"]["token_kinds"] == "email"


def test_ssn_and_card_are_scrubbed(tmp_path: Path) -> None:
    prompt_text = "SSN 123-45-6789 and card 4111 1111 1111 1111"
    result = _delegate(tmp_path, prompt=prompt_text)
    assert "123-45-6789" not in result.junior_stdout
    assert "4111 1111 1111 1111" not in result.junior_stdout
    assert "SSN_1" in result.junior_stdout
    assert "CREDIT_CARD_1" in result.junior_stdout


def test_contract_file_written_for_the_junior(tmp_path: Path) -> None:
    _delegate(tmp_path, prompt="hi")
    contract_file = tmp_path / "locks" / "test-1.contract.json"
    assert contract_file.exists()
    body = json.loads(contract_file.read_text(encoding="utf-8"))
    assert body["name"] == "mechanical-refactor"


# --- Senior verification -------------------------------------------------------


def test_result_starts_pending_and_complete_raises(tmp_path: Path) -> None:
    result = _delegate(tmp_path)
    assert result.state is DelegationState.PENDING_VERIFICATION
    with pytest.raises(VerificationError):
        result.complete()


def test_approved_verdict_completes(tmp_path: Path) -> None:
    result = _delegate(tmp_path)
    result.apply_verdict(VerificationVerdict.APPROVED)
    assert result.state is DelegationState.COMPLETE
    assert result.complete() is result


def test_rejected_verdict_rejects(tmp_path: Path) -> None:
    result = _delegate(tmp_path)
    result.apply_verdict(VerificationVerdict.REJECTED)
    assert result.state is DelegationState.REJECTED
    with pytest.raises(VerificationError):
        result.complete()


def test_double_verdict_raises(tmp_path: Path) -> None:
    result = _delegate(tmp_path)
    result.apply_verdict(VerificationVerdict.APPROVED)
    with pytest.raises(VerificationError):
        result.apply_verdict(VerificationVerdict.APPROVED)


def test_direct_state_assignment_raises(tmp_path: Path) -> None:
    result = _delegate(tmp_path)
    with pytest.raises(AttributeError):
        result.state = DelegationState.COMPLETE  # type: ignore[misc]
    assert result.state is DelegationState.PENDING_VERIFICATION


def test_direct_construction_of_complete_result_raises() -> None:
    # The gate is closed at construction, not just at assignment: no
    # caller can mint an approved result and call complete() on it.
    with pytest.raises(ValueError, match="cannot be complete"):
        DelegationResult(
            delegation_id="cv-2",
            task=TaskKind.LINT_FIX,
            effective_effort=Effort.LOW,
            verification_step=VerificationStep.CHECK_EXIT_AND_DIFF,
            state=DelegationState.COMPLETE,
            verification=VerificationVerdict.APPROVED,
        )


def test_replace_to_complete_raises(tmp_path: Path) -> None:
    import dataclasses

    result = _delegate(tmp_path)
    with pytest.raises(ValueError, match="cannot be complete"):
        dataclasses.replace(result, state=DelegationState.COMPLETE)


def test_runner_verifier_approves_and_rejects(tmp_path: Path) -> None:
    approved = _delegate(
        tmp_path,
        delegation_id="v-approve",
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
    )
    assert approved.state is DelegationState.COMPLETE

    rejected = _delegate(
        tmp_path,
        delegation_id="v-reject",
        verifier=_RecordingVerifier(VerificationVerdict.REJECTED),
    )
    assert rejected.state is DelegationState.REJECTED


def _pending_result() -> DelegationResult:
    return DelegationResult(
        delegation_id="cv-1",
        task=TaskKind.LINT_FIX,
        effective_effort=Effort.LOW,
        verification_step=VerificationStep.CHECK_EXIT_AND_DIFF,
        junior_returncode=0,
        junior_stdout="ok",
    )


def test_command_verifier_exit_code_decides() -> None:
    result = _pending_result()
    assert CommandVerifier("true").verify(result) is VerificationVerdict.APPROVED
    assert CommandVerifier("false").verify(result) is VerificationVerdict.REJECTED


def test_command_verifier_missing_binary_rejects() -> None:
    result = _pending_result()
    assert (
        CommandVerifier("definitely-not-a-binary-xyz").verify(result)
        is VerificationVerdict.REJECTED
    )


def test_command_verifier_timeout_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_guard.delegation as delegation_module

    monkeypatch.setattr(delegation_module, "_VERIFIER_TIMEOUT", 0.2)
    result = _pending_result()
    assert (
        CommandVerifier(f'{sys.executable} -c "import time; time.sleep(5)"').verify(result)
        is VerificationVerdict.REJECTED
    )


def test_command_verifier_empty_and_bad_quoting_reject() -> None:
    result = _pending_result()
    assert CommandVerifier("").verify(result) is VerificationVerdict.REJECTED
    assert CommandVerifier("'unbalanced").verify(result) is VerificationVerdict.REJECTED


def test_split_command_keeps_windows_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    # Plain shlex mangles backslash paths (C:\tools\python.exe becomes
    # C:toolspython.exe), so on Windows the verifier could never run.
    # The Windows branch is pinned here by faking os.name.
    monkeypatch.setattr(os, "name", "nt")
    assert _split_command('C:\\tools\\python.exe -c "print(1)"') == [
        "C:\\tools\\python.exe",
        "-c",
        "print(1)",
    ]
    assert _split_command("C:\\tools\\python.exe script.py") == [
        "C:\\tools\\python.exe",
        "script.py",
    ]
    with pytest.raises(ValueError):
        _split_command('"unbalanced')


def test_summary_carries_junior_output() -> None:
    # The senior verifier must see the deliverable: for the report
    # kinds the deliverable IS the junior's stdout.
    result = _pending_result()
    summary = result.to_summary()
    assert summary["junior_stdout"] == "ok"
    assert summary["junior_stderr"] == ""


def test_summary_truncates_long_junior_output() -> None:
    import mcp_guard.delegation as delegation_module

    result = _pending_result()
    object.__setattr__(
        result, "junior_stdout", "x" * (delegation_module._SUMMARY_OUTPUT_LIMIT + 10)
    )
    summary = result.to_summary()
    assert isinstance(summary["junior_stdout"], str)
    assert "truncated" in summary["junior_stdout"]
    assert len(summary["junior_stdout"]) < delegation_module._SUMMARY_OUTPUT_LIMIT + 100


def test_command_verifier_receives_junior_output(tmp_path: Path) -> None:
    # The tested seam must be the shipped seam: CommandVerifier's
    # stdin carries the junior's stdout, not just the return code.
    script = tmp_path / "dump_stdin.py"
    seen = tmp_path / "seen.json"
    script.write_text(
        "import json, sys; open(sys.argv[1], 'w').write(sys.stdin.read())\n",
        encoding="utf-8",
    )
    junior = [sys.executable, "-c", "import sys; sys.stdout.write('REPORT: all good')"]
    result = _delegate(
        tmp_path,
        prompt="report",
        task=TaskKind.OVER_ENGINEERING,
        delegation_id="vo-1",
        junior_command=junior,
        verifier=CommandVerifier(f"{sys.executable} {script} {seen}"),
    )
    assert result.state is DelegationState.COMPLETE
    payload = json.loads(seen.read_text(encoding="utf-8"))
    assert payload["junior_stdout"] == "REPORT: all good"


def test_command_verifier_stderr_is_kept() -> None:
    verifier = CommandVerifier(
        f"{sys.executable} -c \"import sys; sys.stderr.write('no such check'); sys.exit(1)\""
    )
    result = _pending_result()
    assert verifier.verify(result) is VerificationVerdict.REJECTED
    assert "no such check" in verifier.last_stderr


def test_raising_verifier_rejects(tmp_path: Path) -> None:
    # A verifier that raises is a rejection with an audit event,
    # never a traceback out of delegate().
    class _RaisingVerifier:
        def verify(self, result: DelegationResult) -> VerificationVerdict:
            raise RuntimeError("senior is down")

    result = _delegate(
        tmp_path,
        delegation_id="rv-1",
        verifier=_RaisingVerifier(),
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "RuntimeError" in result.rejection_reason
    rejected = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.VERIFICATION_REJECTED.value
    ]
    assert rejected


# --- Junior execution ----------------------------------------------------------


def test_empty_junior_command_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(DelegationError):
        _delegate(tmp_path, delegation_id="empty-1", junior_command=[])


def test_missing_junior_binary_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(DelegationError):
        _delegate(
            tmp_path,
            delegation_id="missing-1",
            junior_command=["definitely-not-a-binary-xyz"],
        )


def test_junior_timeout_marks_result_timeout(tmp_path: Path) -> None:
    runner = DelegationRunner(
        tmp_path / "locks",
        junior_command=[sys.executable, "-c", "import time; time.sleep(5)"],
        junior_timeout=0.2,
    )
    result = runner.delegate(
        contract=_contract(),
        delegation_id="slow-1",
        task=TaskKind.LINT_FIX,
        prompt="hi",
    )
    assert result.state is DelegationState.TIMEOUT
    assert result.junior_returncode is None
    failed = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.DELEGATION_FAILED.value
    ]
    assert any("timeout" in str(e["detail"]) for e in failed)


def test_timeout_keeps_partial_output(tmp_path: Path) -> None:
    # A timed-out junior's output is the diagnosis: the partial
    # stdout produced before the kill is kept on the TIMEOUT result.
    runner = DelegationRunner(
        tmp_path / "locks",
        junior_command=[
            sys.executable,
            "-c",
            "import sys, time; print('partial', flush=True); time.sleep(30)",
        ],
        junior_timeout=0.5,
    )
    result = runner.delegate(
        contract=_contract(),
        delegation_id="slow-2",
        task=TaskKind.LINT_FIX,
        prompt="hi",
    )
    assert result.state is DelegationState.TIMEOUT
    assert "partial" in result.junior_stdout


def test_hung_git_call_is_a_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A git call that hangs (60 s timeout) must fail the delegation as
    # a typed DelegationError, never escape as a raw traceback.
    import mcp_guard.delegation as delegation_module

    real_run = delegation_module.subprocess.run

    def _hanging_run(*args: object, **kwargs: object) -> object:
        argv = args[0] if args else kwargs.get("args", [])
        if isinstance(argv, list) and argv[:2] == ["git", "-C"]:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=60.0)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(delegation_module.subprocess, "run", _hanging_run)
    with pytest.raises(DelegationError, match="worktree setup failed"):
        _delegate(
            tmp_path,
            contract_text=AGENT,  # isolation: worktree
            delegation_id="git-hang",
            repo_dir=tmp_path,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group kill")
def test_timeout_kills_the_junior_process_group(tmp_path: Path) -> None:
    # The junior spawns a grandchild that sleeps; on timeout the whole
    # POSIX process group is killed, so the grandchild must not survive.
    pid_file = tmp_path / "grandchild.pid"
    junior = [
        sys.executable,
        "-c",
        (
            "import subprocess, sys, time; "
            "p = subprocess.Popen(['sleep', '30']); "
            f"open({str(pid_file)!r}, 'w').write(str(p.pid)); "
            "time.sleep(30)"
        ),
    ]
    runner = DelegationRunner(
        tmp_path / "locks",
        junior_command=junior,
        junior_timeout=0.5,
    )
    result = runner.delegate(
        contract=_contract(),
        delegation_id="pg-1",
        task=TaskKind.LINT_FIX,
        prompt="hi",
    )
    assert result.state is DelegationState.TIMEOUT
    grandchild = int(pid_file.read_text(encoding="utf-8"))
    time.sleep(0.5)
    with pytest.raises(ProcessLookupError):
        os.kill(grandchild, 0)


def test_worktree_isolation_copies_changes_back(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import sys; open('junior-note.txt', 'w').write(sys.stdin.read())",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="refactor this",
        delegation_id="wt-1",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.changed_files == ("junior-note.txt",)
    # The deliverable lands in the main tree only once the senior
    # verifier approves it; without approval it stays staged.
    assert (repo / "junior-note.txt").read_text(encoding="utf-8") == "refactor this"
    # No worktree left behind.
    worktrees = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert worktrees.stdout.count("worktree ") == 1


def test_worktree_deletion_is_mirrored(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    junior = [sys.executable, "-c", "import os; os.remove('README.md')"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="remove the readme",
        delegation_id="wt-2",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.changed_files == ("README.md",)
    assert not (repo / "README.md").exists()


def test_worktree_copy_back_new_directory(tmp_path: Path) -> None:
    # A junior that scaffolds tests into a new directory is the
    # TEST_SCAFFOLD happy path: the directory must land in the main
    # tree, not fail the delegation after the junior succeeded.
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        (
            "import os; os.makedirs('tests', exist_ok=True); "
            "open('tests/test_new.py', 'w').write('def test_x(): pass')"
        ),
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="scaffold tests",
        delegation_id="wt-dir",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.changed_files == ("tests/test_new.py",)
    assert (repo / "tests" / "test_new.py").read_text(encoding="utf-8") == ("def test_x(): pass")


def test_worktree_rename_is_mirrored(tmp_path: Path) -> None:
    # A rename must not leave a stale copy in the main tree: the old
    # path is deleted on copy-back.
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        (
            "import subprocess; subprocess.run("
            "['git', 'mv', 'README.md', 'README-renamed.md'], check=True)"
        ),
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="rename the readme",
        delegation_id="wt-rename",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.changed_files == ("README-renamed.md",)
    assert (repo / "README-renamed.md").exists()
    assert not (repo / "README.md").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink creation needs privilege on Windows")
def test_worktree_symlink_is_preserved_on_copy_back(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import os; os.symlink('README.md', 'README-link.md')",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="link the readme",
        delegation_id="wt-link",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.changed_files == ("README-link.md",)
    assert (repo / "README-link.md").is_symlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink creation needs privilege on Windows")
def test_worktree_escaping_symlink_is_not_recreated(tmp_path: Path) -> None:
    # A junior-controlled link whose target escapes the worktree must
    # never be planted in the operator's tree: it is skipped and
    # audited, and the rest of the deliverable still lands.
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        ("import os; os.symlink('/etc/passwd', 'evil-link'); open('ok.txt', 'w').write('ok')"),
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="plant a link",
        delegation_id="wt-escapelink",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert (repo / "ok.txt").read_text(encoding="utf-8") == "ok"
    assert not (repo / "evil-link").exists()
    failed = [
        e for e in _audit_events(tmp_path) if e["kind"] == DelegationAuditKind.COPYBACK_FAILED.value
    ]
    assert any(e["detail"].get("path") == "evil-link" for e in failed)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_worktree_copy_back_preserves_mode_bits(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import os; open('run.sh', 'w').write('#!/bin/sh\\n'); os.chmod('run.sh', 0o755)",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="add a script",
        delegation_id="wt-mode",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.changed_files == ("run.sh",)
    assert (repo / "run.sh").stat().st_mode & 0o777 == 0o755


def test_worktree_rejection_discards_changes(tmp_path: Path) -> None:
    # A REJECTED verdict discards the staging: nothing lands in the
    # main tree and no worktree is left behind.
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import sys; open('junior-note.txt', 'w').write(sys.stdin.read())",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="refactor this",
        delegation_id="wt-reject",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.REJECTED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.REJECTED
    assert not (repo / "junior-note.txt").exists()
    assert result.worktree_path is None
    worktrees = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert worktrees.stdout.count("worktree ") == 1


def test_worktree_pending_keeps_worktree_and_audits(tmp_path: Path) -> None:
    # No verifier: the result stays pending, the deliverable stays
    # staged in the worktree, and the pending obligation is durable —
    # an audit event records where the staged work lives.
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import sys; open('junior-note.txt', 'w').write(sys.stdin.read())",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="refactor this",
        delegation_id="wt-pending",
        junior_command=junior,
        repo_dir=repo,
    )
    assert result.state is DelegationState.PENDING_VERIFICATION
    assert not (repo / "junior-note.txt").exists()
    assert result.worktree_path is not None
    worktree = Path(result.worktree_path)
    assert (worktree / "junior-note.txt").read_text(encoding="utf-8") == "refactor this"
    pending = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.DELEGATION_PENDING.value
    ]
    assert len(pending) == 1
    assert pending[0]["detail"]["worktree"] == str(worktree)


def test_dirty_tracked_file_edited_by_junior_is_collected(tmp_path: Path) -> None:
    # The operator had already modified README.md before the run: a
    # junior edit to the same tracked file changes its content hash
    # and is collected as the junior's.
    repo = _git_repo(tmp_path)
    (repo / "README.md").write_text("operator edit\n", encoding="utf-8")
    junior = [sys.executable, "-c", "open('README.md', 'a').write('junior edit\\n')"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT_NONE,
        task=TaskKind.LINT_FIX,
        prompt="edit the readme",
        delegation_id="dirty-edit",
        junior_command=junior,
        repo_dir=repo,
    )
    assert result.changed_files == ("README.md",)


def test_dirty_tracked_file_untouched_by_junior_is_not_collected(tmp_path: Path) -> None:
    # The operator's dirty README.md stays the operator's when the
    # junior never touches it: same content hash, not collected.
    repo = _git_repo(tmp_path)
    (repo / "README.md").write_text("operator edit\n", encoding="utf-8")
    junior = [sys.executable, "-c", "open('fix.txt', 'w').write('fixed')"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT_NONE,
        task=TaskKind.LINT_FIX,
        prompt="lint",
        delegation_id="dirty-untouched",
        junior_command=junior,
        repo_dir=repo,
    )
    assert result.changed_files == ("fix.txt",)


def test_run_tests_red_passes_with_test_file_in_new_directory(tmp_path: Path) -> None:
    # Without -uall the new directory collapsed to "tests/" and the
    # run_tests_red precondition false-REJECTED the scaffold.
    repo = _git_repo(tmp_path)
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    junior = [
        sys.executable,
        "-c",
        (
            "import os; os.makedirs('tests', exist_ok=True); "
            "open('tests/test_scaffold.py', 'w').write('def test_x(): pass')"
        ),
    ]
    result = _delegate(
        tmp_path,
        prompt="scaffold tests",
        task=TaskKind.TEST_SCAFFOLD,
        delegation_id="red-dir",
        junior_command=junior,
        verifier=verifier,
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert verifier.called is True


def test_preexisting_untracked_dir_edits_are_collected(tmp_path: Path) -> None:
    # The operator's untracked notes/ dir predates the run: an untouched
    # file in it stays the operator's, but a file the junior edits is
    # the junior's change.
    repo = _git_repo(tmp_path)
    notes = repo / "notes"
    notes.mkdir()
    (notes / "a.txt").write_text("before\n", encoding="utf-8")
    (notes / "b.txt").write_text("untouched\n", encoding="utf-8")
    junior = [
        sys.executable,
        "-c",
        "open('notes/a.txt', 'w').write('after\\n')",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT_NONE,
        task=TaskKind.LINT_FIX,
        prompt="edit the note",
        delegation_id="untracked-1",
        junior_command=junior,
        repo_dir=repo,
    )
    assert result.changed_files == ("notes/a.txt",)


def test_lock_dir_is_excluded_from_changes(tmp_path: Path) -> None:
    # The lock directory lives inside the repo (the CLI default): its
    # audit log and contract file must never count as junior changes.
    repo = _git_repo(tmp_path)
    junior = [sys.executable, "-c", "open('fix.txt', 'w').write('fixed')"]
    runner = DelegationRunner(repo / ".mcp-guard-delegation", junior_command=junior)
    result = runner.delegate(
        contract=_contract(AGENT_NONE),
        delegation_id="lockdir-1",
        task=TaskKind.LINT_FIX,
        prompt="lint",
        repo_dir=repo,
    )
    assert result.changed_files == ("fix.txt",)


def test_worktree_without_repo_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DelegationError):
        _delegate(tmp_path, contract_text=AGENT, delegation_id="wt-norepo")


def test_worktree_setup_failure_is_an_error(tmp_path: Path) -> None:
    # isolation: worktree in a directory that is not a git repo: git
    # refuses, and the delegation fails (never silently unisolated).
    with pytest.raises(DelegationError):
        _delegate(
            tmp_path,
            contract_text=AGENT,
            delegation_id="wt-nogit",
            repo_dir=tmp_path,
        )
    failed = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.DELEGATION_FAILED.value
    ]
    assert any("worktree setup failed" in str(e["detail"]) for e in failed)


def test_worktree_cleanup_failure_is_audited(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    # The junior deletes the worktree's .git pointer: `git worktree
    # remove` then fails, and the runner must audit the failure (and
    # still prune + remove the directory) rather than leak it. The
    # deliverable is lost with the worktree, so the result is REJECTED:
    # check_exit_and_diff finds no diff to approve.
    junior = [sys.executable, "-c", "import os; os.remove('.git')"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.LINT_FIX,
        prompt="break the worktree",
        delegation_id="wt-3",
        junior_command=junior,
        repo_dir=repo,
    )
    assert result.state is DelegationState.REJECTED
    assert result.rejection_reason is not None
    assert "check_exit_and_diff" in result.rejection_reason
    failed = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.WORKTREE_CLEANUP_FAILED.value
    ]
    assert len(failed) == 1
    assert not (tmp_path / "locks" / "wt-3.worktree").exists()


def test_porcelain_z_parses_renames_and_spaces() -> None:
    # -z rename order is new path first, old path second.
    assert _parse_porcelain_z("R  new.txt\0old.txt\0") == [("R ", "new.txt", "old.txt")]
    assert _parse_porcelain_z("?? my file.txt\0") == [("??", "my file.txt", None)]
    assert _parse_porcelain_z(" M changed.py\0") == [(" M", "changed.py", None)]
    assert _parse_porcelain_z("") == []


# --- Secret-shaped prompts ----------------------------------------------------


def test_shape_kinds_detects_shapes() -> None:
    # Known token prefixes, a private-key block, and a credential
    # assignment are secret-shaped; ordinary prose is not.
    # The three fixtures below are spelled in parts, never one literal,
    # so the repo's committed-secret scanner does not flag the test's own
    # fake secrets; the joined strings are what the detector sees.
    assert _shape_kinds("use sk-abcdefgh12345678 here") == {"api_token"}
    assert _shape_kinds("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE") == {"private_key"}
    assert _shape_kinds("api_" + 'key = "abcdef123456"') == {"credential_assignment"}
    assert _shape_kinds("ghp" + "_abcdefghij1234567890") == {"api_token"}
    assert _shape_kinds("the password field must be validated") == set()
    assert _shape_kinds("Fix the lint.") == set()


def test_secret_shaped_prompt_warns_and_audits_kinds_not_values(
    tmp_path: Path,
) -> None:
    # The PII scrubber does not redact arbitrary secrets, so a prompt
    # carrying one must not cross the handoff silently: the delegation
    # still runs (a warning, never a refusal), but the audit trail names
    # only the shape kind, never the secret itself.
    token = "sk-abcdefgh12345678"
    result = _delegate(
        tmp_path,
        prompt=f"Use this key: {token}",
        delegation_id="secret-1",
    )
    assert result.state is DelegationState.PENDING_VERIFICATION
    events = _audit_events(tmp_path)
    warned = [e for e in events if e["kind"] == "secret_shape_warned"]
    assert len(warned) == 1
    assert warned[0]["detail"]["kinds"] == "api_token"
    audit_text = (tmp_path / "locks" / "audit.jsonl").read_text(encoding="utf-8")
    assert token not in audit_text


def test_benign_prompt_leaves_no_secret_warning(tmp_path: Path) -> None:
    result = _delegate(
        tmp_path,
        prompt="the password field must be validated by the junior",
        delegation_id="secret-2",
    )
    assert result.state is DelegationState.PENDING_VERIFICATION
    events = _audit_events(tmp_path)
    assert not [e for e in events if e["kind"] == "secret_shape_warned"]


# --- CLI -----------------------------------------------------------------------


def _write_cli_inputs(tmp_path: Path, contract_text: str = AGENT_NONE) -> tuple[Path, Path]:
    agent = tmp_path / "agent.md"
    agent.write_text(contract_text, encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    return agent, prompt


def _write_cli_inputs_in_repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    """CLI inputs plus a temp git repo the junior can change.

    lint_fix routes to check_exit_and_diff, which needs a changed file
    when the delegation runs against a repo: the junior writes one.
    """
    agent, prompt = _write_cli_inputs(tmp_path)
    return agent, prompt, _git_repo(tmp_path)


# Junior that changes a file in the repo and echoes the scrubbed prompt.
_CLI_JUNIOR_WRITES_FILE = (
    "import sys; open('note.txt', 'w').write('x'); sys.stdout.write(sys.stdin.read())"
)


def test_cli_pending_without_verifier_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 2
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "pending_verification"
    assert summary["delegation_id"].startswith("agent-lint_fix-")
    assert summary["task"] == "lint_fix"
    assert summary["effective_effort"] == "medium"
    assert summary["verification_step"] == "check_exit_and_diff"
    assert summary["changed_files"] == ["note.txt"]


def test_cli_verify_command_approves(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    main(
        [
            "delegate",
            "--contract",
            str(agent),
            "--task",
            "lint_fix",
            "--prompt-file",
            str(prompt),
            "--lock-dir",
            str(tmp_path / "locks"),
            "--repo-dir",
            str(repo),
            "--verify-command",
            "true",
            "--",
            sys.executable,
            "-c",
            _CLI_JUNIOR_WRITES_FILE,
        ]
    )
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "complete"
    assert summary["verification"] == "approved"


def test_cli_rejected_contract_exits_1(tmp_path: Path) -> None:
    agent = tmp_path / "agent.md"
    agent.write_text("Be careful, no frontmatter.\n", encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--",
                sys.executable,
                "-c",
                "pass",
            ]
        )
    assert exc.value.code == 1


def test_cli_missing_junior_command_exits_1(tmp_path: Path) -> None:
    agent, prompt = _write_cli_inputs(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
            ]
        )
    assert exc.value.code == 1


@pytest.mark.parametrize(
    "flag,value", [("--max-delegations", "0"), ("--window-seconds", "0"), ("--timeout", "-1")]
)
def test_cli_flag_validation_exits_1(tmp_path: Path, flag: str, value: str) -> None:
    agent, prompt = _write_cli_inputs(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                flag,
                value,
                "--",
                sys.executable,
                "-c",
                "pass",
            ]
        )
    assert exc.value.code == 1


def test_cli_delegation_id_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--delegation-id",
                "custom-1",
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 2
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["delegation_id"] == "custom-1"


def test_cli_allow_env_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    monkeypatch.setenv("MY_FLAG", "hello")
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--allow-env",
                "MY_FLAG",
                "--",
                sys.executable,
                "-c",
                "import os, sys; open('note.txt', 'w').write('x'); sys.stdout.write(os.environ.get('MY_FLAG', 'missing'))",
            ]
        )
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "hello" in err  # junior output is echoed to stderr


def test_cli_echoes_junior_output_on_rejection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--verify-command",
                "false",
                "--",
                sys.executable,
                "-c",
                "import sys; open('note.txt', 'w').write('x'); sys.stdout.write('junior said this')",
            ]
        )
    assert exc.value.code == 1
    captured = capsys.readouterr()
    summary = json.loads(captured.out.strip().splitlines()[-1])
    assert summary["state"] == "rejected"
    assert "junior said this" in captured.err


def test_cli_defaults_match_constants() -> None:
    import mcp_guard.delegation as delegation_module
    from mcp_guard.cli import build_parser

    parser = build_parser()
    # The delegate subparser holds the flags; find it via the subparsers.
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    delegate_parser = sub.choices["delegate"]
    flags = {a.dest: a.default for a in delegate_parser._actions}
    assert flags["max_delegations"] == delegation_module._DEFAULT_MAX_DELEGATIONS
    assert flags["window_seconds"] == delegation_module._DEFAULT_WINDOW_SECONDS
    assert flags["timeout"] == delegation_module._DEFAULT_JUNIOR_TIMEOUT


def test_cli_verifier_timeout_rejects(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_guard.delegation as delegation_module

    monkeypatch.setattr(delegation_module, "_VERIFIER_TIMEOUT", 0.2)
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--verify-command",
                f'{sys.executable} -c "import time; time.sleep(5)"',
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 1
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "rejected"


def test_cli_repo_dir_flag(tmp_path: Path) -> None:
    # The delegation runs against --repo-dir, never silently against
    # the operator's cwd: the junior's file lands in the named repo.
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 2
    assert (repo / "note.txt").read_text(encoding="utf-8") == "x"


def test_cli_no_repo_dir_skips_diff_precondition(tmp_path: Path) -> None:
    # The library-level no-repo escape is reachable from the CLI: with
    # --no-repo-dir the diff step is skipped and the verifier is the
    # only gate, so a lint_fix run from a non-repo directory stays
    # pending instead of failing its precondition.
    agent, prompt = _write_cli_inputs(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--no-repo-dir",
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.write(sys.stdin.read())",
            ]
        )
    assert exc.value.code == 2


def test_cli_repo_dir_and_no_repo_dir_conflict(tmp_path: Path) -> None:
    agent, prompt = _write_cli_inputs(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(tmp_path),
                "--no-repo-dir",
                "--",
                sys.executable,
                "-c",
                "pass",
            ]
        )
    assert exc.value.code == 1


def test_cli_verifier_stderr_is_surfaced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A missing binary and a rejection on substance must not print
    # the identical line: the verifier's stderr reaches the operator.
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--verify-command",
                f"{sys.executable} -c \"import sys; sys.stderr.write('senior says no'); sys.exit(1)\"",
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 1
    assert "senior says no" in capsys.readouterr().err


# --- Fix-forward round 5 (critique 4: 3xFAIL on head 2187538d) -------------
# Default isolation is worktree; pending is a durable record with a
# resolve path; copy-back refuses operator conflicts and worktree
# drift; the audit rate-limit survives corrupt lines; non-UTF-8 junior
# output returns a result; the tool clauses are advisory, not enforced.


def test_corrupt_audit_lines_do_not_crash_rate_limit(tmp_path: Path) -> None:
    # Round 5, impl B1: a JSON line that is not an object, and an
    # object without "started", used to raise AttributeError/KeyError
    # out of the rate-limit check and wedge every delegation until an
    # operator hand-edited the audit file. Both shapes are skipped now.
    import mcp_guard.delegation as delegation_module

    audit_log = DelegationAuditLog(tmp_path / "locks" / "audit.jsonl")
    now = datetime.now(UTC)
    lines = [
        json.dumps(
            {
                "kind": "delegation_started",
                "delegation_id": "good",
                "started": now.isoformat(),
                "detail": {},
            }
        ),
        "[]",
        '"just a string"',
        "42",
        json.dumps({"kind": "delegation_started", "delegation_id": "no-started"}),
        "{not json",
    ]
    audit_log.path.parent.mkdir(parents=True, exist_ok=True)
    audit_log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert delegation_module.DelegationAuditLog.attempts_in_window(audit_log, 60, now=now) == 1


def test_non_utf8_junior_output_returns_a_result(tmp_path: Path) -> None:
    # Round 5, impl B2: a junior emitting non-UTF-8 bytes used to crash
    # the delegation with an uncaught UnicodeDecodeError. The bytes are
    # replaced, and the delegation still returns a result.
    junior = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.buffer.write(b'\\xff\\xfe binary\\n')",
    ]
    result = _delegate(
        tmp_path,
        prompt="Fix the lint.",
        delegation_id="nonutf8-1",
        junior_command=junior,
    )
    assert result.state is DelegationState.PENDING_VERIFICATION
    assert "binary" in result.junior_stdout
    assert "\ufffd" in result.junior_stdout


def test_default_isolation_contract_needs_repo_dir(tmp_path: Path) -> None:
    # Round 5, arch B1: a contract that does not declare isolation now
    # defaults to worktree, and a worktree delegation without a repo
    # directory fails closed instead of silently degrading.
    with pytest.raises(DelegationError, match="worktree isolation requires repo_dir"):
        _delegate(
            tmp_path,
            contract_text="---\nname: reviewer\ndescription: Reviews diffs.\n---\nBody.\n",
            delegation_id="def-wt-1",
        )


def _pending_worktree_delegation(
    tmp_path: Path, delegation_id: str = "pend-1"
) -> tuple[Path, Path]:
    """Run a worktree delegation with no verifier; returns (repo, locks)."""
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import sys; open('junior-note.txt', 'w').write(sys.stdin.read())",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="refactor this",
        delegation_id=delegation_id,
        junior_command=junior,
        verifier=None,
        repo_dir=repo,
    )
    assert result.state is DelegationState.PENDING_VERIFICATION
    assert result.worktree_path is not None
    assert not (repo / "junior-note.txt").exists()
    return repo, tmp_path / "locks"


def test_pending_resolve_approves_and_lands(tmp_path: Path) -> None:
    # Round 5, arch B2: a pending result is a durable record, and a
    # fresh runner instance can discharge it later.
    repo, locks = _pending_worktree_delegation(tmp_path, "pend-approve")
    pending_path = locks / "pend-approve.pending.json"
    assert pending_path.exists()
    assert (locks / "pend-approve.worktree").exists()
    fresh = DelegationRunner(locks, junior_command=[])
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    result = fresh.resolve_pending("pend-approve", verifier)
    assert verifier.called
    assert result.state is DelegationState.COMPLETE
    assert (repo / "junior-note.txt").read_text(encoding="utf-8") == "refactor this"
    assert not pending_path.exists()
    assert not (locks / "pend-approve.worktree").exists()


def test_pending_resolve_rejects_and_discards(tmp_path: Path) -> None:
    repo, locks = _pending_worktree_delegation(tmp_path, "pend-reject")
    fresh = DelegationRunner(locks, junior_command=[])
    result = fresh.resolve_pending("pend-reject", _RecordingVerifier(VerificationVerdict.REJECTED))
    assert result.state is DelegationState.REJECTED
    assert not (repo / "junior-note.txt").exists()
    assert not (locks / "pend-reject.pending.json").exists()
    assert not (locks / "pend-reject.worktree").exists()


def test_resolve_pending_without_record_raises(tmp_path: Path) -> None:
    runner = DelegationRunner(tmp_path / "locks", junior_command=[])
    with pytest.raises(DelegationError, match="no pending delegation"):
        runner.resolve_pending("no-such-id", _RecordingVerifier(VerificationVerdict.APPROVED))


def test_apply_verdict_approved_refuses_staged_worktree() -> None:
    # Round 5, arch B2: a late APPROVED verdict on a result whose
    # worktree is still staged must not mint COMPLETE with the files
    # still sitting in the worktree. REJECTED stays allowed: the runner
    # discards the staging right after.
    result = DelegationResult(
        delegation_id="staged-1",
        task=TaskKind.LINT_FIX,
        effective_effort=Effort.LOW,
        verification_step=VerificationStep.CHECK_EXIT_AND_DIFF,
        worktree_path="/tmp/some.worktree",
    )
    with pytest.raises(VerificationError, match="has not been landed"):
        result.apply_verdict(VerificationVerdict.APPROVED)
    assert result.state is DelegationState.PENDING_VERIFICATION
    result.apply_verdict(VerificationVerdict.REJECTED)
    assert result.state is DelegationState.REJECTED


def test_setup_worktree_reclaims_crashed_leftover(tmp_path: Path) -> None:
    # Round 5, impl A2 / arch A8: a worktree left behind by a crashed
    # run (no pending record) no longer wedges the id forever.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    stale = locks / "wt-stale.worktree"
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "--detach", str(stale)],
        capture_output=True,
        check=True,
    )
    assert stale.exists()
    junior = [
        sys.executable,
        "-c",
        "import sys; open('junior-note.txt', 'w').write(sys.stdin.read())",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="refactor this",
        delegation_id="wt-stale",
        junior_command=junior,
        verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert (repo / "junior-note.txt").read_text(encoding="utf-8") == "refactor this"
    events = _audit_events(tmp_path)
    assert [e for e in events if e["kind"] == "worktree_reclaimed"]


def test_setup_worktree_refuses_when_pending_record_exists(tmp_path: Path) -> None:
    # Round 5, arch B2: re-delegating with an id whose staged work is
    # still owed a verdict refuses instead of destroying it.
    repo, locks = _pending_worktree_delegation(tmp_path, "pend-clash")
    junior = [
        sys.executable,
        "-c",
        "import sys; open('other.txt', 'w').write('x')",
    ]
    with pytest.raises(DelegationError, match="pending delegation"):
        _delegate(
            tmp_path,
            contract_text=AGENT,
            task=TaskKind.MECHANICAL_REFACTOR,
            prompt="refactor this",
            delegation_id="pend-clash",
            junior_command=junior,
            verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
            repo_dir=repo,
        )
    # The staged work survived the refused re-run.
    assert (locks / "pend-clash.worktree").exists()
    assert (locks / "pend-clash.pending.json").exists()


class _OperatorEditsVerifier:
    """A verifier that edits the main tree before approving."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def verify(self, result: DelegationResult) -> VerificationVerdict:
        (self.repo / "README.md").write_text("operator edit\n", encoding="utf-8")
        return VerificationVerdict.APPROVED


def test_copy_back_refuses_operator_edit_then_resolves(tmp_path: Path) -> None:
    # Round 5, product B1: the operator edits README in the main tree
    # while the delegation runs; the junior edited the same file from
    # HEAD. Copy-back refuses, the operator's edit survives, the
    # worktree is kept, and the approval is persisted — so resolving
    # after the operator reverts lands the junior's work.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    junior = [sys.executable, "-c", "open('README.md', 'w').write('junior edit\\n')"]
    with pytest.raises(DelegationError, match="copy-back conflict"):
        _delegate(
            tmp_path,
            contract_text=AGENT,  # isolation: worktree
            task=TaskKind.MECHANICAL_REFACTOR,
            prompt="edit the readme",
            delegation_id="wt-conflict",
            junior_command=junior,
            verifier=_OperatorEditsVerifier(repo),
            repo_dir=repo,
        )
    assert (repo / "README.md").read_text(encoding="utf-8") == "operator edit\n"
    assert (locks / "wt-conflict.worktree").exists()
    pending = json.loads((locks / "wt-conflict.pending.json").read_text(encoding="utf-8"))
    assert pending["verdict"] == "approved"
    # The operator reverts their edit; resolve re-runs the verifier
    # (a stored APPROVED verdict is audit history only, never trusted)
    # and the approval lands the junior's work.
    (repo / "README.md").write_text("repo\n", encoding="utf-8")
    verifier = _RecordingVerifier(VerificationVerdict.APPROVED)
    result = DelegationRunner(locks, junior_command=[]).resolve_pending("wt-conflict", verifier)
    assert verifier.called
    assert result.state is DelegationState.COMPLETE
    assert (repo / "README.md").read_text(encoding="utf-8") == "junior edit\n"
    assert not (locks / "wt-conflict.pending.json").exists()


def test_copy_back_refuses_drifted_worktree_file(tmp_path: Path) -> None:
    # Round 5, arch A5: a worktree file whose bytes moved after
    # verification (a surviving junior grandchild rewriting it) is
    # refused instead of landing bytes the senior never saw.
    import mcp_guard.delegation as delegation_module

    repo = tmp_path / "repo"
    worktree = tmp_path / "worktree"
    repo.mkdir()
    worktree.mkdir()
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    (worktree / "file.txt").write_text("junior\n", encoding="utf-8")
    runner = DelegationRunner(tmp_path / "locks", junior_command=[])
    audit_log = DelegationAuditLog(tmp_path / "locks" / "audit.jsonl")
    base_sha = delegation_module._file_sha256(repo / "file.txt")
    junior_sha = delegation_module._file_sha256(worktree / "file.txt")
    changes = (("M", "file.txt", None, junior_sha),)
    runner._copy_back(worktree, repo, changes, audit_log, "drift-1", {"file.txt": base_sha})
    assert (repo / "file.txt").read_text(encoding="utf-8") == "junior\n"
    (worktree / "file.txt").write_text("tampered\n", encoding="utf-8")
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    with pytest.raises(DelegationError, match="drift"):
        runner._copy_back(worktree, repo, changes, audit_log, "drift-1", {"file.txt": base_sha})
    assert (repo / "file.txt").read_text(encoding="utf-8") == "base\n"


def test_git_failure_at_change_collection_is_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Round 5, arch A6: when the directory IS a repo, a git failure at
    # change collection is a loud error, not an empty change set a
    # verifier could approve. Without a repo the empty result stands.
    import mcp_guard.delegation as delegation_module

    runner = DelegationRunner(tmp_path / "locks", junior_command=[])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    def _failing_git(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="fatal: bad")

    monkeypatch.setattr(delegation_module.subprocess, "run", _failing_git)
    with pytest.raises(DelegationError, match="change collection failed"):
        runner._collect_changes(repo, {}, lock_dir=tmp_path / "locks")
    plain = tmp_path / "plain"
    plain.mkdir()
    assert runner._collect_changes(plain, {}, lock_dir=tmp_path / "locks") == ()


def test_lock_reclaim_is_mutually_exclusive_under_concurrency(tmp_path: Path) -> None:
    # Round 5, arch A7: two concurrent reclaimers of the same stale
    # lock must never both hold it. The original check-then-unlink
    # let the second reclaimer unlink the first's fresh lock; the
    # re-read before unlink plus the post-create inode verify did not
    # close it under barrier lockstep (both re-read before either
    # created). The kernel arbiter (flock / named mutex) does: the
    # stale file is never unlinked by an acquirer.
    import mcp_guard.delegation as delegation_module

    locks = tmp_path / "locks"
    locks.mkdir()
    guard = LoopGuard(locks)
    audit_log = DelegationAuditLog(locks / "audit.jsonl")
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    dead_pid = dead.pid
    assert not delegation_module._pid_alive(dead_pid)
    violations: list[str] = []
    for _ in range(10):
        (locks / "race-1.delegation.lock").write_text(str(dead_pid), encoding="utf-8")
        current = [0]
        max_seen = [0]
        barrier = threading.Barrier(2)

        def _attempt(
            barrier: threading.Barrier = barrier,
            current: list[int] = current,
            max_seen: list[int] = max_seen,
        ) -> None:
            barrier.wait(timeout=5)
            try:
                with guard._locked("race-1", audit_log):
                    current[0] += 1
                    max_seen[0] = max(max_seen[0], current[0])
                    time.sleep(0.005)
                    current[0] -= 1
            except LoopRefusedError:
                pass

        threads = [threading.Thread(target=_attempt) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        if max_seen[0] > 1:
            violations.append(f"two holders in one round (max {max_seen[0]})")
    assert not violations


class _MutatingVerifier:
    """A verifier that calls apply_verdict on the result it receives."""

    def __init__(self) -> None:
        self.called = False

    def verify(self, result: DelegationResult) -> VerificationVerdict:
        self.called = True
        result.apply_verdict(VerificationVerdict.APPROVED)
        return VerificationVerdict.APPROVED


def test_verifier_receives_a_snapshot_not_the_live_result(tmp_path: Path) -> None:
    # Round 5, arch A9: a programmatic verifier that mutates its
    # argument used to break delegate()'s control flow (its own
    # apply_verdict raised on the live result, before the worktree
    # was discarded, leaking the staging). It now gets a copy: its
    # apply_verdict raises on the staged snapshot instead, delegate()
    # treats it as a raising verifier, and the outcome is a clean
    # REJECTED with the staging discarded — fail-closed, never a crash
    # or a leak.
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import sys; open('junior-note.txt', 'w').write(sys.stdin.read())",
    ]
    verifier = _MutatingVerifier()
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="refactor this",
        delegation_id="wt-snap",
        junior_command=junior,
        verifier=verifier,
        repo_dir=repo,
    )
    assert verifier.called
    assert result.state is DelegationState.REJECTED
    assert "verifier raised" in (result.rejection_reason or "")
    assert not (repo / "junior-note.txt").exists()
    assert not (tmp_path / "locks" / "wt-snap.worktree").exists()


def test_secret_kinds_are_in_the_summary(tmp_path: Path) -> None:
    # Round 5, arch A10: the secret-shape kinds are on the
    # machine-readable summary, so the crossing is visible even under
    # --quiet, where the stderr warning is suppressed.
    token = "sk-" + "a" * 12
    result = _delegate(tmp_path, prompt=f"use {token} to call the api", delegation_id="sec-1")
    assert result.secret_shape_kinds == frozenset({"api_token"})
    assert result.to_summary()["secret_shape_kinds"] == ["api_token"]


def test_secret_shape_check_covers_description(tmp_path: Path) -> None:
    # Round 5, product A8: the contract description is forwarded
    # verbatim alongside the prompt, so a token pasted into it must
    # warn just like one in the prompt.
    token = "sk-" + "b" * 12
    text = AGENT_NONE.replace(
        "description: Delegates mechanical refactors to the junior.",
        f"description: Uses {token} for the refactor.",
    )
    result = _delegate(tmp_path, contract_text=text, delegation_id="sec-desc")
    assert result.secret_shape_kinds == frozenset({"api_token"})
    events = _audit_events(tmp_path)
    warned = [e for e in events if e["kind"] == "secret_shape_warned"]
    assert len(warned) == 1
    assert token not in (tmp_path / "locks" / "audit.jsonl").read_text(encoding="utf-8")


def test_empty_list_item_is_parse_error() -> None:
    # Round 5, impl A7: a "- " line stores an empty-string tool, and
    # is_tool_allowed("") used to return True for it.
    text = "---\nname: reviewer\ndescription: Reviews diffs.\ntools:\n  - \n---\nBody.\n"
    with pytest.raises(FrontmatterParseError, match="empty list item"):
        DelegationContract.from_text(text)


def test_from_mapping_native_types_are_uniform() -> None:
    # Round 5, impl A7: from_mapping used to silently default a
    # natively-typed max_turns int while rejecting a native-bool
    # background. Native types are now honored or rejected uniformly.
    base = {"name": "reviewer", "description": "Reviews diffs."}
    assert DelegationContract.from_mapping({**base, "max_turns": 10}).max_turns == 10
    with pytest.raises(ContractRejectedError):
        DelegationContract.from_mapping({**base, "max_turns": True})
    with pytest.raises(ContractRejectedError):
        DelegationContract.from_mapping({**base, "max_turns": "ten"})
    assert DelegationContract.from_mapping({**base, "background": False}).background is False
    with pytest.raises(ContractRejectedError):
        DelegationContract.from_mapping({**base, "background": True})
    with pytest.raises(ContractRejectedError):
        DelegationContract.from_mapping({**base, "permission_mode": 5})


def test_four_space_list_indent_is_accepted() -> None:
    # Round 5, product A10: real agent files indent lists by four
    # spaces; the parser used to fail those with a misleading "no ':'"
    # error.
    text = "---\nname: reviewer\ndescription: Reviews diffs.\ntools:\n    - Bash\n    - Read\n---\nBody.\n"
    assert DelegationContract.from_text(text).tools == ("bash", "read")


def test_post_kill_drain_gives_up_on_escaping_grandchild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Round 5, impl A9: a setsid-escaping grandchild holding the output
    # pipes open used to hang delegate() forever after the kill. The
    # drain is bounded now: the TIMEOUT result arrives on time.
    import mcp_guard.delegation as delegation_module

    monkeypatch.setattr(delegation_module, "_POST_KILL_DRAIN_TIMEOUT", 0.5)
    junior = [
        sys.executable,
        "-c",
        (
            "import subprocess, sys; subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(30)'], stdout=sys.stdout, "
            "stderr=sys.stderr, start_new_session=True)"
        ),
    ]
    started = time.monotonic()
    result = _delegate(
        tmp_path,
        prompt="Fix the lint.",
        delegation_id="drain-1",
        junior_command=junior,
        junior_timeout=1.0,
    )
    elapsed = time.monotonic() - started
    assert result.state is DelegationState.TIMEOUT
    assert elapsed < 10


def test_audit_write_failure_still_delegates(tmp_path: Path) -> None:
    # Round 5, product A7: a failed audit write is best-effort by
    # design — the delegation proceeds anyway.
    locks = tmp_path / "locks"
    (locks / "audit.jsonl").mkdir(parents=True)
    result = _delegate(tmp_path, prompt="Fix the lint.", delegation_id="audit-fail-1")
    assert result.state is DelegationState.PENDING_VERIFICATION


def test_lock_dir_equal_to_repo_root_excludes_guard_state(tmp_path: Path) -> None:
    # Round 5, impl A6: with --lock-dir equal to the repo root, the
    # audit log, contract file, and lock file used to be collected as
    # junior changes and vacuously satisfy the diff preconditions.
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import sys; open('note.txt', 'w').write('x'); sys.stdout.write(sys.stdin.read())",
    ]
    runner = DelegationRunner(repo, junior_command=junior)
    result = runner.delegate(
        contract=_contract(AGENT_NONE),
        delegation_id="root-lock-1",
        task=TaskKind.LINT_FIX,
        prompt="Fix the lint.",
        repo_dir=repo,
    )
    assert result.state is DelegationState.PENDING_VERIFICATION
    assert result.changed_files == ("note.txt",)


def test_verifier_runs_with_repo_dir_as_cwd(tmp_path: Path) -> None:
    # Round 5, product A5: the verifier receives the deliverable, so it
    # must run where the changed paths resolve — a verifier reading a
    # changed file by relative path approves only when cwd is the repo.
    repo = _git_repo(tmp_path)
    verifier_script = tmp_path / "verifier.py"
    verifier_script.write_text(
        "import sys\ntry:\n    open('note.txt').read()\nexcept OSError:\n    sys.exit(1)\n",
        encoding="utf-8",
    )
    junior = [sys.executable, "-c", "open('note.txt', 'w').write('x')"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT_NONE,
        task=TaskKind.LINT_FIX,
        prompt="Fix the lint.",
        delegation_id="ver-cwd-1",
        junior_command=junior,
        verifier=CommandVerifier(f"{sys.executable} {verifier_script}"),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.repo_dir == str(repo)


def test_cli_resolve_pending_approves(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Round 5, arch B2 (CLI): a pending delegation resolves through
    # `delegate --resolve-pending` with exit 0 and the work landed.
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 2
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "pending_verification"
    delegation_id = summary["delegation_id"]
    main(
        [
            "delegate",
            "--resolve-pending",
            delegation_id,
            "--verify-command",
            "true",
            "--lock-dir",
            str(tmp_path / "locks"),
            "--repo-dir",
            str(repo),
        ]
    )
    resolved = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert resolved["state"] == "complete"
    assert (repo / "note.txt").exists()


def test_cli_resolve_pending_needs_verifier_and_record(tmp_path: Path) -> None:
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["delegate", "--resolve-pending", "no-such-id"])
    assert exc.value.code == 1
    agent, prompt, repo = _write_cli_inputs_in_repo(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--resolve-pending",
                "agent-lint_fix-00000000",
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
            ]
        )
    assert exc.value.code == 1


def test_cli_only_first_double_dash_is_stripped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Round 5, impl A8: a "--" that is a legitimate junior argument
    # (here: a separator the junior itself is told to echo) used to be
    # stripped with every other "--" in the junior command.
    agent, prompt = _write_cli_inputs(tmp_path)
    from mcp_guard.cli import main

    junior_code = "import sys, json; sys.stdout.write(json.dumps(sys.argv[1:]))"
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "diff_review",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--no-repo-dir",
                "--",
                sys.executable,
                "-c",
                junior_code,
                "--",
                "extra",
            ]
        )
    assert exc.value.code == 2
    captured = capsys.readouterr()
    summary = json.loads(captured.out.strip().splitlines()[-1])
    argv = json.loads(summary["junior_stdout"])
    # For `python -c <code> -- extra`, sys.argv[1:] is ["--", "extra"]:
    # the first "--" (the CLI separator) was dropped, the junior's own
    # "--" reached its argv. The old code stripped every "--", so the
    # junior would have seen ["extra"] with no separator at all.
    assert argv == ["--", "extra"]


def test_cli_junior_echo_is_bounded(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Round 5, product A9: the CLI echoed the junior's raw, unbounded
    # output to stderr; a runaway junior could flood the terminal.
    agent, prompt = _write_cli_inputs(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "diff_review",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--no-repo-dir",
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('x' * 20000)",
            ]
        )
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "[... truncated" in captured.err
    assert len(captured.err) < 20000


# --- Fix-forward round 6 (critique 5 on head 45887ad4) -----------------------


def test_spawn_failure_removes_worktree(tmp_path: Path) -> None:
    # Round 6, impl B1: a junior spawn failure in worktree mode must not
    # strand the worktree the delegation just created.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    with pytest.raises(DelegationError, match="junior spawn failed"):
        _delegate(
            tmp_path,
            contract_text=AGENT,  # isolation: worktree
            task=TaskKind.MECHANICAL_REFACTOR,
            prompt="refactor this",
            delegation_id="spawn-fail-wt",
            junior_command=["definitely-not-a-real-binary-xyz"],
            repo_dir=repo,
        )
    assert not (locks / "spawn-fail-wt.worktree").exists()


def test_collect_changes_failure_removes_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Round 6, impl B2: a change-collection failure after the junior ran
    # must not strand the worktree holding unverified work.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"

    def _boom(self: object, *args: object, **kwargs: object) -> None:
        raise DelegationError("boom")

    monkeypatch.setattr(DelegationRunner, "_collect_changes", _boom)
    with pytest.raises(DelegationError, match="boom"):
        _delegate(
            tmp_path,
            contract_text=AGENT,  # isolation: worktree
            task=TaskKind.MECHANICAL_REFACTOR,
            prompt="refactor this",
            delegation_id="collect-fail-wt",
            junior_command=[sys.executable, "-c", "open('note.txt', 'w').write('x')"],
            repo_dir=repo,
        )
    assert not (locks / "collect-fail-wt.worktree").exists()


def test_pid_alive_overflow_is_fail_closed() -> None:
    # Round 6, impl B3: a corrupt lock naming a pid that does not fit in
    # pid_t must refuse fail-closed (alive), never crash the probe.
    assert _pid_alive(9_999_999_999) is True


def test_cli_non_utf8_contract_file_exits_1(tmp_path: Path) -> None:
    # Round 6, impl B4: a non-UTF-8 contract file is an unreadable file
    # and must exit 1 cleanly, never traceback out of main().
    agent = tmp_path / "agent.md"
    agent.write_bytes(b"\xff\xfe not utf-8 \n")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--",
                sys.executable,
                "-c",
                "pass",
            ]
        )
    assert exc.value.code == 1


def _forge_pending_verdict(tmp_path: Path, delegation_id: str, verdict: str) -> None:
    path = tmp_path / "locks" / f"{delegation_id}.pending.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["verdict"] = verdict
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")


def test_resolve_pending_ignores_forged_stored_verdict(tmp_path: Path) -> None:
    # Round 6, arch B1: the pending record lives in the lock directory
    # the junior can reach, so a forged APPROVED verdict in it must not
    # land anything — the senior verifier always re-runs.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    junior = [sys.executable, "-c", "open('note.txt', 'w').write('x')"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="edit the readme",
        delegation_id="forged-1",
        junior_command=junior,
        repo_dir=repo,
    )
    assert result.state is DelegationState.PENDING_VERIFICATION
    _forge_pending_verdict(tmp_path, "forged-1", "approved")
    rejecter = _RecordingVerifier(VerificationVerdict.REJECTED)
    resolved = DelegationRunner(locks, junior_command=[]).resolve_pending("forged-1", rejecter)
    assert rejecter.called
    assert resolved.state is DelegationState.REJECTED
    assert not (repo / "note.txt").exists()
    assert not (locks / "forged-1.worktree").exists()
    assert not (locks / "forged-1.pending.json").exists()

    # And a forged record with a genuinely approving verifier still lands
    # — because the verifier approved, not because the file said so.
    _delegate(
        tmp_path,
        contract_text=AGENT,
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="edit the readme",
        delegation_id="forged-2",
        junior_command=junior,
        repo_dir=repo,
    )
    _forge_pending_verdict(tmp_path, "forged-2", "approved")
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    resolved = DelegationRunner(locks, junior_command=[]).resolve_pending("forged-2", approver)
    assert approver.called
    assert resolved.state is DelegationState.COMPLETE
    assert (repo / "note.txt").read_text(encoding="utf-8") == "x"


def test_copy_back_refuses_preexisting_dirt(tmp_path: Path) -> None:
    # Round 6, arch B2: the conflict baseline is HEAD, not the dirty
    # working tree — a file the operator dirtied before setup and the
    # junior then edited must refuse, not silently overwrite the
    # operator's uncommitted work.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    (repo / "README.md").write_text("operator dirty\n", encoding="utf-8")
    junior = [sys.executable, "-c", "open('README.md', 'w').write('junior edit\\n')"]
    with pytest.raises(DelegationError, match="copy-back conflict"):
        _delegate(
            tmp_path,
            contract_text=AGENT,  # isolation: worktree
            task=TaskKind.MECHANICAL_REFACTOR,
            prompt="edit the readme",
            delegation_id="pre-dirt",
            junior_command=junior,
            verifier=_RecordingVerifier(VerificationVerdict.APPROVED),
            repo_dir=repo,
        )
    assert (repo / "README.md").read_text(encoding="utf-8") == "operator dirty\n"
    assert (locks / "pre-dirt.worktree").exists()
    assert (locks / "pre-dirt.pending.json").exists()


def test_pending_record_blocks_redelegation_in_none_mode(tmp_path: Path) -> None:
    # Round 6, arch B3: the pending obligation is durable in every
    # isolation mode — a fresh delegation with the same id in
    # isolation none must refuse while the first is still pending.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    first = _delegate(
        tmp_path,
        contract_text=AGENT_NONE,
        task=TaskKind.LINT_FIX,
        prompt="Fix the lint.",
        delegation_id="none-clash",
        junior_command=[sys.executable, "-c", "open('note.txt', 'w').write('x')"],
        repo_dir=repo,
    )
    assert first.state is DelegationState.PENDING_VERIFICATION
    assert (locks / "none-clash.pending.json").exists()
    with pytest.raises(DelegationError, match="pending delegation"):
        _delegate(
            tmp_path,
            contract_text=AGENT_NONE,
            task=TaskKind.LINT_FIX,
            prompt="Fix the lint again.",
            delegation_id="none-clash",
            repo_dir=repo,
        )
    assert (locks / "none-clash.pending.json").exists()


def test_timeout_in_none_mode_writes_pending_record(tmp_path: Path) -> None:
    # Round 6, arch B3: a timeout in isolation none leaves partial
    # writes in the operator tree, so the verification obligation must
    # survive as a pending record the senior can still discharge.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    junior = [
        sys.executable,
        "-c",
        "import time; open('slow.txt', 'w').write('x'); time.sleep(30)",
    ]
    result = _delegate(
        tmp_path,
        contract_text=AGENT_NONE,
        task=TaskKind.LINT_FIX,
        prompt="Fix the lint.",
        delegation_id="none-timeout",
        junior_command=junior,
        repo_dir=repo,
        junior_timeout=0.2,
    )
    assert result.state is DelegationState.TIMEOUT
    pending_path = locks / "none-timeout.pending.json"
    assert pending_path.exists()
    record = json.loads(pending_path.read_text(encoding="utf-8"))
    assert record["timed_out"] is True
    assert "slow.txt" in record["changed_files"]
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    resolved = DelegationRunner(locks, junior_command=[]).resolve_pending("none-timeout", approver)
    assert approver.called
    assert resolved.state is DelegationState.COMPLETE
    assert (repo / "slow.txt").read_text(encoding="utf-8") == "x"
    assert not pending_path.exists()


def test_verifier_runs_in_worktree(tmp_path: Path) -> None:
    # Round 6, arch B4: in worktree mode the deliverable lives only in
    # the worktree, so the verifier must run there — a verifier reading
    # a changed file by relative path approves only when cwd is the
    # worktree, not the pre-delegation main tree.
    repo = _git_repo(tmp_path)
    verifier_script = tmp_path / "verifier.py"
    verifier_script.write_text(
        "import sys\ntry:\n    open('note.txt').read()\nexcept OSError:\n    sys.exit(1)\n",
        encoding="utf-8",
    )
    junior = [sys.executable, "-c", "open('note.txt', 'w').write('x')"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.LINT_FIX,
        prompt="Fix the lint.",
        delegation_id="ver-cwd-wt",
        junior_command=junior,
        verifier=CommandVerifier(f"{sys.executable} {verifier_script}"),
        repo_dir=repo,
    )
    assert result.state is DelegationState.COMPLETE
    assert result.worktree_path is None
    assert (repo / "note.txt").read_text(encoding="utf-8") == "x"


def test_preset_verification_rejected_at_construction() -> None:
    # Round 6, arch A12: a freshly constructed result cannot carry a
    # preset verification — only apply_verdict sets it.
    with pytest.raises(ValueError, match="preset verification"):
        DelegationResult(
            delegation_id="pv-1",
            task=TaskKind.LINT_FIX,
            effective_effort=Effort.LOW,
            verification_step=VerificationStep.CHECK_EXIT_AND_DIFF,
            verification=VerificationVerdict.APPROVED,
        )


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_cli_timeout_nan_inf_exits_1(tmp_path: Path, value: str) -> None:
    # Round 6, impl A6: --timeout nan/inf would silently disable the
    # junior timeout, so the flag validation must refuse them.
    agent, prompt = _write_cli_inputs(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                f"--timeout={value}",
                "--",
                sys.executable,
                "-c",
                "pass",
            ]
        )
    assert exc.value.code == 1


def test_non_utf8_lock_file_refuses_fail_closed(tmp_path: Path) -> None:
    # Round 6, impl F1 (critique-6 re-review): a lock file that is not
    # valid UTF-8 is corrupt input, and a corrupt lock must refuse
    # fail-closed — never crash the probe with a UnicodeDecodeError.
    locks = tmp_path / "locks"
    locks.mkdir()
    (locks / "bad-lock.delegation.lock").write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(LoopRefusedError, match="lock unreadable"):
        _delegate(
            tmp_path,
            contract_text=AGENT_NONE,
            task=TaskKind.LINT_FIX,
            prompt="Fix the lint.",
            delegation_id="bad-lock",
        )


# --- Fix-forward round 7 (critique-6 arch/product FAILs) --------------------


def _tamper_pending_record(tmp_path: Path, delegation_id: str, **updates: object) -> None:
    path = tmp_path / "locks" / f"{delegation_id}.pending.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record.update(updates)
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")


def test_resolve_pending_ignores_forged_change_paths(tmp_path: Path) -> None:
    # Round 7, arch F1: the record's change list is never trusted — a
    # forged path escaping the tree must refuse, never copy/delete
    # an arbitrary file through _copy_back.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    outside = tmp_path / "outside.txt"
    outside.write_text("do not touch\n", encoding="utf-8")
    junior = [sys.executable, "-c", "open('note.txt', 'w').write('x')"]
    _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="edit the readme",
        delegation_id="forged-paths",
        junior_command=junior,
        repo_dir=repo,
    )
    _tamper_pending_record(
        tmp_path,
        "forged-paths",
        changes=[["M", "../outside.txt", None, "0" * 64]],
    )
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    with pytest.raises(DelegationError, match="escapes the tree"):
        DelegationRunner(locks, junior_command=[]).resolve_pending("forged-paths", approver)
    assert not approver.called
    assert outside.read_text(encoding="utf-8") == "do not touch\n"
    assert (locks / "forged-paths.pending.json").exists()
    assert (locks / "forged-paths.worktree").exists()


def test_resolve_pending_recomputes_head_baseline(tmp_path: Path) -> None:
    # Round 7, arch F1: the HEAD baseline is recomputed from live git
    # at resolve time — a forged snapshot blessing the operator's
    # current dirty bytes must not let copy-back overwrite them.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    junior = [sys.executable, "-c", "open('README.md', 'w').write('junior edit\\n')"]
    _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="edit the readme",
        delegation_id="forged-snap",
        junior_command=junior,
        repo_dir=repo,
    )
    # The operator dirties README after the delegation ran; the forger
    # then rewrites the stored snapshot to bless those exact bytes.
    (repo / "README.md").write_text("operator dirty\n", encoding="utf-8")
    forged = hashlib.sha256(b"operator dirty\n").hexdigest()
    _tamper_pending_record(tmp_path, "forged-snap", main_snapshot={"README.md": forged})
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    with pytest.raises(DelegationError, match="copy-back conflict"):
        DelegationRunner(locks, junior_command=[]).resolve_pending("forged-snap", approver)
    assert approver.called
    assert (repo / "README.md").read_text(encoding="utf-8") == "operator dirty\n"
    assert (locks / "forged-snap.worktree").exists()
    assert (locks / "forged-snap.pending.json").exists()


def test_resolve_pending_rejects_stale_change_list(tmp_path: Path) -> None:
    # Round 7, arch F1: the change list is re-derived from the live
    # worktree — a record whose stored list is empty still lands the
    # work the junior actually did, because the verifier judged it.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    junior = [sys.executable, "-c", "open('note.txt', 'w').write('x')"]
    _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="edit the readme",
        delegation_id="stale-list",
        junior_command=junior,
        repo_dir=repo,
    )
    _tamper_pending_record(tmp_path, "stale-list", changes=[])
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    result = DelegationRunner(locks, junior_command=[]).resolve_pending("stale-list", approver)
    assert approver.called
    assert result.state is DelegationState.COMPLETE
    assert result.changed_files == ("note.txt",)
    assert (repo / "note.txt").read_text(encoding="utf-8") == "x"


def test_resolve_pending_refuses_forged_worktree_path(tmp_path: Path) -> None:
    # Round 7, arch F1: a worktree path outside the lock directory is
    # refused — the verifier must never run with cwd in a forger's tree.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "note.txt").write_text("forged\n", encoding="utf-8")
    junior = [sys.executable, "-c", "open('note.txt', 'w').write('x')"]
    _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="edit the readme",
        delegation_id="forged-wt",
        junior_command=junior,
        repo_dir=repo,
    )
    _tamper_pending_record(tmp_path, "forged-wt", worktree=str(evil))
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    with pytest.raises(DelegationError, match="outside the lock directory"):
        DelegationRunner(locks, junior_command=[]).resolve_pending("forged-wt", approver)
    assert not approver.called
    assert not (repo / "note.txt").exists()


def test_resolve_pending_refuses_vanished_worktree(tmp_path: Path) -> None:
    # Round 7, product A3: a vanished worktree is a lost deliverable,
    # not a judged rejection — resolve raises and keeps the record.
    import shutil

    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    junior = [sys.executable, "-c", "open('note.txt', 'w').write('x')"]
    _delegate(
        tmp_path,
        contract_text=AGENT,  # isolation: worktree
        task=TaskKind.MECHANICAL_REFACTOR,
        prompt="edit the readme",
        delegation_id="gone-wt",
        junior_command=junior,
        repo_dir=repo,
    )
    shutil.rmtree(locks / "gone-wt.worktree")
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    with pytest.raises(DelegationError, match="worktree is gone"):
        DelegationRunner(locks, junior_command=[]).resolve_pending("gone-wt", approver)
    assert not approver.called
    assert (locks / "gone-wt.pending.json").exists()


def test_resolve_pending_runs_step_precondition_on_timeout(tmp_path: Path) -> None:
    # Round 7, arch F2: a timeout record whose artifacts cannot satisfy
    # its step is rejected without consulting the verifier — the senior
    # never judges a delegation the in-run path would have refused.
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    junior = [sys.executable, "-c", "import time; time.sleep(30)"]
    result = _delegate(
        tmp_path,
        contract_text=AGENT_NONE,
        task=TaskKind.LINT_FIX,
        prompt="Fix the lint.",
        delegation_id="timeout-precond",
        junior_command=junior,
        repo_dir=repo,
        junior_timeout=0.2,
    )
    assert result.state is DelegationState.TIMEOUT
    assert (locks / "timeout-precond.pending.json").exists()
    approver = _RecordingVerifier(VerificationVerdict.APPROVED)
    resolved = DelegationRunner(locks, junior_command=[]).resolve_pending(
        "timeout-precond", approver
    )
    assert not approver.called
    assert resolved.state is DelegationState.REJECTED
    assert resolved.rejection_reason is not None
    assert "check_exit_and_diff" in resolved.rejection_reason
    assert not (locks / "timeout-precond.pending.json").exists()


def test_cli_worktree_default_journey(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Round 7, product B1: the default operator journey through the
    # actual CLI — default (worktree) contract, delegate exits 2 with
    # nothing landed, --resolve-pending lands the work and removes
    # the worktree.
    agent = tmp_path / "agent.md"
    agent.write_text(AGENT, encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    repo = _git_repo(tmp_path)
    locks = tmp_path / "locks"
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(locks),
                "--repo-dir",
                str(repo),
                "--",
                sys.executable,
                "-c",
                _CLI_JUNIOR_WRITES_FILE,
            ]
        )
    assert exc.value.code == 2
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "pending_verification"
    delegation_id = summary["delegation_id"]
    assert summary["worktree_path"] is not None
    assert not (repo / "note.txt").exists()
    assert Path(summary["worktree_path"]).exists()
    main(
        [
            "delegate",
            "--resolve-pending",
            delegation_id,
            "--verify-command",
            "true",
            "--lock-dir",
            str(locks),
            "--repo-dir",
            str(repo),
        ]
    )
    resolved = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert resolved["state"] == "complete"
    assert (repo / "note.txt").read_text(encoding="utf-8") == "x"
    assert not Path(summary["worktree_path"]).exists()
    assert not (locks / f"{delegation_id}.pending.json").exists()


def test_cli_timeout_in_none_mode_names_resolve(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Round 7, product A1: a timeout that leaves a durable pending
    # record must tell the operator the resolve command at the moment
    # it matters, not only in the docs.
    agent, prompt = _write_cli_inputs(tmp_path)
    repo = _git_repo(tmp_path)
    from mcp_guard.cli import main

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "delegate",
                "--contract",
                str(agent),
                "--task",
                "lint_fix",
                "--prompt-file",
                str(prompt),
                "--lock-dir",
                str(tmp_path / "locks"),
                "--repo-dir",
                str(repo),
                "--timeout",
                "0.2",
                "--",
                sys.executable,
                "-c",
                "import time; open('slow.txt', 'w').write('x'); time.sleep(30)",
            ]
        )
    assert exc.value.code == 1
    # The hint is a log line (basicConfig is a no-op under pytest's
    # own logging setup, so capsys never sees it): assert on the
    # captured log records instead.
    assert any("--resolve-pending" in record.message for record in caplog.records)
    captured = capsys.readouterr()
    summary = json.loads(captured.out.strip().splitlines()[-1])
    assert summary["state"] == "timeout"
