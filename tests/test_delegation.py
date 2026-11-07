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
    _parse_porcelain_z,
    _pid_alive,
    parse_frontmatter,
    route_for,
    sanitize_delegation_id,
)

AGENT = """---
name: codex-refactor
description: Delegates mechanical refactors to the junior.
tools:
  - Bash
  - Read
denied_tools:
  - Bash
model: sonnet
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
    assert contract.name == "codex-refactor"
    assert contract.description.startswith("Delegates mechanical")
    assert contract.tools == ("bash", "read")
    assert contract.denied_tools == ("bash",)
    assert contract.model == "sonnet"
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
    assert contract.isolation is Isolation.NONE
    assert contract.effort is None  # inherits the routed task kind's effort
    assert contract.max_turns == 25
    assert contract.memory is MemoryScope.NONE
    assert contract.model == "inherit"


def test_parse_frontmatter_returns_the_field_map() -> None:
    fields = parse_frontmatter(AGENT)
    assert fields["name"] == "codex-refactor"
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
    assert body["name"] == "codex-refactor"
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
    assert body["name"] == "codex-refactor"
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
    assert body["name"] == "codex-refactor"


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
        repo_dir=repo,
    )
    assert result.changed_files == ("junior-note.txt",)
    # The deliverable lands in the main tree for senior review.
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
        repo_dir=repo,
    )
    assert result.changed_files == ("README.md",)
    assert not (repo / "README.md").exists()


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
    # still prune + remove the directory) rather than leak it.
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
    assert result.state is DelegationState.PENDING_VERIFICATION
    failed = [
        e
        for e in _audit_events(tmp_path)
        if e["kind"] == DelegationAuditKind.WORKTREE_CLEANUP_FAILED.value
    ]
    assert len(failed) == 1
    assert not (tmp_path / "locks" / "wt-3.worktree").exists()


def test_porcelain_z_parses_renames_and_spaces() -> None:
    assert _parse_porcelain_z("R  old.txt\0new.txt\0") == [("R ", "new.txt")]
    assert _parse_porcelain_z("?? my file.txt\0") == [("??", "my file.txt")]
    assert _parse_porcelain_z(" M changed.py\0") == [(" M", "changed.py")]
    assert _parse_porcelain_z("") == []


# --- CLI -----------------------------------------------------------------------


def _write_cli_inputs(tmp_path: Path, contract_text: str = AGENT_NONE) -> tuple[Path, Path]:
    agent = tmp_path / "agent.md"
    agent.write_text(contract_text, encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    return agent, prompt


def test_cli_pending_without_verifier_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
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
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.write(sys.stdin.read())",
            ]
        )
    assert exc.value.code == 2
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "pending_verification"
    assert summary["delegation_id"].startswith("agent-lint_fix-")
    assert summary["task"] == "lint_fix"
    assert summary["effective_effort"] == "medium"
    assert summary["verification_step"] == "check_exit_and_diff"
    assert summary["changed_files"] == []


def test_cli_verify_command_approves(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    agent, prompt = _write_cli_inputs(tmp_path)
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
            "--verify-command",
            "true",
            "--",
            sys.executable,
            "-c",
            "import sys; sys.stdout.write(sys.stdin.read())",
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
                "--delegation-id",
                "custom-1",
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.write(sys.stdin.read())",
            ]
        )
    assert exc.value.code == 2
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["delegation_id"] == "custom-1"


def test_cli_allow_env_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, prompt = _write_cli_inputs(tmp_path)
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
                "--allow-env",
                "MY_FLAG",
                "--",
                sys.executable,
                "-c",
                "import os, sys; sys.stdout.write(os.environ.get('MY_FLAG', 'missing'))",
            ]
        )
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "hello" in err  # junior output is echoed to stderr


def test_cli_echoes_junior_output_on_rejection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
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
                "--verify-command",
                "false",
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('junior said this')",
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
                "--verify-command",
                f'{sys.executable} -c "import time; time.sleep(5)"',
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.write(sys.stdin.read())",
            ]
        )
    assert exc.value.code == 1
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "rejected"
