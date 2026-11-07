"""Adversarial tests for the delegation protocol (rat #67).

Every acceptance criterion from the issue is pinned by a failing-first
test: contract rejection, all three loop-prevention layers, secret
scrubbing before the handoff, and mandatory senior verification.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
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
    Effort,
    FrontmatterParseError,
    Isolation,
    LoopGuard,
    LoopLayer,
    LoopRefusedError,
    MemoryScope,
    PermissionMode,
    TaskKind,
    VerificationError,
    VerificationVerdict,
    parse_frontmatter,
    route_for,
)
from mcp_guard.delegation import DelegationState as State

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


def _runner(tmp_path: Path, **kwargs: object) -> DelegationRunner:
    return DelegationRunner(tmp_path / "locks", **kwargs)  # type: ignore[arg-type]


def _delegate(tmp_path: Path, prompt: str = "Fix the lint.", **kwargs: object) -> DelegationResult:
    contract_text = str(kwargs.pop("contract_text", AGENT_NONE))
    return _runner(tmp_path).delegate(
        contract_text=contract_text,
        task_kind=TaskKind.LINT_FIX,
        prompt=prompt,
        delegation_id="test-1",
        junior_command=ECHO_JUNIOR,
        **kwargs,  # type: ignore[arg-type]
    )


# --- Frontmatter parsing -----------------------------------------------------


def test_valid_contract_parses_all_fields() -> None:
    contract = parse_frontmatter(AGENT)
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
    contract = parse_frontmatter("---\nname: reviewer\ndescription: Reviews diffs.\n---\nBody.\n")
    assert contract.tools == ()
    assert contract.denied_tools == ()
    assert contract.permission_mode is PermissionMode.DEFAULT
    assert contract.isolation is Isolation.NONE
    assert contract.effort is Effort.MEDIUM
    assert contract.max_turns == 25
    assert contract.memory is MemoryScope.NONE
    assert contract.model == "inherit"


def test_no_frontmatter_is_rejected_not_defaulted() -> None:
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("Be careful with this file.\nNo contract here.\n")


def test_verbal_be_careful_is_not_a_contract() -> None:
    # The issue's acceptance criterion, verbatim: verbal 'be careful' is
    # NOT a contract. A prompt begging for care, with no frontmatter, must
    # still be rejected.
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("Please be very careful, double-check everything.\n")


def test_unclosed_frontmatter_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("---\nname: x\ndescription: y\n")


def test_unknown_field_is_rejected_not_ignored() -> None:
    with pytest.raises(FrontmatterParseError, match="unknown frontmatter"):
        parse_frontmatter("---\nname: x\ndescription: y\nsecret_backdoor: true\n---\n")


def test_missing_name_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("---\ndescription: No name.\n---\n")


def test_missing_description_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("---\nname: x\n---\n")


def test_uppercase_name_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("---\nname: CodexRefactor\ndescription: y\n---\n")


def test_invalid_enum_value_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        parse_frontmatter("---\nname: x\ndescription: y\neffort: ludicrous\n---\n")


def test_nested_map_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        parse_frontmatter("---\nname: x\ndescription: y\nnested:\n  key: value\n---\n")


def test_duplicate_field_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError, match="duplicate"):
        parse_frontmatter("---\nname: x\nname: y\ndescription: z\n---\n")


def test_max_turns_zero_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("---\nname: x\ndescription: y\nmax_turns: 0\n---\n")


def test_max_turns_bool_is_rejected() -> None:
    with pytest.raises(ContractRejectedError):
        parse_frontmatter("---\nname: x\ndescription: y\nmax_turns: true\n---\n")


def test_inline_flow_list_is_rejected() -> None:
    with pytest.raises(FrontmatterParseError):
        parse_frontmatter("---\nname: x\ndescription: y\ntools: [Bash, Read]\n---\n")


# --- Contract enforcement ----------------------------------------------------


def test_denylist_beats_allowlist() -> None:
    contract = parse_frontmatter(AGENT)
    assert contract.is_tool_allowed("Bash") is False  # denied AND allowed
    assert contract.is_tool_allowed("Read") is True
    assert contract.is_tool_allowed("Write") is False  # not allowlisted


def test_tool_names_normalize_case_and_space() -> None:
    contract = parse_frontmatter(AGENT)
    assert contract.is_tool_allowed("  bash ") is False
    assert contract.is_tool_allowed("READ") is True


def test_empty_allowlist_allows_anything_not_denied() -> None:
    contract = DelegationContract(name="open", description="Open contract.", denied_tools=("bash",))
    assert contract.is_tool_allowed("Read") is True
    assert contract.is_tool_allowed("Bash") is False


# --- Routing matrix ----------------------------------------------------------


def test_every_task_kind_has_exactly_one_route() -> None:
    assert set(ROUTING_MATRIX) == set(TaskKind)
    for kind in TaskKind:
        route = route_for(kind)
        assert route.task_kind is kind
        assert isinstance(route.effort, Effort)


def test_routing_matrix_matches_source_table() -> None:
    assert route_for(TaskKind.LINT_FIX).effort is Effort.LOW
    assert route_for(TaskKind.COVERAGE_GAP).effort is Effort.HIGH
    assert route_for(TaskKind.MECHANICAL_REFACTOR).verification.value == ("semantic_diff_check")
    assert route_for(TaskKind.DIFF_REVIEW).verification.value == "human_reviews"


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


def test_child_env_carries_depth_marker(tmp_path: Path) -> None:
    junior = [
        sys.executable,
        "-c",
        f"import os, sys; sys.stdout.write(os.environ[{DEPTH_ENV_VAR!r}])",
    ]
    result = _runner(tmp_path).delegate(
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
        task_kind=TaskKind.LINT_FIX,
        prompt="hi",
        delegation_id="depth-1",
        junior_command=junior,
    )
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
    (lock_dir / "stale-1.lock").write_text(
        json.dumps({"pid": dead_pid, "created": datetime.now(UTC).isoformat()}),
        encoding="utf-8",
    )
    guard = LoopGuard(lock_dir)
    audit = DelegationAuditLog(tmp_path / "audit.jsonl")
    with guard.guard("stale-1", {}, audit):
        pass
    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(e["kind"] == DelegationAuditKind.LOCK_RECLAIMED.value for e in events)


def test_lock_with_live_pid_is_not_reclaimed(tmp_path: Path) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    (lock_dir / "live-1.lock").write_text(
        json.dumps({"pid": os.getpid(), "created": datetime.now(UTC).isoformat()}),
        encoding="utf-8",
    )
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


# --- Loop prevention, layer 3: audit rate-limit ------------------------------


def test_rate_limit_counts_across_runner_instances(tmp_path: Path) -> None:
    # Layer 3 is cross-process: two separate runners share the audit file,
    # so the cap must count both.
    guard = LoopGuard(tmp_path / "locks", max_delegations=2, window_seconds=60)
    for n in range(2):
        _runner(tmp_path, loop_guard=guard).delegate(
            contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
            task_kind=TaskKind.LINT_FIX,
            prompt="hi",
            delegation_id=f"rate-{n}",
            junior_command=ECHO_JUNIOR,
        )
    with pytest.raises(LoopRefusedError) as exc:
        _runner(tmp_path, loop_guard=guard).delegate(
            contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
            task_kind=TaskKind.LINT_FIX,
            prompt="hi",
            delegation_id="rate-2",
            junior_command=ECHO_JUNIOR,
        )
    assert exc.value.layer is LoopLayer.AUDIT_RATE_LIMIT


def test_old_attempts_outside_window_do_not_count(tmp_path: Path) -> None:
    audit_path = tmp_path / "locks" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    old = (datetime.now(UTC) - timedelta(seconds=3600)).isoformat()
    audit_path.write_text(
        json.dumps(
            {
                "timestamp": old,
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
                "timestamp": now,
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


# --- Secret scrubbing ----------------------------------------------------------


def test_prompt_is_scrubbed_before_the_junior_sees_it(tmp_path: Path) -> None:
    secret = "contact me at ada@example.com or call 555-123-4567"
    result = _delegate(
        tmp_path,
        prompt=secret,
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
    )
    assert "ada@example.com" not in result.junior_stdout
    assert "555-123-4567" not in result.junior_stdout
    assert result.token_count == 2
    assert result.token_kinds == ("email", "phone")


def test_audit_log_never_holds_prompt_values(tmp_path: Path) -> None:
    email = "ada@example.com"
    _delegate(
        tmp_path,
        prompt=f"reach {email}",
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
    )
    audit_text = (tmp_path / "locks" / "audit.jsonl").read_text(encoding="utf-8")
    assert email not in audit_text
    assert "EMAIL_1" in audit_text or "email" in audit_text


# --- Senior verification -------------------------------------------------------


def test_result_starts_pending_and_complete_raises(tmp_path: Path) -> None:
    result = _delegate(
        tmp_path,
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
    )
    assert result.state is State.PENDING_VERIFICATION
    with pytest.raises(VerificationError):
        result.complete()


def test_approved_verdict_completes(tmp_path: Path) -> None:
    result = _delegate(
        tmp_path,
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
    )
    result.apply_verdict(VerificationVerdict.APPROVED)
    assert result.state is State.COMPLETE
    assert result.complete() is result


def test_rejected_verdict_rejects(tmp_path: Path) -> None:
    result = _delegate(
        tmp_path,
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
    )
    result.apply_verdict(VerificationVerdict.REJECTED)
    assert result.state is State.REJECTED
    with pytest.raises(VerificationError):
        result.complete()


def test_double_verdict_raises(tmp_path: Path) -> None:
    result = _delegate(
        tmp_path,
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
    )
    result.apply_verdict(VerificationVerdict.APPROVED)
    with pytest.raises(VerificationError):
        result.apply_verdict(VerificationVerdict.APPROVED)


def test_runner_verifier_approves_and_rejects(tmp_path: Path) -> None:
    contract = AGENT.replace("isolation: worktree", "isolation: none")

    class _Approve:
        def verify(self, result: DelegationResult) -> VerificationVerdict:
            return VerificationVerdict.APPROVED

    class _Reject:
        def verify(self, result: DelegationResult) -> VerificationVerdict:
            return VerificationVerdict.REJECTED

    approved = _runner(tmp_path, verifier=_Approve()).delegate(
        contract_text=contract,
        task_kind=TaskKind.LINT_FIX,
        prompt="hi",
        delegation_id="v-approve",
        junior_command=ECHO_JUNIOR,
    )
    assert approved.state is State.COMPLETE

    rejected = _runner(tmp_path, verifier=_Reject()).delegate(
        contract_text=contract,
        task_kind=TaskKind.LINT_FIX,
        prompt="hi",
        delegation_id="v-reject",
        junior_command=ECHO_JUNIOR,
    )
    assert rejected.state is State.REJECTED


def test_command_verifier_exit_code_decides() -> None:
    result = DelegationResult(
        delegation_id="cv-1",
        task_kind=TaskKind.LINT_FIX,
        contract_name="x",
        prompt_hash="abc",
        token_kinds=(),
        token_count=0,
        junior_stdout="ok",
        junior_stderr="",
        junior_returncode=0,
    )
    assert CommandVerifier(["true"]).verify(result) is VerificationVerdict.APPROVED
    assert CommandVerifier(["false"]).verify(result) is VerificationVerdict.REJECTED


# --- Junior execution ----------------------------------------------------------


def test_empty_junior_command_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(DelegationError):
        _runner(tmp_path).delegate(
            contract_text=AGENT,
            task_kind=TaskKind.LINT_FIX,
            prompt="hi",
            delegation_id="empty-1",
            junior_command=[],
        )


def test_junior_timeout_marks_result_timeout(tmp_path: Path) -> None:
    runner = DelegationRunner(
        tmp_path / "locks",
        junior_timeout=0.2,
    )
    result = runner.delegate(
        contract_text=AGENT.replace("isolation: worktree", "isolation: none"),
        task_kind=TaskKind.LINT_FIX,
        prompt="hi",
        delegation_id="slow-1",
        junior_command=[sys.executable, "-c", "import time; time.sleep(5)"],
    )
    assert result.state is State.TIMEOUT
    assert result.junior_returncode is None


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


def test_worktree_isolation_keeps_main_tree_clean(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    junior = [
        sys.executable,
        "-c",
        "import sys; open('junior-note.txt', 'w').write(sys.stdin.read())",
    ]
    result = _runner(tmp_path).delegate(
        contract_text=AGENT,  # isolation: worktree
        task_kind=TaskKind.MECHANICAL_REFACTOR,
        prompt="refactor this",
        delegation_id="wt-1",
        junior_command=junior,
        repo_dir=repo,
    )
    assert result.changed_files == ("junior-note.txt",)
    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert status.stdout == "", "main worktree must stay clean"
    assert not (repo / "junior-note.txt").exists()
    # No worktree left behind.
    worktrees = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert worktrees.stdout.count("worktree ") == 1


def test_worktree_without_repo_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DelegationError):
        _runner(tmp_path).delegate(
            contract_text=AGENT,  # isolation: worktree, no repo_dir
            task_kind=TaskKind.LINT_FIX,
            prompt="hi",
            delegation_id="wt-norepo",
            junior_command=ECHO_JUNIOR,
        )


# --- CLI -----------------------------------------------------------------------


def test_cli_pending_without_verifier_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    agent = tmp_path / "agent.md"
    agent.write_text(AGENT.replace("isolation: worktree", "isolation: none"), encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    lock_dir = tmp_path / "locks"
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
                str(lock_dir),
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.write(sys.stdin.read())",
            ]
        )
    assert exc.value.code == 2
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["state"] == "pending_verification"


def test_cli_verify_command_approves(tmp_path: Path) -> None:
    agent = tmp_path / "agent.md"
    agent.write_text(AGENT.replace("isolation: worktree", "isolation: none"), encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    lock_dir = tmp_path / "locks"
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
            str(lock_dir),
            "--verify-command",
            "true",
            "--",
            sys.executable,
            "-c",
            "import sys; sys.stdout.write(sys.stdin.read())",
        ]
    )


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
    agent = tmp_path / "agent.md"
    agent.write_text(AGENT.replace("isolation: worktree", "isolation: none"), encoding="utf-8")
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
            ]
        )
    assert exc.value.code == 1
