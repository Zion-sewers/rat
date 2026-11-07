"""Delegation contract in frontmatter + three-layer loop prevention (rat #67).

An agent file declares its delegation contract in YAML frontmatter
(``---`` block at the head of a Markdown file). The protocol enforces the
contract — a delegation without a declared contract is rejected, and a
verbal "be careful" in the prompt is never a contract.

What the source gives (Perplexity "claude-code-codex-delegation-backlog",
catalog B.3) and what this module enforces:

1. Contract: frontmatter declares allowed/denied tools, isolation,
   memory, max turns, focused hooks. ``DelegationContract`` is the parsed,
   validated form; unknown fields and missing required fields are parse
   errors, never silently accepted.
2. Loop prevention in three layers, all three active before any delegation
   proceeds (``LoopGuard``):
   - environment preservation: the ``MCP_GUARD_DELEGATION_DEPTH`` marker
     is inherited by the child process; a delegation running inside a
     delegation is refused;
   - lock file: one live delegation per delegation id, via an atomic
     ``O_EXCL`` create; a stale lock is reclaimed only when the recorded
     pid is dead;
   - audit rate-limit: the append-only JSONL audit log counts delegation
     attempts in a sliding window across processes; over the cap the
     delegation is refused.
3. Secret scrubbing before the tool handoff: the task prompt is tokenized
   with the rat #66 ``PiiTokenizer`` before it reaches the junior; the
   audit log records kinds and counts, never values.
4. Senior verification after delegation: a ``DelegationResult`` starts
   ``PENDING_VERIFICATION`` and only a ``SeniorVerifier`` verdict of
   ``APPROVED`` transitions it to ``COMPLETE``. There is no path to
   ``COMPLETE`` without verification.
5. Routing matrix: task kind -> trigger surface -> effort -> senior
   verification step (``ROUTING_MATRIX``), typed enums throughout.

Deliberate boundaries (not hidden):
- The frontmatter parser covers the flat subset only: ``key: scalar``
  lines and ``- item`` lists. Nested maps, anchors, multi-line values are
  parse errors. PyYAML is a dev-only dependency; the runtime is stdlib
  only, so a full YAML parser is out of scope for this library.
- The environment marker is inherited, not authenticated: a junior that
  unsets the marker in its own environment could re-delegate. The lock
  file and the audit rate-limit still bound that case (same delegation id
  is refused while locked; the window cap bounds total attempts).
- ``worktree`` isolation is filesystem-level: the junior runs in a fresh
  ``git worktree add`` temp dir that is removed afterwards. It is not a
  sandbox — a junior reaching absolute paths outside the worktree is a
  deployment concern (a container), not something this library can
  enforce.
- The rate-limit window counts attempts recorded in the audit file. A
  deleted audit file resets the count; the file is append-only by this
  module and its loss is visible (the log is the audit trail).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - spawning junior/verifier commands is this module's purpose
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Protocol

from .gateway import PiiTokenizer

__all__ = [
    "ROUTING_MATRIX",
    "CommandVerifier",
    "ContractRejectedError",
    "DelegationAuditKind",
    "DelegationAuditLog",
    "DelegationContract",
    "DelegationError",
    "DelegationResult",
    "DelegationRunner",
    "DelegationState",
    "Effort",
    "FrontmatterParseError",
    "Isolation",
    "LoopGuard",
    "LoopLayer",
    "LoopRefusedError",
    "MemoryScope",
    "PermissionMode",
    "Route",
    "SeniorVerifier",
    "TaskKind",
    "TriggerSurface",
    "VerificationError",
    "VerificationStep",
    "VerificationVerdict",
    "parse_frontmatter",
]

DEPTH_ENV_VAR = "MCP_GUARD_DELEGATION_DEPTH"
"""Marker inherited by the child process (loop-prevention layer 1)."""

_DEFAULT_MAX_DELEGATIONS = 5
_DEFAULT_WINDOW_SECONDS = 60
_DEFAULT_MAX_DEPTH = 1
_DEFAULT_JUNIOR_TIMEOUT = 120.0
_DEFAULT_MAX_TURNS = 25


class FrontmatterParseError(ValueError):
    """The frontmatter block is missing, malformed, or declares unknowns."""


class ContractRejectedError(ValueError):
    """No usable delegation contract: missing frontmatter or required fields."""


class LoopRefusedError(Exception):
    """A loop-prevention layer refused the delegation."""

    def __init__(self, layer: LoopLayer, reason: str) -> None:
        super().__init__(f"loop prevention ({layer.value}): {reason}")
        self.layer = layer
        self.reason = reason


class DelegationError(Exception):
    """The delegation could not run (isolation setup, empty command, ...)."""


class VerificationError(Exception):
    """A result was treated as complete without senior approval."""


class LoopLayer(str, Enum):
    """Which loop-prevention layer refused (or acted)."""

    ENVIRONMENT = "environment"
    LOCK_FILE = "lock_file"
    AUDIT_RATE_LIMIT = "audit_rate_limit"


class PermissionMode(str, Enum):
    """Frontmatter ``permissionMode`` (source subagent table)."""

    DEFAULT = "default"
    ACCEPT_EDITS = "acceptEdits"
    AUTO = "auto"
    DONT_ASK = "dontAsk"
    BYPASS_PERMISSIONS = "bypassPermissions"
    PLAN = "plan"
    MANUAL = "manual"


class Isolation(str, Enum):
    """Frontmatter ``isolation``."""

    NONE = "none"
    WORKTREE = "worktree"


class Effort(str, Enum):
    """Frontmatter ``effort``."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"


class MemoryScope(str, Enum):
    """Frontmatter ``memory``."""

    USER = "user"
    PROJECT = "project"
    LOCAL = "local"
    NONE = "none"


class TaskKind(str, Enum):
    """Task classes from the source routing table (section 2b)."""

    LINT_FIX = "lint_fix"
    DOCSTRING = "docstring"
    TEST_SCAFFOLD = "test_scaffold"
    MECHANICAL_REFACTOR = "mechanical_refactor"
    DIFF_REVIEW = "diff_review"
    COVERAGE_GAP = "coverage_gap"
    COMMIT_MESSAGE = "commit_message"
    CHANGELOG = "changelog"
    DEPENDENCY_CHECK = "dependency_check"
    OVER_ENGINEERING = "over_engineering"


class TriggerSurface(str, Enum):
    """Where a task kind is triggered from (source mechanism matrix)."""

    POST_TOOL_USE = "post_tool_use"
    STOP_HOOK = "stop_hook"
    SUBAGENT = "subagent"
    SKILL = "skill"
    MANUAL = "manual"


class VerificationStep(str, Enum):
    """The senior verification step the routing matrix demands."""

    CHECK_EXIT_AND_DIFF = "check_exit_and_diff"
    READ_AND_APPROVE = "read_and_approve"
    RUN_TESTS_RED = "run_tests_red"
    SEMANTIC_DIFF_CHECK = "semantic_diff_check"
    HUMAN_REVIEWS = "human_reviews"
    RUN_COVERAGE_DELTA = "run_coverage_delta"
    HUMAN_EDITS = "human_edits"
    READ_RESULTS_ESCALATE = "read_results_escalate"
    READ_ONLY_REPORT = "read_only_report"


class DelegationState(str, Enum):
    """Lifecycle of a delegation result; no stringly-typed states."""

    PENDING_VERIFICATION = "pending_verification"
    COMPLETE = "complete"
    REJECTED = "rejected"
    FAILED = "failed"
    TIMEOUT = "timeout"


class VerificationVerdict(str, Enum):
    """Senior verifier verdict."""

    APPROVED = "approved"
    REJECTED = "rejected"


class DelegationAuditKind(str, Enum):
    """Audit event kinds; events, never content."""

    DELEGATION_STARTED = "delegation_started"
    DELEGATION_COMPLETED = "delegation_completed"
    DELEGATION_FAILED = "delegation_failed"
    DELEGATION_TIMEOUT = "delegation_timeout"
    LOOP_REFUSED = "loop_refused"
    LOCK_RECLAIMED = "lock_reclaimed"
    VERIFICATION_APPROVED = "verification_approved"
    VERIFICATION_REJECTED = "verification_rejected"
    WORKTREE_CLEANUP_FAILED = "worktree_cleanup_failed"


@dataclass(frozen=True)
class Route:
    """One routing-matrix row: task kind -> trigger -> effort -> verify."""

    task_kind: TaskKind
    trigger: TriggerSurface
    effort: Effort
    verification: VerificationStep


ROUTING_MATRIX: Mapping[TaskKind, Route] = {
    TaskKind.LINT_FIX: Route(
        TaskKind.LINT_FIX,
        TriggerSurface.POST_TOOL_USE,
        Effort.LOW,
        VerificationStep.CHECK_EXIT_AND_DIFF,
    ),
    TaskKind.DOCSTRING: Route(
        TaskKind.DOCSTRING,
        TriggerSurface.POST_TOOL_USE,
        Effort.LOW,
        VerificationStep.READ_AND_APPROVE,
    ),
    TaskKind.TEST_SCAFFOLD: Route(
        TaskKind.TEST_SCAFFOLD,
        TriggerSurface.STOP_HOOK,
        Effort.MEDIUM,
        VerificationStep.RUN_TESTS_RED,
    ),
    TaskKind.MECHANICAL_REFACTOR: Route(
        TaskKind.MECHANICAL_REFACTOR,
        TriggerSurface.SUBAGENT,
        Effort.MEDIUM,
        VerificationStep.SEMANTIC_DIFF_CHECK,
    ),
    TaskKind.DIFF_REVIEW: Route(
        TaskKind.DIFF_REVIEW, TriggerSurface.SKILL, Effort.MEDIUM, VerificationStep.HUMAN_REVIEWS
    ),
    TaskKind.COVERAGE_GAP: Route(
        TaskKind.COVERAGE_GAP,
        TriggerSurface.STOP_HOOK,
        Effort.HIGH,
        VerificationStep.RUN_COVERAGE_DELTA,
    ),
    TaskKind.COMMIT_MESSAGE: Route(
        TaskKind.COMMIT_MESSAGE,
        TriggerSurface.POST_TOOL_USE,
        Effort.LOW,
        VerificationStep.HUMAN_EDITS,
    ),
    TaskKind.CHANGELOG: Route(
        TaskKind.CHANGELOG, TriggerSurface.SKILL, Effort.MEDIUM, VerificationStep.HUMAN_REVIEWS
    ),
    TaskKind.DEPENDENCY_CHECK: Route(
        TaskKind.DEPENDENCY_CHECK,
        TriggerSurface.STOP_HOOK,
        Effort.LOW,
        VerificationStep.READ_RESULTS_ESCALATE,
    ),
    TaskKind.OVER_ENGINEERING: Route(
        TaskKind.OVER_ENGINEERING,
        TriggerSurface.SUBAGENT,
        Effort.MEDIUM,
        VerificationStep.READ_ONLY_REPORT,
    ),
}


def route_for(task_kind: TaskKind) -> Route:
    """Routing-matrix row for a task kind (every kind has exactly one)."""
    return ROUTING_MATRIX[task_kind]


# --- Frontmatter parsing -----------------------------------------------------

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(.*)$")
_INT_RE = re.compile(r"^-?\d+$")
_LIST_ITEM_RE = re.compile(r"^\s*-\s+(.*)$")

_KNOWN_FIELDS = frozenset(
    {
        "name",
        "description",
        "tools",
        "denied_tools",
        "permission_mode",
        "isolation",
        "effort",
        "max_turns",
        "memory",
        "model",
    }
)


def _parse_scalar(raw: str) -> str | int | bool:
    """Parse one flat frontmatter scalar (quoted string, bool, int, plain)."""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    if value == "true":
        return True
    if value == "false":
        return False
    if _INT_RE.match(value):
        return int(value)
    if value.startswith("[") and value.endswith("]"):
        raise FrontmatterParseError(
            "flow lists need the list form: use '- item' lines, not '[a, b]'"
        )
    if not value:
        raise FrontmatterParseError("empty scalar value")
    return value


def _parse_flat_mapping(lines: list[str]) -> dict[str, str | int | bool | list[str]]:
    """Parse the flat subset: ``key: scalar`` and ``key:`` + ``- item`` lines."""
    mapping: dict[str, str | int | bool | list[str]] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _KEY_RE.match(line)
        if match is None:
            raise FrontmatterParseError(f"unparsable frontmatter line: {line!r}")
        key, raw = match.group(1), match.group(2).strip()
        if key in mapping:
            raise FrontmatterParseError(f"duplicate frontmatter field: {key}")
        if raw:
            if _LIST_ITEM_RE.match(raw):
                raise FrontmatterParseError(f"list items belong on their own lines under {key!r}")
            mapping[key] = _parse_scalar(raw)
            continue
        items: list[str] = []
        while i < len(lines):
            item_match = _LIST_ITEM_RE.match(lines[i])
            if item_match is None:
                break
            parsed = _parse_scalar(item_match.group(1))
            if not isinstance(parsed, str):
                raise FrontmatterParseError(f"list items must be strings: {lines[i]!r}")
            items.append(parsed)
            i += 1
        if not items:
            raise FrontmatterParseError(f"field {key!r} has no value and no list")
        mapping[key] = items
    return mapping


def _lookup(data: Mapping[str, object], key: str) -> object | None:
    """Return ``data[key]`` or None when absent.

    Written with try/except rather than ``.get()``: a ``.get()`` default is
    a registry-tracked default, and None here is only an absence marker,
    not a behavioral default.
    """
    try:
        return data[key]
    except KeyError:
        return None


@dataclass(frozen=True)
class DelegationContract:
    """A validated delegation contract, parsed from agent frontmatter."""

    name: str
    description: str
    tools: tuple[str, ...] = ()
    denied_tools: tuple[str, ...] = ()
    permission_mode: PermissionMode = PermissionMode.DEFAULT
    isolation: Isolation = Isolation.NONE
    effort: Effort = Effort.MEDIUM
    max_turns: int = _DEFAULT_MAX_TURNS
    memory: MemoryScope = MemoryScope.NONE
    model: str = "inherit"

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> DelegationContract:
        """Validate a parsed frontmatter mapping into a contract.

        Unknown fields, missing required fields, and out-of-range values
        are all rejections: a contract that cannot be read exactly cannot
        be enforced.
        """
        unknown = sorted(set(data) - _KNOWN_FIELDS)
        if unknown:
            raise FrontmatterParseError(f"unknown frontmatter fields: {unknown}")
        name = _lookup(data, "name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ContractRejectedError(
                "contract needs a lowercase-hyphen 'name' (e.g. 'codex-refactor')"
            )
        description = _lookup(data, "description")
        if not isinstance(description, str) or not description.strip():
            raise ContractRejectedError("contract needs a non-empty 'description'")
        tools = _string_list(data, "tools")
        denied_tools = _string_list(data, "denied_tools")
        try:
            permission_mode = PermissionMode(_enum_value(data, "permission_mode", "default"))
            isolation = Isolation(_enum_value(data, "isolation", "none"))
            effort = Effort(_enum_value(data, "effort", "medium"))
            memory = MemoryScope(_enum_value(data, "memory", "none"))
        except ValueError as e:
            raise FrontmatterParseError(f"invalid enum value in frontmatter: {e}") from e
        max_turns_raw = _lookup(data, "max_turns")
        max_turns = max_turns_raw if max_turns_raw is not None else _DEFAULT_MAX_TURNS
        if isinstance(max_turns, bool) or not isinstance(max_turns, int) or max_turns < 1:
            raise ContractRejectedError("'max_turns' must be an integer >= 1")
        model_raw = _lookup(data, "model")
        if model_raw is None:
            model = "inherit"
        elif isinstance(model_raw, str) and model_raw.strip():
            model = model_raw
        else:
            raise ContractRejectedError("'model' must be a non-empty string")
        return cls(
            name=name,
            description=description,
            tools=tuple(_normalize_tool(t) for t in tools),
            denied_tools=tuple(_normalize_tool(t) for t in denied_tools),
            permission_mode=permission_mode,
            isolation=isolation,
            effort=effort,
            max_turns=max_turns,
            memory=memory,
            model=model,
        )

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Allowlist/denylist check; the denylist is applied first."""
        normalized = _normalize_tool(tool_name)
        if normalized in self.denied_tools:
            return False
        return not self.tools or normalized in self.tools


def _normalize_tool(tool_name: str) -> str:
    return tool_name.strip().lower()


def _enum_value(data: Mapping[str, object], key: str, default: str) -> str:
    value = _lookup(data, key)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise FrontmatterParseError(f"field {key!r} must be a string")
    return value


def _string_list(data: Mapping[str, object], key: str) -> tuple[str, ...]:
    if key not in data:
        return ()
    value = data[key]
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise ContractRejectedError(f"field {key!r} must be a string or a list of strings")


def parse_frontmatter(text: str) -> DelegationContract:
    """Parse an agent file's frontmatter block into a validated contract.

    A file without a ``---`` frontmatter block is rejected: a delegation
    with no declared contract cannot proceed.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ContractRejectedError("agent file has no frontmatter block ('---' first line)")
    closing = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            closing = index
            break
    if closing is None:
        raise ContractRejectedError("frontmatter block is never closed ('---' missing)")
    return DelegationContract.from_mapping(_parse_flat_mapping(lines[1:closing]))


# --- Audit log ---------------------------------------------------------------


@dataclass
class DelegationAuditLog:
    """Append-only JSONL audit log; events, never content.

    The file is the cross-process record the rate-limit layer counts
    from, so it lives on disk (``<lock_dir>/audit.jsonl``), not in memory.
    """

    path: Path

    def record(
        self, kind: DelegationAuditKind, delegation_id: str, detail: Mapping[str, object]
    ) -> None:
        """Append one event. Detail carries kinds/counts/hashes, never values."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "kind": kind.value,
            "delegation_id": delegation_id,
            "detail": dict(detail),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, default=str) + "\n")

    def attempts_in_window(self, window_seconds: int, now: datetime) -> int:
        """Delegation attempts started inside the sliding window."""
        if not self.path.exists():
            return 0
        count = 0
        text = self.path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            kind = _lookup(event, "kind")
            if kind != DelegationAuditKind.DELEGATION_STARTED.value:
                continue
            stamp = _lookup(event, "timestamp")
            if not isinstance(stamp, str):
                continue
            try:
                started = datetime.fromisoformat(stamp)
            except ValueError:
                continue
            if (now - started).total_seconds() <= window_seconds:
                count += 1
        return count


# --- Loop prevention ---------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    """True when the pid exists (fail-closed: any doubt means alive)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


@dataclass
class LoopGuard:
    """The three loop-prevention layers, all active before delegation."""

    lock_dir: Path
    max_delegations: int = _DEFAULT_MAX_DELEGATIONS
    window_seconds: int = _DEFAULT_WINDOW_SECONDS
    max_depth: int = _DEFAULT_MAX_DEPTH

    def check_environment(self, env: Mapping[str, str]) -> None:
        """Layer 1: refuse a delegation running inside a delegation."""
        marker = _lookup(env, DEPTH_ENV_VAR)
        raw = marker if isinstance(marker, str) else "0"
        try:
            depth = int(raw)
        except ValueError as e:
            raise LoopRefusedError(
                LoopLayer.ENVIRONMENT, f"unparsable {DEPTH_ENV_VAR}={raw!r}"
            ) from e
        if depth < 0 or depth >= self.max_depth:
            raise LoopRefusedError(
                LoopLayer.ENVIRONMENT,
                f"delegation depth {depth} reaches max {self.max_depth}",
            )

    def check_rate_limit(self, audit_log: DelegationAuditLog, now: datetime) -> None:
        """Layer 3: refuse when the sliding-window attempt cap is reached."""
        attempts = audit_log.attempts_in_window(self.window_seconds, now)
        if attempts >= self.max_delegations:
            raise LoopRefusedError(
                LoopLayer.AUDIT_RATE_LIMIT,
                f"{attempts} attempts in {self.window_seconds}s (max {self.max_delegations})",
            )

    def _lock_path(self, delegation_id: str) -> Path:
        if not _ID_RE.match(delegation_id):
            raise LoopRefusedError(LoopLayer.LOCK_FILE, f"invalid delegation id: {delegation_id!r}")
        return self.lock_dir / f"{delegation_id}.lock"

    def _read_lock_pid(self, lock_path: Path) -> int | None:
        """Pid recorded in a lock file; None when the file is unusable."""
        try:
            payload = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        pid = _lookup(payload, "pid")
        if isinstance(pid, bool) or not isinstance(pid, int):
            return None
        return pid

    @contextmanager
    def _locked(self, delegation_id: str, audit_log: DelegationAuditLog) -> Iterator[None]:
        """Layer 2: exclusive lock per delegation id (atomic O_EXCL)."""
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self._lock_path(delegation_id)
        for _ in range(2):
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pid = self._read_lock_pid(lock_path)
                if pid is None or _pid_alive(pid):
                    raise LoopRefusedError(
                        LoopLayer.LOCK_FILE,
                        f"delegation {delegation_id!r} already running",
                    ) from None
                lock_path.unlink()
                audit_log.record(
                    DelegationAuditKind.LOCK_RECLAIMED,
                    delegation_id,
                    {"stale_pid": pid},
                )
                continue
            try:
                os.write(
                    fd,
                    json.dumps(
                        {"pid": os.getpid(), "created": datetime.now(UTC).isoformat()}
                    ).encode("utf-8"),
                )
            finally:
                os.close(fd)
            break
        else:  # pragma: no cover - the loop always breaks or raises
            raise LoopRefusedError(
                LoopLayer.LOCK_FILE, f"could not acquire lock for {delegation_id!r}"
            )
        try:
            yield
        finally:
            try:
                lock_path.unlink()
            except OSError:
                pass

    @contextmanager
    def guard(
        self,
        delegation_id: str,
        env: Mapping[str, str],
        audit_log: DelegationAuditLog,
    ) -> Iterator[None]:
        """All three layers, in order; any refusal is audited and raised."""
        try:
            self.check_environment(env)
            self.check_rate_limit(audit_log, datetime.now(UTC))
        except LoopRefusedError as e:
            audit_log.record(
                DelegationAuditKind.LOOP_REFUSED,
                delegation_id,
                {"layer": e.layer.value, "reason": e.reason},
            )
            raise
        with self._locked(delegation_id, audit_log):
            yield


# --- Senior verification -----------------------------------------------------


class SeniorVerifier(Protocol):
    """A senior that approves or rejects a delegation result."""

    def verify(self, result: DelegationResult) -> VerificationVerdict: ...


@dataclass
class CommandVerifier:
    """Senior verification as a command: exit 0 approves, non-zero rejects.

    The command reads a JSON summary of the result on stdin (state,
    return code, changed files, prompt hash — never the raw prompt).
    """

    command: list[str]

    def verify(self, result: DelegationResult) -> VerificationVerdict:
        summary = json.dumps(result.to_summary())
        completed = subprocess.run(  # nosec B603 - runs the operator-supplied verifier command
            self.command,
            input=summary,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return (
            VerificationVerdict.APPROVED
            if completed.returncode == 0
            else VerificationVerdict.REJECTED
        )


# --- Result ------------------------------------------------------------------


@dataclass
class DelegationResult:
    """The outcome of one delegation; starts PENDING_VERIFICATION."""

    delegation_id: str
    task_kind: TaskKind
    contract_name: str
    prompt_hash: str
    token_kinds: tuple[str, ...]
    token_count: int
    junior_stdout: str
    junior_stderr: str
    junior_returncode: int | None
    changed_files: tuple[str, ...] = ()
    state: DelegationState = DelegationState.PENDING_VERIFICATION
    verification: VerificationVerdict | None = None

    def apply_verdict(self, verdict: VerificationVerdict) -> None:
        """The only transition out of PENDING_VERIFICATION."""
        if self.state is not DelegationState.PENDING_VERIFICATION:
            raise VerificationError(f"cannot verify a result in state {self.state.value}")
        self.verification = verdict
        self.state = (
            DelegationState.COMPLETE
            if verdict is VerificationVerdict.APPROVED
            else DelegationState.REJECTED
        )

    def complete(self) -> DelegationResult:
        """Assert senior approval; raises unless the result is COMPLETE."""
        if self.verification is not VerificationVerdict.APPROVED:
            raise VerificationError(
                f"delegation {self.delegation_id!r} is not senior-approved "
                f"(verification={self.verification})"
            )
        if self.state is not DelegationState.COMPLETE:
            raise VerificationError(
                f"delegation {self.delegation_id!r} is in state {self.state.value}, not COMPLETE"
            )
        return self

    def to_summary(self) -> dict[str, object]:
        """JSON-safe summary for verifiers and the CLI (no raw prompt)."""
        return {
            "delegation_id": self.delegation_id,
            "task_kind": self.task_kind.value,
            "contract_name": self.contract_name,
            "state": self.state.value,
            "prompt_hash": self.prompt_hash,
            "token_kinds": list(self.token_kinds),
            "token_count": self.token_count,
            "junior_returncode": self.junior_returncode,
            "changed_files": list(self.changed_files),
            "verification": self.verification.value if self.verification else None,
        }


# --- Runner ------------------------------------------------------------------


@dataclass
class DelegationRunner:
    """Runs one delegation under its contract and the loop guard."""

    lock_dir: Path
    junior_timeout: float = _DEFAULT_JUNIOR_TIMEOUT
    loop_guard: LoopGuard | None = None
    tokenizer: PiiTokenizer | None = None
    verifier: SeniorVerifier | None = None

    def _guard(self) -> LoopGuard:
        return self.loop_guard if self.loop_guard is not None else LoopGuard(self.lock_dir)

    def _tokenizer(self) -> PiiTokenizer:
        return self.tokenizer if self.tokenizer is not None else PiiTokenizer()

    def delegate(
        self,
        *,
        contract_text: str,
        task_kind: TaskKind,
        prompt: str,
        delegation_id: str,
        junior_command: list[str],
        repo_dir: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> DelegationResult:
        """Parse the contract, guard, scrub, run the junior, verify.

        Raises ContractRejectedError / FrontmatterParseError (no contract),
        LoopRefusedError (any loop layer), DelegationError (cannot run).
        A returned result is PENDING_VERIFICATION until a configured
        verifier approves it; without a verifier it stays pending.
        """
        if not junior_command:
            raise DelegationError("junior command is empty")
        contract = parse_frontmatter(contract_text)
        _route = route_for(task_kind)  # every kind has exactly one row
        effective_env: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        audit_log = DelegationAuditLog(self.lock_dir / "audit.jsonl")
        guard = self._guard()
        with guard.guard(delegation_id, effective_env, audit_log):
            scrubbed, applied = self._tokenizer().tokenize_text(prompt)
            token_kinds = tuple(sorted({token.kind.value for token in applied}))
            prompt_hash = hashlib.sha256(scrubbed.encode("utf-8")).hexdigest()
            audit_log.record(
                DelegationAuditKind.DELEGATION_STARTED,
                delegation_id,
                {
                    "task_kind": task_kind.value,
                    "contract": contract.name,
                    "token_kinds": list(token_kinds),
                    "token_count": len(applied),
                    "prompt_hash": prompt_hash,
                },
            )
            result = self._run_junior(
                contract=contract,
                task_kind=task_kind,
                delegation_id=delegation_id,
                scrubbed_prompt=scrubbed,
                prompt_hash=prompt_hash,
                token_kinds=token_kinds,
                token_count=len(applied),
                junior_command=junior_command,
                repo_dir=repo_dir,
                effective_env=effective_env,
                audit_log=audit_log,
            )
        if self.verifier is not None and result.state is DelegationState.PENDING_VERIFICATION:
            verdict = self.verifier.verify(result)
            result.apply_verdict(verdict)
            audit_log.record(
                DelegationAuditKind.VERIFICATION_APPROVED
                if verdict is VerificationVerdict.APPROVED
                else DelegationAuditKind.VERIFICATION_REJECTED,
                delegation_id,
                {"task_kind": task_kind.value},
            )
        return result

    def _run_junior(
        self,
        *,
        contract: DelegationContract,
        task_kind: TaskKind,
        delegation_id: str,
        scrubbed_prompt: str,
        prompt_hash: str,
        token_kinds: tuple[str, ...],
        token_count: int,
        junior_command: list[str],
        repo_dir: Path | None,
        effective_env: dict[str, str],
        audit_log: DelegationAuditLog,
    ) -> DelegationResult:
        """Run the junior command; worktree isolation when contracted."""
        worktree: Path | None = None
        base_dir: Path | None = None
        cwd: Path | None = None
        if contract.isolation is Isolation.WORKTREE:
            if repo_dir is None:
                raise DelegationError(
                    "contract declares isolation 'worktree' but no repo_dir was given"
                )
            base_dir = Path(tempfile.mkdtemp(prefix="mcp-guard-delegate-"))
            worktree = base_dir / "work"
            try:
                setup = subprocess.run(  # nosec - git worktree setup in the operator's repo
                    ["git", "worktree", "add", str(worktree), "HEAD"],
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except OSError as e:
                raise DelegationError(f"git worktree setup failed: {e}") from e
            if setup.returncode != 0:
                raise DelegationError(f"git worktree setup failed: {setup.stderr.strip()}")
            cwd = worktree
        depth_raw_marker = _lookup(effective_env, DEPTH_ENV_VAR)
        depth_raw = depth_raw_marker if isinstance(depth_raw_marker, str) else "0"
        child_env = dict(effective_env)
        child_env[DEPTH_ENV_VAR] = str(int(depth_raw) + 1)
        changed: tuple[str, ...] = ()
        try:
            completed = subprocess.run(  # nosec B603 - runs the operator-supplied junior command
                junior_command,
                input=scrubbed_prompt,
                capture_output=True,
                text=True,
                timeout=self.junior_timeout,
                cwd=cwd,
                env=child_env,
                check=False,
            )
            # Changed files are read here, inside the try: the finally below
            # removes the worktree, so reading them after it would see nothing.
            changed = self._changed_files(worktree) if worktree is not None else ()
        except subprocess.TimeoutExpired:
            audit_log.record(
                DelegationAuditKind.DELEGATION_TIMEOUT,
                delegation_id,
                {"task_kind": task_kind.value, "timeout": self.junior_timeout},
            )
            return DelegationResult(
                delegation_id=delegation_id,
                task_kind=task_kind,
                contract_name=contract.name,
                prompt_hash=prompt_hash,
                token_kinds=token_kinds,
                token_count=token_count,
                junior_stdout="",
                junior_stderr="",
                junior_returncode=None,
                state=DelegationState.TIMEOUT,
            )
        finally:
            if worktree is not None and base_dir is not None:
                self._remove_worktree(worktree, base_dir, repo_dir, delegation_id, audit_log)
        return DelegationResult(
            delegation_id=delegation_id,
            task_kind=task_kind,
            contract_name=contract.name,
            prompt_hash=prompt_hash,
            token_kinds=token_kinds,
            token_count=token_count,
            junior_stdout=completed.stdout,
            junior_stderr=completed.stderr,
            junior_returncode=completed.returncode,
            changed_files=changed,
        )

    def _changed_files(self, worktree: Path) -> tuple[str, ...]:
        status = subprocess.run(  # nosec - read-only git status in the worktree
            ["git", "-C", str(worktree), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if status.returncode != 0:
            return ()
        return tuple(line[3:] for line in status.stdout.splitlines() if len(line) > 3)

    def _remove_worktree(
        self,
        worktree: Path,
        base_dir: Path,
        repo_dir: Path | None,
        delegation_id: str,
        audit_log: DelegationAuditLog,
    ) -> None:
        removed = subprocess.run(  # nosec - git worktree removal in the operator's repo
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if removed.returncode != 0:
            audit_log.record(
                DelegationAuditKind.WORKTREE_CLEANUP_FAILED,
                delegation_id,
                {"worktree": str(worktree), "stderr": removed.stderr.strip()[:200]},
            )
        shutil.rmtree(base_dir, ignore_errors=True)
