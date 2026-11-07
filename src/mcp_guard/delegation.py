"""Delegated-agent contract enforcement for the mcp-guard gateway.

The module is a thin boundary layer, not a model. A delegation is a
request to run a junior agent in a subprocess; this module checks the
request against a contract declared in frontmatter, enforces three
loop-prevention layers, scrubs PII out of the prompt and out of the
junior's environment, and refuses to mark the result complete until a
senior verifier approves it.

Enforcement scope, stated plainly:

- This library enforces directly: the contract parses and is validated
  (``DelegationContract``); the junior is isolated in a worktree when
  the contract asks for it; the three loop-prevention layers run on
  every delegation (``LoopGuard``); the prompt is scrubbed and the
  junior's environment is built from a small allowlist; the result
  stays ``PENDING_VERIFICATION`` until a senior verifier approves it;
  the routed verification step's mechanical preconditions are checked
  by the runner before the verifier is consulted.
- The contract fields that only a junior runtime can enforce
  (``tools``, ``permission_mode``, ``max_turns``, ``effort``,
  ``memory``, ``model``) are forwarded to the junior as environment
  variables and as a JSON contract file (``MCP_GUARD_CONTRACT_FILE``);
  the junior runtime enforces them. ``is_tool_allowed`` is the check a
  harness applies when it mediates a tool call on the junior's behalf.
- The audit log is a trusted input: a forged or deleted audit file
  degrades the rate-limit layer (a deleted file resets the count; a
  forged future timestamp is skipped, never counted), and a failed
  audit write is logged, never fatal. Corrupt lines are skipped for
  counting, so the count can undercount when the file is damaged.

A PII scrub in the prompt does not mean the junior is safe to hand
untrusted text: the scrubber replaces recognised patterns, it does
not redact arbitrary secrets, and the junior runtime is untrusted
by design.
"""

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess  # nosec B404 - spawning junior/verifier commands is this module's purpose
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Protocol, TypedDict

from .gateway import PiiTokenizer

logger = logging.getLogger(__name__)

# Default values are the single source of truth for the delegation
# defaults. The CLI repeats the values as argparse defaults (literals,
# so the defaults registry can track them); a test pins the two sides
# equal. See tests/test_delegation.py::test_cli_defaults_match_constants.
_DEFAULT_MAX_DELEGATIONS = 5
_DEFAULT_WINDOW_SECONDS = 60
_DEFAULT_MAX_DEPTH = 1
_DEFAULT_JUNIOR_TIMEOUT = 120.0
_DEFAULT_MAX_TURNS = 25
_VERIFIER_TIMEOUT = 60.0
_GIT_TIMEOUT = 60.0

# Audit-file reads are bounded to this tail: the rate-limit window is
# seconds, so only recent events can matter. Older events are outside
# the window by construction (timestamps are monotonic, append-only).
_AUDIT_TAIL_BYTES = 1_048_576

# Empty-lock-file retry: between os.open and the pid write the file is
# momentarily empty; a concurrent reader retries briefly instead of
# refusing on a lock that is still being created.
_LOCK_RETRY_ATTEMPTS = 3
_LOCK_RETRY_DELAY = 0.01

# The global audit lock serializes the rate-limit check + STARTED
# record critical section (milliseconds). Contention waits, it never
# fails fast: a spurious refusal here would reject a valid delegation.
_GLOBAL_LOCK_TIMEOUT = 5.0
_GLOBAL_LOCK_POLL = 0.05

# Environment variables a junior is allowed to inherit. Everything
# else in the parent environment is dropped: the junior never sees a
# raw secret that happened to be exported. PATH and HOME are needed
# for the junior to run at all; SYSTEMROOT/COMSPEC/PATHEXT are the
# Windows equivalents a child process needs to spawn anything.
_SAFE_ENV_VARS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
    }
)

_CONTRACT_ENV_PREFIX = "MCP_GUARD_CONTRACT_"
_CONTRACT_FILE_ENV = "MCP_GUARD_CONTRACT_FILE"
DEPTH_ENV_VAR = "MCP_GUARD_DELEGATION_DEPTH"
"""Marker inherited by the child process (loop-prevention layer 1)."""
_DEPTH_ENV_VAR = DEPTH_ENV_VAR
_LOCK_FILENAME = "delegation.lock"
_AUDIT_LOCK_ID = "audit-global"

# A changed file is a test file when its name or path matches one of
# these patterns. Used by the RUN_TESTS_RED precondition: a test
# scaffold that produced no test file fails the step.
_TEST_FILE_PATTERNS = ("test_", "_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")


class DelegationError(Exception):
    """The delegation could not be run (not a loop refusal)."""


class VerificationError(DelegationError):
    """A result was treated as complete without senior approval."""


class LoopLayer(str, Enum):
    """Which loop-prevention layer refused (or acted)."""

    ENVIRONMENT = "environment"
    LOCK_FILE = "lock_file"
    AUDIT_RATE_LIMIT = "audit_rate_limit"


class LoopRefusedError(Exception):
    """A loop-prevention layer refused the delegation.

    ``layer`` names the layer: ``ENVIRONMENT`` (L1), ``LOCK_FILE``
    (L2), or ``AUDIT_RATE_LIMIT`` (L3). The refusal is fail-closed:
    the caller must not retry without changing the request.
    """

    def __init__(self, layer: LoopLayer, reason: str) -> None:
        super().__init__(f"loop prevention ({layer.value}): {reason}")
        self.layer = layer
        self.reason = reason


class FrontmatterParseError(Exception):
    """The frontmatter block could not be parsed."""


class ContractRejectedError(Exception):
    """The contract failed validation (missing/invalid fields)."""


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


class Effort(str, Enum):
    """The effort the junior may spend on the delegation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"


class MemoryScope(str, Enum):
    """The memory scope the junior may read."""

    USER = "user"
    PROJECT = "project"
    LOCAL = "local"
    NONE = "none"


class TriggerSurface(str, Enum):
    """Where a task kind is triggered from (source mechanism matrix)."""

    POST_TOOL_USE = "post_tool_use"
    STOP_HOOK = "stop_hook"
    SUBAGENT = "subagent"
    SKILL = "skill"
    MANUAL = "manual"


class VerificationStep(str, Enum):
    """The senior verification step the routed task kind requires."""

    CHECK_EXIT_AND_DIFF = "check_exit_and_diff"
    READ_AND_APPROVE = "read_and_approve"
    RUN_TESTS_RED = "run_tests_red"
    SEMANTIC_DIFF_CHECK = "semantic_diff_check"
    HUMAN_REVIEWS = "human_reviews"
    RUN_COVERAGE_DELTA = "run_coverage_delta"
    HUMAN_EDITS = "human_edits"
    READ_RESULTS_ESCALATE = "read_results_escalate"
    READ_ONLY_REPORT = "read_only_report"


class PermissionMode(str, Enum):
    """How the junior may act without asking."""

    DEFAULT = "default"
    ACCEPT_EDITS = "acceptEdits"
    AUTO = "auto"
    DONT_ASK = "dontAsk"
    BYPASS_PERMISSIONS = "bypassPermissions"
    PLAN = "plan"
    MANUAL = "manual"


class Isolation(str, Enum):
    """Whether the junior runs in a worktree."""

    WORKTREE = "worktree"
    NONE = "none"


class DelegationState(str, Enum):
    """Where a delegation result stands."""

    PENDING_VERIFICATION = "pending_verification"
    COMPLETE = "complete"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


class VerificationVerdict(str, Enum):
    """What the senior verifier decided."""

    APPROVED = "approved"
    REJECTED = "rejected"


class DelegationAuditKind(str, Enum):
    """The audit events a delegation emits (JSONL, one per line)."""

    DELEGATION_STARTED = "delegation_started"
    DELEGATION_COMPLETED = "delegation_completed"
    DELEGATION_FAILED = "delegation_failed"
    LOOP_REFUSED = "loop_refused"
    LOCK_RECLAIMED = "lock_reclaimed"
    VERIFICATION_APPROVED = "verification_approved"
    VERIFICATION_REJECTED = "verification_rejected"
    WORKTREE_CLEANUP_FAILED = "worktree_cleanup_failed"
    COPYBACK_FAILED = "copyback_failed"


class ContractDict(TypedDict, total=False):
    """The JSON shape a parsed delegation contract is serialized as."""

    name: str
    description: str
    model: str
    tools: list[str]
    denied_tools: list[str]
    permission_mode: str
    isolation: str
    effort: str | None
    max_turns: int
    memory: str
    background: bool


@dataclass(frozen=True)
class Route:
    """One routing-matrix row: task kind -> trigger -> effort -> verify."""

    task_kind: TaskKind
    trigger: TriggerSurface
    effort: Effort
    verification: VerificationStep


ROUTING_MATRIX: dict[TaskKind, Route] = {
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


def route_for(task: TaskKind) -> Route:
    """Return the route for a task kind (KeyError for an unknown kind)."""
    return ROUTING_MATRIX[task]


def _step_precondition_failed(result: "DelegationResult", route: Route) -> str | None:
    """Check the routed verification step's mechanical precondition.

    Returns a reason string when the step cannot pass, else None. The
    runner rejects the result without consulting the verifier when a
    precondition fails: the matrix step gates the outcome, it is not
    advice the verifier may ignore. Steps that need a human (HUMAN_*)
    or a read (READ_*) only require a clean junior exit here; the human
    or the reader does the rest through the verifier.
    """
    if result.junior_returncode != 0:
        return (
            f"junior exited {result.junior_returncode}, step {route.verification.value} requires 0"
        )
    step = route.verification
    if step is VerificationStep.RUN_TESTS_RED:
        has_test = any(
            any(pattern in path for pattern in _TEST_FILE_PATTERNS) for path in result.changed_files
        )
        if not has_test:
            return "step run_tests_red requires at least one changed test file"
    elif step in (
        VerificationStep.SEMANTIC_DIFF_CHECK,
        VerificationStep.RUN_COVERAGE_DELTA,
    ):
        if not result.changed_files:
            return f"step {step.value} requires at least one changed file"
    elif step is VerificationStep.READ_ONLY_REPORT:
        if not result.junior_stdout.strip():
            return "step read_only_report requires junior output"
    return None


# ---------------------------------------------------------------------------
# Frontmatter parsing (stdlib-only, flat subset of YAML)
# ---------------------------------------------------------------------------

# CamelCase spellings real Claude Code agent files use, mapped to the
# snake_case fields this parser accepts. Unknown keys are still rejected.
_CAMEL_CASE_ALIASES = {
    "permissionMode": "permission_mode",
    "maxTurns": "max_turns",
    "deniedTools": "denied_tools",
}

_CONTRACT_FIELDS = {
    "name",
    "description",
    "model",
    "tools",
    "denied_tools",
    "permission_mode",
    "isolation",
    "effort",
    "max_turns",
    "memory",
    "background",
}

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")


def _normalize_tool(tool_name: str) -> str:
    """Tool names normalize (strip + lowercase) before the check."""
    return tool_name.strip().lower()


_LIST_FIELDS = {"tools", "denied_tools"}


def _lookup(fields: dict[str, str | list[str]], key: str) -> str | list[str] | None:
    """Return ``fields[key]``, or None when absent (absence marker).

    Callers decide what absence means (default, rejection, or
    fail-closed refusal). A plain ``.get(key, default)`` would make the
    default a registry-tracked dict-fallback; this keeps absence
    explicit and untracked.
    """
    try:
        return fields[key]
    except KeyError:
        return None


def _parse_scalar(value: str) -> str | bool | int:
    """Parse one flat frontmatter scalar value.

    Quoted strings must be balanced: an unbalanced quote is a parse
    error, not a literal that silently keeps the quote character.
    """
    stripped = value.strip()
    if stripped.startswith(('"', "'")):
        if len(stripped) < 2 or stripped[-1] != stripped[0]:
            raise FrontmatterParseError(f"unbalanced quote in frontmatter value: {value!r}")
        return stripped[1:-1]
    if stripped in ("true", "false"):
        return stripped == "true"
    if re.fullmatch(r"-?\d+", stripped):
        return int(stripped)
    return stripped


def _string_list(value: str) -> list[str]:
    """Parse a frontmatter list value: ``- item`` block form only.

    A bare scalar (``tools: Bash``) is a parse error: a list field
    must be written as a list, or a silent one-item allowlist is
    exactly the kind of ambiguity this module refuses. A flow list
    (``tools: [Bash, Read]``) is likewise rejected: the flat subset
    is ``key:`` + ``- item`` lines.
    """
    stripped = value.strip()
    if stripped.startswith("["):
        raise FrontmatterParseError(
            "flow lists need the list form: use '- item' lines, not '[a, b]'"
        )
    raise FrontmatterParseError(f"list field must use - item form, got: {value!r}")


def _parse_frontmatter_block(lines: list[str]) -> dict[str, str | list[str]]:
    """Parse the ``key: value`` lines of one frontmatter block."""
    fields: dict[str, str | list[str]] = {}
    current_list_key: str | None = None
    for raw_line in lines:
        line = raw_line.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.startswith(("- ", "\t- ", "  - ")):
            if current_list_key is None:
                raise FrontmatterParseError(f"list item without a list field: {line!r}")
            item = line.strip()[2:].strip().strip("\"'")
            existing = fields[current_list_key]
            if not isinstance(existing, list):
                raise FrontmatterParseError(f"list item for non-list field {current_list_key!r}")
            existing.append(item)
            continue
        if ":" not in line:
            raise FrontmatterParseError(f"frontmatter line has no ':': {line!r}")
        key, _, raw_value = line.partition(":")
        key = key.strip()
        key = _CAMEL_CASE_ALIASES.get(key, key)
        if key not in _CONTRACT_FIELDS:
            raise FrontmatterParseError(f"unknown frontmatter field: {key!r}")
        if key in fields:
            raise FrontmatterParseError(f"duplicate frontmatter field: {key!r}")
        value = raw_value.strip()
        if key in _LIST_FIELDS:
            if value:
                fields[key] = _string_list(value)
            else:
                fields[key] = []
            current_list_key = key
            continue
        current_list_key = None
        parsed = _parse_scalar(value)
        if isinstance(parsed, bool):
            fields[key] = "true" if parsed else "false"
        elif isinstance(parsed, int):
            fields[key] = str(parsed)
        else:
            fields[key] = parsed
    return fields


def parse_frontmatter(text: str) -> dict[str, str | list[str]]:
    """Parse the leading ``---`` frontmatter block of a Markdown file.

    Returns the flat field map. A file without a leading block, an
    unclosed block, or a block with unknown/duplicate fields is a
    parse error.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise FrontmatterParseError("no leading '---' frontmatter block")
    end = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = index
            break
    if end is None:
        raise FrontmatterParseError("unclosed frontmatter block")
    return _parse_frontmatter_block(lines[1:end])


@dataclass(frozen=True)
class DelegationContract:
    """A parsed, validated delegation contract.

    ``effort`` is None when the contract does not declare one: the
    runner then inherits the routed task kind's effort. ``tools`` is
    an allowlist: an empty allowlist denies every tool (fail-closed);
    a contract that declares no tools delegates nothing.
    """

    name: str
    description: str
    model: str = "inherit"
    tools: tuple[str, ...] = ()
    denied_tools: tuple[str, ...] = ()
    permission_mode: PermissionMode = PermissionMode.DEFAULT
    isolation: Isolation = Isolation.NONE
    effort: Effort | None = None
    max_turns: int = _DEFAULT_MAX_TURNS
    memory: MemoryScope = MemoryScope.NONE
    background: bool = False

    @classmethod
    def from_mapping(cls, fields: dict[str, str | list[str]]) -> "DelegationContract":
        """Validate a parsed frontmatter map into a contract.

        Unknown keys are rejected by the parser before this runs; here
        the required fields and the value domains are enforced. A
        contract that fails validation is rejected, never repaired.
        """
        name = _lookup(fields, "name")
        description = _lookup(fields, "description")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ContractRejectedError(
                "contract needs a lowercase-hyphen 'name' (e.g. 'codex-refactor')"
            )
        if not isinstance(description, str) or not description.strip():
            raise ContractRejectedError("contract requires a non-empty 'description'")
        tools = _lookup(fields, "tools") or []
        denied_tools = _lookup(fields, "denied_tools") or []
        if not isinstance(tools, list) or not isinstance(denied_tools, list):
            raise ContractRejectedError("'tools' and 'denied_tools' must be lists")
        permission_mode = PermissionMode.DEFAULT
        raw_mode = _lookup(fields, "permission_mode")
        if isinstance(raw_mode, str) and raw_mode:
            try:
                permission_mode = PermissionMode(raw_mode)
            except ValueError:
                raise ContractRejectedError(f"unknown permission_mode: {raw_mode!r}") from None
        isolation = Isolation.NONE
        raw_isolation = _lookup(fields, "isolation")
        if isinstance(raw_isolation, str) and raw_isolation:
            try:
                isolation = Isolation(raw_isolation)
            except ValueError:
                raise ContractRejectedError(f"unknown isolation: {raw_isolation!r}") from None
        effort: Effort | None = None
        raw_effort = _lookup(fields, "effort")
        if isinstance(raw_effort, str) and raw_effort:
            try:
                effort = Effort(raw_effort)
            except ValueError:
                raise ContractRejectedError(f"unknown effort: {raw_effort!r}") from None
        max_turns = _DEFAULT_MAX_TURNS
        raw_turns = _lookup(fields, "max_turns")
        if isinstance(raw_turns, str) and raw_turns:
            try:
                max_turns = int(raw_turns)
            except ValueError:
                raise ContractRejectedError(f"max_turns is not an integer: {raw_turns!r}") from None
            if max_turns < 1:
                raise ContractRejectedError("max_turns must be >= 1")
        background = _lookup(fields, "background") == "true"
        model = _lookup(fields, "model")
        raw_memory = _lookup(fields, "memory")
        memory = MemoryScope.NONE
        if isinstance(raw_memory, str) and raw_memory:
            try:
                memory = MemoryScope(raw_memory)
            except ValueError:
                raise ContractRejectedError(f"unknown memory: {raw_memory!r}") from None
        return cls(
            name=name,
            description=description,
            model=model if isinstance(model, str) else "inherit",
            tools=tuple(_normalize_tool(str(item)) for item in tools),
            denied_tools=tuple(_normalize_tool(str(item)) for item in denied_tools),
            permission_mode=permission_mode,
            isolation=isolation,
            effort=effort,
            max_turns=max_turns,
            memory=memory,
            background=background,
        )

    @classmethod
    def from_text(cls, text: str) -> "DelegationContract":
        """Parse frontmatter text into a validated contract."""
        return cls.from_mapping(parse_frontmatter(text))

    def is_tool_allowed(self, tool: str) -> bool:
        """Whether the contract allows the named tool.

        An empty allowlist denies everything (fail-closed): a contract
        that declares no tools delegates no tool use. A denied tool is
        never allowed, even when it is also listed in the allowlist.
        Tool names normalize before the check, so ``READ`` and
        ``  bash `` match the stored lowercase entries.
        """
        normalized = _normalize_tool(tool)
        if normalized in self.denied_tools:
            return False
        if not self.tools:
            return False
        return normalized in self.tools

    def to_dict(self) -> ContractDict:
        """Serialize the contract (the JSON the junior receives)."""
        return {
            "name": self.name,
            "description": self.description,
            "model": self.model,
            "tools": list(self.tools),
            "denied_tools": list(self.denied_tools),
            "permission_mode": self.permission_mode.value,
            "isolation": self.isolation.value,
            "effort": self.effort.value if self.effort is not None else None,
            "max_turns": self.max_turns,
            "memory": self.memory.value,
            "background": self.background,
        }

    def to_env(self, effective_effort: Effort) -> dict[str, str]:
        """The contract as environment variables for the junior.

        The junior runtime enforces tools, permission_mode, max_turns,
        effort, memory, and model from these; this library enforces
        isolation, loop prevention, scrubbing, and verification.
        """
        return {
            f"{_CONTRACT_ENV_PREFIX}NAME": self.name,
            f"{_CONTRACT_ENV_PREFIX}MODEL": self.model,
            f"{_CONTRACT_ENV_PREFIX}TOOLS": ",".join(self.tools),
            f"{_CONTRACT_ENV_PREFIX}DENIED_TOOLS": ",".join(self.denied_tools),
            f"{_CONTRACT_ENV_PREFIX}PERMISSION_MODE": self.permission_mode.value,
            f"{_CONTRACT_ENV_PREFIX}ISOLATION": self.isolation.value,
            f"{_CONTRACT_ENV_PREFIX}EFFORT": effective_effort.value,
            f"{_CONTRACT_ENV_PREFIX}MAX_TURNS": str(self.max_turns),
            f"{_CONTRACT_ENV_PREFIX}MEMORY": self.memory.value,
        }


# ---------------------------------------------------------------------------
# Audit log (append-only JSONL; kinds and counts, never values)
# ---------------------------------------------------------------------------


@dataclass
class AuditEvent:
    """One audit-log line."""

    kind: DelegationAuditKind
    delegation_id: str
    started: datetime
    detail: dict[str, str | int]

    def to_json(self) -> str:
        """Serialize one event as a single JSONL line."""
        return json.dumps(
            {
                "kind": self.kind.value,
                "delegation_id": self.delegation_id,
                "started": self.started.isoformat(),
                "detail": self.detail,
            },
            sort_keys=True,
        )


@dataclass
class DelegationAuditLog:
    """The append-only JSONL audit log for one delegation directory.

    ``record`` is best-effort by design: a failed write is logged and
    never fatal, so an audit failure cannot mask the delegation outcome
    it was recording. The cost is visible degradation: a STARTED event
    that never lands is not counted by the rate limit.
    """

    path: Path

    def record(
        self,
        kind: DelegationAuditKind,
        delegation_id: str,
        detail: dict[str, str | int],
        started: datetime | None = None,
    ) -> None:
        """Append one event. Never raises: OSError is logged."""
        event = AuditEvent(
            kind=kind,
            delegation_id=delegation_id,
            started=started or datetime.now(UTC),
            detail=detail,
        )
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(event.to_json() + "\n")
        except OSError:
            logger.warning("audit log write failed for %s", self.path, exc_info=True)

    def _read_recent_lines(self) -> list[str]:
        """Read the audit tail (bounded): only recent lines can be
        inside the rate-limit window, and the file is append-only with
        monotonic timestamps."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return []
        try:
            with self.path.open("rb") as handle:
                if size > _AUDIT_TAIL_BYTES:
                    handle.seek(size - _AUDIT_TAIL_BYTES)
                    handle.readline()  # drop the partial first line
                raw = handle.read()
        except OSError:
            logger.warning("audit log read failed for %s", self.path, exc_info=True)
            return []
        return raw.decode("utf-8", errors="replace").splitlines()

    def attempts_in_window(self, window_seconds: int, now: datetime | None = None) -> int:
        """Count DELEGATION_STARTED events in the last ``window_seconds``.

        A line that does not parse, a naive timestamp (coerced to UTC:
        this module only ever writes aware UTC), or a future-dated
        event (forged or clock-skewed) is skipped, never counted.
        """
        current = now or datetime.now(UTC)
        count = 0
        for line in self._read_recent_lines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("kind") != DelegationAuditKind.DELEGATION_STARTED.value:
                continue
            try:
                started = datetime.fromisoformat(str(entry["started"]))
            except (ValueError, TypeError):
                continue
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            if started > current:
                continue
            if (current - started).total_seconds() <= window_seconds:
                count += 1
        return count


# ---------------------------------------------------------------------------
# Three-layer loop prevention
# ---------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    """Whether a pid is alive. Fail-closed: any error means alive.

    POSIX uses ``os.kill(pid, 0)``. On Windows that call does NOT
    probe liveness: sig 0 is CTRL_C_EVENT, so it broadcasts Ctrl+C to
    the console process group instead. The Windows branch uses
    OpenProcess + GetExitCodeProcess (STILL_ACTIVE == 259).
    """
    if os.name == "nt":
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _pid_alive_windows(pid: int) -> bool:
    """Windows liveness probe via OpenProcess + GetExitCodeProcess."""
    import ctypes
    from ctypes import wintypes

    # WinDLL exists only on Windows; getattr keeps mypy (Linux) quiet
    # and this function only ever runs when os.name == "nt".
    windll = getattr(ctypes, "WinDLL", None)
    if windll is None:
        return True
    kernel32 = windll("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = (
        wintypes.HANDLE,
        wintypes.LPDWORD,
    )
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    # PROCESS_QUERY_LIMITED_INFORMATION (0x1000) is enough to read the
    # exit code and is the least-privilege access right for this probe.
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD(0)
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


@dataclass
class LoopGuard:
    """The three loop-prevention layers, all active before any
    delegation proceeds.

    L1 environment: the ``MCP_GUARD_DELEGATION_DEPTH`` marker is
    inherited by the child; a delegation running inside a delegation
    is refused.
    L2 lock file: one live delegation per delegation id, via an atomic
    ``O_EXCL`` create; a stale lock is reclaimed only when the
    recorded pid is dead.
    L3 audit rate-limit: the append-only JSONL audit log counts
    delegation attempts in a sliding window across processes; over the
    cap the delegation is refused. The check and the STARTED record
    are serialized under a global audit lock, so the cap is a real
    bound even under concurrency.
    """

    lock_dir: Path
    max_delegations: int = _DEFAULT_MAX_DELEGATIONS
    window_seconds: int = _DEFAULT_WINDOW_SECONDS
    max_depth: int = _DEFAULT_MAX_DEPTH

    def check_environment(self, env: dict[str, str]) -> None:
        """L1: refuse a delegation that is already inside one."""
        depth = env.get(_DEPTH_ENV_VAR)
        if depth is None:
            return
        try:
            value = int(depth)
        except ValueError:
            raise LoopRefusedError(
                LoopLayer.ENVIRONMENT,
                f"invalid {_DEPTH_ENV_VAR} value: {depth!r}",
            ) from None
        if value >= self.max_depth:
            raise LoopRefusedError(
                LoopLayer.ENVIRONMENT,
                f"delegation depth {value} >= max {self.max_depth}",
            )

    def check_rate_limit(self, audit_log: DelegationAuditLog, now: datetime | None = None) -> None:
        """L3: refuse when the window already holds the cap.

        Callers must hold the global audit lock around the check and
        the STARTED record that follows it (see ``serialized_audit``):
        the check alone is not atomic.
        """
        attempts = audit_log.attempts_in_window(self.window_seconds, now=now)
        if attempts >= self.max_delegations:
            raise LoopRefusedError(
                LoopLayer.AUDIT_RATE_LIMIT,
                f"{attempts} delegations in {self.window_seconds}s >= max {self.max_delegations}",
            )

    def _lock_path(self, delegation_id: str) -> Path:
        if not _ID_RE.match(delegation_id):
            raise LoopRefusedError(LoopLayer.LOCK_FILE, f"invalid delegation id: {delegation_id!r}")
        return self.lock_dir / f"{delegation_id}.{_LOCK_FILENAME}"

    def _read_lock_pid(self, path: Path) -> int | None:
        """Read the pid recorded in a lock file (None: empty/corrupt)."""
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    def _lock_file_empty(self, path: Path) -> bool:
        """Whether a lock file exists but holds no bytes yet."""
        try:
            return path.stat().st_size == 0
        except OSError:
            return False

    def _locked(
        self, delegation_id: str, audit_log: DelegationAuditLog
    ) -> AbstractContextManager[None]:
        """Acquire the per-id lock (fail-fast on contention).

        A stale lock (recorded pid dead) is reclaimed and audited.
        Between os.open and the pid write the file is momentarily
        empty; a reader retries briefly before refusing on a lock
        that is still being created, rather than treating an empty
        file as a corrupt lock.
        """

        @contextmanager
        def acquire() -> Iterator[None]:
            path = self._lock_path(delegation_id)
            self.lock_dir.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pid = self._read_lock_pid(path)
                if pid is None and self._lock_file_empty(path):
                    for _ in range(_LOCK_RETRY_ATTEMPTS):
                        time.sleep(_LOCK_RETRY_DELAY)
                        pid = self._read_lock_pid(path)
                        if pid is not None:
                            break
                if pid is not None and _pid_alive(pid):
                    raise LoopRefusedError(
                        LoopLayer.LOCK_FILE,
                        f"delegation {delegation_id!r} already running (pid {pid})",
                    )
                if pid is not None:
                    audit_log.record(
                        DelegationAuditKind.LOCK_RECLAIMED,
                        delegation_id,
                        {"pid": pid},
                    )
                    path.unlink(missing_ok=True)
                    try:
                        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    except FileExistsError:
                        raise LoopRefusedError(
                            LoopLayer.LOCK_FILE,
                            f"delegation {delegation_id!r} already running",
                        ) from None
                else:
                    # Unreadable lock (corrupt content, or still empty
                    # after the creation retry): fail closed. A lock
                    # whose owner cannot be proven dead stays locked
                    # until an operator removes it.
                    raise LoopRefusedError(
                        LoopLayer.LOCK_FILE,
                        f"delegation {delegation_id!r} already running (lock unreadable)",
                    )
            try:
                os.write(fd, str(os.getpid()).encode("utf-8"))
            finally:
                os.close(fd)
            try:
                yield
            finally:
                path.unlink(missing_ok=True)

        return acquire()

    def _serialized_audit(self, audit_log: DelegationAuditLog) -> AbstractContextManager[None]:
        """Hold the global audit lock (waits on contention).

        Serializes the rate-limit check + STARTED record critical
        section. The lock is acquired only here, never held across a
        delegation run, and always after the per-id lock, so no
        circular wait is possible.
        """

        @contextmanager
        def acquire() -> Iterator[None]:
            # Enter the lock by hand (not `with`): the retry loop must
            # only catch refusals from ACQUIRING the lock. A refusal
            # raised by the body (the rate-limit check) must propagate
            # at once; catching it here would retry the body and yield
            # twice, which a contextmanager generator forbids. A fresh
            # lock object is built per attempt: a @contextmanager
            # object is single-use, and re-entering one raises.
            deadline = time.monotonic() + _GLOBAL_LOCK_TIMEOUT
            while True:
                lock = self._locked(_AUDIT_LOCK_ID, audit_log)
                try:
                    lock.__enter__()
                    break
                except LoopRefusedError:
                    if time.monotonic() >= deadline:
                        raise LoopRefusedError(
                            LoopLayer.AUDIT_RATE_LIMIT,
                            "audit serialization timeout",
                        ) from None
                    time.sleep(_GLOBAL_LOCK_POLL)
            try:
                yield
            finally:
                lock.__exit__(None, None, None)

        return acquire()

    def guard(
        self,
        delegation_id: str,
        env: dict[str, str],
        audit_log: DelegationAuditLog,
    ) -> AbstractContextManager[None]:
        """Hold L1 + L2 for the whole delegation lifecycle.

        The environment check and the per-id lock span the junior run
        AND the verification step: a second delegation with the same
        id cannot start while the first is PENDING_VERIFICATION. Every
        refusal (including a lock refusal) is audited before it is
        re-raised.
        """

        @contextmanager
        def acquire() -> Iterator[None]:
            try:
                self.check_environment(env)
                with self._locked(delegation_id, audit_log):
                    yield
            except LoopRefusedError as error:
                audit_log.record(
                    DelegationAuditKind.LOOP_REFUSED,
                    delegation_id,
                    {"layer": error.layer.value, "reason": error.reason},
                )
                raise

        return acquire()


# ---------------------------------------------------------------------------
# Senior verification
# ---------------------------------------------------------------------------


class SeniorVerifier(Protocol):
    """A senior verifier decides a pending delegation result."""

    def verify(self, result: "DelegationResult") -> VerificationVerdict: ...


@dataclass
class CommandVerifier:
    """A verifier that runs a command and approves on exit 0.

    The command receives the result summary as JSON on stdin. A
    verifier that cannot run (missing binary, timeout, bad quoting)
    REJECTS: a verification that did not happen is not an approval.
    """

    command: str

    def verify(self, result: "DelegationResult") -> VerificationVerdict:
        """Run the command; approve only on exit 0."""
        try:
            argv = shlex.split(self.command)
        except ValueError:
            return VerificationVerdict.REJECTED
        if not argv:
            return VerificationVerdict.REJECTED
        try:
            completed = subprocess.run(  # nosec B603 - runs the operator-supplied verifier command
                argv,
                input=json.dumps(result.to_summary()),
                capture_output=True,
                text=True,
                timeout=_VERIFIER_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return VerificationVerdict.REJECTED
        if completed.returncode == 0:
            return VerificationVerdict.APPROVED
        return VerificationVerdict.REJECTED


# ---------------------------------------------------------------------------
# Delegation result
# ---------------------------------------------------------------------------


@dataclass
class DelegationResult:
    """The outcome of one delegation run.

    The result starts PENDING_VERIFICATION and only ``apply_verdict``
    (the senior verifier) or ``complete`` may move it to COMPLETE or
    REJECTED. Direct assignment to ``state``, ``verification``, or
    ``rejection_reason`` raises AttributeError: the supported API is
    the transition methods, and a caller that constructs a result
    directly (or uses ``dataclasses.replace``) bypasses the gate by
    construction, which the docs state rather than hide.
    """

    delegation_id: str
    task: TaskKind
    effective_effort: Effort
    verification_step: VerificationStep
    state: DelegationState = DelegationState.PENDING_VERIFICATION
    verification: VerificationVerdict | None = None
    junior_returncode: int | None = None
    junior_stdout: str = ""
    junior_stderr: str = ""
    changed_files: tuple[str, ...] = ()
    rejection_reason: str | None = None
    _sealed: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if name in ("state", "verification", "rejection_reason") and self.__dict__.get("_sealed"):
            raise AttributeError(
                f"{name} may only change through apply_verdict/complete; "
                "direct assignment bypasses the verification gate"
            )
        super().__setattr__(name, value)

    def _transition(
        self,
        state: DelegationState,
        verification: VerificationVerdict | None = None,
        rejection_reason: str | None = None,
    ) -> None:
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "verification", verification)
        object.__setattr__(self, "rejection_reason", rejection_reason)

    def apply_verdict(self, verdict: VerificationVerdict) -> None:
        """Apply the senior verdict. Only APPROVED completes.

        The only transition out of PENDING_VERIFICATION: a second
        verdict raises rather than silently overwriting the first.
        """
        if self.state is not DelegationState.PENDING_VERIFICATION:
            raise VerificationError(f"cannot verify a result in state {self.state.value}")
        if verdict is VerificationVerdict.APPROVED:
            self._transition(DelegationState.COMPLETE, verification=verdict)
        else:
            self._transition(DelegationState.REJECTED, verification=verdict)

    def reject_with_reason(self, reason: str) -> None:
        """Reject without a senior verdict (routed step precondition)."""
        if self.state is not DelegationState.PENDING_VERIFICATION:
            raise VerificationError(f"cannot reject a result in state {self.state.value}")
        self._transition(DelegationState.REJECTED, verification=None, rejection_reason=reason)

    def complete(self) -> "DelegationResult":
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
        """The machine-readable summary (the verifier's stdin)."""
        return {
            "delegation_id": self.delegation_id,
            "task": self.task.value,
            "state": self.state.value,
            "verification": (self.verification.value if self.verification else None),
            "effective_effort": self.effective_effort.value,
            "verification_step": self.verification_step.value,
            "junior_returncode": self.junior_returncode,
            "changed_files": list(self.changed_files),
            "rejection_reason": self.rejection_reason,
        }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def sanitize_delegation_id(raw: str) -> str:
    """Sanitize a derived delegation id (invalid chars become '-';
    an id that would be empty or invalid after sanitizing falls back
    to a hash of the raw value, so it never collides silently)."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-.")
    if sanitized and _ID_RE.match(sanitized):
        return sanitized
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"delegation-{digest}"


@dataclass
class DelegationRunner:
    """Runs one delegation: guard, scrub, forward, run, verify.

    The runner owns the seams the library can enforce (isolation,
    loop prevention, scrubbing, verification, step preconditions) and
    forwards the contract fields only a junior runtime can enforce.
    """

    lock_dir: Path
    guard: LoopGuard | None = None
    junior_command: list[str] = field(default_factory=list)
    junior_timeout: float = _DEFAULT_JUNIOR_TIMEOUT
    env_allowlist: frozenset[str] | None = None
    extra_env_vars: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.guard is None:
            self.guard = LoopGuard(self.lock_dir)

    def delegate(
        self,
        contract: DelegationContract,
        delegation_id: str,
        task: TaskKind,
        prompt: str,
        repo_dir: Path | None = None,
        verifier: SeniorVerifier | None = None,
        env: dict[str, str] | None = None,
    ) -> DelegationResult:
        """Run one delegation against a validated contract.

        The guard (L1 + L2) spans the junior run AND verification; the
        rate-limit check and the STARTED record are serialized under
        the global audit lock. A delegation without a contract is
        rejected before anything runs: the caller must pass a parsed
        ``DelegationContract``, a verbal "be careful" is not one.
        """
        guard = self.guard
        if guard is None:
            raise DelegationError("runner has no loop guard")
        effective_env = dict(env) if env is not None else dict(os.environ)
        audit_log = DelegationAuditLog(self.lock_dir / "audit.jsonl")
        route = route_for(task)
        effective_effort = contract.effort if contract.effort is not None else route.effort
        contract_file = self.lock_dir / f"{delegation_id}.contract.json"
        try:
            with guard.guard(delegation_id, effective_env, audit_log):
                tokenizer = PiiTokenizer()
                scrubbed, tokens = tokenizer.tokenize_text(prompt)
                prompt_hash = hashlib.sha256(scrubbed.encode("utf-8")).hexdigest()[:16]
                with guard._serialized_audit(audit_log):
                    guard.check_rate_limit(audit_log)
                    audit_log.record(
                        DelegationAuditKind.DELEGATION_STARTED,
                        delegation_id,
                        {
                            "task": task.value,
                            "step": route.verification.value,
                            "prompt_hash": prompt_hash,
                            "token_kinds": ",".join(sorted({token.kind.value for token in tokens})),
                            "token_count": len(tokens),
                        },
                    )
                child_env = self._child_env(
                    effective_env,
                    contract,
                    task,
                    route,
                    effective_effort,
                    contract_file,
                )
                result = self._run_junior(
                    contract=contract,
                    delegation_id=delegation_id,
                    task=task,
                    route=route,
                    effective_effort=effective_effort,
                    scrubbed_prompt=scrubbed,
                    repo_dir=repo_dir,
                    child_env=child_env,
                    contract_file=contract_file,
                    audit_log=audit_log,
                )
                if result.state is DelegationState.TIMEOUT:
                    return result
                precondition = _step_precondition_failed(result, route)
                if precondition is not None:
                    result.reject_with_reason(precondition)
                    audit_log.record(
                        DelegationAuditKind.VERIFICATION_REJECTED,
                        delegation_id,
                        {"reason": precondition, "step": route.verification.value},
                    )
                    return result
                if verifier is not None:
                    verdict = verifier.verify(result)
                    result.apply_verdict(verdict)
                    audit_log.record(
                        (
                            DelegationAuditKind.VERIFICATION_APPROVED
                            if verdict is VerificationVerdict.APPROVED
                            else DelegationAuditKind.VERIFICATION_REJECTED
                        ),
                        delegation_id,
                        {"step": route.verification.value},
                    )
                return result
        except LoopRefusedError:
            raise
        except DelegationError:
            raise
        except OSError as error:
            raise DelegationError(f"delegation failed: {error}") from error

    def _child_env(
        self,
        effective_env: dict[str, str],
        contract: DelegationContract,
        task: TaskKind,
        route: Route,
        effective_effort: Effort,
        contract_file: Path,
    ) -> dict[str, str]:
        """Build the junior's environment: allowlisted vars only,
        plus the depth marker, the forwarded contract, and the
        contract-file path. Everything else is dropped."""
        allowed = (
            self.env_allowlist if self.env_allowlist is not None else _SAFE_ENV_VARS
        ) | self.extra_env_vars
        child_env = {key: effective_env[key] for key in allowed if key in effective_env}
        depth = effective_env.get(_DEPTH_ENV_VAR, "0")
        try:
            child_env[_DEPTH_ENV_VAR] = str(int(depth) + 1)
        except ValueError:
            child_env[_DEPTH_ENV_VAR] = "1"
        child_env.update(contract.to_env(effective_effort))
        child_env[_CONTRACT_FILE_ENV] = str(contract_file)
        child_env["MCP_GUARD_TASK_KIND"] = task.value
        child_env["MCP_GUARD_VERIFICATION_STEP"] = route.verification.value
        return child_env

    def _write_contract_file(self, contract: DelegationContract, contract_file: Path) -> None:
        """Write the contract JSON the junior runtime reads."""
        contract_file.parent.mkdir(parents=True, exist_ok=True)
        contract_file.write_text(
            json.dumps(contract.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _run_junior(
        self,
        contract: DelegationContract,
        delegation_id: str,
        task: TaskKind,
        route: Route,
        effective_effort: Effort,
        scrubbed_prompt: str,
        repo_dir: Path | None,
        child_env: dict[str, str],
        contract_file: Path,
        audit_log: DelegationAuditLog,
    ) -> DelegationResult:
        """Run the junior subprocess, collect its output, and (for a
        worktree) copy its changes back to the main worktree."""
        if not self.junior_command:
            raise DelegationError("junior command is empty")
        worktree: Path | None = None
        cwd = repo_dir
        before_status: frozenset[str] = frozenset()
        if contract.isolation is Isolation.WORKTREE:
            if repo_dir is None:
                raise DelegationError("worktree isolation requires repo_dir")
            worktree = self.lock_dir / f"{delegation_id}.worktree"
            try:
                self._setup_worktree(repo_dir, worktree)
            except (OSError, subprocess.CalledProcessError) as error:
                audit_log.record(
                    DelegationAuditKind.DELEGATION_FAILED,
                    delegation_id,
                    {"reason": f"worktree setup failed: {error}"},
                )
                raise DelegationError(f"worktree setup failed: {error}") from error
            cwd = worktree
        else:
            before_status = self._status_paths(repo_dir)
        try:
            self._write_contract_file(contract, contract_file)
        except OSError as error:
            raise DelegationError(f"contract file write failed: {error}") from error
        try:
            proc = subprocess.Popen(  # nosec B603 - runs the operator-supplied junior command
                self.junior_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=child_env,
                start_new_session=(os.name != "nt"),
            )
        except OSError as error:
            audit_log.record(
                DelegationAuditKind.DELEGATION_FAILED,
                delegation_id,
                {"reason": f"junior spawn failed: {error}"},
            )
            raise DelegationError(f"junior spawn failed: {error}") from error
        try:
            stdout, stderr = proc.communicate(input=scrubbed_prompt, timeout=self.junior_timeout)
        except subprocess.TimeoutExpired:
            # Kill the whole process group on POSIX so grandchildren
            # die with the junior; on Windows terminate the child
            # (grandchildren may survive there: documented boundary).
            if os.name != "nt":
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
            else:
                proc.kill()
            proc.communicate()
            if worktree is not None and repo_dir is not None:
                self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
            result = DelegationResult(
                delegation_id=delegation_id,
                task=task,
                effective_effort=effective_effort,
                verification_step=route.verification,
                state=DelegationState.TIMEOUT,
                junior_returncode=None,
                junior_stdout="",
                junior_stderr="",
            )
            audit_log.record(
                DelegationAuditKind.DELEGATION_FAILED,
                delegation_id,
                {"reason": "junior timeout"},
            )
            return result
        changes = self._collect_changes(cwd, before_status)
        changed_files = tuple(path for _, path in changes)
        result = DelegationResult(
            delegation_id=delegation_id,
            task=task,
            effective_effort=effective_effort,
            verification_step=route.verification,
            junior_returncode=proc.returncode,
            junior_stdout=stdout,
            junior_stderr=stderr,
            changed_files=changed_files,
        )
        audit_log.record(
            DelegationAuditKind.DELEGATION_COMPLETED,
            delegation_id,
            {"returncode": proc.returncode},
        )
        if worktree is not None and repo_dir is not None:
            try:
                self._copy_back(worktree, repo_dir, changes)
            except OSError as error:
                audit_log.record(
                    DelegationAuditKind.COPYBACK_FAILED,
                    delegation_id,
                    {"reason": str(error), "worktree": str(worktree)},
                )
                raise DelegationError(
                    f"copy-back failed (worktree kept at {worktree}): {error}"
                ) from error
            self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
        return result

    def _setup_worktree(self, repo_dir: Path, worktree: Path) -> None:
        """Create a fresh worktree at HEAD for the junior."""
        subprocess.run(  # nosec - git worktree setup in the operator's repo
            ["git", "-C", str(repo_dir), "worktree", "add", "--detach", str(worktree)],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=True,
        )

    def _status_paths(self, repo_dir: Path | None) -> frozenset[str]:
        """The set of dirty paths in a repo (empty when not a repo)."""
        if repo_dir is None:
            return frozenset()
        try:
            completed = subprocess.run(  # nosec - read-only git status in the repo
                ["git", "-C", str(repo_dir), "status", "--porcelain", "-z"],
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT,
                check=False,
            )
        except OSError:
            return frozenset()
        if completed.returncode != 0:
            return frozenset()
        return frozenset(path for _, path in _parse_porcelain_z(completed.stdout))

    def _collect_changes(
        self, cwd: Path | None, before: frozenset[str]
    ) -> tuple[tuple[str, str], ...]:
        """The (status, path) changes the junior made in ``cwd``.

        Compared against the pre-run snapshot, so pre-existing dirt
        in the operator's tree is attributed to the operator, not the
        junior. A fresh worktree has an empty snapshot, so every
        change is the junior's.
        """
        if cwd is None:
            return ()
        try:
            completed = subprocess.run(  # nosec - read-only git status in the worktree
                ["git", "-C", str(cwd), "status", "--porcelain", "-z"],
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT,
                check=False,
            )
        except OSError:
            return ()
        if completed.returncode != 0:
            return ()
        pairs = _parse_porcelain_z(completed.stdout)
        return tuple(pair for pair in pairs if pair[1] not in before)

    def _copy_back(
        self,
        worktree: Path,
        repo_dir: Path,
        changes: tuple[tuple[str, str], ...],
    ) -> None:
        """Copy the junior's changes from the worktree to the main
        tree, mirroring deletions. The deliverable lands in the
        operator's tree for senior review; nothing is committed."""
        for status, path in changes:
            source = worktree / path
            target = repo_dir / path
            if "D" in status:
                target.unlink(missing_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def _remove_worktree(
        self,
        repo_dir: Path,
        worktree: Path,
        audit_log: DelegationAuditLog,
        delegation_id: str,
    ) -> None:
        """Remove the worktree; on failure prune and remove the tree,
        and audit the failure rather than silently leaking it."""
        try:
            subprocess.run(  # nosec - git worktree removal in the operator's repo
                ["git", "-C", str(repo_dir), "worktree", "remove", "--force", str(worktree)],
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError):
            audit_log.record(
                DelegationAuditKind.WORKTREE_CLEANUP_FAILED,
                delegation_id,
                {"worktree": str(worktree)},
            )
            subprocess.run(  # nosec - git worktree prune in the operator's repo
                ["git", "-C", str(repo_dir), "worktree", "prune"],
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT,
                check=False,
            )
            shutil.rmtree(worktree, ignore_errors=True)


def _parse_porcelain_z(output: str) -> list[tuple[str, str]]:
    """Parse ``git status --porcelain -z`` output into (status, path)
    pairs. NUL-separated, so quoted and renamed paths parse exactly:
    a rename is ``R  old`` followed by ``new`` as the next record.
    """
    pairs: list[tuple[str, str]] = []
    records = [record for record in output.split("\0") if record]
    index = 0
    while index < len(records):
        record = records[index]
        status = record[:2]
        if status.startswith(("R", "C")):
            index += 1
            if index < len(records):
                pairs.append((status, records[index]))
        else:
            pairs.append((status, record[3:]))
        index += 1
    return pairs


__all__ = [
    "DEPTH_ENV_VAR",
    "ROUTING_MATRIX",
    "AuditEvent",
    "CommandVerifier",
    "ContractDict",
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
    "route_for",
    "sanitize_delegation_id",
]
