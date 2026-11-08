"""Delegated-agent contract enforcement for the mcp-guard gateway.

The module is a thin boundary layer, not a model. A delegation is a
request to run a junior agent in a subprocess; this module checks the
request against a contract declared in frontmatter, enforces three
loop-prevention guardrails, scrubs PII out of the prompt and out of the
junior's environment, and refuses to mark the result complete until a
senior verifier approves it. The guardrails bound accidental
re-delegation; they do not contain a junior that means to re-delegate
(it can unset the depth marker, pick a fresh delegation id, or delete
the audit file — see the Boundaries section in docs/spec.md).

Enforcement scope, stated plainly:

- This library enforces directly: the contract parses and is validated
  (``DelegationContract``); the junior is isolated in a worktree by
  default (``isolation: worktree``; ``isolation: none`` is an explicit,
  warned opt-in that edits the operator tree directly); the three
  loop-prevention guardrails run on every delegation (``LoopGuard``);
  the prompt is scrubbed and the junior's environment is built from a
  small allowlist; the result stays ``PENDING_VERIFICATION`` until a
  senior verifier approves it; the routed verification step's
  mechanical preconditions are checked by the runner before the
  verifier is consulted; a pending result is persisted as a pending
  record that ``resolve_pending`` can discharge later.
- The contract fields that only a junior runtime can enforce
  (``tools``, ``permission_mode``, ``max_turns``, ``effort``,
  ``memory``, ``model``) are forwarded to the junior as environment
  variables and as a JSON contract file (``MCP_GUARD_CONTRACT_FILE``)
  as requests the junior runtime is asked to honour. Nothing in this
  repository enforces them on an arbitrary subprocess: the junior
  runtime is untrusted by design, so a contract that declares
  ``tools: [Read]`` does not stop a junior command from running
  anything else. ``is_tool_allowed`` is the check a mediating harness
  applies when it mediates a tool call on the junior's behalf; the
  runner and the CLI never call it.
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
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Protocol, TypedDict

from .concealment import PipelineManifest, StagedFile, augmentation_scan
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
# A contract is supposed to bound the junior: no turn budget above this
# is accepted (40x the default). Module constant, not registry-tracked
# (see defaults_registry.py: the scanner covers only signature defaults,
# .get fallbacks, except paths, and argparse defaults).
_MAX_TURNS_LIMIT = 1000
_VERIFIER_TIMEOUT = 60.0
_GIT_TIMEOUT = 60.0
# Bound on the post-kill drain: after a junior timeout the runner kills
# the process group and drains the pipes once more. A grandchild that
# escaped the kill (setsid) and still holds a pipe open would hang an
# unbounded drain forever, so the drain gives up after this long.
_POST_KILL_DRAIN_TIMEOUT = 5.0

# Audit-file reads are bounded to this tail: the rate-limit window is
# seconds, so only recent events can matter. Older events are outside
# the window by construction (timestamps are monotonic, append-only).
_AUDIT_TAIL_BYTES = 1_048_576

# Empty-lock-file retry: between os.open and the pid write the file is
# momentarily empty; a concurrent reader retries briefly instead of
# refusing on a lock that is still being created.
_LOCK_RETRY_ATTEMPTS = 3
_LOCK_RETRY_DELAY = 0.01

# Arbiter-acquire retries: a holder may release (unlink + close) just
# as a fresh acquirer opens the path, leaving the acquirer guarding a
# stale inode. The acquirer releases and retries from the content
# check instead of proceeding on a file the path no longer names.
_LOCK_ACQUIRE_ATTEMPTS = 3

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

# The verifier's stdin carries bounded junior output (see
# ``DelegationResult.to_summary``): enough for the senior to read the
# deliverable, never an unbounded dump of a runaway junior.
_SUMMARY_OUTPUT_LIMIT = 8_000

# Secret-shaped material in a prompt: shapes with near-zero false-positive
# risk on ordinary prose. This is a WARNING, never a refusal: the operator
# wrote the prompt, and a warning that names only the shape kind (never
# the matched value) is the honest signal. Arbitrary secrets are not
# redacted by the PII scrubber, so a prompt carrying one must not cross
# the handoff silently.
# The trigger prefixes are spelled with single-character classes ([-], [_])
# so the file text never contains them contiguously: the repo's
# committed-secret scanner greps for these same prefixes and would flag
# the detector's own table. Each class matches exactly one literal
# character, so the detected language is unchanged.
_SECRET_SHAPE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("private_key", r"-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----"),
    ("api_token", r"s[k][-][A-Za-z0-9]{8,}"),
    ("api_token", r"sk[-]ant[-][A-Za-z0-9_-]{8,}"),
    ("api_token", r"ghp[_][A-Za-z0-9]{20,}"),
    ("api_token", r"gho[_][A-Za-z0-9]{20,}"),
    ("api_token", r"gh[u][_][A-Za-z0-9]{20,}"),
    ("api_token", r"gh[s][_][A-Za-z0-9]{20,}"),
    ("api_token", r"gh[r][_][A-Za-z0-9]{20,}"),
    ("api_token", r"github[_]pat[_][A-Za-z0-9_]{20,}"),
    ("api_token", r"AKI[A][0-9A-Z]{16}"),
    ("api_token", r"xo[x][baprs][-][A-Za-z0-9-]{8,}"),
    ("api_token", r"glpa[t][-][A-Za-z0-9_-]{8,}"),
    ("api_token", r"h[f][_][A-Za-z0-9]{20,}"),
    ("api_token", r"AIz[a][0-9A-Za-z_-]{35}"),
    (
        "credential_assignment",
        (
            r"\b(?:api[_-]?key|api[_-]?token|access[_-]?token|secret|password|passwd)"
            r"\s*[:=]\s*['\"]?[^\s'\",;]{8,}['\"]?"
        ),
    ),
)


def _shape_kinds(text: str) -> frozenset[str]:
    """The secret-shape kinds present in a prompt (names only, never values)."""
    found: set[str] = set()
    for kind, pattern in _SECRET_SHAPE_PATTERNS:
        if re.search(pattern, text):
            found.add(kind)
    return frozenset(found)


# A changed file is a test file when its BASENAME starts with "test_" or
# ends with one of these suffixes. The match is on the basename, never the
# full path: substring matching over the path lets "latest_notes.txt" or a
# file under "test_data/" count as a test file. Used by the RUN_TESTS_RED
# precondition: a test scaffold that produced no test file fails the step.
_TEST_FILE_NAME_PREFIX = "test_"
_TEST_FILE_SUFFIXES = ("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")


def _is_test_file(path: str) -> bool:
    """True when the changed path is a test file (basename match only)."""
    name = Path(path).name
    return name.startswith(_TEST_FILE_NAME_PREFIX) or name.endswith(_TEST_FILE_SUFFIXES)


def _bounded_output(text: str) -> str:
    """Truncate junior output for the verifier's stdin (marked)."""
    if len(text) <= _SUMMARY_OUTPUT_LIMIT:
        return text
    return (
        text[:_SUMMARY_OUTPUT_LIMIT]
        + f"\n[... truncated, {len(text) - _SUMMARY_OUTPUT_LIMIT} more chars]"
    )


# The pending record written by ``delegate`` and read by
# ``resolve_pending``. A version mismatch refuses the record rather
# than guessing at its shape.
_PENDING_VERSION = 1


def _file_sha256(path: Path) -> str:
    """The hex digest of a file's bytes ("" when it cannot be read)."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _resolve_path(path: Path) -> Path:
    """Resolve a path, raising RuntimeError on a symlink loop.

    ``Path.resolve()`` raised on loops up to Python 3.12; from 3.13
    non-strict resolve returns the looping path unresolved instead
    (it delegates to ``os.path.realpath``, which suppresses the loop
    error unless strict), so code that relied on the raise silently
    stopped detecting loops. A resolved path that still contains a
    symlink component is a loop: realpath resolves every non-loop
    link. Dangling links are unaffected: their target is not a
    symlink, so they resolve to the (nonexistent) target as before.
    """
    resolved = path.resolve()
    current = resolved
    while True:
        if current.is_symlink():
            raise RuntimeError(f"symlink loop detected at {current}")
        if current.parent == current:
            return resolved
        current = current.parent


def _git_file_matches_head(repo_dir: Path, path: str) -> bool:
    """Whether git considers a working-tree file unchanged vs HEAD.

    ``git diff --quiet HEAD`` applies the clean filters, so a file
    whose bytes differ from its HEAD blob only by line-ending
    conversion (a CRLF working file against an LF blob under
    core.autocrlf on Windows) reads as clean here, while the raw
    byte comparison in the conflict check reads it as operator work.
    False on any git failure: the caller then refuses, fail-closed.
    """
    try:
        compared = subprocess.run(  # nosec - read-only git diff in the repo
            ["git", "-C", str(repo_dir), "diff", "--quiet", "HEAD", "--", path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return compared.returncode == 0


class DelegationError(Exception):
    """The delegation could not be run (not a loop refusal)."""


class VerificationError(DelegationError):
    """A result was treated as complete without senior approval."""


class LoopLayer(str, Enum):
    """Which loop-prevention layer refused (or acted)."""

    ENVIRONMENT = "environment"
    LOCK_FILE = "lock_file"
    AUDIT_RATE_LIMIT = "audit_rate_limit"
    AUDIT_LOCK = "audit_lock"


class LoopRefusedError(Exception):
    """A loop-prevention layer refused the delegation.

    ``layer`` names the layer: ``ENVIRONMENT`` (L1), ``LOCK_FILE``
    (L2), ``AUDIT_RATE_LIMIT`` (L3), or ``AUDIT_LOCK`` (the global
    audit lock could not be acquired in time: lock contention, not a
    rate refusal). The refusal is fail-closed:
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
    SECRET_SHAPE_WARNED = "secret_shape_warned"  # nosec B105 - audit-kind label, not a credential
    DELEGATION_PENDING = "delegation_pending"
    DELEGATION_DISCARDED = "delegation_discarded"
    WORKTREE_RECLAIMED = "worktree_reclaimed"


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


def _step_precondition_failed(
    result: "DelegationResult",
    route: Route,
    repo_dir: Path | None = None,
    *,
    allow_missing_returncode: bool = False,
) -> str | None:
    """Check the routed verification step's mechanical precondition.

    Returns a reason string when the step cannot pass, else None. The
    runner rejects the result without consulting the verifier when a
    precondition fails: the matrix step gates the outcome, it is not
    advice the verifier may ignore. Steps that need a human (HUMAN_*)
    or a read (READ_AND_APPROVE) only require a clean junior exit here;
    the human or the reader does the rest through the verifier, which
    now receives the junior output. The diff precondition applies only
    when the delegation runs against a repo directory: without one
    there is no tree to diff, and the verifier is the only gate.
    ``allow_missing_returncode`` is for a timeout record resolved
    later: the junior was killed, so there is no exit code to check,
    but the step conditions on the recorded artifacts (changed files,
    junior output) still apply — a timeout must not complete a step
    its artifacts cannot satisfy.
    """
    if result.junior_returncode != 0 and not (
        allow_missing_returncode and result.junior_returncode is None
    ):
        return (
            f"junior exited {result.junior_returncode}, step {route.verification.value} requires 0"
        )
    step = route.verification
    if step is VerificationStep.RUN_TESTS_RED:
        has_test = any(_is_test_file(path) for path in result.changed_files)
        if not has_test:
            return "step run_tests_red requires at least one changed test file"
    elif step is VerificationStep.CHECK_EXIT_AND_DIFF:
        if repo_dir is not None and not result.changed_files:
            return "step check_exit_and_diff requires at least one changed file"
    elif step in (
        VerificationStep.SEMANTIC_DIFF_CHECK,
        VerificationStep.RUN_COVERAGE_DELTA,
    ):
        # Same rule as CHECK_EXIT_AND_DIFF: without a repo directory there
        # is no tree to diff, and the verifier is the only gate. Requiring
        # a changed file unconditionally made these routes unreachable
        # without a repo.
        if repo_dir is not None and not result.changed_files:
            return f"step {step.value} requires at least one changed file"
    elif step is VerificationStep.READ_ONLY_REPORT:
        if not result.junior_stdout.strip():
            return "step read_only_report requires junior output"
    elif step is VerificationStep.READ_RESULTS_ESCALATE:
        if not result.junior_stdout.strip():
            return "step read_results_escalate requires junior output"
    return None


def _validate_change_paths(
    changes: tuple[tuple[str, str, str | None, str], ...],
) -> None:
    """Refuse change paths that escape the tree.

    The pending record is unauthenticated JSON in a junior-reachable
    directory, so a forged record must not smuggle absolute paths or
    ``..`` segments into ``_copy_back``: ``worktree / path`` and
    ``repo_dir / path`` follow them, and a ``D`` status would delete an
    arbitrary file (and a forged ``old_path`` a second one). The check
    is platform-independent: backslashes and drive prefixes are
    separators and absolutes on Windows even though PurePosixPath
    does not see them (``..\\evil`` has no ``..`` part, ``C:\\evil``
    is not absolute in POSIX terms), so they are rejected outright.
    Raises ``DelegationError``.
    """
    for _status, path, old_path, _sha in changes:
        for candidate in (path, old_path):
            if candidate is None:
                continue
            pure = PurePosixPath(candidate)
            if (
                not candidate
                or pure.is_absolute()
                or ".." in pure.parts
                or "\\" in candidate
                or (len(candidate) >= 2 and candidate[1] == ":" and candidate[0].isalpha())
                or candidate.startswith("\\\\")
            ):
                raise DelegationError(
                    f"change path {candidate!r} escapes the tree; refusing to land it"
                )


# ---------------------------------------------------------------------------
# Frontmatter parsing (stdlib-only, flat subset of YAML)
# ---------------------------------------------------------------------------

# CamelCase spellings real agent files use, mapped to the
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
        if line.startswith(("- ", "\t- ", " - ", "  - ", "   - ", "    - ")) or line in (
            "-",
            "\t-",
            " -",
            "  -",
            "   -",
            "    -",
        ):
            if current_list_key is None:
                raise FrontmatterParseError(f"list item without a list field: {line!r}")
            item = line.strip()[1:].strip().strip("\"'")
            if not item:
                raise FrontmatterParseError(f"empty list item in frontmatter: {line!r}")
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
    parse error. A leading UTF-8 byte-order mark is accepted.
    """
    text = text.removeprefix("\ufeff")
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
    runner then inherits the routed task kind's effort. ``isolation``
    defaults to ``worktree``: the junior's changes stay staged until
    a senior verifier approves them. ``isolation: none`` is an
    explicit opt-in — the junior then edits the operator tree
    directly, and verification gates completion, not the files.
    ``tools`` is an allowlist for a mediating harness:
    ``is_tool_allowed`` denies every tool on an empty allowlist
    (fail-closed), but the runner and the CLI never mediate the
    junior's tool calls, so for the shipped CLI the allowlist is a
    request forwarded to the junior runtime, not an enforced
    boundary. ``background`` is always False: a contract declaring
    background execution is rejected, because this runner runs the
    junior synchronously.
    """

    name: str
    description: str
    model: str = "inherit"
    tools: tuple[str, ...] = ()
    denied_tools: tuple[str, ...] = ()
    permission_mode: PermissionMode = PermissionMode.DEFAULT
    isolation: Isolation = Isolation.WORKTREE
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
                "contract needs a lowercase-hyphen 'name' (e.g. 'mechanical-refactor')"
            )
        if not isinstance(description, str) or not description.strip():
            raise ContractRejectedError("contract requires a non-empty 'description'")
        tools = _lookup(fields, "tools") or []
        denied_tools = _lookup(fields, "denied_tools") or []
        if not isinstance(tools, list) or not isinstance(denied_tools, list):
            raise ContractRejectedError("'tools' and 'denied_tools' must be lists")
        permission_mode = PermissionMode.DEFAULT
        raw_mode = _lookup(fields, "permission_mode")
        if raw_mode is not None:
            if not isinstance(raw_mode, str) or not raw_mode:
                raise ContractRejectedError(f"permission_mode must be a string, got: {raw_mode!r}")
            try:
                permission_mode = PermissionMode(raw_mode)
            except ValueError:
                raise ContractRejectedError(f"unknown permission_mode: {raw_mode!r}") from None
        isolation = Isolation.WORKTREE
        raw_isolation = _lookup(fields, "isolation")
        if raw_isolation is not None:
            if not isinstance(raw_isolation, str) or not raw_isolation:
                raise ContractRejectedError(f"isolation must be a string, got: {raw_isolation!r}")
            try:
                isolation = Isolation(raw_isolation)
            except ValueError:
                raise ContractRejectedError(f"unknown isolation: {raw_isolation!r}") from None
        effort: Effort | None = None
        raw_effort = _lookup(fields, "effort")
        if raw_effort is not None:
            if not isinstance(raw_effort, str) or not raw_effort:
                raise ContractRejectedError(f"effort must be a string, got: {raw_effort!r}")
            try:
                effort = Effort(raw_effort)
            except ValueError:
                raise ContractRejectedError(f"unknown effort: {raw_effort!r}") from None
        max_turns = _DEFAULT_MAX_TURNS
        raw_turns = _lookup(fields, "max_turns")
        if raw_turns is not None:
            if isinstance(raw_turns, bool):
                raise ContractRejectedError(f"max_turns must be an integer, got: {raw_turns!r}")
            if isinstance(raw_turns, int):
                max_turns = raw_turns
            elif isinstance(raw_turns, str) and raw_turns:
                try:
                    max_turns = int(raw_turns)
                except ValueError:
                    raise ContractRejectedError(
                        f"max_turns is not an integer: {raw_turns!r}"
                    ) from None
            else:
                raise ContractRejectedError(f"max_turns must be an integer, got: {raw_turns!r}")
            if max_turns < 1:
                raise ContractRejectedError("max_turns must be >= 1")
            if max_turns > _MAX_TURNS_LIMIT:
                raise ContractRejectedError(f"max_turns must be <= {_MAX_TURNS_LIMIT}")
        raw_background = _lookup(fields, "background")
        if (
            raw_background is None
            or raw_background == "false"
            or (isinstance(raw_background, bool) and not raw_background)
        ):
            background = False
        elif raw_background == "true" or (isinstance(raw_background, bool) and raw_background):
            raise ContractRejectedError(
                "background delegations are not supported by this runner: "
                "it runs the junior in the foreground (omit 'background' "
                "or declare 'background: false')"
            )
        else:
            raise ContractRejectedError(
                f"background must be 'true' or 'false', got: {raw_background!r}"
            )
        model = _lookup(fields, "model")
        if model is not None and not isinstance(model, str):
            raise ContractRejectedError(f"model must be a string, got: {type(model).__name__}")
        raw_memory = _lookup(fields, "memory")
        memory = MemoryScope.NONE
        if raw_memory is not None:
            if not isinstance(raw_memory, str) or not raw_memory:
                raise ContractRejectedError(f"memory must be a string, got: {raw_memory!r}")
            try:
                memory = MemoryScope(raw_memory)
            except ValueError:
                raise ContractRejectedError(f"unknown memory: {raw_memory!r}") from None
        return cls(
            name=name,
            description=description,
            model=model if isinstance(model, str) and model.strip() else "inherit",
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
        that declares no tools delegates no tool use — within this
        check. This is a helper for a mediating harness: the runner
        and the CLI never call it, and a junior subprocess is not
        mediated, so the allowlist does not by itself bound what the
        junior runs. A denied tool is never allowed, even when it is
        also listed in the allowlist. Tool names normalize before the
        check, so ``READ`` and ``  bash `` match the stored lowercase
        entries.
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

        The junior runtime is asked to honour tools, permission_mode,
        max_turns, effort, memory, and model from these; nothing in
        this repository enforces them on an arbitrary subprocess. This
        library enforces isolation, loop prevention, scrubbing, and
        verification.
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

        A line that does not parse, a line that is not a JSON object,
        an object without a parseable ``started`` field, a naive
        timestamp (coerced to UTC: this module only ever writes aware
        UTC), or a future-dated event (forged or clock-skewed) is
        skipped, never counted.
        """
        current = now or datetime.now(UTC)
        count = 0
        for line in self._read_recent_lines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            if entry.get("kind") != DelegationAuditKind.DELEGATION_STARTED.value:
                continue
            started_raw = entry.get("started")
            if started_raw is None:
                continue
            try:
                started = datetime.fromisoformat(str(started_raw))
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
    OpenProcess + GetExitCodeProcess (STILL_ACTIVE == 259). A pid
    outside the DWORD range names no process on either platform, but
    the lock naming it is corrupt, not dead, so it is alive by the
    same fail-closed rule — checked up front, because ctypes would
    silently truncate it into a DWORD on Windows and probe a
    different pid, and ``os.kill(-1, 0)`` on POSIX would signal the
    process group.
    """
    if pid < 0 or pid > 0xFFFF_FFFF:
        return True
    if os.name == "nt":
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OverflowError:
        # A pid that does not fit in pid_t (e.g. 9999999999 in a
        # corrupt lock file) names no process, but the lock is
        # corrupt, not dead: fail closed (alive).
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


def _unlink_retry(path: Path) -> None:
    """Unlink a lock file, retrying share violations.

    On Windows a file cannot be unlinked while another thread or
    process holds it open (WinError 32): a concurrent ``_read_lock_pid``
    may have it open for a moment. Retry briefly instead of failing
    the delegation on a transient share violation; on POSIX the first
    attempt succeeds. The final attempt raises if the file is still
    held: a lock that cannot be released must fail loudly, never
    silently strand a live delegation id.
    """
    for _ in range(50):
        try:
            path.unlink(missing_ok=True)
            return
        except PermissionError:
            time.sleep(0.02)
    path.unlink(missing_ok=True)


@dataclass
class _LockArbiter:
    """The kernel arbiter behind one delegation lock.

    The pid file is informational (which pid holds the id, for the
    refusal message and the reclaim audit) and fail-closed on its
    content; exclusion itself is a kernel object held for the whole
    ``with`` block: ``flock`` on POSIX, a named mutex on Windows.
    The stale file is never unlinked by an acquirer — only by the
    holder on release, while it still holds the arbiter — so the
    old unlink-then-create reclaim race (two reclaimers both
    re-reading a stale pid, one unlinking the other's fresh lock
    and stranding two holders on one id) cannot happen: the
    arbiter, not the file's existence, decides who holds the id.
    """

    path: Path
    fd: int | None = None
    mutex: int | None = None  # Windows named-mutex handle, when held

    @classmethod
    def acquire(cls, path: Path) -> "_LockArbiter | None":
        """Acquire the arbiter for ``path`` (None: held by another)."""
        if os.name == "nt":
            return cls._acquire_windows(path)
        return cls._acquire_posix(path)

    @classmethod
    def _acquire_posix(cls, path: Path) -> "_LockArbiter | None":
        import fcntl

        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            return None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return None
        return cls(path=path, fd=fd)

    @classmethod
    def _acquire_windows(cls, path: Path) -> "_LockArbiter | None":
        import ctypes
        import hashlib
        from ctypes import wintypes

        # WinDLL exists only on Windows; getattr keeps mypy (Linux)
        # quiet and this method only ever runs when os.name == "nt".
        windll = getattr(ctypes, "WinDLL", None)
        if windll is None:
            return None
        kernel32 = windll("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = (
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        )
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
        )
        kernel32.ReleaseMutex.restype = wintypes.BOOL
        kernel32.ReleaseMutex.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        try:
            resolved = os.fspath(path.resolve())
        except OSError:
            resolved = os.fspath(path.absolute())
        name = "Local\\mcp-guard-lock-" + hashlib.sha256(resolved.encode("utf-8")).hexdigest()
        handle = kernel32.CreateMutexW(None, 0, name)
        if not handle:
            return None
        # WAIT_OBJECT_0 (0): acquired. WAIT_ABANDONED (0x80): the
        # previous owner died without releasing; ownership passes
        # to us, which is exactly the stale-lock case. Anything else
        # (WAIT_TIMEOUT) means another holder owns the mutex.
        result = kernel32.WaitForSingleObject(handle, 0)
        if result not in (0, 0x80):
            kernel32.CloseHandle(handle)
            return None
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
            return None
        return cls(path=path, fd=fd, mutex=handle)

    def inode(self) -> int:
        """The inode of the file this arbiter guards (0: unknown)."""
        if self.fd is None:
            return 0
        try:
            return os.fstat(self.fd).st_ino
        except OSError:
            return 0

    def write_pid(self, pid: int) -> None:
        """Record our pid in the lock file.

        Truncate first: the stale pid may be longer than ours, and
        a plain write would leave its tail behind (``123999``).
        """
        if self.fd is None:
            raise OSError("lock arbiter has no file descriptor")
        os.ftruncate(self.fd, 0)
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.write(self.fd, str(pid).encode("utf-8"))

    def release(self) -> None:
        """Release the arbiter and remove the lock file."""
        if os.name == "nt":
            self._release_windows()
        else:
            self._release_posix()

    def _release_posix(self) -> None:
        # Unlink while still holding the flock, then close: closing
        # first would let a fresh acquirer lock the file and then
        # have it unlinked from under it.
        _unlink_retry(self.path)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _release_windows(self) -> None:
        # Windows cannot unlink an open file (share violation), so
        # the fd closes first; the named mutex — held until after
        # the unlink — is what keeps a fresh acquirer from racing
        # the release.
        import ctypes
        from ctypes import wintypes

        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        _unlink_retry(self.path)
        if self.mutex is not None:
            windll = getattr(ctypes, "WinDLL", None)
            if windll is not None:
                kernel32 = windll("kernel32", use_last_error=True)
                kernel32.ReleaseMutex.restype = wintypes.BOOL
                kernel32.ReleaseMutex.argtypes = (wintypes.HANDLE,)
                kernel32.CloseHandle.restype = wintypes.BOOL
                kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
                kernel32.ReleaseMutex(self.mutex)
                kernel32.CloseHandle(self.mutex)
            self.mutex = None


@dataclass
class LoopGuard:
    """The three loop-prevention layers, all active before any
    delegation proceeds.

    L1 environment: the ``MCP_GUARD_DELEGATION_DEPTH`` marker is
    inherited by the child; a delegation running inside a delegation
    is refused.
    L2 lock file: one live delegation per delegation id, via a kernel
    arbiter (flock on POSIX, named mutex on Windows) held for the
    whole delegation; the pid file is informational (which pid holds
    the id) and fail-closed on its content, and a stale lock is
    reclaimed only when the recorded pid is dead — the stale file is
    never unlinked by an acquirer, only by the holder on release
    while it still holds the arbiter, so two concurrent reclaimers
    cannot strand two holders on one id.
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
        if value < 0 or value >= self.max_depth:
            raise LoopRefusedError(
                LoopLayer.ENVIRONMENT,
                f"delegation depth {value} outside [0, {self.max_depth})",
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
        except (OSError, UnicodeDecodeError):
            # A lock file that cannot be read — or is not valid UTF-8 —
            # is corrupt, not dead: None makes the caller refuse
            # fail-closed ("lock unreadable") instead of crashing the
            # probe on corrupt input.
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

        The pid file is informational and fail-closed: a live pid
        or an unreadable (corrupt/empty) file refuses. Exclusion
        itself is a kernel arbiter (``_LockArbiter``: flock on POSIX,
        named mutex on Windows) held for the whole ``with`` block:
        the stale file is never unlinked by an acquirer, so two
        reclaimers cannot strand two holders on one id the way the
        old unlink-then-create reclaim could. Between the arbiter
        acquisition and the pid write the file is momentarily empty;
        a reader retries briefly before refusing on a lock that is
        still being created, rather than treating an empty file as a
        corrupt lock.
        """

        @contextmanager
        def acquire() -> Iterator[None]:
            path = self._lock_path(delegation_id)
            self.lock_dir.mkdir(parents=True, exist_ok=True)
            holder: _LockArbiter | None = None
            for _ in range(_LOCK_ACQUIRE_ATTEMPTS):
                pid = self._read_lock_pid(path)
                if pid is None and self._lock_file_empty(path):
                    for _ in range(_LOCK_RETRY_ATTEMPTS):
                        time.sleep(_LOCK_RETRY_DELAY)
                        pid = self._read_lock_pid(path)
                        if pid is not None:
                            break
                if pid is None and path.exists():
                    # Unreadable lock (corrupt content, or still empty
                    # after the creation retry): fail closed. A lock
                    # whose owner cannot be proven dead stays locked
                    # until an operator removes it.
                    raise LoopRefusedError(
                        LoopLayer.LOCK_FILE,
                        f"delegation {delegation_id!r} already running (lock unreadable)",
                    )
                if pid is not None and _pid_alive(pid):
                    raise LoopRefusedError(
                        LoopLayer.LOCK_FILE,
                        f"delegation {delegation_id!r} already running (pid {pid})",
                    )
                holder = _LockArbiter.acquire(path)
                if holder is None:
                    raise LoopRefusedError(
                        LoopLayer.LOCK_FILE,
                        f"delegation {delegation_id!r} already running",
                    )
                # The holder may have opened the path just as the
                # previous holder released it: the file the arbiter
                # guards can be a stale inode the path no longer
                # points at. A vanished path is a retry, never a
                # skip: proceeding on an unlinked inode would let a
                # fresh holder of the new file share the id.
                # (A zero inode means the platform does not report
                # one; the check is skipped there, not faked.)
                try:
                    ours = holder.inode()
                    theirs = os.stat(path).st_ino
                except OSError:
                    holder.release()
                    holder = None
                    continue
                if ours and theirs and ours != theirs:
                    holder.release()
                    holder = None
                    continue
                break
            if holder is None:
                raise LoopRefusedError(
                    LoopLayer.LOCK_FILE,
                    f"delegation {delegation_id!r} already running (lock replaced during acquire)",
                )
            try:
                # The reclaim is recorded only after the arbiter
                # proves this holder owns the path: a lost race above
                # must not leave a reclaim in the audit that never
                # happened. The pid is re-read after acquiring: the
                # file may have turned over since the pre-check.
                reclaimed_pid = self._read_lock_pid(path)
                holder.write_pid(os.getpid())
            except OSError:
                holder.release()
                raise LoopRefusedError(
                    LoopLayer.LOCK_FILE,
                    f"delegation {delegation_id!r} already running (lock unwritable)",
                ) from None
            if reclaimed_pid is not None:
                audit_log.record(
                    DelegationAuditKind.LOCK_RECLAIMED,
                    delegation_id,
                    {"pid": reclaimed_pid},
                )
            try:
                yield
            finally:
                holder.release()

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
                            LoopLayer.AUDIT_LOCK,
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
        AND the verification step while ``delegate()`` holds them: a
        second delegation with the same id cannot start while the first
        is still running. Once ``delegate()`` returns a result that is
        still PENDING_VERIFICATION, the lock is released — but the pending
        obligation is durable: ``delegate()`` writes a pending record
        (``<lock_dir>/<id>.pending.json``) and audits DELEGATION_PENDING
        (with the staged worktree path, when there is one) before it
        returns, so the fact that verification is still owed survives
        the process exit and ``resolve_pending`` can discharge it later.
        Every refusal (including a lock refusal) is audited before it
        is re-raised.
        """

        @contextmanager
        def acquire() -> Iterator[None]:
            try:
                if delegation_id == _AUDIT_LOCK_ID:
                    # The global audit lock uses this id: a delegation with
                    # the same id would deadlock the rate-limit critical
                    # section against its own live pid.
                    raise LoopRefusedError(
                        LoopLayer.AUDIT_LOCK,
                        f"delegation id {_AUDIT_LOCK_ID!r} is reserved for the global audit lock",
                    )
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


def _split_command(command: str) -> list[str]:
    """Split a verifier command line the way the platform reads it.

    POSIX: plain shlex (a backslash escapes the next character).
    Windows: shlex with posix=False, so backslashes stay path
    separators instead of escapes (plain shlex would mangle
    ``C:\\tools\\python.exe`` into ``C:toolspython.exe`` and the
    verifier could never run). posix=False keeps double quotes in the
    token, so one surrounding pair per token is stripped; single
    quotes inside (e.g. in a ``-c`` program) are left alone.
    """
    argv = shlex.split(command, posix=(os.name != "nt"))
    if os.name == "nt":
        argv = [
            token[1:-1]
            if len(token) >= 2 and token.startswith('"') and token.endswith('"')
            else token
            for token in argv
        ]
    return argv


@dataclass
class CommandVerifier:
    """A verifier that runs a command and approves on exit 0.

    The command receives the result summary as JSON on stdin. A
    verifier that cannot run (missing binary, timeout, bad quoting)
    REJECTS: a verification that did not happen is not an approval.
    The verifier's stderr from the last run is kept on ``last_stderr``
    (bounded): a missing binary and a rejection on substance must not
    look identical to the operator.
    """

    command: str
    last_stderr: str = field(default="", init=False)

    def verify(self, result: "DelegationResult") -> VerificationVerdict:
        """Run the command; approve only on exit 0.

        The verifier runs where the deliverable lives: the worktree
        when the result carries one, else the repo directory. A
        verifier that cannot find the deliverable is a rubber stamp —
        in worktree mode the changed bytes exist only in the worktree,
        so running in the main tree would judge pre-delegation bytes.
        """
        try:
            argv = _split_command(self.command)
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
                encoding="utf-8",
                timeout=_VERIFIER_TIMEOUT,
                cwd=result.worktree_path or result.repo_dir,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return VerificationVerdict.REJECTED
        self.last_stderr = _bounded_output(completed.stderr)
        if completed.returncode == 0:
            return VerificationVerdict.APPROVED
        return VerificationVerdict.REJECTED


@dataclass
class ConcealmentVerifier:
    """A pre-gate verifier for the concealment catalog (rat #75).

    Checks the staged files of a delegation result against the visible
    pipeline manifest (augmentation-embedding detector): a staged file
    no pipeline stage references, or one only a later stage consumes
    with no declared origin, rejects the result — the staged work never
    lands, even when the senior verifier would approve it.

    This is a pre-gate, not a senior: it REQUIRES an inner senior
    verifier, and a concealment-clean result is handed to that inner
    verifier for the actual approval. Constructing without one raises
    TypeError — a pre-gate that approved on its own would let staged
    work land with no senior review. A manifest with no stages is
    rejected at ``PipelineManifest`` construction, so this verifier
    never runs against an empty pipeline.
    """

    manifest: PipelineManifest
    inner: SeniorVerifier

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, PipelineManifest):
            raise TypeError("ConcealmentVerifier needs a PipelineManifest")
        if self.inner is None:
            raise TypeError("ConcealmentVerifier needs an inner senior verifier")

    def verify(self, result: "DelegationResult") -> VerificationVerdict:
        """Run the concealment check first, then the senior verifier.

        A staged path that escapes the tree (``..`` / absolute) raises
        ValueError from ``StagedFile`` — both ``delegate`` and
        ``resolve_pending`` turn a raising verifier into a rejection,
        so a hostile change list rejects instead of crashing the run.
        """
        staged = tuple(StagedFile(path) for path in result.changed_files)
        finding = augmentation_scan(staged, self.manifest)
        if finding.tripped:
            return VerificationVerdict.REJECTED
        return self.inner.verify(result)


# ---------------------------------------------------------------------------
# Delegation result
# ---------------------------------------------------------------------------


@dataclass
class DelegationResult:
    """The outcome of one delegation run.

    The result starts PENDING_VERIFICATION and only ``apply_verdict``
    (the senior verifier) or ``complete`` may move it to COMPLETE or
    REJECTED. Direct assignment to ``state``, ``verification``, or
    ``rejection_reason`` raises AttributeError, and construction in a
    terminal state raises ValueError: a freshly constructed result is
    PENDING_VERIFICATION, or TIMEOUT when the runner builds it after a
    junior timeout. A caller that constructs a result directly (or
    uses ``dataclasses.replace``) can therefore never mint an approved
    result; the supported API is the transition methods.
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
    # Where staged junior work lives while the result is pending (worktree
    # isolation only): the files exist ONLY here until an APPROVED verdict
    # lands them. None once the worktree is removed (approved/rejected) or
    # when the delegation never used a worktree. The verifier reads the
    # deliverable from this path; the CLI prints it for the operator.
    worktree_path: str | None = None
    # The repo directory the delegation ran against (None when run
    # without one): carried in the summary so the verifier can resolve
    # the changed paths, and so a pending record can be discharged
    # later without re-deriving it.
    repo_dir: str | None = None
    # The secret-shape kinds found in the prompt / contract fields
    # (names only, never values): surfaced in the summary so the
    # crossing is visible on the machine-readable path even under
    # --quiet, where the stderr warning is suppressed.
    secret_shape_kinds: frozenset[str] = frozenset()
    _sealed: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.state not in (
            DelegationState.PENDING_VERIFICATION,
            DelegationState.TIMEOUT,
        ):
            raise ValueError(
                f"a freshly constructed result cannot be {self.state.value}: "
                "only PENDING_VERIFICATION (or TIMEOUT, built by the runner) "
                "is constructible; COMPLETE/REJECTED come from apply_verdict"
            )
        if self.verification is not None:
            raise ValueError(
                "a freshly constructed result cannot carry a preset "
                "verification: only apply_verdict sets it"
            )
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
        An APPROVED verdict is refused while ``worktree_path`` is
        still set: staged work must be landed first (the runner does
        that inside ``delegate`` / ``resolve_pending``), or a late
        approval would mint COMPLETE with the files still sitting in
        the worktree. A REJECTED verdict is allowed with staging set:
        the runner discards the staging right after.
        """
        if self.state is not DelegationState.PENDING_VERIFICATION:
            raise VerificationError(f"cannot verify a result in state {self.state.value}")
        if verdict is VerificationVerdict.APPROVED and self.worktree_path is not None:
            raise VerificationError(
                "cannot complete: staged worktree has not been landed "
                f"(worktree at {self.worktree_path}); resolve the pending "
                "delegation through the runner instead"
            )
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
        """The machine-readable summary (the verifier's stdin).

        The senior verifier must be able to read the deliverable, so
        the summary carries bounded junior stdout/stderr alongside the
        return code and the changed files: for the report kinds the
        deliverable *is* the junior's stdout, and a verifier that
        never sees it is a rubber stamp. Output is truncated at
        ``_SUMMARY_OUTPUT_LIMIT`` chars with a marker, never dropped
        silently.
        """
        return {
            "delegation_id": self.delegation_id,
            "task": self.task.value,
            "state": self.state.value,
            "verification": (self.verification.value if self.verification else None),
            "effective_effort": self.effective_effort.value,
            "verification_step": self.verification_step.value,
            "junior_returncode": self.junior_returncode,
            "junior_stdout": _bounded_output(self.junior_stdout),
            "junior_stderr": _bounded_output(self.junior_stderr),
            "changed_files": list(self.changed_files),
            "rejection_reason": self.rejection_reason,
            "worktree_path": self.worktree_path,
            "repo_dir": self.repo_dir,
            "secret_shape_kinds": sorted(self.secret_shape_kinds),
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
        identity_token: str | None = None,
    ) -> DelegationResult:
        """Run one delegation against a validated contract.

        The guard (L1 + L2) spans the junior run AND verification; the
        rate-limit check and the STARTED record are serialized under
        the global audit lock. A delegation without a contract is
        rejected before anything runs: the caller must pass a parsed
        ``DelegationContract``, a verbal "be careful" is not one.
        ``identity_token`` (rat #70, from ``delegate --identity``)
        attributes the delegation to the delegating user's scope in
        the STARTED audit event; the admission check itself (contract
        tools inside the scope) is the CLI's job, before this runs.
        """
        guard = self.guard
        if guard is None:
            raise DelegationError("runner has no loop guard")
        effective_env = dict(env) if env is not None else dict(os.environ)
        audit_log = DelegationAuditLog(self.lock_dir / "audit.jsonl")
        route = route_for(task)
        effective_effort = contract.effort if contract.effort is not None else route.effort
        contract_file = self.lock_dir / f"{delegation_id}.contract.json"
        if contract.isolation is Isolation.NONE:
            # Explicit opt-in, warned: in this mode the junior edits
            # the operator tree directly and verification gates
            # completion, not the files.
            logger.warning(
                "delegation %s uses isolation: none — the junior edits "
                "the working tree directly; approval gates acting on "
                "the changes, not their presence",
                delegation_id,
            )
        try:
            with guard.guard(delegation_id, effective_env, audit_log):
                # A pending record for this id means staged work (or,
                # in isolation none, unverified edits) still owes a
                # senior verdict — in every isolation mode, not just
                # worktree. Re-delegating would overwrite that
                # obligation, so refuse before anything runs.
                if self._pending_path(delegation_id).exists():
                    raise DelegationError(
                        f"a pending delegation {delegation_id!r} still awaits a senior verdict; "
                        "resolve it first (delegate --resolve-pending) or discard it "
                        "(delegate --discard-pending) instead of re-delegating"
                    )
                tokenizer = PiiTokenizer()
                scrubbed, tokens = tokenizer.tokenize_text(prompt)
                prompt_hash = hashlib.sha256(scrubbed.encode("utf-8")).hexdigest()[:16]
                # The description and model are forwarded verbatim to
                # the junior alongside the prompt, so a token pasted
                # into them must warn just like one in the prompt.
                shape_kinds = (
                    _shape_kinds(prompt)
                    | _shape_kinds(contract.description)
                    | _shape_kinds(contract.model)
                )
                if shape_kinds:
                    # The PII scrubber does not redact arbitrary secrets, so a
                    # secret-shaped prompt must not cross the handoff
                    # silently: warn (kinds only, never values) and leave an
                    # audit trace. This is a warning, never a refusal — the
                    # operator wrote the prompt.
                    logger.warning(
                        "prompt for %s looks secret-bearing (%s); the PII scrubber "
                        "does not redact arbitrary secrets, so the junior will "
                        "see them verbatim",
                        delegation_id,
                        ",".join(sorted(shape_kinds)),
                    )
                    audit_log.record(
                        DelegationAuditKind.SECRET_SHAPE_WARNED,
                        delegation_id,
                        {
                            "kinds": ",".join(sorted(shape_kinds)),
                            "kind_count": len(shape_kinds),
                        },
                    )
                with guard._serialized_audit(audit_log):
                    guard.check_rate_limit(audit_log)
                    started_detail: dict[str, str | int] = {
                        "task": task.value,
                        "step": route.verification.value,
                        "prompt_hash": prompt_hash,
                        "token_kinds": ",".join(sorted({token.kind.value for token in tokens})),
                        "token_count": len(tokens),
                    }
                    if identity_token is not None:
                        started_detail["identity"] = identity_token
                    audit_log.record(
                        DelegationAuditKind.DELEGATION_STARTED,
                        delegation_id,
                        started_detail,
                    )
                child_env = self._child_env(
                    effective_env,
                    contract,
                    task,
                    route,
                    effective_effort,
                    contract_file,
                )
                result, changes, worktree, main_snapshot = self._run_junior(
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
                    shape_kinds=shape_kinds,
                )
                if result.state is DelegationState.TIMEOUT:
                    if contract.isolation is Isolation.NONE:
                        # The partial writes are already in the
                        # operator tree and cannot be discarded, so
                        # the verification obligation must survive as
                        # a pending record: without it the timeout
                        # leaves unverified work with no path to a
                        # senior verdict. (Worktree mode already
                        # removed the staging in _run_junior, so
                        # there is nothing left to verify there.)
                        self._write_pending_file(
                            delegation_id=delegation_id,
                            task=task,
                            route=route,
                            effective_effort=effective_effort,
                            result=result,
                            changes=changes,
                            worktree=None,
                            repo_dir=repo_dir,
                            contract=contract,
                            main_snapshot=main_snapshot,
                            verdict=None,
                            timed_out=True,
                        )
                        audit_log.record(
                            DelegationAuditKind.DELEGATION_PENDING,
                            delegation_id,
                            {
                                "isolation": contract.isolation.value,
                                "timed_out": True,
                            },
                        )
                    return result
                precondition = _step_precondition_failed(result, route, repo_dir=repo_dir)
                if precondition is not None:
                    result.reject_with_reason(precondition)
                    audit_log.record(
                        DelegationAuditKind.VERIFICATION_REJECTED,
                        delegation_id,
                        {"reason": precondition, "step": route.verification.value},
                    )
                    self._discard_worktree(repo_dir, worktree, audit_log, delegation_id, result)
                    return result
                if verifier is not None:
                    try:
                        # The verifier gets a snapshot copy, never the
                        # live result: a programmatic verifier that
                        # calls apply_verdict on its argument (or
                        # mutates the result) must not break delegate()'s
                        # control flow or leak the staged worktree.
                        # (Its apply_verdict on the staged snapshot
                        # raises VerificationError, which the handler
                        # below turns into a rejection with the staging
                        # discarded — fail-closed, never a leak.)
                        verdict = verifier.verify(replace(result))
                    except Exception as error:  # noqa: BLE001 - a raising verifier is a rejection, never a crash
                        audit_log.record(
                            DelegationAuditKind.VERIFICATION_REJECTED,
                            delegation_id,
                            {
                                "reason": f"verifier raised {type(error).__name__}",
                                "step": route.verification.value,
                            },
                        )
                        result.reject_with_reason(
                            f"verifier raised {type(error).__name__}: {error}"
                        )
                        self._discard_worktree(repo_dir, worktree, audit_log, delegation_id, result)
                        return result
                    if verdict is VerificationVerdict.APPROVED:
                        # TIMEOUT returns above, so an approved result
                        # always has a junior return code; None here is a
                        # bug, and completing without one would audit a
                        # made-up value — fail closed instead.
                        if result.junior_returncode is None:
                            raise DelegationError(
                                "cannot complete: approved delegation has no junior return code"
                            )
                        # Land the deliverable BEFORE the verdict is applied:
                        # a copy-back failure leaves the result pending, never
                        # complete with unlanded files.
                        if worktree is not None and repo_dir is not None:
                            try:
                                self._copy_back(
                                    worktree,
                                    repo_dir,
                                    changes,
                                    audit_log,
                                    delegation_id,
                                    main_snapshot,
                                )
                            except (OSError, DelegationError) as error:
                                audit_log.record(
                                    DelegationAuditKind.COPYBACK_FAILED,
                                    delegation_id,
                                    {"reason": str(error), "worktree": str(worktree)},
                                )
                                # The approval is recorded in the
                                # pending record as audit history, but
                                # resolve_pending never trusts it: the
                                # senior verifier re-runs before
                                # anything lands.
                                self._write_pending_file(
                                    delegation_id=delegation_id,
                                    task=task,
                                    route=route,
                                    effective_effort=effective_effort,
                                    result=result,
                                    changes=changes,
                                    worktree=worktree,
                                    repo_dir=repo_dir,
                                    contract=contract,
                                    main_snapshot=main_snapshot,
                                    verdict=VerificationVerdict.APPROVED,
                                )
                                raise DelegationError(
                                    f"copy-back failed (worktree kept at {worktree}): {error}"
                                ) from error
                            self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
                            result.worktree_path = None
                        result.apply_verdict(verdict)
                        audit_log.record(
                            DelegationAuditKind.VERIFICATION_APPROVED,
                            delegation_id,
                            {"step": route.verification.value},
                        )
                        audit_log.record(
                            DelegationAuditKind.DELEGATION_COMPLETED,
                            delegation_id,
                            {"returncode": result.junior_returncode},
                        )
                    else:
                        try:
                            result.apply_verdict(verdict)
                        except VerificationError:
                            # The verdict cannot apply (a bug, not a
                            # rejection): discard the staging before the
                            # error propagates, so no worktree leaks.
                            self._discard_worktree(
                                repo_dir, worktree, audit_log, delegation_id, result
                            )
                            raise
                        audit_log.record(
                            DelegationAuditKind.VERIFICATION_REJECTED,
                            delegation_id,
                            {"step": route.verification.value},
                        )
                        self._discard_worktree(repo_dir, worktree, audit_log, delegation_id, result)
                    return result
                # No verifier: the result stays pending and the worktree stays
                # staged, not landed. The pending obligation is durable: a
                # pending record on disk (plus an audit event recording
                # where the staged work lives) lets resolve_pending
                # discharge it later, and the lock release does not erase
                # the fact that verification is still owed.
                self._write_pending_file(
                    delegation_id=delegation_id,
                    task=task,
                    route=route,
                    effective_effort=effective_effort,
                    result=result,
                    changes=changes,
                    worktree=worktree,
                    repo_dir=repo_dir,
                    contract=contract,
                    main_snapshot=main_snapshot,
                    verdict=None,
                )
                audit_log.record(
                    DelegationAuditKind.DELEGATION_PENDING,
                    delegation_id,
                    {
                        "isolation": contract.isolation.value,
                        **({"worktree": str(worktree)} if worktree is not None else {}),
                    },
                )
                return result
        except LoopRefusedError:
            raise
        except DelegationError:
            raise
        except OSError as error:
            raise DelegationError(f"delegation failed: {error}") from error

    def _pending_path(self, delegation_id: str) -> Path:
        """The pending record for a delegation id."""
        return self.lock_dir / f"{delegation_id}.pending.json"

    def _unlink_pending(self, delegation_id: str) -> None:
        """Delete the pending record; a failed delete is a typed
        failure, never a traceback out of ``resolve_pending``."""
        try:
            self._pending_path(delegation_id).unlink(missing_ok=True)
        except OSError as error:
            raise DelegationError(
                f"could not delete pending record for {delegation_id!r}: {error}"
            ) from error

    def _write_pending_file(
        self,
        delegation_id: str,
        task: TaskKind,
        route: Route,
        effective_effort: Effort,
        result: DelegationResult,
        changes: tuple[tuple[str, str, str | None, str], ...],
        worktree: Path | None,
        repo_dir: Path | None,
        contract: DelegationContract,
        main_snapshot: dict[str, str] | None,
        verdict: VerificationVerdict | None,
        timed_out: bool = False,
    ) -> None:
        """Persist the pending obligation. Best-effort, never raises:
        a pending record that cannot be written is logged, and the
        audit event still records where staged work lives.

        The write is atomic (temp file + rename) so a crash mid-write
        never leaves a torn record. The stored ``verdict`` and
        ``main_snapshot`` are audit history only — what was in force
        when the record was written — and ``resolve_pending`` never
        trusts them: the senior verifier always re-runs, the change
        list is re-derived from live state, and the HEAD baseline is
        recomputed from live git. The record carries NO pre-run
        baseline: a record-supplied baseline can be forged to the
        post-run hashes and hide junior changes, so isolation-none
        re-derivation compares live git status against HEAD instead.
        ``timed_out`` marks a record written after a junior timeout,
        where no return code exists.
        """
        record: dict[str, object] = {
            "version": _PENDING_VERSION,
            "delegation_id": delegation_id,
            "task": task.value,
            "effective_effort": effective_effort.value,
            "verification_step": route.verification.value,
            "junior_returncode": result.junior_returncode,
            "junior_stdout": result.junior_stdout,
            "junior_stderr": result.junior_stderr,
            "changed_files": list(result.changed_files),
            "changes": [[status, path, old_path, sha] for status, path, old_path, sha in changes],
            "worktree": str(worktree) if worktree is not None else None,
            "repo_dir": str(repo_dir) if repo_dir is not None else None,
            "contract": contract.to_dict(),
            "main_snapshot": main_snapshot,
            "secret_shape_kinds": sorted(result.secret_shape_kinds),
            "verdict": verdict.value if verdict is not None else None,
            "timed_out": timed_out,
        }
        try:
            path = self._pending_path(delegation_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            logger.warning(
                "pending record write failed for %s: the pending "
                "obligation survives only as an audit event",
                delegation_id,
                exc_info=True,
            )

    def resolve_pending(
        self,
        delegation_id: str,
        verifier: SeniorVerifier,
        repo_dir: Path | None = None,
    ) -> DelegationResult:
        """Discharge a pending delegation recorded by ``delegate``.

        Loads the pending record, re-acquires the per-id lock (a live
        delegation with the same id refuses), and finishes what
        ``delegate`` left open. The senior verifier ALWAYS re-runs,
        and the routed step's mechanical precondition runs before it,
        exactly as in the in-run path. The pending record is
        unauthenticated JSON in a junior-reachable directory, so what
        it says is trusted only where it cannot be re-derived: the
        task, the junior exit code, and the junior output are taken
        from the record, and the record's shape is enforced (a
        worktree-mode record cannot be timed out, a non-timeout record
        must carry an exit code, a timeout record must carry none).
        Everything that decides a landing is re-derived instead: the
        stored verdict is audit history only, the change list is
        re-derived from live state (the worktree, or live git status
        against HEAD for isolation none — the record carries no
        baseline), the HEAD baseline is recomputed from live git, the
        worktree must be exactly this delegation's worktree and
        registered in the operator-supplied repo, the stored
        contract's isolation must agree with the record's worktree
        field, and the isolation-none branch refuses when staging for
        this id exists on disk or is registered in the operator repo
        (the contract and the worktree field live in the same
        unsigned record, so a coherent flip of both cannot be the
        anchor — live git is), and the repo must be supplied by the
        operator — the stored repo is never used on its own. Report-kind steps (their
        deliverable is the recorded junior output) cannot be resolved
        from a pending record at all: re-run the delegation with a
        verifier, or discard the pending record with
        ``discard_pending``. Approval lands the staged work through
        the same conflict- and drift-checked copy-back as the in-run
        path; rejection discards the staging.
        The pending record is deleted on any terminal outcome. Raises
        ``DelegationError`` when no pending record exists, it is
        corrupt, its shape is impossible, the staged worktree is gone
        or is not this delegation's, or a change path escapes the tree.
        """
        guard = self.guard
        if guard is None:
            raise DelegationError("runner has no loop guard")
        if not _ID_RE.match(delegation_id):
            # The record is read before the guard validates the id, so
            # a library caller could otherwise traverse (`../`) to an
            # arbitrary *.pending.json. The CLI sanitizes ids; the
            # library enforces the same shape here.
            raise DelegationError(f"invalid delegation id {delegation_id!r}")
        try:
            record = json.loads(self._pending_path(delegation_id).read_text(encoding="utf-8"))
            if not isinstance(record, dict) or record["version"] != _PENDING_VERSION:
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: record missing or corrupt"
                )
            task = TaskKind(record["task"])
            route = route_for(task)
            effective_effort = Effort(record["effective_effort"])
            worktree_raw = record["worktree"]
            if worktree_raw is not None and not isinstance(worktree_raw, str):
                # The genuine writer emits a string or None; any other
                # type is malformed, not "no worktree" — silently
                # reinterpreting it would complete without landing.
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: worktree is not a path string"
                )
            worktree = Path(worktree_raw) if isinstance(worktree_raw, str) else None
            stored_repo = record["repo_dir"]
            if stored_repo is not None and not isinstance(stored_repo, str):
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: repo_dir is not a path string"
                )
            if repo_dir is None and isinstance(stored_repo, str):
                # The landing target is operator-chosen, never
                # record-chosen: a library caller passing no repo, or
                # the CLI's --no-repo-dir, must not silently land into
                # whatever repo the record names (the verifier's cwd
                # would be record-chosen too). The operator supplies
                # the repo at resolve time; a record naming no repo
                # resolves with none.
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    "the record names a repo but no --repo-dir was given; "
                    "pass --repo-dir to confirm the landing target"
                )
            resolved_repo = repo_dir
            if (
                repo_dir is not None
                and isinstance(stored_repo, str)
                and Path(stored_repo).resolve() != repo_dir.resolve()
            ):
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    f"--repo-dir {repo_dir} does not match the recorded repo {stored_repo}"
                )
            record_changes = tuple(
                (str(status), str(path), (str(old) if old is not None else None), str(sha))
                for status, path, old, sha in record["changes"]
            )
            timed_out_raw = record.get("timed_out", False)
            if not isinstance(timed_out_raw, bool):
                # bool() of a non-empty string is True: a forged
                # "timed_out": "false" would silently select the
                # timeout path and skip the exit-code gate.
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: timed_out is not a boolean"
                )
            timed_out = timed_out_raw
            shape_kinds = frozenset(str(kind) for kind in record["secret_shape_kinds"])
            # The result fields are read here, inside the converting
            # try: a record with any of them deleted raised a raw
            # KeyError out of resolve_pending before.
            junior_returncode = record.get("junior_returncode")
            junior_stdout = record["junior_stdout"]
            junior_stderr = record["junior_stderr"]
            # The stored contract's isolation is read here too: the
            # cross-check below refuses a record whose worktree field
            # disagrees with it, so the record cannot pick its own
            # isolation mode. A missing or malformed contract is a
            # corrupt record, never a default.
            contract_raw = record["contract"]
            if not isinstance(contract_raw, dict):
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: contract is not a mapping"
                )
            contract_isolation = contract_raw["isolation"]
            if contract_isolation not in (Isolation.WORKTREE.value, Isolation.NONE.value):
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: contract isolation is not valid"
                )
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            raise DelegationError(f"no pending delegation {delegation_id!r}: {error}") from error
        # The record's shape must be one the in-run path can produce:
        # a worktree-mode timeout discards the staging in _run_junior,
        # so a worktree record marked timed out is forged by
        # construction, and a timeout record carries no exit code while
        # a non-timeout record always carries one. Without these
        # invariants a forged record could select its own exit-code
        # skip (timed_out) and complete a step with no exit code at all.
        if timed_out and worktree is not None:
            raise DelegationError(
                f"cannot resolve pending delegation {delegation_id!r}: "
                "a timed-out record cannot have a staged worktree"
            )
        if timed_out and junior_returncode is not None:
            raise DelegationError(
                f"cannot resolve pending delegation {delegation_id!r}: "
                "a timed-out record cannot carry a junior exit code"
            )
        if not timed_out and junior_returncode is None:
            raise DelegationError(
                f"cannot resolve pending delegation {delegation_id!r}: "
                "a record that did not time out must carry the junior exit code"
            )
        # The cross-check catches a single-field edit: a forger
        # nulling the worktree of a worktree-mode record would
        # otherwise flip it into isolation-none mode, and the
        # verifier would judge the main tree while the staged work
        # is orphaned. The reverse flip (a worktree on a none-mode
        # record) would land staged work the contract says was never
        # staged. Either mismatch refuses with the record kept. The
        # cross-check alone cannot catch a coherent flip of both
        # fields — they live in the same unsigned record — so each
        # branch carries its own live anchor below: the worktree
        # branch requires registration in the operator repo, and
        # the none branch refuses when staging for this id exists.
        if contract_isolation == Isolation.WORKTREE.value and worktree is None:
            raise DelegationError(
                f"cannot resolve pending delegation {delegation_id!r}: "
                "the stored contract declares worktree isolation but "
                "the record carries no worktree"
            )
        if contract_isolation == Isolation.NONE.value and worktree is not None:
            raise DelegationError(
                f"cannot resolve pending delegation {delegation_id!r}: "
                "the stored contract declares isolation none but the "
                "record carries a worktree"
            )
        if route.verification in (
            VerificationStep.READ_ONLY_REPORT,
            VerificationStep.READ_RESULTS_ESCALATE,
        ):
            # The step's deliverable IS the recorded junior output, so
            # there is nothing live to re-derive it from: a forged
            # record could pick the task kind and supply the output and
            # the gate would open on zero junior work. Refuse rather
            # than complete on recorded stdout; re-run the delegation
            # with a verifier, or discard the pending record with
            # ``delegate --discard-pending``.
            raise DelegationError(
                f"cannot resolve pending delegation {delegation_id!r}: "
                f"step {route.verification.value} cannot be resolved from a "
                "pending record — its deliverable is the recorded junior "
                "output, which cannot be re-derived; re-run the delegation "
                "with a verifier, or discard the pending record with "
                "`mcp-guard delegate --discard-pending "
                f"{delegation_id}`"
            )
        if worktree is not None and resolved_repo is None:
            raise DelegationError(
                f"cannot resolve pending delegation {delegation_id!r}: "
                "staged worktree needs a repo directory"
            )
        # The record is unauthenticated JSON in a junior-reachable
        # directory, so nothing in it that decides a landing is
        # trusted: the stored verdict is ignored (round 6), and so are
        # the stored change list and HEAD snapshot (this round).
        guard_files = frozenset(
            {
                "audit.jsonl",
                f"{delegation_id}.contract.json",
                f"{delegation_id}.{_LOCK_FILENAME}",
                f"{delegation_id}.pending.json",
                f"{delegation_id}.pending.json.tmp",
            }
        )
        if worktree is not None:
            if not worktree.exists() and not worktree.is_symlink():
                # A vanished worktree is a lost deliverable, not a
                # judged rejection: refuse loudly and keep the record.
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    f"staged worktree is gone ({worktree})"
                )
            # Containment is not identity: another delegation's live
            # worktree sits inside the lock directory too, and a forged
            # record pointing at it would land that delegation's staged
            # work under this id. The legitimate worktree is exactly
            # lock_dir/<id>.worktree (created in _run_junior).
            try:
                worktree_resolved = _resolve_path(worktree)
                expected_worktree = _resolve_path(self.lock_dir / f"{delegation_id}.worktree")
            except (OSError, RuntimeError) as error:
                # A symlink loop in a forged worktree path must refuse
                # typed, never escape as a traceback.
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    f"staged worktree path cannot be resolved ({error})"
                ) from error
            if worktree_resolved != expected_worktree:
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    f"staged worktree {worktree} is not this delegation's "
                    f"worktree ({expected_worktree})"
                )
            # The stored repo string is not proof the staging belongs
            # to the operator's repo: a forged record can echo
            # whatever repo the operator passes, and a nulled stored
            # repo disables the string match entirely. Live git is
            # the anchor — the repo must list this worktree.
            if resolved_repo is not None and not self._worktree_registered_in_repo(
                worktree_resolved, resolved_repo
            ):
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    f"staged worktree {worktree} is not registered in "
                    f"the operator repo {resolved_repo}; refusing to "
                    "land another repo's work"
                )
            # Re-derive the change list from the live worktree and the
            # HEAD baseline from live git: a forged record must not
            # choose what lands or what the conflict check compares
            # against. The recorded list is validated too: an escaping
            # path in it is evidence of tampering and refuses loudly
            # instead of being silently ignored. The verifier then
            # judges the same live bytes that copy-back lands
            # (drift-checked across the verify).
            _validate_change_paths(record_changes)
            changes = self._collect_changes(
                worktree, {}, lock_dir=self.lock_dir, guard_files=guard_files
            )
            _validate_change_paths(changes)
            main_snapshot = (
                self._main_tree_snapshot(resolved_repo) if resolved_repo is not None else None
            )
            if main_snapshot is None:
                # No HEAD baseline means the copy-back conflict check
                # cannot run: at resolve time no fresh delegation is at
                # stake, so refuse rather than land without it. The
                # record is kept and resolve can be retried once git
                # can list the tree again.
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    "HEAD baseline unavailable (git could not list the "
                    "main tree); copy-back cannot conflict-check"
                )
        else:
            # Isolation none: there is no worktree to re-derive from,
            # so the change list is re-derived from live git status
            # against HEAD alone — the record carries no baseline and
            # its stored list is never used. A record-supplied baseline
            # can be forged to the post-run hashes and hide junior
            # changes, and a missing baseline cannot be told apart
            # from a deleted one, so neither is accepted: the only
            # baseline the resolver trusts is HEAD, read from live
            # git. Operator dirt present before the run is therefore
            # included in what the verifier sees — widening, never
            # hiding. Without a repo directory there is no live state
            # to derive from at all, so resolve refuses and the
            # operator discards the record instead. There is no
            # copy-back in this mode, so no HEAD baseline is needed.
            if resolved_repo is None:
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    "isolation-none changes can only be re-derived from "
                    "live git status in a repo directory; pass "
                    "--repo-dir, or discard the pending record with "
                    "`mcp-guard delegate --discard-pending "
                    f"{delegation_id}`"
                )
            # Live anchor for the mode: the stored contract and the
            # worktree field live in the same unsigned record, so a
            # coherent flip of both passes the cross-check above and
            # would resolve a worktree-mode delegation against the
            # main tree, orphaning the staged work. The none branch
            # therefore refuses whenever staging for this id exists
            # on disk or is registered in the operator repo — live
            # git decides, never the record. A git failure here
            # reports not-registered and the re-derivation below
            # fails closed on it anyway (git status must succeed
            # to collect changes from a repo).
            try:
                expected_worktree = _resolve_path(self.lock_dir / f"{delegation_id}.worktree")
            except (OSError, RuntimeError) as error:
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    f"staged worktree path cannot be resolved ({error})"
                ) from error
            if expected_worktree.exists() or expected_worktree.is_symlink():
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    "a worktree exists for this delegation but the record "
                    "claims isolation none; the record is inconsistent — "
                    "discard the pending record with "
                    "`mcp-guard delegate --discard-pending "
                    f"{delegation_id}` or restore the record"
                )
            if self._worktree_registered_in_repo(expected_worktree, resolved_repo):
                raise DelegationError(
                    f"cannot resolve pending delegation {delegation_id!r}: "
                    "a worktree is registered for this delegation in "
                    f"{resolved_repo} but the record claims isolation "
                    "none; the record is inconsistent — discard the "
                    "pending record with `mcp-guard delegate "
                    f"--discard-pending {delegation_id}` or restore the record"
                )
            _validate_change_paths(record_changes)
            changes = self._collect_changes(
                resolved_repo,
                {},
                lock_dir=self.lock_dir,
                guard_files=guard_files,
            )
            _validate_change_paths(changes)
            main_snapshot = None
        audit_log = DelegationAuditLog(self.lock_dir / "audit.jsonl")
        result = DelegationResult(
            delegation_id=delegation_id,
            task=task,
            effective_effort=effective_effort,
            verification_step=route.verification,
            junior_returncode=junior_returncode,
            junior_stdout=str(junior_stdout),
            junior_stderr=str(junior_stderr),
            changed_files=tuple(path for _, path, _, _ in changes),
            worktree_path=str(worktree) if worktree is not None else None,
            repo_dir=str(resolved_repo) if resolved_repo is not None else None,
            secret_shape_kinds=shape_kinds,
        )
        with guard.guard(delegation_id, dict(os.environ), audit_log):
            # The stored verdict is audit history only and is never
            # trusted: the pending record lives in the lock directory
            # the junior can reach, so a forged APPROVED verdict must
            # not land anything. The senior verifier always re-runs.
            # The routed step gates the outcome here exactly as in the
            # in-run path: a record whose artifacts cannot satisfy its
            # step is rejected without consulting the verifier. (A
            # timeout record has no exit code, so that check is
            # skipped for it — the step conditions on the recorded
            # artifacts still apply.)
            precondition = _step_precondition_failed(
                result,
                route,
                repo_dir=resolved_repo,
                allow_missing_returncode=timed_out,
            )
            if precondition is not None:
                result.reject_with_reason(precondition)
                audit_log.record(
                    DelegationAuditKind.VERIFICATION_REJECTED,
                    delegation_id,
                    {"reason": precondition, "step": route.verification.value},
                )
                self._discard_worktree(resolved_repo, worktree, audit_log, delegation_id, result)
                self._unlink_pending(delegation_id)
                return result
            try:
                verdict = verifier.verify(replace(result))
            except Exception as error:  # noqa: BLE001 - a raising verifier is a rejection, never a crash
                result.reject_with_reason(f"verifier raised {type(error).__name__}: {error}")
                audit_log.record(
                    DelegationAuditKind.VERIFICATION_REJECTED,
                    delegation_id,
                    {
                        "reason": f"verifier raised {type(error).__name__}",
                        "step": route.verification.value,
                    },
                )
                self._discard_worktree(resolved_repo, worktree, audit_log, delegation_id, result)
                self._unlink_pending(delegation_id)
                return result
            if verdict is VerificationVerdict.APPROVED:
                if result.junior_returncode is None and not timed_out:
                    raise DelegationError(
                        "cannot complete: approved delegation has no junior return code"
                    )
                if worktree is not None and resolved_repo is not None:
                    try:
                        self._copy_back(
                            worktree,
                            resolved_repo,
                            changes,
                            audit_log,
                            delegation_id,
                            main_snapshot,
                        )
                    except (OSError, DelegationError) as error:
                        audit_log.record(
                            DelegationAuditKind.COPYBACK_FAILED,
                            delegation_id,
                            {"reason": str(error), "worktree": str(worktree)},
                        )
                        raise DelegationError(
                            f"copy-back failed (worktree kept at {worktree}): {error}"
                        ) from error
                    self._remove_worktree(resolved_repo, worktree, audit_log, delegation_id)
                    result.worktree_path = None
                result.apply_verdict(verdict)
                audit_log.record(
                    DelegationAuditKind.VERIFICATION_APPROVED,
                    delegation_id,
                    {"step": route.verification.value},
                )
                audit_log.record(
                    DelegationAuditKind.DELEGATION_COMPLETED,
                    delegation_id,
                    # A timed-out delegation has no return code (-1 is
                    # the "no exit code" sentinel, never a real code).
                    {
                        "returncode": result.junior_returncode
                        if result.junior_returncode is not None
                        else -1
                    },
                )
            else:
                result.apply_verdict(verdict)
                audit_log.record(
                    DelegationAuditKind.VERIFICATION_REJECTED,
                    delegation_id,
                    {"step": route.verification.value},
                )
                self._discard_worktree(resolved_repo, worktree, audit_log, delegation_id, result)
            self._unlink_pending(delegation_id)
            return result

    def discard_pending(self, delegation_id: str, repo_dir: Path | None = None) -> None:
        """Discard a pending delegation without verification.

        The discharge path for pending records resolve cannot
        discharge — report-kind steps above all: their deliverable is
        the recorded junior output, so resolve refuses them and the
        record would otherwise strand forever. Discarding deletes
        the pending record and removes the staged worktree when there
        is one; it never lands anything and never consults a
        verifier. In isolation-none mode the junior's edits are
        already in the operator tree and stay there, unapproved —
        discarding drops the obligation, not the bytes. The removal
        decision is by live state, never by the record: the worktree
        field is nullable and lives in the same unsigned JSON as the
        contract, so a nulled field must not delete the record while
        staging stays on disk, and a stored repo string must not
        choose the removal repo on its own. The worktree removed is
        exactly ``lock_dir/<id>.worktree``: a record naming any other
        path is refused and kept, so a forged record cannot delete an
        arbitrary directory. Removal runs in the operator repo when
        one is given and lists the worktree, else in the stored repo
        only when live git there lists it; staging that exists but is
        registered nowhere refuses with the record kept. Removal is
        verified after the fact — the remover never raises — so a
        surviving worktree keeps the record instead of stranding it.
        The per-id lock is held while discarding, so a live
        delegation with the same id cannot start mid-discard. Raises
        ``DelegationError`` when no pending record exists, it is
        corrupt, or its worktree is not this delegation's.
        """
        guard = self.guard
        if guard is None:
            raise DelegationError("runner has no loop guard")
        if not _ID_RE.match(delegation_id):
            # The record is read before the guard validates the id, so
            # a library caller could otherwise traverse (`../`) to an
            # arbitrary *.pending.json. The CLI sanitizes ids; the
            # library enforces the same shape here.
            raise DelegationError(f"invalid delegation id {delegation_id!r}")
        try:
            record = json.loads(self._pending_path(delegation_id).read_text(encoding="utf-8"))
            if not isinstance(record, dict) or record["version"] != _PENDING_VERSION:
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: record missing or corrupt"
                )
            worktree_raw = record["worktree"]
            if worktree_raw is not None and not isinstance(worktree_raw, str):
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: worktree is not a path string"
                )
            worktree = Path(worktree_raw) if isinstance(worktree_raw, str) else None
            stored_repo = record["repo_dir"]
            if stored_repo is not None and not isinstance(stored_repo, str):
                raise DelegationError(
                    f"no pending delegation {delegation_id!r}: repo_dir is not a path string"
                )
            task = str(record["task"])
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            raise DelegationError(f"no pending delegation {delegation_id!r}: {error}") from error
        audit_log = DelegationAuditLog(self.lock_dir / "audit.jsonl")
        with guard.guard(delegation_id, dict(os.environ), audit_log):
            # Live state decides what is removed; the record's
            # worktree field only bounds identity (a non-null field
            # naming another path refuses below). A nulled field on a
            # worktree-mode record must not delete the record while
            # the staging stays on disk.
            try:
                expected_worktree = _resolve_path(self.lock_dir / f"{delegation_id}.worktree")
            except (OSError, RuntimeError) as error:
                raise DelegationError(
                    f"cannot discard pending delegation {delegation_id!r}: "
                    f"staged worktree path cannot be resolved ({error})"
                ) from error
            if worktree is not None:
                try:
                    worktree_resolved = _resolve_path(worktree)
                except (OSError, RuntimeError) as error:
                    raise DelegationError(
                        f"cannot discard pending delegation {delegation_id!r}: "
                        f"staged worktree path cannot be resolved ({error})"
                    ) from error
                if worktree_resolved != expected_worktree:
                    raise DelegationError(
                        f"cannot discard pending delegation {delegation_id!r}: "
                        f"staged worktree {worktree} is not this delegation's "
                        f"worktree ({expected_worktree})"
                    )
            staging_on_disk = expected_worktree.exists() or expected_worktree.is_symlink()
            registered_in_operator = repo_dir is not None and self._worktree_registered_in_repo(
                expected_worktree, repo_dir
            )
            stored_repo_path = Path(stored_repo) if isinstance(stored_repo, str) else None
            registered_in_stored = (
                stored_repo_path is not None
                and self._worktree_registered_in_repo(expected_worktree, stored_repo_path)
            )
            if staging_on_disk or registered_in_operator or registered_in_stored:
                if repo_dir is not None:
                    if not registered_in_operator:
                        raise DelegationError(
                            f"cannot discard pending delegation {delegation_id!r}: "
                            "staging exists for this delegation but is not "
                            f"registered in the operator repo {repo_dir}; pass "
                            "the repo where it is registered, or omit --repo-dir"
                        )
                    removal_repo = repo_dir
                elif stored_repo_path is not None and registered_in_stored:
                    # The stored repo names where git runs only
                    # because live git there lists this worktree.
                    removal_repo = stored_repo_path
                else:
                    raise DelegationError(
                        f"cannot discard pending delegation {delegation_id!r}: "
                        "staging exists for this delegation but is not "
                        "registered in any repo supplied or recorded; pass "
                        "--repo-dir naming the repo where it is "
                        "registered, or remove the worktree manually"
                    )
                self._remove_worktree(removal_repo, expected_worktree, audit_log, delegation_id)
                # _remove_worktree never raises: it prunes and removes
                # best-effort. Verify the removal took effect before
                # deleting the record — a surviving worktree must keep
                # the record, not strand it.
                if expected_worktree.exists() or expected_worktree.is_symlink():
                    raise DelegationError(
                        f"cannot discard pending delegation {delegation_id!r}: "
                        "staged worktree could not be removed; the record is kept"
                    )
                if self._worktree_registered_in_repo(expected_worktree, removal_repo):
                    raise DelegationError(
                        f"cannot discard pending delegation {delegation_id!r}: "
                        "staged worktree is still registered in "
                        f"{removal_repo}; the record is kept"
                    )
            self._unlink_pending(delegation_id)
            audit_log.record(
                DelegationAuditKind.DELEGATION_DISCARDED,
                delegation_id,
                {"task": task},
            )

    def _worktree_registered_in_repo(self, worktree: Path, repo_dir: Path) -> bool:
        """Whether live git lists this worktree under the operator repo.

        The record's stored repo string is not proof the staging
        belongs to the operator's repo: a forged record can echo
        whatever repo the operator passes, and a nulled stored repo
        disables the string match entirely. ``git worktree list`` is
        the live anchor — the repo must know the worktree. False on
        any git failure: the caller refuses, fail-closed.
        """
        try:
            listed = subprocess.run(  # nosec - read-only git worktree list in the repo
                ["git", "-C", str(repo_dir), "worktree", "list", "--porcelain"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_GIT_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if listed.returncode != 0:
            return False
        for line in listed.stdout.splitlines():
            if not line.startswith("worktree "):
                continue
            try:
                if _resolve_path(Path(line[len("worktree ") :].strip())) == worktree:
                    return True
            except (OSError, RuntimeError):
                continue
        return False

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
        shape_kinds: frozenset[str] = frozenset(),
    ) -> tuple[
        DelegationResult,
        tuple[tuple[str, str, str | None, str], ...],
        Path | None,
        dict[str, str] | None,
    ]:
        """Run the junior subprocess and collect its output and changes.

        For a worktree the changes are NOT copied back here: the worktree
        is kept until delegate() decides. An APPROVED verdict lands them;
        a rejection discards the staging; a pending result keeps the
        worktree on disk (see DELEGATION_PENDING). Copying back before the
        verdict would defeat the worktree's purpose — keeping unverified
        junior work out of the operator tree — so this method never lands
        anything. Returns (result, changes, worktree-or-None,
        main-tree-snapshot-or-None). Each change carries the worktree
        file hash at collect time, so copy-back can refuse when the
        deliverable moved after verification. The pre-run status
        snapshot stays inside this method: it separates the junior's
        changes from operator dirt present before the run, and it is
        never persisted — a record-supplied baseline could be forged
        to the post-run hashes and hide junior changes, so
        ``resolve_pending`` re-derives isolation-none changes from
        live git status against HEAD instead.
        """
        if not self.junior_command:
            raise DelegationError("junior command is empty")
        worktree: Path | None = None
        cwd = repo_dir
        before_snapshot: dict[str, str] = {}
        main_snapshot: dict[str, str] | None = None
        if contract.isolation is Isolation.WORKTREE:
            if repo_dir is None:
                raise DelegationError("worktree isolation requires repo_dir")
            worktree = self.lock_dir / f"{delegation_id}.worktree"
            try:
                self._setup_worktree(repo_dir, worktree, delegation_id, audit_log)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                audit_log.record(
                    DelegationAuditKind.DELEGATION_FAILED,
                    delegation_id,
                    {"reason": f"worktree setup failed: {error}"},
                )
                raise DelegationError(f"worktree setup failed: {error}") from error
            except DelegationError as error:
                audit_log.record(
                    DelegationAuditKind.DELEGATION_FAILED,
                    delegation_id,
                    {"reason": f"worktree setup failed: {error}"},
                )
                raise
            cwd = worktree
            # The baseline for the copy-back conflict check: the main
            # tree's HEAD blob hashes. A target whose bytes differ
            # from its HEAD blob carries uncommitted operator work —
            # dirty before setup or edited while the delegation ran —
            # and copy-back refuses rather than overwriting it.
            main_snapshot = self._main_tree_snapshot(repo_dir)
            if self._status_snapshot(repo_dir):
                logger.warning(
                    "delegation %s: the main tree is dirty at setup; "
                    "copy-back will refuse any file the operator edits "
                    "while the delegation runs",
                    delegation_id,
                )
        else:
            before_snapshot = self._status_snapshot(repo_dir)
        # Guard-state files are excluded from change collection by
        # exact name (the lock dir may be the repo root, where a
        # directory exclusion would exclude everything) — including
        # the pending-record temp file, so a crashed atomic write
        # never looks like a junior change.
        guard_files = frozenset(
            {
                "audit.jsonl",
                contract_file.name,
                f"{delegation_id}.{_LOCK_FILENAME}",
                f"{delegation_id}.pending.json",
                f"{delegation_id}.pending.json.tmp",
            }
        )
        try:
            self._write_contract_file(contract, contract_file)
        except OSError as error:
            # The worktree was just created for this delegation: a
            # contract-file failure must not strand it.
            if worktree is not None and repo_dir is not None:
                self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
            raise DelegationError(f"contract file write failed: {error}") from error
        try:
            proc = subprocess.Popen(  # nosec B603 - runs the operator-supplied junior command
                self.junior_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
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
            # The worktree was just created for this delegation: a
            # spawn failure must not strand it.
            if worktree is not None and repo_dir is not None:
                self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
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
            # The output produced before the kill is the diagnosis:
            # keep it on the TIMEOUT result instead of discarding it.
            # The drain is bounded: a grandchild that escaped the kill
            # (setsid) and still holds a pipe open would hang an
            # unbounded communicate() forever with the per-id lock
            # held, so a second timeout gives up with empty output.
            try:
                stdout, stderr = proc.communicate(timeout=_POST_KILL_DRAIN_TIMEOUT)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "delegation %s: post-kill drain timed out (a junior "
                    "grandchild still holds the output pipes); output "
                    "is discarded rather than hanging the delegation",
                    delegation_id,
                )
                try:
                    proc.kill()
                except OSError:
                    pass
                stdout, stderr = "", ""
            if worktree is not None and repo_dir is not None:
                self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
                timeout_changes: tuple[tuple[str, str, str | None, str], ...] = ()
            else:
                # isolation none: the partial writes are in the
                # operator tree and cannot be discarded, so collect
                # them for the pending record delegate() writes —
                # otherwise the timeout leaves unverified work with
                # no path to verification.
                try:
                    timeout_changes = self._collect_changes(
                        cwd,
                        before_snapshot,
                        lock_dir=self.lock_dir,
                        guard_files=guard_files,
                    )
                except DelegationError:
                    logger.warning(
                        "delegation %s: timeout changes could not be "
                        "collected; partial work in the operator tree "
                        "is unverified and unrecorded",
                        delegation_id,
                        exc_info=True,
                    )
                    timeout_changes = ()
            result = DelegationResult(
                delegation_id=delegation_id,
                task=task,
                effective_effort=effective_effort,
                verification_step=route.verification,
                state=DelegationState.TIMEOUT,
                junior_returncode=None,
                junior_stdout=stdout,
                junior_stderr=stderr,
                changed_files=tuple(path for _, path, _, _ in timeout_changes),
                repo_dir=str(repo_dir) if repo_dir is not None else None,
                secret_shape_kinds=shape_kinds,
            )
            audit_log.record(
                DelegationAuditKind.DELEGATION_FAILED,
                delegation_id,
                {"reason": "junior timeout"},
            )
            return result, timeout_changes, None, main_snapshot
        try:
            changes = self._collect_changes(
                cwd,
                before_snapshot,
                lock_dir=self.lock_dir,
                guard_files=guard_files,
            )
        except DelegationError:
            # Change collection failed after the junior ran: the
            # worktree holds unverified work that cannot be listed,
            # so it must not strand — remove it and fail loudly.
            if worktree is not None and repo_dir is not None:
                self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
            raise
        changed_files = tuple(path for _, path, _, _ in changes)
        result = DelegationResult(
            delegation_id=delegation_id,
            task=task,
            effective_effort=effective_effort,
            verification_step=route.verification,
            junior_returncode=proc.returncode,
            junior_stdout=stdout,
            junior_stderr=stderr,
            changed_files=changed_files,
            worktree_path=str(worktree) if worktree is not None else None,
            repo_dir=str(repo_dir) if repo_dir is not None else None,
            secret_shape_kinds=shape_kinds,
        )
        return result, changes, worktree, main_snapshot

    def _main_tree_snapshot(self, repo_dir: Path) -> dict[str, str] | None:
        """SHA-256 of the HEAD blob contents of every tracked file in the main tree.

        The copy-back conflict baseline: a target whose current bytes
        differ from its HEAD blob carries uncommitted operator work —
        dirty before setup or edited while the delegation ran — and
        copy-back refuses rather than overwriting it, unless landing
        is a byte-identical no-op. Hashing the working tree instead
        would bless pre-existing dirt: a file dirty at setup and
        untouched since would match its setup hash and be overwritten
        silently. The hashes are content hashes (the same function as
        ``_file_sha256`` on the target), never the git blob ids: a blob
        id hashes the object header too and can never equal a content
        hash. None when git cannot list the tree: without a baseline
        the conflict check cannot run, so copy-back proceeds with a
        warning instead of refusing every file (documented residual,
        not a silent pass).
        """
        try:
            listed = subprocess.run(  # nosec - read-only git ls-tree in the repo
                ["git", "-C", str(repo_dir), "ls-tree", "HEAD", "-r", "-z"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_GIT_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            logger.warning(
                "main-tree snapshot failed for %s: copy-back runs without a conflict baseline",
                repo_dir,
            )
            return None
        if listed.returncode != 0:
            logger.warning(
                "main-tree snapshot failed for %s: copy-back runs without a conflict baseline",
                repo_dir,
            )
            return None
        entries: list[tuple[str, str]] = []
        for entry in listed.stdout.split("\0"):
            if not entry:
                continue
            meta, _, path = entry.partition("\t")
            parts = meta.split()
            if len(parts) != 3 or parts[1] != "blob" or not path:
                continue
            entries.append((path, parts[2]))
        if not entries:
            return {}
        return self._snapshot_from_batch(repo_dir, entries)

    @staticmethod
    def _snapshot_from_batch(
        repo_dir: Path, entries: list[tuple[str, str]]
    ) -> dict[str, str] | None:
        """Read HEAD blob contents via one ``git cat-file --batch`` call
        and return SHA-256 content hashes per path. Bytes throughout:
        text decoding would corrupt binary content hashes."""
        try:
            batch = subprocess.run(  # nosec - read-only git cat-file in the repo
                ["git", "-C", str(repo_dir), "cat-file", "--batch"],
                input=("".join(sha + "\n" for _, sha in entries)).encode("ascii"),
                capture_output=True,
                timeout=_GIT_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            logger.warning(
                "main-tree snapshot failed for %s: copy-back runs without a conflict baseline",
                repo_dir,
            )
            return None
        if batch.returncode != 0:
            logger.warning(
                "main-tree snapshot failed for %s: copy-back runs without a conflict baseline",
                repo_dir,
            )
            return None
        snapshot: dict[str, str] = {}
        data = batch.stdout
        pos = 0
        try:
            for path, _sha in entries:
                nl = data.index(b"\n", pos)
                header = data[pos:nl].decode("ascii").split()
                pos = nl + 1
                if len(header) != 3 or header[1] != "blob":
                    return None
                size = int(header[2])
                content = data[pos : pos + size]
                if len(content) != size:
                    return None
                pos += size + 1  # trailing LF after the object
                snapshot[path] = hashlib.sha256(content).hexdigest()
        except (ValueError, IndexError):
            return None
        return snapshot

    def _setup_worktree(
        self, repo_dir: Path, worktree: Path, delegation_id: str, audit_log: DelegationAuditLog
    ) -> None:
        """Create a fresh worktree at HEAD for the junior.

        A leftover worktree path from a crashed run is reclaimed: the
        caller holds the per-id lock, so no live delegation with this
        id is running. A pending record for the same id means staged
        work is still owed a verdict — reclaiming would destroy it,
        so setup refuses instead and the operator resolves the pending
        delegation first.
        """
        if worktree.exists() or worktree.is_symlink():
            if self._pending_path(delegation_id).exists():
                raise DelegationError(
                    f"a pending delegation {delegation_id!r} still has staged "
                    f"work at {worktree}; resolve it first "
                    "(delegate --resolve-pending) instead of re-delegating"
                )
            logger.warning(
                "reclaiming leftover worktree at %s (no pending record for %s)",
                worktree,
                delegation_id,
            )
            self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
            audit_log.record(
                DelegationAuditKind.WORKTREE_RECLAIMED,
                delegation_id,
                {"worktree": str(worktree)},
            )
        subprocess.run(  # nosec - git worktree setup in the operator's repo
            ["git", "-C", str(repo_dir), "worktree", "add", "--detach", str(worktree)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT,
            check=True,
        )

    def _status_snapshot(self, repo_dir: Path | None) -> dict[str, str]:
        """The pre-run snapshot: path -> content hash of the working tree.

        Every dirty path is hashed, tracked or untracked: a tracked file
        the operator had already modified is the operator's only while
        its content is unchanged — a junior edit to it changes the hash
        and is collected as the junior's. A deleted file hashes to ""
        (unreadable): a junior edit that restores it differs and is
        collected, while a still-deleted file matches and stays the
        operator's. Empty when not a repo or when git cannot run: the
        junior's changes are then all collected, never silently dropped.
        ``-uall`` lists untracked files individually: without it a new
        directory collapses to one ``dir/`` record and the files inside
        it are invisible to change collection.
        """
        if repo_dir is None:
            return {}
        try:
            completed = subprocess.run(  # nosec - read-only git status in the repo
                ["git", "-C", str(repo_dir), "status", "--porcelain", "-z", "-uall"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_GIT_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        if completed.returncode != 0:
            return {}
        snapshot: dict[str, str] = {}
        for status, path, _ in _parse_porcelain_z(completed.stdout):
            snapshot[path] = _file_sha256(repo_dir / path)
        return snapshot

    def _collect_changes(
        self,
        cwd: Path | None,
        before: dict[str, str],
        lock_dir: Path | None = None,
        guard_files: frozenset[str] | None = None,
    ) -> tuple[tuple[str, str, str | None, str], ...]:
        """The (status, path, rename-source, worktree-hash) changes the junior made.

        Compared against the pre-run snapshot, so pre-existing dirt
        in the operator's tree is attributed to the operator, not the
        junior: a path whose content hash is unchanged is skipped, and
        only a changed hash (or a path absent from the snapshot) is
        collected. A fresh worktree has an empty snapshot, so every
        change is the junior's. The lock directory is excluded
        explicitly: with ``-uall`` its audit log and contract file
        would otherwise appear as junior changes and vacuously satisfy
        the diff preconditions. When the lock directory IS the repo
        root, the directory exclusion cannot apply (it would exclude
        everything), so the guard-state files are excluded by exact
        name instead (``guard_files``). Each collected change carries
        the worktree file's hash at collect time: copy-back refuses
        when the bytes moved after verification. A git failure is a
        loud error when this directory is a repo (``.git`` present):
        silently returning no changes would let a verifier approve an
        empty deliverable. Without a repo there is no tree to diff,
        and the empty result stands.
        """
        if cwd is None:
            return ()
        try:
            completed = subprocess.run(  # nosec - read-only git status in the worktree
                ["git", "-C", str(cwd), "status", "--porcelain", "-z", "-uall"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_GIT_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            if (cwd / ".git").exists():
                raise DelegationError(f"change collection failed: {error}") from error
            return ()
        if completed.returncode != 0:
            if (cwd / ".git").exists():
                raise DelegationError(
                    "change collection failed: git status exited "
                    f"{completed.returncode}: {completed.stderr.strip()}"
                )
            return ()
        exclude_prefix: str | None = None
        if lock_dir is not None:
            try:
                relative = lock_dir.resolve().relative_to(cwd.resolve())
                exclude_prefix = relative.as_posix()
            except (ValueError, OSError, RuntimeError):
                exclude_prefix = None
        guard_paths: set[str] = set()
        if guard_files and lock_dir is not None:
            for name in guard_files:
                try:
                    guard_paths.add(
                        (lock_dir / name).resolve().relative_to(cwd.resolve()).as_posix()
                    )
                except (ValueError, OSError, RuntimeError):
                    continue
        collected: list[tuple[str, str, str | None, str]] = []
        for status, path, old_path in _parse_porcelain_z(completed.stdout):
            if (
                exclude_prefix is not None
                and exclude_prefix != "."
                and (path == exclude_prefix or path.startswith(exclude_prefix + "/"))
            ):
                continue
            if path in guard_paths:
                continue
            if path in before and _file_sha256(cwd / path) == before[path]:
                continue
            collected.append((status, path, old_path, _file_sha256(cwd / path)))
        return tuple(collected)

    def _copy_back(
        self,
        worktree: Path,
        repo_dir: Path,
        changes: tuple[tuple[str, str, str | None, str], ...],
        audit_log: DelegationAuditLog,
        delegation_id: str,
        main_snapshot: dict[str, str] | None = None,
    ) -> None:
        """Copy the junior's changes from the worktree to the main
        tree, mirroring deletions and renames. The deliverable lands in
        the operator's tree for senior review; nothing is committed.
        Mode bits are preserved; a symlink is recreated as a link
        (falling back to a regular copy where the platform refuses
        one) — but only when its target stays inside the worktree: a
        junior-controlled link to an absolute path, or one that escapes
        the tree, is skipped and audited rather than planted in the
        operator's tree. A directory record cannot occur (``-uall``
        lists files), but one is skipped rather than failing the
        delegation on a directory copy. Two refusals guard the landing:
        a worktree file whose bytes moved after verification (drift
        vs the hash recorded at collect time) is refused, and a target
        whose bytes differ from its HEAD blob (uncommitted operator
        work, dirty before setup or edited while the delegation ran)
        is refused unless landing is a byte-identical no-op — landing
        either would destroy work the senior never saw or the junior
        never saw.
        A refusal raises ``DelegationError`` with the worktree kept:
        the caller turns it into a pending record, never a COMPLETE
        result. With no baseline (``main_snapshot`` None: git could
        not list the tree at setup) the conflict check is skipped and
        a warning is logged instead of refusing every file.
        """
        try:
            worktree_resolved = _resolve_path(worktree)
        except (OSError, RuntimeError) as error:
            # A symlink loop in the worktree path must refuse typed
            # rather than escaping out of copy-back.
            raise DelegationError(
                f"copy-back refused: worktree path cannot be resolved ({error})"
            ) from error
        if main_snapshot is None:
            logger.warning(
                "delegation %s: copy-back runs without a main-tree "
                "baseline; operator edits underneath the worktree are "
                "not conflict-checked",
                delegation_id,
            )
        for status, path, old_path, sha in changes:
            source = worktree / path
            target = repo_dir / path
            if main_snapshot is not None:
                self._refuse_on_conflict(repo_dir, path, old_path, main_snapshot, sha)
            # The drift check runs for deletions too: a deleted file
            # hashes to "" (unreadable), matching the sha recorded at
            # collect time, while a file re-created in the worktree
            # after verification hashes differently and refuses — the
            # "land only bytes the senior saw" invariant is not
            # silently dropped for deletions.
            if _file_sha256(source) != sha:
                raise DelegationError(
                    f"copy-back refused: {path!r} changed in the worktree "
                    "after verification (drift); refusing to land bytes "
                    "the senior never saw"
                )
            if "D" in status:
                target.unlink(missing_ok=True)
                continue
            if old_path is not None:
                (repo_dir / old_path).unlink(missing_ok=True)
            if source.is_dir() and not source.is_symlink():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                try:
                    link_target = _resolve_path(source.parent / source.readlink())
                except (OSError, RuntimeError):
                    # An unreadable or looping link target raises here;
                    # skip and audit it like an escaping link rather
                    # than escaping the exception out of copy-back.
                    logger.warning(
                        "skipping symlink %s: its target cannot be resolved",
                        path,
                    )
                    audit_log.record(
                        DelegationAuditKind.COPYBACK_FAILED,
                        delegation_id,
                        {
                            "path": path,
                            "reason": "symlink target cannot be resolved",
                        },
                    )
                    continue
                if not link_target.is_relative_to(worktree_resolved):
                    logger.warning(
                        "skipping symlink %s: its target escapes the worktree",
                        path,
                    )
                    audit_log.record(
                        DelegationAuditKind.COPYBACK_FAILED,
                        delegation_id,
                        {
                            "path": path,
                            "reason": "symlink target escapes the worktree",
                        },
                    )
                    continue
                try:
                    target.unlink(missing_ok=True)
                    target.symlink_to(source.readlink())
                    continue
                except OSError:
                    pass
            shutil.copy2(source, target)

    @staticmethod
    def _refuse_on_conflict(
        repo_dir: Path,
        path: str,
        old_path: str | None,
        main_snapshot: dict[str, str],
        worktree_sha: str,
    ) -> None:
        """Refuse a landing that would overwrite operator work.

        ``main_snapshot`` is the HEAD blob hash per tracked file. A
        target whose current bytes differ from its HEAD blob carries
        uncommitted operator work — dirty before setup or edited
        while the delegation ran — and landing would destroy it, so
        it is refused unless the landing is a byte-identical no-op
        (the current bytes already equal the worktree bytes).
        A target absent from the snapshot that exists now was created
        meanwhile and is refused the same way. A rename's old path is
        checked the same way before it is unlinked. The raw byte
        comparison is not the whole story: under core.autocrlf on
        Windows a git-clean file carries CRLF bytes against an LF
        blob, so a raw mismatch that git itself reads as clean
        (``git diff --quiet HEAD``) is a line-ending difference, not
        operator work, and does not refuse. Raises
        ``DelegationError``; the caller keeps the worktree and the
        result stays pending.
        """
        check_paths = [path, old_path] if old_path is not None else [path]
        for check_path in check_paths:
            target = repo_dir / check_path
            head = main_snapshot.get(check_path)
            if head is None:
                # The file is not HEAD-tracked: landing over an
                # operator-created file (or unlinking one the junior
                # deleted) destroys work the delegation never staged —
                # unless the bytes are already identical to the
                # junior's, in which case landing is a no-op.
                if (target.exists() or target.is_symlink()) and _file_sha256(
                    target
                ) != worktree_sha:
                    raise DelegationError(
                        f"copy-back conflict: {check_path!r} appeared in the "
                        "main tree during the delegation; refusing to "
                        "overwrite operator work"
                    )
                continue
            current = _file_sha256(target)
            if current != head and current != worktree_sha:
                if _git_file_matches_head(repo_dir, check_path):
                    continue
                raise DelegationError(
                    f"copy-back conflict: {check_path!r} changed in the "
                    "main tree (uncommitted operator work); refusing to "
                    "overwrite operator work"
                )

    def _discard_worktree(
        self,
        repo_dir: Path | None,
        worktree: Path | None,
        audit_log: DelegationAuditLog,
        delegation_id: str,
        result: DelegationResult,
    ) -> None:
        """Remove a staged worktree without landing it; clear the pointer.

        Used on every non-approved outcome (precondition rejection,
        verifier rejection, raising verifier): the junior's work is
        discarded with the staging, never copied into the operator tree.
        """
        if worktree is not None and repo_dir is not None:
            self._remove_worktree(repo_dir, worktree, audit_log, delegation_id)
        result.worktree_path = None

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
                encoding="utf-8",
                errors="replace",
                timeout=_GIT_TIMEOUT,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            audit_log.record(
                DelegationAuditKind.WORKTREE_CLEANUP_FAILED,
                delegation_id,
                {"worktree": str(worktree)},
            )
            try:
                subprocess.run(  # nosec - git worktree prune in the operator's repo
                    ["git", "-C", str(repo_dir), "worktree", "prune"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=_GIT_TIMEOUT,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass  # best-effort prune; the rmtree below still runs
            shutil.rmtree(worktree, ignore_errors=True)


def _parse_porcelain_z(output: str) -> list[tuple[str, str, str | None]]:
    """Parse ``git status --porcelain -z`` output into (status, path,
    rename-source) triples. NUL-separated, so quoted and renamed paths
    parse exactly. Note the -z field order for a rename: the record
    carries the NEW path first (``R  new``) and the OLD path follows
    as the next record. The old path is kept: dropping it would make a
    rename look like a pure addition and leave a stale file behind on
    copy-back. Non-rename records carry ``None`` as the third item.
    """
    triples: list[tuple[str, str, str | None]] = []
    records = [record for record in output.split("\0") if record]
    index = 0
    while index < len(records):
        record = records[index]
        status = record[:2]
        if status.startswith(("R", "C")):
            index += 1
            if index < len(records):
                triples.append((status, record[3:], records[index]))
        else:
            triples.append((status, record[3:], None))
        index += 1
    return triples


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
