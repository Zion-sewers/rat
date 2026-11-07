"""MCP least-privilege lifecycle (rat #68): off by default, narrow enable,
teardown after task.

The lifecycle is the ownership layer over the gateway: a task enables
exactly the servers it names, calls route only through those servers, and
ending the task stops every server and VERIFIES each one is actually dead
(process poll, not a flag the transport sets) before the task record is
dropped. A teardown that leaves a server alive raises instead of
reporting clean — the task stays live so the caller can retry the teardown.

Contract:
- Default-deny: no server runs until a task enables it by name. A call
  naming a server the task did not enable is refused before any send and
  audited (``SERVER_DENIED``).
- Narrow enable: ``begin_task`` starts exactly the named servers; every
  other registered server stays down. One server belongs to at most one
  live task at a time.
- Verified teardown: ``end_task`` stops each transport and independently
  probes ``is_alive`` until the process is gone (bounded poll loop). Any
  survivor fails the teardown with a report listing the survivors.
- Tokens never cross tasks: one ``PiiTokenizer`` is shared by a task's
  servers (so a token minted on one server resolves on another server of
  the same task) and is cleared when the task ends.
- Audit events, never content: the lifecycle log records task/server
  names and outcomes only — never tool arguments or results.

Deliberate boundaries (not hidden):
- The lifecycle enforces policy over the caller's DECLARED task and
  server names. It cannot authenticate who is calling; the agent harness
  declares the task. Same boundary as the gateway's declared trust level.
- ``fuzz`` / ``scan`` are single-run tools that exit when done; the
  persistent connector surface is the gateway session, so the gateway
  CLI is the lifecycle's production consumer. Fuzz/scan keep their
  existing context-manager teardown, unchanged.
- A server that survives ``stop()`` keeps its task live. The caller must
  retry ``end_task`` (or kill the process out of band); the lifecycle
  never drops a task it could not verify dead.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Protocol

from .gateway import Gateway, GatewayAuditLog, GatewayPolicy, PiiTokenizer, TrustLevel
from .transport import JsonDict, StdioTransport

__all__ = [
    "Lifecycle",
    "LifecycleAuditLog",
    "LifecycleError",
    "LifecycleEvent",
    "LifecycleKind",
    "ServerNotEnabledError",
    "ServerRegistry",
    "ServerSpec",
    "ServerTransport",
    "TaskError",
    "TaskHandle",
    "TeardownFailedError",
    "TeardownReport",
    "TransportFactory",
    "UnknownServerError",
]

logger = logging.getLogger(__name__)

# Bounded window for the post-stop liveness probe: after stop() returns,
# the child is terminated or killed, but reaping is asynchronous, so poll
# until it is gone or this window expires. A server still alive after the
# window fails the teardown instead of being assumed dead.
_TEARDOWN_VERIFY_TIMEOUT_S = 2.0
_TEARDOWN_VERIFY_POLL_S = 0.05


class LifecycleError(Exception):
    """Base class for lifecycle failures (fail-closed, never silent)."""


class UnknownServerError(LifecycleError):
    """``begin_task`` named a server the registry does not know."""

    def __init__(self, server_name: str) -> None:
        self.server_name = server_name
        super().__init__(f"unknown server {server_name!r}: not in the registry")


class ServerNotEnabledError(LifecycleError):
    """A call named a server the task did not enable."""

    def __init__(self, task_id: str, server_name: str) -> None:
        self.task_id = task_id
        self.server_name = server_name
        super().__init__(f"server {server_name!r} is not enabled for task {task_id!r}")


class TaskError(LifecycleError):
    """Bad task id: unknown, duplicate, or empty."""


class TeardownFailedError(LifecycleError):
    """``end_task`` left one or more servers alive; carries the report."""

    def __init__(self, report: TeardownReport) -> None:
        self.report = report
        super().__init__(
            f"teardown failed for task {report.task_id!r}: "
            f"{len(report.failed)} server(s) still alive: " + ", ".join(sorted(report.failed))
        )


class LifecycleKind(str, Enum):
    """Lifecycle audit event kinds — facts of access, never content."""

    TASK_BEGUN = "task_begun"
    SERVER_ENABLED = "server_enabled"
    SERVER_DENIED = "server_denied"
    TASK_ENDED = "task_ended"
    TEARDOWN_VERIFIED = "teardown_verified"
    TEARDOWN_FAILED = "teardown_failed"


@dataclass(frozen=True)
class LifecycleEvent:
    """One lifecycle audit event: what happened, to which task/server."""

    seq: int
    timestamp: str
    kind: LifecycleKind
    task_id: str
    detail: str
    server: str | None = None

    def to_dict(self) -> JsonDict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "kind": self.kind.value,
            "task_id": self.task_id,
            "detail": self.detail,
            "server": self.server,
        }


class LifecycleAuditLog:
    """Append-only audit log (in-memory; serialize with ``to_json``)."""

    def __init__(self) -> None:
        self._events: list[LifecycleEvent] = []
        self._seq = 0

    def __len__(self) -> int:
        return len(self._events)

    def record(
        self,
        kind: LifecycleKind,
        task_id: str,
        detail: str,
        server: str | None = None,
    ) -> LifecycleEvent:
        self._seq += 1
        event = LifecycleEvent(
            seq=self._seq,
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            kind=kind,
            task_id=task_id,
            detail=detail,
            server=server,
        )
        self._events.append(event)
        return event

    def events(self) -> tuple[LifecycleEvent, ...]:
        return tuple(self._events)

    def to_json(self) -> list[JsonDict]:
        return [e.to_dict() for e in self._events]


@dataclass(frozen=True)
class ServerSpec:
    """One registered MCP server: its name and spawn command."""

    name: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class ServerRegistry:
    """The servers a lifecycle may enable, by name.

    The registry is data, not state: it names the servers that exist.
    Nothing in it runs until a task enables it.
    """

    servers: Mapping[str, ServerSpec] = field(default_factory=dict)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self.servers))

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> ServerRegistry:
        """Parse a registry file mapping: ``{"servers": {name: [cmd...]}}``.

        Wrong shapes fail closed (TypeError); an empty command or an
        empty command part fails closed (ValueError); unknown top-level
        keys are ignored so registry files stay forward-compatible.
        """
        if not isinstance(data, dict):
            raise TypeError("server registry must be a JSON object")
        servers_data = data.get("servers", {})
        if not isinstance(servers_data, dict):
            raise TypeError("server registry 'servers' must be an object")
        servers: dict[str, ServerSpec] = {}
        for name, command in servers_data.items():
            if not isinstance(name, str) or not name:
                raise ValueError(f"server registry name must be a non-empty string, got {name!r}")
            if not isinstance(command, list) or not command:
                raise ValueError(f"server {name!r}: command must be a non-empty list")
            if any(not isinstance(part, str) or not part for part in command):
                raise TypeError(f"server {name!r}: command parts must be non-empty strings")
            servers[name] = ServerSpec(name=name, command=tuple(command))
        return cls(servers=servers)


class ServerTransport(Protocol):
    """The transport surface the lifecycle needs: spawn, call, stop, probe.

    ``StdioTransport`` satisfies this structurally. The lifecycle never
    assumes how a transport spawns: teardown verification reads
    ``is_alive`` (an OS-level probe for the real transport), never a flag
    the transport sets itself.
    """

    def start(self) -> None: ...

    def stop(self) -> None: ...

    @property
    def is_alive(self) -> bool: ...

    def list_tools(self) -> list[JsonDict]: ...

    def call_tool(self, tool_name: str, arguments: JsonDict) -> JsonDict: ...

    def last_exchange(self) -> tuple[JsonDict | None, object]: ...


TransportFactory = Callable[[tuple[str, ...]], ServerTransport]
"""Build a transport for a server command (default: StdioTransport)."""


def _default_transport(command: tuple[str, ...]) -> ServerTransport:
    return StdioTransport(list(command))


@dataclass(frozen=True)
class TaskHandle:
    """The capability a begun task carries: its id and enabled servers."""

    task_id: str
    servers: tuple[str, ...]


@dataclass(frozen=True)
class TeardownReport:
    """The verified outcome of ``end_task``: which servers are dead."""

    task_id: str
    servers: tuple[str, ...]
    verified: tuple[str, ...]
    failed: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.failed

    def to_dict(self) -> JsonDict:
        return {
            "task_id": self.task_id,
            "servers": list(self.servers),
            "verified": list(self.verified),
            "failed": list(self.failed),
            "ok": self.ok,
        }


@dataclass
class _BoundServer:
    transport: ServerTransport
    gateway: Gateway


@dataclass
class _Task:
    task_id: str
    servers: dict[str, _BoundServer]
    tokenizer: PiiTokenizer


def _await_dead(transport: ServerTransport, timeout_s: float) -> bool:
    """Poll until the transport's process is gone, or the window expires."""
    deadline = time.monotonic() + timeout_s
    while True:
        if not transport.is_alive:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_TEARDOWN_VERIFY_POLL_S)


class Lifecycle:
    """Least-privilege ownership of MCP servers, per task.

    All servers start disabled. A task enables a narrow subset by name;
    calls route only through enabled servers; ending the task stops every
    server and verifies each one dead before the task record is dropped.
    """

    def __init__(
        self,
        registry: ServerRegistry,
        policy: GatewayPolicy,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._factory = transport_factory if transport_factory is not None else _default_transport
        self._tasks: dict[str, _Task] = {}
        self._audit = LifecycleAuditLog()

    @property
    def registry(self) -> ServerRegistry:
        return self._registry

    @property
    def audit_log(self) -> LifecycleAuditLog:
        return self._audit

    def live_tasks(self) -> tuple[str, ...]:
        return tuple(sorted(self._tasks))

    def enabled_servers(self, task_id: str) -> tuple[str, ...]:
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskError(f"unknown task {task_id!r}: no such live task")
        return tuple(sorted(task.servers))

    def begin_task(self, task_id: str, server_names: tuple[str, ...] | list[str]) -> TaskHandle:
        """Enable exactly ``server_names`` for ``task_id`` and start them.

        Validates everything before starting anything. A start failure
        part-way through rolls back: already-started servers are stopped
        (and probed dead) and the task record is dropped, so a failed
        begin never leaves a half-enabled task behind.
        """
        if not isinstance(task_id, str) or not task_id:
            raise TaskError("task_id must be a non-empty string")
        if task_id in self._tasks:
            raise TaskError(f"task {task_id!r} is already live")
        names = tuple(server_names)
        if not names:
            raise TaskError("begin_task needs at least one server: empty enablement refused")
        if len(set(names)) != len(names):
            raise TaskError(f"task {task_id!r}: duplicate server names in enable list")
        for name in names:
            if name not in self._registry.servers:
                raise UnknownServerError(name)
        for other_id, other in self._tasks.items():
            for name in names:
                if name in other.servers:
                    raise TaskError(f"server {name!r} is already owned by live task {other_id!r}")
        tokenizer = PiiTokenizer()
        bound: dict[str, _BoundServer] = {}
        started: list[str] = []
        try:
            for name in names:
                spec = self._registry.servers[name]
                transport = self._factory(spec.command)
                transport.start()
                started.append(name)
                bound[name] = _BoundServer(
                    transport=transport,
                    gateway=Gateway(transport, self._policy, tokenizer),
                )
        except Exception:  # re-raises below: BLE001 does not fire on re-raise
            for name in reversed(started):
                try:
                    bound[name].transport.stop()
                    if not _await_dead(bound[name].transport, _TEARDOWN_VERIFY_TIMEOUT_S):
                        logger.warning(
                            "rollback stop left server %r alive after failed begin of task %r",
                            name,
                            task_id,
                        )
                except Exception:  # noqa: BLE001 - rollback must not mask the begin failure
                    logger.warning(
                        "rollback stop failed for server %r after failed begin of task %r",
                        name,
                        task_id,
                    )
            raise
        self._tasks[task_id] = _Task(task_id=task_id, servers=bound, tokenizer=tokenizer)
        self._audit.record(LifecycleKind.TASK_BEGUN, task_id, f"{len(names)} server(s) enabled")
        for name in names:
            self._audit.record(
                LifecycleKind.SERVER_ENABLED, task_id, "enabled for task", server=name
            )
        return TaskHandle(task_id=task_id, servers=tuple(names))

    def _bound(self, task_id: str, server_name: str) -> _BoundServer:
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskError(f"unknown task {task_id!r}: no such live task")
        bound = task.servers.get(server_name)
        if bound is None:
            self._audit.record(
                LifecycleKind.SERVER_DENIED,
                task_id,
                "not enabled for task",
                server=server_name,
            )
            raise ServerNotEnabledError(task_id, server_name)
        return bound

    def call_tool(
        self,
        task_id: str,
        server_name: str,
        tool_name: str,
        arguments: JsonDict,
        caller_trust: TrustLevel = TrustLevel.LOW,
    ) -> JsonDict:
        """One gated call through the task's server (default-deny enforced).

        Refuses (before any send) when the task is unknown or the server
        is not enabled for it. Otherwise delegates to the bound gateway,
        which enforces trust levels and tokenizes PII as usual.
        """
        bound = self._bound(task_id, server_name)
        return bound.gateway.call_tool(tool_name, arguments, caller_trust)

    def list_tools(self, task_id: str, server_name: str) -> list[JsonDict]:
        """Annotated tool list of the task's server (gateway trust attached)."""
        bound = self._bound(task_id, server_name)
        return bound.gateway.annotate_tools(bound.transport.list_tools())

    def gateway_audit_log(self, task_id: str, server_name: str) -> GatewayAuditLog:
        """The bound gateway's audit log (read view for the session owner)."""
        bound = self._bound(task_id, server_name)
        return bound.gateway.audit_log

    def end_task(self, task_id: str) -> TeardownReport:
        """Stop every server of the task and VERIFY each one dead.

        On full success the tokenizer is cleared and the task record is
        dropped. On any survivor the report is raised (never returned as
        clean) and the task stays live so the caller can retry.
        """
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskError(f"unknown task {task_id!r}: no such live task")
        verified: list[str] = []
        failed: list[str] = []
        for name, bound in task.servers.items():
            try:
                bound.transport.stop()
            except Exception:  # noqa: BLE001 - a raising stop() is a failed teardown, not a crash
                failed.append(name)
                continue
            if _await_dead(bound.transport, _TEARDOWN_VERIFY_TIMEOUT_S):
                verified.append(name)
            else:
                failed.append(name)
        report = TeardownReport(
            task_id=task_id,
            servers=tuple(sorted(task.servers)),
            verified=tuple(sorted(verified)),
            failed=tuple(sorted(failed)),
        )
        for name in verified:
            self._audit.record(
                LifecycleKind.TEARDOWN_VERIFIED,
                task_id,
                "server stopped and verified dead",
                server=name,
            )
        for name in failed:
            self._audit.record(
                LifecycleKind.TEARDOWN_FAILED,
                task_id,
                "server still alive after stop",
                server=name,
            )
        if failed:
            raise TeardownFailedError(report)
        task.tokenizer.clear()
        del self._tasks[task_id]
        self._audit.record(LifecycleKind.TASK_ENDED, task_id, "all servers torn down and verified")
        return report
