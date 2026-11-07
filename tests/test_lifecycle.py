"""MCP least-privilege lifecycle (rat #68): off by default, narrow enable,
teardown after task — verified, not asserted in prose."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_guard.cli import _GatewaySession, _handle_gateway_begin, _handle_gateway_line
from mcp_guard.gateway import GatewayPolicy, TrustLevel
from mcp_guard.lifecycle import (
    Lifecycle,
    LifecycleKind,
    ServerNotEnabledError,
    ServerRegistry,
    ServerSpec,
    TaskError,
    TeardownFailedError,
    UnknownServerError,
)
from mcp_guard.transport import JsonDict, StdioTransport

REPO_ROOT = Path(__file__).resolve().parent.parent

POLICY = GatewayPolicy(tools={"secret_tool": TrustLevel.HIGH}, default_trust=TrustLevel.LOW)

TOOLS = [
    {
        "name": "lookup",
        "description": "answer a question",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
    },
    {
        "name": "secret_tool",
        "description": "read a secret record",
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
    },
]

FAKE_SERVER = """\
import json, sys

TOOLS = [
    {"name": "lookup", "description": "answer a question",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05"}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": "answer for " + json.dumps(args)}]}})
"""


FAKE_SERVER_ERROR_CALL = """\
import json, sys

TOOLS = [
    {"name": "lookup", "description": "answer a question",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    {"name": "explode", "description": "always fails",
     "inputSchema": {"type": "object", "properties": {}}},
]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05"}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "explode":
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32603, "message": "kaboom"}})
        else:
            send({"jsonrpc": "2.0", "id": rid,
                  "result": {"content": [{"type": "text", "text": "answer for " + json.dumps(args)}]}})
"""

FAKE_SERVER_LIST_ERROR = """\
import json, sys

TOOLS = [
    {"name": "lookup", "description": "answer a question",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05"}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid,
              "error": {"code": -32603, "message": "list kaboom"}})
    elif method == "tools/call":
        params = req.get("params", {})
        args = params.get("arguments", {})
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": "answer for " + json.dumps(args)}]}})
"""


FAKE_SERVER_INIT_ERROR = """\
import json, sys

TOOLS = [
    {"name": "lookup", "description": "answer a question",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid,
              "error": {"code": -32603, "message": "init kaboom"}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = req.get("params", {})
        args = params.get("arguments", {})
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": "answer for " + json.dumps(args)}]}})
"""


FAKE_SERVER_TOOLS_NOT_LIST = """\
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05"}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": "not-a-list"}})
    elif method == "tools/call":
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": "answer"}]}})
"""


FAKE_SERVER_RESULT_NOT_OBJECT = """\
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05"}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": "not-an-object"})
    elif method == "tools/call":
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": "answer"}]}})
"""

FAKE_SERVER_BARE_JSON = """\
import json, sys

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method")
    if method == "initialize":
        # A bare JSON value, not a response object: valid JSON, wrong shape.
        sys.stdout.write(json.dumps("hello") + "\\n")
        sys.stdout.flush()
"""


class FakeTransport:
    """In-memory stand-in for a server transport (no subprocess)."""

    def __init__(self, command: tuple[str, ...] = ()) -> None:
        self.command = command
        self.started = False
        self.stopped = False
        self._alive = False
        self.calls: list[JsonDict] = []
        self.result_text = "ok"

    def start(self) -> None:
        self.started = True
        self._alive = True

    def stop(self) -> None:
        self.stopped = True
        self._alive = False

    @property
    def is_alive(self) -> bool:
        return self._alive

    @property
    def pid(self) -> int | None:
        return 4242

    def list_tools(self) -> list[JsonDict]:
        return [dict(tool) for tool in TOOLS]

    def call_tool(self, tool_name: str, arguments: JsonDict) -> JsonDict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"content": [{"type": "text", "text": self.result_text}]}

    def last_exchange(self) -> tuple[JsonDict | None, object]:
        if not self.calls:
            return None, None
        return {"jsonrpc": "2.0", "id": len(self.calls), "method": "tools/call"}, len(self.calls)


def _registry(*names: str) -> ServerRegistry:
    return ServerRegistry(servers={name: ServerSpec(name, (f"fake-{name}",)) for name in names})


def _lifecycle(*names: str, created: list[FakeTransport] | None = None) -> Lifecycle:
    def factory(command: tuple[str, ...]) -> FakeTransport:
        transport = FakeTransport(command)
        if created is not None:
            created.append(transport)
        return transport

    return Lifecycle(_registry(*names), POLICY, transport_factory=factory)


# --- Registry parsing --------------------------------------------------------


def test_registry_from_mapping_ok() -> None:
    registry = ServerRegistry.from_mapping(
        {"servers": {"a": ["python", "-m", "srv"], "b": ["./srv"]}}
    )
    assert registry.names == ("a", "b")
    assert registry.servers["a"].command == ("python", "-m", "srv")


def test_registry_from_mapping_rejects_bad_shapes() -> None:
    with pytest.raises(TypeError):
        ServerRegistry.from_mapping(["not", "a", "mapping"])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ServerRegistry.from_mapping({"servers": ["a"]})
    with pytest.raises(ValueError):
        ServerRegistry.from_mapping({"servers": {"": ["cmd"]}})
    with pytest.raises(ValueError):
        ServerRegistry.from_mapping({"servers": {"a": []}})
    with pytest.raises(ValueError):
        ServerRegistry.from_mapping({"servers": {"a": "cmd"}})
    with pytest.raises(TypeError):
        ServerRegistry.from_mapping({"servers": {"a": ["ok", 7]}})
    with pytest.raises(TypeError):
        ServerRegistry.from_mapping({"servers": {"a": ["ok", ""]}})


def test_registry_from_mapping_empty_is_allowed() -> None:
    assert ServerRegistry.from_mapping({}).names == ()


# --- Default-deny ------------------------------------------------------------


def test_call_before_begin_is_refused() -> None:
    lc = _lifecycle("a")
    with pytest.raises(TaskError):
        lc.call_tool("t1", "a", "lookup", {"q": "x"})


def test_call_to_non_enabled_server_is_refused_and_audited() -> None:
    lc = _lifecycle("a", "b")
    lc.begin_task("t1", ["a"])
    with pytest.raises(ServerNotEnabledError):
        lc.call_tool("t1", "b", "lookup", {"q": "x"})
    denied = [
        e
        for e in lc.audit_log.events()
        if e.kind is LifecycleKind.SERVER_DENIED and e.server == "b"
    ]
    assert len(denied) == 1
    assert denied[0].task_id == "t1"


def test_call_after_end_is_refused() -> None:
    lc = _lifecycle("a")
    lc.begin_task("t1", ["a"])
    lc.end_task("t1")
    with pytest.raises(TaskError):
        lc.call_tool("t1", "a", "lookup", {"q": "x"})


def test_begin_validates_before_starting_anything() -> None:
    created: list[FakeTransport] = []
    lc = _lifecycle("a", created=created)
    with pytest.raises(TaskError):
        lc.begin_task("", ["a"])
    with pytest.raises(TaskError):
        lc.begin_task("t1", [])
    with pytest.raises(TaskError):
        lc.begin_task("t1", ["a", "a"])
    with pytest.raises(UnknownServerError):
        lc.begin_task("t1", ["nope"])
    assert created == [], "validation failure must not start any server"
    assert lc.live_tasks() == ()


def test_second_task_cannot_own_the_same_server() -> None:
    lc = _lifecycle("a", "b")
    lc.begin_task("t1", ["a"])
    with pytest.raises(TaskError):
        lc.begin_task("t2", ["a", "b"])
    assert lc.live_tasks() == ("t1",)
    lc.end_task("t1")
    lc.begin_task("t2", ["a", "b"])
    assert lc.enabled_servers("t2") == ("a", "b")


def test_duplicate_task_id_is_refused() -> None:
    lc = _lifecycle("a")
    lc.begin_task("t1", ["a"])
    with pytest.raises(TaskError):
        lc.begin_task("t1", ["a"])


# --- Narrow enable -----------------------------------------------------------


def test_begin_enables_only_named_servers() -> None:
    created: list[FakeTransport] = []
    lc = _lifecycle("a", "b", created=created)
    handle = lc.begin_task("t1", ["b"])
    assert handle.servers == ("b",)
    assert lc.enabled_servers("t1") == ("b",)
    assert lc.live_tasks() == ("t1",)
    started = [t.command for t in created if t.started]
    assert started == [("fake-b",)]
    assert created[0].command == ("fake-b",)


def test_call_routes_to_the_enabled_server_only() -> None:
    created: list[FakeTransport] = []
    lc = _lifecycle("a", "b", created=created)
    lc.begin_task("t1", ["a"])
    result = lc.call_tool("t1", "a", "lookup", {"q": "hours"})
    assert result["content"][0]["text"] == "ok"
    by_command = {t.command: t for t in created}
    assert len(by_command[("fake-a",)].calls) == 1
    assert by_command[("fake-a",)].calls[0]["arguments"] == {"q": "hours"}


def test_gateway_trust_still_enforced_inside_a_task() -> None:
    from mcp_guard.gateway import TrustDeniedError

    lc = _lifecycle("a")
    lc.begin_task("t1", ["a"])
    with pytest.raises(TrustDeniedError):
        lc.call_tool("t1", "a", "secret_tool", {"id": "1"}, TrustLevel.LOW)
    result = lc.call_tool("t1", "a", "secret_tool", {"id": "1"}, TrustLevel.HIGH)
    assert result["content"][0]["text"] == "ok"


def test_list_tools_annotates_trust() -> None:
    lc = _lifecycle("a")
    lc.begin_task("t1", ["a"])
    tools = lc.list_tools("t1", "a")
    by_name = {t["name"]: t for t in tools}
    assert by_name["secret_tool"]["mcp_guard_trust_level"] == "high"
    assert by_name["lookup"]["mcp_guard_trust_level"] == "low"


# --- Partial begin rolls back -------------------------------------------------


class _FailingStartTransport(FakeTransport):
    def start(self) -> None:
        raise ConnectionError("server refused the handshake")


def test_partial_begin_rolls_back_started_servers() -> None:
    created: list[FakeTransport] = []

    def factory(command: tuple[str, ...]) -> FakeTransport:
        if command == ("fake-b",):
            transport = _FailingStartTransport(command)
        else:
            transport = FakeTransport(command)
        created.append(transport)
        return transport

    lc = Lifecycle(_registry("a", "b"), POLICY, transport_factory=factory)
    with pytest.raises(ConnectionError):
        lc.begin_task("t1", ["a", "b"])
    assert lc.live_tasks() == (), "failed begin must leave no live task"
    first = created[0]
    assert first.started and first.stopped and not first.is_alive
    assert created[1].started is False


def test_failed_begin_stops_the_failing_transport(tmp_path: Path) -> None:
    """Round-2 BLOCKING: a begin whose server fails its own start (the
    initialize handshake answers with an error envelope) must stop that
    transport too — its process is already spawned, so dropping the
    handle would leak a live, unowned server. The previously-started
    server is rolled back as well."""
    bad_server = tmp_path / "bad_server.py"
    bad_server.write_text(FAKE_SERVER_INIT_ERROR, encoding="utf-8")
    good_server = tmp_path / "good_server.py"
    good_server.write_text(FAKE_SERVER, encoding="utf-8")
    created: list[StdioTransport] = []

    def factory(command: tuple[str, ...]) -> StdioTransport:
        transport = StdioTransport(list(command))
        created.append(transport)
        return transport

    registry = ServerRegistry(
        servers={
            "good": ServerSpec("good", (sys.executable, str(good_server))),
            "bad": ServerSpec("bad", (sys.executable, str(bad_server))),
        }
    )
    lc = Lifecycle(registry, POLICY, transport_factory=factory)
    with pytest.raises(RuntimeError, match="init kaboom"):
        lc.begin_task("t1", ["good", "bad"])
    assert lc.live_tasks() == (), "failed begin must leave no live task"
    try:
        for transport in created:
            assert not transport.is_alive, "failed begin left a server process alive"
            proc = transport._proc
            assert proc is not None
            # Independent OS-level check (same shape as
            # test_end_task_verifies_real_subprocess_dead): wait() reaps
            # through waitpid; a still-running process raises TimeoutExpired.
            assert proc.wait(timeout=5) is not None
    finally:
        # Never leak a child if the assertion above failed.
        for transport in created:
            transport.stop()


class _FailingStubbornTransport(FakeTransport):
    """start() fails AND stop() is a no-op: the server survives rollback."""

    def start(self) -> None:
        self.started = True
        self._alive = True
        raise RuntimeError("init kaboom")

    def stop(self) -> None:
        pass  # no-op: the server survives the rollback stop


def test_failed_begin_records_teardown_failed_when_rollback_cannot_kill() -> None:
    """Round-3 B1: a rollback that cannot verify its server dead must say
    so in the audit log — the session closing line carries the lifecycle
    audit log, so it is the only stdout signal that a failed begin left
    a process behind."""
    created: list[_FailingStubbornTransport] = []

    def factory(command: tuple[str, ...]) -> _FailingStubbornTransport:
        transport = _FailingStubbornTransport(command)
        created.append(transport)
        return transport

    lc = Lifecycle(_registry("a"), POLICY, transport_factory=factory)
    with pytest.raises(RuntimeError, match="init kaboom"):
        lc.begin_task("t1", ["a"])
    assert lc.live_tasks() == ()
    kinds = [(e.kind, e.task_id, e.server) for e in lc.audit_log.events()]
    assert (LifecycleKind.TEARDOWN_FAILED, "t1", "a") in kinds


# --- Tokens never cross tasks -------------------------------------------------


def test_tokenizer_shared_within_a_task_cleared_between_tasks() -> None:
    created: list[FakeTransport] = []
    lc = _lifecycle("a", "b", created=created)
    lc.begin_task("t1", ["a", "b"])
    by_command = {t.command: t for t in created}
    by_command[("fake-a",)].result_text = "contact jane.doe@example.com"
    result = lc.call_tool("t1", "a", "lookup", {"q": "who"})
    text = result["content"][0]["text"]
    assert "[EMAIL_1]" in text
    assert "jane.doe@example.com" not in text
    # Same token into the second server of the SAME task resolves back.
    lc.call_tool("t1", "b", "lookup", {"q": "[EMAIL_1]"})
    assert by_command[("fake-b",)].calls[0]["arguments"] == {"q": "jane.doe@example.com"}
    lc.end_task("t1")
    # New task: the stale token must NOT resolve (tokenizer was cleared).
    # begin_task builds a FRESH transport for "b": it is the last created.
    lc.begin_task("t2", ["b"])
    new_b = created[-1]
    lc.call_tool("t2", "b", "lookup", {"q": "[EMAIL_1]"})
    assert new_b.calls[-1]["arguments"] == {"q": "[EMAIL_1]"}
    lc.end_task("t2")


def test_stale_token_never_rebinds_across_tasks() -> None:
    """B1 regression: counters stay monotonic, so a stale token is literal.

    A token minted in task 1 must never silently resolve to a different
    person's value in task 2. The lifecycle owns one tokenizer whose
    counters never restart: the next minted value is [EMAIL_2], and
    replaying the stale [EMAIL_1] passes through as literal text.
    """
    created: list[FakeTransport] = []
    lc = _lifecycle("a", "b", created=created)
    lc.begin_task("t1", ["a"])
    by_command = {t.command: t for t in created}
    by_command[("fake-a",)].result_text = "contact jane.doe@example.com"
    result = lc.call_tool("t1", "a", "lookup", {"q": "who"})
    assert "[EMAIL_1]" in result["content"][0]["text"]
    lc.end_task("t1")
    lc.begin_task("t2", ["a"])
    # begin_task builds a FRESH transport for "a": it is the last created.
    new_a = created[-1]
    new_a.result_text = "contact bob@example.com"
    result = lc.call_tool("t2", "a", "lookup", {"q": "who"})
    assert "[EMAIL_2]" in result["content"][0]["text"], "counter must not restart per task"
    # Stale token from t1: must arrive at the server as literal text,
    # never rebound to bob's address.
    lc.call_tool("t2", "a", "lookup", {"q": "[EMAIL_1]"})
    assert new_a.calls[-1]["arguments"] == {"q": "[EMAIL_1]"}
    lc.end_task("t2")


def test_audit_log_len_and_gateway_audit_read_view() -> None:
    lc = _lifecycle("a")
    assert lc.registry.names == ("a",)
    assert len(lc.audit_log) == 0
    lc.begin_task("t1", ["a"])
    assert len(lc.audit_log) == 2  # TASK_BEGUN + SERVER_ENABLED
    lc.call_tool("t1", "a", "lookup", {"q": "x"})
    audit = lc.gateway_audit_log("t1", "a")
    assert any(e.kind.value == "call_allowed" for e in audit.events())
    # A read view of a server the task did not enable refuses WITHOUT
    # appending a denial event: reading a log is not an access attempt.
    before = len(lc.audit_log)
    with pytest.raises(ServerNotEnabledError):
        lc.gateway_audit_log("t1", "nope")
    assert len(lc.audit_log) == before
    with pytest.raises(TaskError):
        lc.enabled_servers("nope")


def test_default_factory_spawns_real_stdio_transport(tmp_path: Path) -> None:
    """No factory passed: the default builds a real StdioTransport."""
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    registry = ServerRegistry(servers={"srv": ServerSpec("srv", (sys.executable, str(server)))})
    lc = Lifecycle(registry, POLICY)
    lc.begin_task("t1", ["srv"])
    result = lc.call_tool("t1", "srv", "lookup", {"q": "hours"})
    assert "answer for" in result["content"][0]["text"]
    assert lc.end_task("t1").ok


class _StubbornStartTransport(FakeTransport):
    """stop() never kills it: rollback must still surface the begin error."""

    def stop(self) -> None:
        self.stopped = True  # claims to stop; _alive stays True


def test_rollback_survives_uncooperative_stop() -> None:
    created: list[FakeTransport] = []

    def factory(command: tuple[str, ...]) -> FakeTransport:
        if command == ("fake-a",):
            transport = _StubbornStartTransport(command)
        else:
            transport = _FailingStartTransport(command)
        created.append(transport)
        return transport

    lc = Lifecycle(_registry("a", "b"), POLICY, transport_factory=factory)
    with pytest.raises(ConnectionError):
        lc.begin_task("t1", ["a", "b"])
    assert lc.live_tasks() == ()
    assert created[0].started and created[0].stopped and created[0].is_alive


class _ExplodingStopTransport(FakeTransport):
    """stop() raises: rollback must still surface the begin error."""

    def stop(self) -> None:
        raise RuntimeError("stop exploded")


def test_rollback_survives_raising_stop() -> None:
    created: list[FakeTransport] = []

    def factory(command: tuple[str, ...]) -> FakeTransport:
        if command == ("fake-a",):
            transport = _ExplodingStopTransport(command)
        else:
            transport = _FailingStartTransport(command)
        created.append(transport)
        return transport

    lc = Lifecycle(_registry("a", "b"), POLICY, transport_factory=factory)
    with pytest.raises(ConnectionError):
        lc.begin_task("t1", ["a", "b"])
    assert lc.live_tasks() == ()


# --- Verified teardown -------------------------------------------------------


def test_end_task_verifies_real_subprocess_dead(tmp_path: Path) -> None:
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    created: list[StdioTransport] = []

    def factory(command: tuple[str, ...]) -> StdioTransport:
        transport = StdioTransport(list(command))
        created.append(transport)
        return transport

    registry = ServerRegistry(servers={"srv": ServerSpec("srv", (sys.executable, str(server)))})
    lc = Lifecycle(registry, POLICY, transport_factory=factory)
    lc.begin_task("t1", ["srv"])
    assert created[0].is_alive
    proc = created[0]._proc
    assert proc is not None
    lc.call_tool("t1", "srv", "lookup", {"q": "hours"})
    report = lc.end_task("t1")
    assert report.ok and report.verified == ("srv",) and report.failed == ()
    assert not created[0].is_alive
    # Independent OS-level check: wait() reaps the child through waitpid
    # (a different call than the poll() behind is_alive) and returns its
    # exit code; a still-running process raises TimeoutExpired instead.
    # (os.kill(pid, 0) is NOT portable: on Windows it does not raise for
    # a dead process, so it cannot serve as the independent check.)
    assert proc.wait(timeout=5) is not None
    assert lc.live_tasks() == ()


class _StubbornTransport(FakeTransport):
    """stop() is a no-op and the process stays alive: teardown must fail."""

    stop_raises = False

    def stop(self) -> None:
        if self.stop_raises:
            raise RuntimeError("stop exploded")
        self.stopped = True  # claims to have stopped; _alive stays True


def test_teardown_failure_raises_and_keeps_task_live_for_retry() -> None:
    created: list[_StubbornTransport] = []

    def factory(command: tuple[str, ...]) -> _StubbornTransport:
        transport = _StubbornTransport(command)
        created.append(transport)
        return transport

    lc = Lifecycle(_registry("a"), POLICY, transport_factory=factory)
    lc.begin_task("t1", ["a"])
    with pytest.raises(TeardownFailedError) as excinfo:
        lc.end_task("t1")
    report = excinfo.value.report
    assert not report.ok and report.failed == ("a",)
    assert lc.live_tasks() == ("t1",), "failed teardown keeps the task live"
    failed_events = [e for e in lc.audit_log.events() if e.kind is LifecycleKind.TEARDOWN_FAILED]
    assert len(failed_events) == 1
    # Retry after the transport starts cooperating: teardown succeeds.
    created[0]._alive = False
    report = lc.end_task("t1")
    assert report.ok
    assert lc.live_tasks() == ()


def test_stop_raising_counts_as_teardown_failure() -> None:
    created: list[_StubbornTransport] = []

    def factory(command: tuple[str, ...]) -> _StubbornTransport:
        transport = _StubbornTransport(command)
        transport.stop_raises = True
        created.append(transport)
        return transport

    lc = Lifecycle(_registry("a"), POLICY, transport_factory=factory)
    lc.begin_task("t1", ["a"])
    with pytest.raises(TeardownFailedError) as excinfo:
        lc.end_task("t1")
    assert excinfo.value.report.failed == ("a",)


def test_end_unknown_task_is_refused() -> None:
    lc = _lifecycle("a")
    with pytest.raises(TaskError):
        lc.end_task("nope")


def test_teardown_report_shape() -> None:
    lc = _lifecycle("a")
    lc.begin_task("t1", ["a"])
    report = lc.end_task("t1")
    assert report.to_dict() == {
        "task_id": "t1",
        "servers": ["a"],
        "verified": ["a"],
        "failed": [],
        "ok": True,
        "pids": {"a": 4242},
    }


def test_begin_task_rejects_bare_string_server_names() -> None:
    lc = _lifecycle("a", "b")
    with pytest.raises(TaskError, match="not a bare string"):
        lc.begin_task("t1", "ab")  # type: ignore[arg-type]


def test_gateway_constructed_only_in_lifecycle() -> None:
    """Guard: the lifecycle is the only Gateway owner in src/.

    Least-privilege is a property of the choke point only if nothing
    else constructs a Gateway and calls tools around it. This AST scan
    fails the suite the moment another module starts building Gateways.
    """
    src = REPO_ROOT / "src" / "mcp_guard"
    offenders: list[str] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Gateway"
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno}")
    assert len(offenders) == 1, offenders
    assert offenders[0].startswith("src/mcp_guard/lifecycle.py:"), offenders


# --- Audit: facts only --------------------------------------------------------


def test_audit_log_carries_facts_never_content() -> None:
    lc = _lifecycle("a")
    lc.begin_task("t1", ["a"])
    lc.call_tool("t1", "a", "lookup", {"q": "my secret question"})
    with pytest.raises(ServerNotEnabledError):
        lc.call_tool("t1", "nope", "lookup", {"q": "x"})
    lc.end_task("t1")
    blob = json.dumps(lc.audit_log.to_json())
    assert "my secret question" not in blob
    kinds = [e.kind for e in lc.audit_log.events()]
    assert kinds == [
        LifecycleKind.TASK_BEGUN,
        LifecycleKind.SERVER_ENABLED,
        LifecycleKind.SERVER_DENIED,
        LifecycleKind.TEARDOWN_VERIFIED,
        LifecycleKind.TASK_ENDED,
    ]


# --- CLI ----------------------------------------------------------------------


def _run_cli(args: list[str], stdin: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "mcp_guard.cli", *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
        cwd=str(REPO_ROOT),
    )


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_cli_single_server_session_reports_verified_teardown(tmp_path: Path) -> None:
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    requests = json.dumps({"tool": "lookup", "arguments": {"q": "hours"}})
    proc = _run_cli(
        [
            "gateway",
            "--policy",
            str(policy),
            "--",
            sys.executable,
            str(server),
        ],
        requests,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert lines[0]["tools"][0]["name"] == "lookup"
    assert lines[1]["tool"] == "lookup" and "denied" not in lines[1]
    closing = lines[-1]
    assert closing["event"] == "gateway_closed"
    teardown = closing["teardown"]
    assert teardown["task_id"] == "session"
    assert teardown["servers"] == ["default"]
    assert teardown["verified"] == ["default"]
    assert teardown["failed"] == [] and teardown["ok"] is True
    assert isinstance(teardown["pids"]["default"], int) and teardown["pids"]["default"] > 0
    assert any(e["kind"] == "teardown_verified" for e in closing["lifecycle_audit"])


def test_cli_multi_server_narrow_enable(tmp_path: Path) -> None:
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    servers = _write(
        tmp_path,
        "servers.json",
        json.dumps(
            {"servers": {"a": [sys.executable, str(server)], "b": [sys.executable, str(server)]}}
        ),
    )
    requests = "\n".join(
        [
            # Call before any task begins: refused, session survives.
            json.dumps({"server": "a", "tool": "lookup", "arguments": {"q": "x"}}),
            json.dumps({"task": "begin", "servers": ["a"]}),
            json.dumps({"server": "a", "tool": "lookup", "arguments": {"q": "x"}}),
            # Narrow: b was not enabled for this task.
            json.dumps({"server": "b", "tool": "lookup", "arguments": {"q": "x"}}),
            json.dumps({"task": "end"}),
            # Task ended: further calls refused.
            json.dumps({"server": "a", "tool": "lookup", "arguments": {"q": "x"}}),
        ]
    )
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--servers", str(servers)],
        requests,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert lines[0] == {"servers": ["a", "b"]}
    assert lines[1]["error"].startswith("no live task")
    assert lines[2]["task"] == "begun" and lines[2]["tools"]["a"][0]["name"] == "lookup"
    assert lines[3]["tool"] == "lookup" and "denied" not in lines[3]
    assert lines[4]["denied"] is True
    assert "not enabled" in lines[4]["reason"]
    # Round-3 B2: the denied CLI call records its server_denied event on
    # the call path (the audit probe before it is a read view and records
    # nothing on its own).
    assert any(e["kind"] == "server_denied" for e in lines[4]["lifecycle_audit"])
    assert lines[5]["task"] == "ended"
    assert lines[5]["teardown"]["ok"] is True
    assert lines[6]["error"].startswith("no live task")
    closing = lines[7]
    assert closing["event"] == "gateway_closed"
    assert closing["teardown"] is None  # no live task left at EOF
    assert any(e["kind"] == "server_denied" for e in closing["lifecycle_audit"])
    # Round-4 impl advisory: exactly one denial for the one denied call.
    assert sum(1 for e in closing["lifecycle_audit"] if e["kind"] == "server_denied") == 1


def test_cli_servers_file_errors_are_fail_closed(tmp_path: Path) -> None:
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    bad = _write(tmp_path, "servers.json", json.dumps({"servers": {"a": []}}))
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--servers", str(bad)],
        "",
    )
    assert proc.returncode == 1
    assert "Invalid servers file" in proc.stderr
    # --servers + a server command together is refused.
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--servers", str(bad), "--", "echo", "hi"],
        "",
    )
    assert proc.returncode == 1
    assert "Cannot combine --servers" in proc.stderr


def test_cli_tool_error_envelope_does_not_kill_session(tmp_path: Path) -> None:
    """B2 regression: a server error envelope is an error line, not a dead
    session. The next request is still processed and EOF still tears the
    task down with verified teardown."""
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER_ERROR_CALL)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    servers = _write(
        tmp_path,
        "servers.json",
        json.dumps({"servers": {"a": [sys.executable, str(server)]}}),
    )
    requests = "\n".join(
        [
            json.dumps({"task": "begin", "servers": ["a"]}),
            json.dumps({"server": "a", "tool": "explode", "arguments": {}}),
            json.dumps({"server": "a", "tool": "lookup", "arguments": {"q": "still here"}}),
        ]
    )
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--servers", str(servers)],
        requests,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert lines[0] == {"servers": ["a"]}
    assert lines[1]["task"] == "begun"
    assert lines[2]["tool"] == "explode" and "kaboom" in lines[2]["error"]
    assert lines[3]["tool"] == "lookup" and "denied" not in lines[3]
    closing = lines[4]
    assert closing["event"] == "gateway_closed"
    assert closing["teardown"]["ok"] is True
    assert closing["teardown"]["verified"] == ["a"]
    assert isinstance(closing["teardown"]["pids"]["a"], int)
    # Multi-server mode: the closing line carries the per-server audits
    # instead of the single consolidated "audit" key.
    assert "audit" not in closing
    assert any(e["kind"] == "call_allowed" for e in closing["server_audits"]["a"])


def test_cli_begin_rolls_back_when_tools_list_fails(tmp_path: Path) -> None:
    """A begin whose tools/list errors is rolled back, not half-enabled:
    the error is printed, the task is dropped, and a later begin of a
    healthy server still works in the same session."""
    bad_server = _write(tmp_path, "bad_server.py", FAKE_SERVER_LIST_ERROR)
    good_server = _write(tmp_path, "good_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    servers = _write(
        tmp_path,
        "servers.json",
        json.dumps(
            {
                "servers": {
                    "a": [sys.executable, str(bad_server)],
                    "b": [sys.executable, str(good_server)],
                }
            }
        ),
    )
    requests = "\n".join(
        [
            json.dumps({"task": "begin", "servers": ["a"]}),
            json.dumps({"task": "begin", "servers": ["b"]}),
            json.dumps({"server": "b", "tool": "lookup", "arguments": {"q": "x"}}),
        ]
    )
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--servers", str(servers)],
        requests,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert lines[0] == {"servers": ["a", "b"]}
    assert "list kaboom" in lines[1]["error"]
    assert lines[2]["task"] == "begun"
    assert lines[3]["tool"] == "lookup" and "denied" not in lines[3]
    closing = lines[4]
    assert closing["event"] == "gateway_closed"
    assert closing["teardown"]["ok"] is True
    assert closing["teardown"]["verified"] == ["b"]


def test_cli_single_server_list_failure_prints_gateway_closed(tmp_path: Path) -> None:
    """Round-2 BLOCKING: a single-server session whose tools/list fails
    still prints gateway_closed (with the rolled-back teardown report)
    instead of dying with an empty stdout, and exits 1."""
    server = _write(tmp_path, "bad_server.py", FAKE_SERVER_LIST_ERROR)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--", sys.executable, str(server)],
        "",
    )
    assert proc.returncode == 1, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert len(lines) == 1
    closing = lines[0]
    assert closing["event"] == "gateway_closed"
    assert "list kaboom" in closing["error"]
    assert closing["teardown"]["ok"] is True
    assert closing["teardown"]["verified"] == ["default"]
    assert closing["teardown"]["failed"] == []


def test_cli_single_server_begin_failure_prints_gateway_closed(tmp_path: Path) -> None:
    """Same close contract when the single server fails its own start
    (initialize answers with an error envelope): gateway_closed with the
    error and no teardown, exit 1."""
    server = _write(tmp_path, "bad_server.py", FAKE_SERVER_INIT_ERROR)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--", sys.executable, str(server)],
        "",
    )
    assert proc.returncode == 1, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert len(lines) == 1
    closing = lines[0]
    assert closing["event"] == "gateway_closed"
    assert "init kaboom" in closing["error"]
    assert closing["teardown"] is None
    # Round-3 B1: the rollback stopped the server, so no teardown_failed
    # event: teardown null + a clean audit log means "nothing left
    # behind", distinct from a rollback that left a server alive.
    assert not any(e["kind"] == "teardown_failed" for e in closing["lifecycle_audit"])


class _FlakyPipeTransport(FakeTransport):
    """First call dies mid-write (BrokenPipeError); later calls succeed."""

    def __init__(self, command: tuple[str, ...] = ()) -> None:
        super().__init__(command)
        self._call_count = 0

    def call_tool(self, tool_name: str, arguments: JsonDict) -> JsonDict:
        self._call_count += 1
        if self._call_count == 1:
            raise BrokenPipeError("server died mid-write")
        return super().call_tool(tool_name, arguments)


def test_cli_broken_pipe_is_error_line_not_dead_session(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Advisory: a BrokenPipeError (an OSError, not a ConnectionError) on
    the write path is an error line for that request, never a dead
    session — the next request is still answered."""
    created: list[_FlakyPipeTransport] = []

    def factory(command: tuple[str, ...]) -> _FlakyPipeTransport:
        transport = _FlakyPipeTransport(command)
        created.append(transport)
        return transport

    lc = Lifecycle(_registry("a"), POLICY, transport_factory=factory)
    session = _GatewaySession(lc, "a")
    _handle_gateway_begin(session, {"task_id": "t1", "servers": ["a"]})
    _handle_gateway_line(
        session, json.dumps({"server": "a", "tool": "lookup", "arguments": {"q": "x"}})
    )
    _handle_gateway_line(
        session, json.dumps({"server": "a", "tool": "lookup", "arguments": {"q": "y"}})
    )
    lines = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert lines[0]["task"] == "begun"
    assert lines[1]["tool"] == "lookup" and "died mid-write" in lines[1]["error"]
    assert lines[2]["tool"] == "lookup" and "error" not in lines[2] and "denied" not in lines[2]
    lc.end_task("t1")


def test_cli_begin_scrubs_pii_tool_names_in_annotated_list(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fix-forward (round-5 B1): the {"task": "begun"} line carries the
    annotated tool list, and tool names/descriptions are server-controlled
    free text — they print tokenized, never raw. The scrub happens at
    the print site, so the harness still calls tools by their real names.
    Round-6 fix-forward: the task id is caller-supplied free text too,
    so the begin line carries it tokenized as well."""

    class _PiiToolsTransport(FakeTransport):
        def list_tools(self) -> list[JsonDict]:
            return [
                {
                    "name": "lookup-jane.doe@example.com",
                    "description": "Answer for jane.doe@example.com",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ]

    def factory(command: tuple[str, ...]) -> _PiiToolsTransport:
        return _PiiToolsTransport(command)

    lc = Lifecycle(_registry("a"), POLICY, transport_factory=factory)
    session = _GatewaySession(lc, "a")
    _handle_gateway_begin(session, {"task_id": "jane.doe@example.com", "servers": ["a"]})
    out = capsys.readouterr().out
    assert "jane.doe@example.com" not in out
    lines = [json.loads(line) for line in out.strip().splitlines()]
    assert lines[0]["task"] == "begun"
    assert lines[0]["task_id"] == "[EMAIL_1]"
    listed = lines[0]["tools"]["a"]
    # The whole name is one email address, so it tokenizes to a single
    # [EMAIL_1]; the description's email is a different value, so it
    # mints [EMAIL_2] — numbering is per distinct value.
    assert listed[0]["name"] == "[EMAIL_1]"
    assert listed[0]["description"] == "Answer for [EMAIL_2]"
    lc.end_task("jane.doe@example.com")


def test_cli_pii_task_id_never_reaches_stdout_whole_session(tmp_path: Path) -> None:
    """Fix-forward (implementation B1/A1, round 6): a PII-bearing task id
    is caller-supplied free text, and it flows into the begun line, the
    denied line's lifecycle-audit block, the ended line's teardown, and
    the gateway_closed line — assert the raw value appears nowhere on
    stdout across the whole multi-server session."""
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    servers = _write(
        tmp_path,
        "servers.json",
        json.dumps({"servers": {"a": [sys.executable, str(server)]}}),
    )
    requests = "\n".join(
        [
            json.dumps({"task": "begin", "servers": ["a"], "task_id": "jane.doe@example.com"}),
            # Call on a server the task did not enable: denied line with
            # a lifecycle-audit block carrying the task id.
            json.dumps({"server": "b", "tool": "lookup", "arguments": {"q": "x"}}),
            json.dumps({"task": "end"}),
        ]
    )
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--servers", str(servers)],
        requests,
    )
    assert proc.returncode == 0, proc.stderr
    assert "jane.doe@example.com" not in proc.stdout
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert lines[0] == {"servers": ["a"]}
    assert lines[1]["task"] == "begun" and lines[1]["task_id"] == "[EMAIL_1]"
    assert lines[2]["denied"] is True
    assert lines[3]["task"] == "ended" and lines[3]["task_id"] == "[EMAIL_1]"
    assert lines[3]["teardown"]["task_id"] == "[EMAIL_1]"
    assert lines[4]["event"] == "gateway_closed"
    assert any(event["task_id"] == "[EMAIL_1]" for event in lines[4]["lifecycle_audit"])


def test_cli_single_server_malformed_tools_list_prints_gateway_closed(tmp_path: Path) -> None:
    """Round-3 impl B1: a well-formed tools/list response with a wrongly
    shaped tools value is a transport failure (ConnectionError), so the
    single-server session still closes with gateway_closed, verified
    teardown, exit 1 — instead of dying with an empty stdout."""
    server = _write(tmp_path, "bad_server.py", FAKE_SERVER_TOOLS_NOT_LIST)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--", sys.executable, str(server)],
        "",
    )
    assert proc.returncode == 1, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert len(lines) == 1
    closing = lines[0]
    assert closing["event"] == "gateway_closed"
    assert "malformed" in closing["error"]
    assert closing["teardown"]["ok"] is True
    assert closing["teardown"]["verified"] == ["default"]
    assert closing["teardown"]["failed"] == []


def test_cli_begin_nonexistent_command_is_error_line(tmp_path: Path) -> None:
    """Round-3 impl A1: the OSError widening's real new coverage is a spawn
    failure (FileNotFoundError: an OSError but not a ConnectionError) — the
    begin fails as an error line and the session survives to a clean close."""
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    servers = _write(
        tmp_path,
        "servers.json",
        json.dumps({"servers": {"a": ["definitely-not-a-real-command-xyz"]}}),
    )
    requests = json.dumps({"task": "begin", "servers": ["a"]})
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--servers", str(servers)],
        requests,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert lines[0] == {"servers": ["a"]}
    # The spawn failure is an error line (not a dead session). The exact
    # OS message differs by platform — Windows omits the command name
    # from the FileNotFoundError text (CreateProcess raises bare, unlike
    # the POSIX errpipe which carries the filename) — so assert only
    # that it is a non-empty error, not the command name.
    assert isinstance(lines[1].get("error"), str) and lines[1]["error"]
    closing = lines[2]
    assert closing["event"] == "gateway_closed"
    assert closing["teardown"] is None


def test_cli_single_server_result_not_object_prints_gateway_closed(tmp_path: Path) -> None:
    """Round-4 impl B1: a tools/list whose result is not an object is a
    transport failure, so the single-server session still closes with
    gateway_closed, verified teardown, exit 1."""
    server = _write(tmp_path, "bad_server.py", FAKE_SERVER_RESULT_NOT_OBJECT)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--", sys.executable, str(server)],
        "",
    )
    assert proc.returncode == 1, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert len(lines) == 1
    closing = lines[0]
    assert closing["event"] == "gateway_closed"
    assert "malformed" in closing["error"]
    assert closing["teardown"]["ok"] is True
    assert closing["teardown"]["verified"] == ["default"]
    assert closing["teardown"]["failed"] == []


def test_cli_single_server_bare_json_response_prints_gateway_closed(tmp_path: Path) -> None:
    """Round-4 impl B2: a bare JSON value response (not an object) at
    initialize is a transport failure: gateway_closed with the error and
    no teardown, exit 1."""
    server = _write(tmp_path, "bad_server.py", FAKE_SERVER_BARE_JSON)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    proc = _run_cli(
        ["gateway", "--policy", str(policy), "--", sys.executable, str(server)],
        "",
    )
    assert proc.returncode == 1, proc.stderr
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    assert len(lines) == 1
    closing = lines[0]
    assert closing["event"] == "gateway_closed"
    assert "Invalid JSON" in closing["error"]
    assert closing["teardown"] is None
