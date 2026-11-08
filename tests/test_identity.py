"""Identity propagation (rat #70): the agent acts with the user's
permissions, never a super-key.

Every test here is behavioral and adversarial: a denied call must never
reach the server, a handle must never work for another user or a widened
scope, a revoked handle must refuse on the NEXT call, and the audit log
must attribute every action to a scope without ever carrying the raw
user id. User ids use the example.com / synthetic-person pattern so no
real personal data appears anywhere.
"""

from __future__ import annotations

import ast
import json
import os
import stat
import subprocess
import sys
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_guard.gateway import (
    AuditKind,
    Gateway,
    GatewayPolicy,
    TrustDeniedError,
    TrustLevel,
)
from mcp_guard.identity import (
    CredentialError,
    CredentialHandle,
    IdentityContext,
    IdentityVault,
    PermissionScope,
    ScopeDeniedError,
    ScopeExpiredError,
)
from mcp_guard.lifecycle import (
    Lifecycle,
    LifecycleKind,
    ServerRegistry,
    ServerSpec,
)
from mcp_guard.transport import JsonDict

REPO_ROOT = Path(__file__).resolve().parent.parent

USER = "dana@example.com"
OTHER_USER = "noor@example.com"
NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=UTC)
PAST = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
FUTURE = datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC)


def _scope(
    user_id: str = USER,
    servers: frozenset[str] = frozenset({"default"}),
    tools: frozenset[str] = frozenset({"lookup", "search"}),
    expires_at: datetime | None = None,
) -> PermissionScope:
    return PermissionScope(user_id=user_id, servers=servers, tools=tools, expires_at=expires_at)


def _bound_scope(expires_at: datetime | None = None) -> tuple[IdentityVault, IdentityContext]:
    """A vault + a live-bound context for the default scope."""
    vault = IdentityVault()
    scope = _scope(expires_at=expires_at)
    return vault, vault.issue_context(scope, NOW)


class FakeTransport:
    """Records every send; answers canned tool results."""

    def __init__(self, results: dict[str, dict] | None = None) -> None:
        self.calls: list[dict] = []
        self.results = results or {}
        self._id = 0

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        self._id += 1
        return self.results.get(tool_name, {"content": [{"type": "text", "text": "ok"}]})

    def last_exchange(self) -> tuple[dict | None, object]:
        if not self.calls:
            return None, None
        last = self.calls[-1]
        return (
            {
                "jsonrpc": "2.0",
                "id": self._id,
                "method": "tools/call",
                "params": {"name": last["tool"], "arguments": last["arguments"]},
            },
            self._id,
        )


class FakeLifecycleTransport:
    """In-memory stand-in for a server transport (no subprocess)."""

    def __init__(self, command: tuple[str, ...] = ()) -> None:
        self.command = command
        self.started = False
        self.stopped = False
        self._alive = False
        self.calls: list[JsonDict] = []

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
        return [
            {"name": "lookup", "description": "answer a question"},
            {"name": "delete_record", "description": "delete a record"},
        ]

    def call_tool(self, tool_name: str, arguments: JsonDict) -> JsonDict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"content": [{"type": "text", "text": "ok"}]}

    def last_exchange(self) -> tuple[JsonDict | None, object]:
        if not self.calls:
            return None, None
        return {"jsonrpc": "2.0", "id": len(self.calls), "method": "tools/call"}, len(self.calls)


def _policy() -> GatewayPolicy:
    return GatewayPolicy(
        tools={"delete_record": TrustLevel.HIGH, "lookup": TrustLevel.LOW},
        default_trust=TrustLevel.LOW,
    )


def _lifecycle(*names: str, created: list[FakeLifecycleTransport] | None = None) -> Lifecycle:
    def factory(command: tuple[str, ...]) -> FakeLifecycleTransport:
        transport = FakeLifecycleTransport(command)
        if created is not None:
            created.append(transport)
        return transport

    registry = ServerRegistry(servers={name: ServerSpec(name, (f"fake-{name}",)) for name in names})
    return Lifecycle(registry, _policy(), transport_factory=factory)


class _FutureDatetime(datetime):
    """datetime whose now() is a fixed future instant (expiry tests)."""

    _fixed: datetime = FUTURE

    @classmethod
    def now(cls, tz: object = None) -> datetime:
        return cls._fixed


# --- PermissionScope: parsing ---------------------------------------------------


def test_scope_from_mapping_ok() -> None:
    scope = PermissionScope.from_mapping(
        {
            "user_id": USER,
            "servers": ["default", "archive"],
            "tools": ["lookup", "Search "],
            "expires_at": "2027-01-01T00:00:00Z",
        }
    )
    assert scope.user_id == USER
    assert scope.servers == frozenset({"default", "archive"})
    assert scope.tools == frozenset({"lookup", "search"})
    assert scope.expires_at == FUTURE


def test_scope_from_mapping_defaults_are_deny_by_default() -> None:
    scope = PermissionScope.from_mapping({"user_id": USER})
    assert scope.servers == frozenset()
    assert scope.tools == frozenset()
    assert scope.expires_at is None
    assert not scope.allows_tool("lookup")
    assert not scope.allows_server("default")


def test_scope_from_mapping_rejects_unknown_keys() -> None:
    with pytest.raises(ValueError, match="unknown keys"):
        PermissionScope.from_mapping({"user_id": USER, "toolz": ["lookup"]})


def test_scope_from_mapping_requires_user_id() -> None:
    with pytest.raises(ValueError, match="user_id"):
        PermissionScope.from_mapping({"tools": ["lookup"]})
    with pytest.raises(ValueError, match="user_id"):
        PermissionScope.from_mapping({"user_id": "   "})
    with pytest.raises(TypeError):
        PermissionScope.from_mapping({"user_id": 7})


def test_scope_from_mapping_rejects_bad_shapes() -> None:
    with pytest.raises(TypeError):
        PermissionScope.from_mapping({"user_id": USER, "servers": "default"})
    with pytest.raises(TypeError):
        PermissionScope.from_mapping({"user_id": USER, "tools": [1]})
    with pytest.raises(TypeError):
        PermissionScope.from_mapping(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_scope_from_mapping_rejects_naive_expiry() -> None:
    with pytest.raises(ValueError, match="timezone"):
        PermissionScope.from_mapping({"user_id": USER, "expires_at": "2027-01-01T00:00:00"})
    with pytest.raises(TypeError):
        PermissionScope.from_mapping({"user_id": USER, "expires_at": 12345})


def test_scope_and_handle_reject_naive_datetimes_at_construction() -> None:
    """A naive expiry must be refused at construction, never compared:
    comparing it against aware UTC time raises TypeError mid-session
    instead of producing a denial, so the shape is denied up front."""
    naive = datetime(2027, 1, 1, 0, 0, 0)  # noqa: DTZ001 - naive is the point: refused at construction
    with pytest.raises(ValueError, match="timezone"):
        PermissionScope(user_id=USER, expires_at=naive)
    with pytest.raises(ValueError, match="timezone"):
        CredentialHandle(
            handle_id="h1",
            user_id=USER,
            scope_fingerprint="f" * 64,
            issued_at=NOW,
            expires_at=naive,
        )
    with pytest.raises(ValueError, match="timezone"):
        CredentialHandle(
            handle_id="h1",
            user_id=USER,
            scope_fingerprint="f" * 64,
            issued_at=naive,
        )


def test_naive_expiry_is_denied_not_raised_when_reached() -> None:
    """Defense in depth: an object built without __post_init__ that
    carries a naive expiry must deny (is_expired True), never raise
    TypeError on the aware comparison."""
    scope = PermissionScope.__new__(PermissionScope)
    object.__setattr__(scope, "expires_at", datetime(2027, 1, 1, 0, 0, 0))  # noqa: DTZ001 - naive is the point: denied, never compared
    assert scope.is_expired(NOW) is True
    handle = CredentialHandle.__new__(CredentialHandle)
    object.__setattr__(handle, "expires_at", datetime(2027, 1, 1, 0, 0, 0))  # noqa: DTZ001 - naive is the point: denied, never compared
    assert handle.is_expired(NOW) is True


def test_scope_round_trip_preserves_grant() -> None:
    scope = _scope(expires_at=FUTURE)
    again = PermissionScope.from_mapping(scope.to_mapping())
    assert again == scope
    assert again.fingerprint() == scope.fingerprint()


def test_scope_is_frozen_and_unwidenable() -> None:
    scope = _scope()
    with pytest.raises(FrozenInstanceError):
        scope.tools = frozenset({"delete_record"})  # type: ignore[misc]
    with pytest.raises(AttributeError):
        scope.tools.add("delete_record")  # type: ignore[attr-defined]


# --- PermissionScope: membership -----------------------------------------------


def test_tool_names_match_normalized() -> None:
    scope = _scope()
    assert scope.allows_tool("lookup")
    assert scope.allows_tool(" Lookup ")
    assert scope.allows_tool("LOOKUP")
    assert not scope.allows_tool("delete_record")
    assert not scope.allows_tool(" lookup2 ")
    with pytest.raises(TypeError):
        scope.allows_tool(7)  # type: ignore[arg-type]


def test_server_names_match_exactly_not_case_folded() -> None:
    scope = _scope(servers=frozenset({"default"}))
    assert scope.allows_server("default")
    assert scope.allows_server(" default ")
    assert not scope.allows_server("Default")
    assert not scope.allows_server("DEFAULT")


def test_scope_expiry_is_injectable_now() -> None:
    scope = _scope(expires_at=FUTURE)
    assert not scope.is_expired(NOW)
    assert scope.is_expired(FUTURE)
    assert not _scope().is_expired(FUTURE)


def test_fingerprint_is_canonical_across_insertion_orders() -> None:
    first = PermissionScope(
        user_id=USER,
        servers=frozenset({"b", "a"}),
        tools=frozenset({"y", "x"}),
        expires_at=FUTURE,
    )
    second = PermissionScope(
        user_id=USER,
        servers=frozenset({"a", "b"}),
        tools=frozenset({"x", "y"}),
        expires_at=FUTURE,
    )
    assert first.fingerprint() == second.fingerprint()
    assert first.fingerprint() != _scope().fingerprint()
    assert _scope(user_id=OTHER_USER).fingerprint() != _scope().fingerprint()


# --- IdentityVault: issue / check / revoke --------------------------------------


def test_vault_issue_and_check_ok() -> None:
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    assert handle.user_id == USER
    assert handle.scope_fingerprint == scope.fingerprint()
    assert handle.expires_at is None
    vault.check(handle, scope, NOW)
    assert len(vault) == 1
    assert vault.handles_for(USER) == (handle,)


def test_vault_issue_refuses_other_users_scope() -> None:
    vault = IdentityVault()
    with pytest.raises(CredentialError):
        vault.issue(OTHER_USER, _scope(), NOW)


def test_vault_issue_refuses_expired_scope() -> None:
    vault = IdentityVault()
    with pytest.raises(ScopeExpiredError):
        vault.issue(USER, _scope(expires_at=PAST), NOW)


def test_vault_check_refuses_unknown_handle() -> None:
    vault = IdentityVault()
    scope = _scope()
    forged = CredentialHandle(
        handle_id="forged-handle-id",
        user_id=USER,
        scope_fingerprint=scope.fingerprint(),
        issued_at=NOW,
    )
    with pytest.raises(CredentialError, match="unknown"):
        vault.check(forged, scope, NOW)


def test_vault_check_refuses_cross_user_handle() -> None:
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    with pytest.raises(CredentialError):
        vault.check(handle, _scope(user_id=OTHER_USER), NOW)


def test_vault_check_refuses_widened_scope() -> None:
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    widened = _scope(tools=frozenset({"lookup", "search", "delete_record"}))
    with pytest.raises(CredentialError, match="different scope"):
        vault.check(handle, widened, NOW)


def test_vault_check_refuses_expired_handle() -> None:
    vault = IdentityVault()
    scope = _scope(expires_at=FUTURE)
    handle = vault.issue(USER, scope, NOW)
    with pytest.raises(ScopeExpiredError):
        vault.check(handle, scope, FUTURE)


def test_vault_revoke_refuses_next_check() -> None:
    vault = IdentityVault()
    handle = vault.issue(USER, _scope(), NOW)
    vault.revoke(handle.handle_id)
    with pytest.raises(CredentialError, match="revoked"):
        vault.check(handle, _scope(), NOW)


def test_vault_revoke_unknown_raises() -> None:
    with pytest.raises(CredentialError, match="unknown"):
        IdentityVault().revoke("no-such-handle")


def test_vault_has_no_shared_or_super_credential_api() -> None:
    """A super-key must be unrepresentable, not merely discouraged:
    no method or attribute name on the vault may promise a shared,
    global, or super credential."""
    names = [n.lower() for n in dir(IdentityVault)]
    for banned in ("global", "shared", "super", "master", "root_key", "all_users"):
        assert not any(banned in n for n in names), f"vault exposes {banned!r} API"
    tree = ast.parse((REPO_ROOT / "src" / "mcp_guard" / "identity.py").read_text(encoding="utf-8"))
    defined = {
        node.name.lower()
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for banned in ("global", "shared", "super"):
        assert not any(banned in n for n in defined), f"identity.py defines {banned!r}"


# --- IdentityVault: persistence -------------------------------------------------


def test_vault_save_load_round_trip(tmp_path: Path) -> None:
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    vault.revoke(handle.handle_id)
    other = vault.issue(USER, _scope(tools=frozenset({"lookup"})), NOW)
    path = tmp_path / "vault.json"
    vault.save(path)
    loaded = IdentityVault.load(path)
    assert loaded.handles_for(USER) == tuple(sorted((handle, other), key=lambda h: h.handle_id))
    loaded.check(other, _scope(tools=frozenset({"lookup"})), NOW)
    with pytest.raises(CredentialError, match="revoked"):
        loaded.check(handle, scope, NOW)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_vault_file_mode_is_0600(tmp_path: Path) -> None:
    """The vault file must be owner-only where the platform has
    permission bits. Windows has no POSIX mode bits (os.open's mode
    argument is best-effort there), so this is asserted on POSIX
    only — the same convention as test_lock_file_mode_is_0600."""
    vault = IdentityVault()
    vault.issue(USER, _scope(), NOW)
    path = tmp_path / "vault.json"
    vault.save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_vault_save_enforces_mode_on_resave(tmp_path: Path) -> None:
    """A re-save over a world-readable vault file must tighten the mode:
    os.open's mode argument applies only at creation, so without the
    fchmod a re-save silently leaves the inventory world-readable."""
    vault = IdentityVault()
    vault.issue(USER, _scope(), NOW)
    path = tmp_path / "vault.json"
    path.write_text("{}", encoding="utf-8")
    # 0640 (group-readable, not world-readable): wide enough to prove
    # the re-save tightens the mode, without tripping the
    # overly-permissive-chmod scanner the way 0644 would.
    os.chmod(path, 0o640)
    vault.save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = IdentityVault.load(path)
    assert len(loaded) == 1


def test_vault_load_refuses_tampered_fingerprint(tmp_path: Path) -> None:
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    path = tmp_path / "vault.json"
    vault.save(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["handles"][0]["scope_fingerprint"] = "0" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = IdentityVault.load(path)
    with pytest.raises(CredentialError, match="different scope"):
        loaded.check(handle, scope, NOW)


def test_vault_check_refuses_presented_forged_fingerprint() -> None:
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    forged = CredentialHandle(
        handle_id=handle.handle_id,
        user_id=handle.user_id,
        scope_fingerprint="0" * 64,
        issued_at=handle.issued_at,
        expires_at=handle.expires_at,
    )
    with pytest.raises(CredentialError, match="different scope"):
        vault.check(forged, scope, NOW)


def test_vault_load_refuses_unknown_keys_and_versions(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    path.write_text(json.dumps({"version": 1, "handles": [], "revoked": [], "extra": 1}))
    with pytest.raises(ValueError, match="unknown keys"):
        IdentityVault.load(path)
    path.write_text(json.dumps({"version": 99, "handles": [], "revoked": []}))
    with pytest.raises(ValueError, match="version"):
        IdentityVault.load(path)
    path.write_text(json.dumps({"version": 1, "handles": [], "revoked": ["ghost"]}))
    with pytest.raises(CredentialError, match="unknown handle"):
        IdentityVault.load(path)


# --- IdentityContext ------------------------------------------------------------


def test_context_rejects_mismatched_pair() -> None:
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    with pytest.raises(CredentialError, match="different user"):
        IdentityContext(scope=_scope(user_id=OTHER_USER), credential=handle, vault=vault)
    with pytest.raises(CredentialError, match="different scope"):
        IdentityContext(scope=_scope(tools=frozenset({"lookup"})), credential=handle, vault=vault)


def test_context_rejects_expired_credential_at_bind() -> None:
    vault = IdentityVault()
    scope = _scope(expires_at=PAST)
    handle = CredentialHandle(
        handle_id="expired-handle",
        user_id=USER,
        scope_fingerprint=scope.fingerprint(),
        issued_at=PAST,
        expires_at=PAST,
    )
    with pytest.raises(ScopeExpiredError):
        IdentityContext(scope=scope, credential=handle, vault=vault)


def test_context_requires_a_vault_and_a_handle_it_knows() -> None:
    """A vault-less context cannot be constructed, and a handle the
    vault never issued is refused at bind time: revocation must never
    silently stop being enforced because the caller built the context
    by hand."""
    vault = IdentityVault()
    scope = _scope()
    handle = vault.issue(USER, scope, NOW)
    with pytest.raises(TypeError):
        IdentityContext(scope=scope, credential=handle)  # type: ignore[call-arg]
    stranger_vault = IdentityVault()
    with pytest.raises(CredentialError, match="unknown credential handle"):
        IdentityContext(scope=scope, credential=handle, vault=stranger_vault)


def test_audit_token_is_stable_one_way_and_never_raw() -> None:
    _, ctx = _bound_scope()
    assert ctx.audit_token.startswith("user-")
    assert ctx.audit_token == _bound_scope()[1].audit_token
    assert USER not in ctx.audit_token


def test_context_check_call_and_server() -> None:
    _, ctx = _bound_scope()
    ctx.check_call("lookup", NOW)
    ctx.check_call(" LOOKUP ", NOW)
    ctx.check_server("default", NOW)
    with pytest.raises(ScopeDeniedError, match="tool"):
        ctx.check_call("delete_record", NOW)
    with pytest.raises(ScopeDeniedError, match="server"):
        ctx.check_server("archive", NOW)


def test_context_check_call_refuses_expired_scope_with_injected_now() -> None:
    _, ctx = _bound_scope(expires_at=FUTURE)
    with pytest.raises(ScopeExpiredError):
        ctx.check_call("lookup", FUTURE)
    with pytest.raises(ScopeExpiredError):
        ctx.check_server("default", FUTURE)


def test_context_check_call_refuses_revoked_handle_live() -> None:
    vault, ctx = _bound_scope()
    ctx.check_call("lookup", NOW)
    vault.revoke(ctx.credential.handle_id)
    with pytest.raises(CredentialError, match="revoked"):
        ctx.check_call("lookup", NOW)


# --- Gateway integration --------------------------------------------------------


def _bound_gateway() -> tuple[FakeTransport, Gateway, IdentityContext]:
    transport = FakeTransport()
    _, ctx = _bound_scope()
    gateway = Gateway(transport, _policy(), identity=ctx)
    return transport, gateway, ctx


def test_gateway_allows_in_scope_call_and_attributes_it() -> None:
    transport, gateway, ctx = _bound_gateway()
    gateway.call_tool("lookup", {"q": "x"}, TrustLevel.LOW)
    assert len(transport.calls) == 1
    events = gateway.audit_log.events()
    assert events[-1].kind is AuditKind.CALL_ALLOWED
    assert events[-1].identity == ctx.audit_token
    assert USER not in json.dumps(gateway.audit_log.to_json())


def test_gateway_bind_revalidates_handle_against_vault() -> None:
    """A revocation issued between context construction and gateway
    bind is refused at bind time, before any call."""
    vault, ctx = _bound_scope()
    vault.revoke(ctx.credential.handle_id)
    with pytest.raises(CredentialError, match="revoked"):
        Gateway(FakeTransport(), _policy(), identity=ctx)


def test_gateway_denies_out_of_scope_tool_before_any_send() -> None:
    transport, gateway, ctx = _bound_gateway()
    with pytest.raises(ScopeDeniedError):
        gateway.call_tool("delete_record", {"id": "1"}, TrustLevel.HIGH)
    assert transport.calls == [], "denied call reached the server"
    events = gateway.audit_log.events()
    assert events[-1].kind is AuditKind.IDENTITY_DENIED
    assert events[-1].identity == ctx.audit_token
    assert USER not in json.dumps(gateway.audit_log.to_json())


def test_gateway_denies_revoked_handle_on_next_call() -> None:
    vault, ctx = _bound_scope()
    transport = FakeTransport()
    gateway = Gateway(transport, _policy(), identity=ctx)
    gateway.call_tool("lookup", {"q": "x"}, TrustLevel.LOW)
    vault.revoke(ctx.credential.handle_id)
    with pytest.raises(CredentialError, match="revoked"):
        gateway.call_tool("lookup", {"q": "x"}, TrustLevel.LOW)
    assert len(transport.calls) == 1, "revoked call reached the server"
    assert gateway.audit_log.events()[-1].kind is AuditKind.CREDENTIAL_REFUSED


def test_gateway_expiry_refuses_before_trust_check(monkeypatch: pytest.MonkeyPatch) -> None:
    _, ctx = _bound_scope(expires_at=FUTURE)
    transport = FakeTransport()
    gateway = Gateway(transport, _policy(), identity=ctx)
    monkeypatch.setattr("mcp_guard.identity.datetime", _FutureDatetime)
    with pytest.raises(ScopeExpiredError):
        gateway.call_tool("lookup", {"q": "x"}, TrustLevel.LOW)
    assert transport.calls == []
    assert gateway.audit_log.events()[-1].kind is AuditKind.IDENTITY_EXPIRED


def test_gateway_identity_check_runs_before_trust_check() -> None:
    _, gateway, _ = _bound_gateway()
    # delete_record is out of scope AND high trust for a LOW caller:
    # the identity denial must win (no trust verdict for a denied identity).
    with pytest.raises(ScopeDeniedError):
        gateway.call_tool("delete_record", {"id": "1"}, TrustLevel.LOW)
    assert gateway.audit_log.events()[-1].kind is AuditKind.IDENTITY_DENIED
    # In-scope tool, LOW caller on a HIGH-trust tool: identity passes,
    # trust still denies.
    _, ctx2 = _bound_scope()
    gateway2 = Gateway(
        FakeTransport(),
        GatewayPolicy(
            tools={"lookup": TrustLevel.HIGH},
            default_trust=TrustLevel.LOW,
        ),
        identity=ctx2,
    )
    with pytest.raises(TrustDeniedError):
        gateway2.call_tool("lookup", {"q": "x"}, TrustLevel.LOW)
    assert gateway2.audit_log.events()[-1].kind is AuditKind.CALL_DENIED


def test_gateway_annotate_tools_filters_out_of_scope() -> None:
    _, gateway, _ = _bound_gateway()
    tools = [
        {"name": "lookup", "description": "ok"},
        {"name": "delete_record", "description": "nope"},
        {"name": "search", "description": "ok"},
    ]
    names = [t["name"] for t in gateway.annotate_tools(tools)]
    assert names == ["lookup", "search"]
    assert Gateway(FakeTransport(), _policy()).annotate_tools(tools) != gateway.annotate_tools(
        tools
    )


def test_gateway_without_identity_keeps_legacy_behavior() -> None:
    transport = FakeTransport()
    gateway = Gateway(transport, _policy())
    with pytest.raises(TrustDeniedError):
        gateway.call_tool("delete_record", {"id": "1"}, TrustLevel.LOW)
    gateway.call_tool("lookup", {"q": "x"}, TrustLevel.LOW)
    assert gateway.audit_log.events()[-1].identity is None


# --- Lifecycle integration ------------------------------------------------------


def test_lifecycle_begin_refuses_out_of_scope_server_before_any_spawn() -> None:
    created: list[FakeLifecycleTransport] = []
    lifecycle = _lifecycle("default", "archive", created=created)
    _, ctx = _bound_scope()
    with pytest.raises(ScopeDeniedError, match="server"):
        lifecycle.begin_task("t1", ["archive"], identity=ctx)
    assert created == [], "refused task spawned a server process"
    assert lifecycle.live_tasks() == ()
    events = lifecycle.audit_log.events()
    assert events[-1].kind is LifecycleKind.SERVER_DENIED
    assert events[-1].identity == ctx.audit_token


def test_lifecycle_begin_binds_identity_and_enforces_tool_scope() -> None:
    created: list[FakeLifecycleTransport] = []
    lifecycle = _lifecycle("default", created=created)
    _, ctx = _bound_scope()
    lifecycle.begin_task("t1", ["default"], identity=ctx)
    assert lifecycle.enabled_servers("t1") == ("default",)
    lifecycle.call_tool("t1", "default", "lookup", {}, TrustLevel.LOW)
    assert len(created[0].calls) == 1
    with pytest.raises(ScopeDeniedError):
        lifecycle.call_tool("t1", "default", "delete_record", {}, TrustLevel.HIGH)
    assert len(created[0].calls) == 1, "denied call reached the server"
    kinds = [e.kind for e in lifecycle.audit_log.events()]
    assert LifecycleKind.TASK_BEGUN in kinds
    assert LifecycleKind.SERVER_ENABLED in kinds
    lifecycle.end_task("t1")
    # The attribution assertion runs AFTER end_task on purpose: the
    # teardown and task-end events must carry the token too, and an
    # assertion placed before end_task cannot catch a gap on the
    # session-close path.
    events = lifecycle.audit_log.events()
    assert all(e.identity == ctx.audit_token for e in events)
    assert [e.kind for e in events if e.kind is LifecycleKind.TEARDOWN_VERIFIED]
    assert [e.kind for e in events if e.kind is LifecycleKind.TASK_ENDED]


def test_lifecycle_begin_refuses_expired_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[FakeLifecycleTransport] = []
    lifecycle = _lifecycle("default", created=created)
    _, ctx = _bound_scope(expires_at=FUTURE)
    monkeypatch.setattr("mcp_guard.identity.datetime", _FutureDatetime)
    with pytest.raises(ScopeExpiredError):
        lifecycle.begin_task("t1", ["default"], identity=ctx)
    assert created == []


# --- CLI: gateway --identity ------------------------------------------------------

FAKE_SERVER = """\
import json, sys

TOOLS = [
    {"name": "lookup", "description": "answer a question",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    {"name": "delete_record", "description": "delete a record",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
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
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text", "text": "answer"}]}})
"""


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


def _scope_file(tmp_path: Path, **overrides: object) -> Path:
    data: dict[str, object] = {
        "user_id": USER,
        "servers": ["default"],
        "tools": ["lookup"],
    }
    data.update(overrides)
    return _write(tmp_path, "scope.json", json.dumps(data))


def _cli_lines(proc: subprocess.CompletedProcess[str]) -> list[dict]:
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def test_cli_gateway_identity_allows_in_scope_call(tmp_path: Path) -> None:
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    scope = _scope_file(tmp_path)
    call = json.dumps({"tool": "lookup", "arguments": {"q": "hours"}})
    proc = _run_cli(
        [
            "gateway",
            "--policy",
            str(policy),
            "--identity",
            str(scope),
            "--",
            sys.executable,
            str(server),
        ],
        call + "\n",
    )
    assert proc.returncode == 0, proc.stderr
    lines = _cli_lines(proc)
    assert lines[0]["tools"] and [t["name"] for t in lines[0]["tools"]] == ["lookup"]
    assert lines[0]["tools"][0]["mcp_guard_trust_level"] == "low"
    assert lines[1]["tool"] == "lookup"
    assert "result" in lines[1]
    audit = lines[1]["audit"]
    assert audit[0]["kind"] == "call_allowed"
    assert audit[0]["identity"].startswith("user-")
    assert USER not in json.dumps(lines)


def test_cli_gateway_identity_denies_out_of_scope_call_and_keeps_session(tmp_path: Path) -> None:
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    scope = _scope_file(tmp_path)
    stdin = (
        "\n".join(
            [
                json.dumps({"tool": "delete_record", "arguments": {"id": "1"}}),
                json.dumps({"tool": "lookup", "arguments": {"q": "hours"}}),
            ]
        )
        + "\n"
    )
    proc = _run_cli(
        [
            "gateway",
            "--policy",
            str(policy),
            "--identity",
            str(scope),
            "--",
            sys.executable,
            str(server),
        ],
        stdin,
    )
    assert proc.returncode == 0, proc.stderr
    lines = _cli_lines(proc)
    assert lines[1]["denied"] is True
    assert lines[1]["audit"][0]["kind"] == "identity_denied"
    assert lines[2]["tool"] == "lookup"
    assert "result" in lines[2]


def test_cli_gateway_identity_refuses_out_of_scope_server(tmp_path: Path) -> None:
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    scope = _scope_file(tmp_path, servers=["other"])
    proc = _run_cli(
        [
            "gateway",
            "--policy",
            str(policy),
            "--identity",
            str(scope),
            "--",
            sys.executable,
            str(server),
        ],
        "",
    )
    assert proc.returncode == 1
    lines = _cli_lines(proc)
    assert "not in identity scope" in json.dumps(lines[-1])


def test_cli_gateway_identity_rejects_bad_scope_file(tmp_path: Path) -> None:
    server = _write(tmp_path, "fake_server.py", FAKE_SERVER)
    policy = _write(tmp_path, "policy.json", json.dumps({"tools": {}, "default_trust": "low"}))
    bad = _write(tmp_path, "scope.json", json.dumps({"user_id": USER, "toolz": ["lookup"]}))
    proc = _run_cli(
        [
            "gateway",
            "--policy",
            str(policy),
            "--identity",
            str(bad),
            "--",
            sys.executable,
            str(server),
        ],
        "",
    )
    assert proc.returncode == 1
    assert "unknown keys" in proc.stderr
    missing = tmp_path / "nope.json"
    proc = _run_cli(
        [
            "gateway",
            "--policy",
            str(policy),
            "--identity",
            str(missing),
            "--",
            sys.executable,
            str(server),
        ],
        "",
    )
    assert proc.returncode == 1


# --- Errors carry no secrets -------------------------------------------------------


def test_error_messages_never_carry_user_id_or_secrets() -> None:
    _, ctx = _bound_scope()
    for exc in (
        ScopeDeniedError("tool", "delete_record"),
        ScopeExpiredError(FUTURE),
        CredentialError("unknown credential handle"),
    ):
        assert USER not in str(exc)
    with pytest.raises(ScopeDeniedError) as e:
        ctx.check_call("delete_record", NOW)
    assert USER not in str(e.value)


# --- CLI: delegate --identity (admission control + attribution) ----------------

_DELEGATE_CONTRACT = """\
---
name: mechanical-refactor
description: Delegates mechanical refactors to the junior.
tools:
  - Bash
  - Read
denied_tools:
  - Bash
model: small-local
effort: medium
isolation: none
permission_mode: auto
max_turns: 10
memory: project
---

You are a mechanical refactor coordinator.
"""


def _delegate_cli_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    agent = tmp_path / "agent.md"
    agent.write_text(_DELEGATE_CONTRACT, encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Fix the lint.", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return agent, prompt, repo


def test_cli_delegate_identity_refuses_contract_tools_outside_scope(tmp_path: Path) -> None:
    agent, prompt, repo = _delegate_cli_inputs(tmp_path)
    scope = _scope_file(tmp_path, tools=["read"])
    proc = _run_cli(
        [
            "delegate",
            "--contract",
            str(agent),
            "--task",
            "lint_fix",
            "--prompt-file",
            str(prompt),
            "--identity",
            str(scope),
            "--lock-dir",
            str(tmp_path / "locks"),
            "--repo-dir",
            str(repo),
            "--",
            sys.executable,
            "-c",
            "open('ran.txt', 'w').write('x')",
        ],
        "",
    )
    assert proc.returncode == 1, proc.stderr
    assert "outside the identity scope" in proc.stderr
    assert not (repo / "ran.txt").exists(), "refused delegation still ran the junior"


def test_cli_delegate_identity_admits_in_scope_and_attributes(tmp_path: Path) -> None:
    agent, prompt, repo = _delegate_cli_inputs(tmp_path)
    scope = _scope_file(tmp_path, tools=["bash", "read"])
    proc = _run_cli(
        [
            "delegate",
            "--contract",
            str(agent),
            "--task",
            "lint_fix",
            "--prompt-file",
            str(prompt),
            "--identity",
            str(scope),
            "--verify-command",
            "true",
            "--lock-dir",
            str(tmp_path / "locks"),
            "--repo-dir",
            str(repo),
            "--",
            sys.executable,
            "-c",
            "import sys; open('note.txt', 'w').write('x'); sys.stdout.write(sys.stdin.read())",
        ],
        "",
    )
    assert proc.returncode == 0, proc.stderr
    lines = _cli_lines(proc)
    assert lines[-1]["state"] == "complete"
    audit_path = tmp_path / "locks" / "audit.jsonl"
    audit_text = audit_path.read_text(encoding="utf-8")
    assert USER not in audit_text, "raw user id leaked into the delegation audit log"
    started = [
        json.loads(line)
        for line in audit_text.splitlines()
        if json.loads(line)["kind"] == "delegation_started"
    ]
    assert len(started) == 1
    expected_token = (
        IdentityVault()
        .issue_context(
            PermissionScope.from_mapping(
                {"user_id": USER, "servers": ["default"], "tools": ["bash", "read"]}
            )
        )
        .audit_token
    )
    assert started[0]["detail"]["identity"] == expected_token
