"""Identity propagation (rat #70): the agent acts with the user's
permissions, never a super-key.

Source: Perplexity Cato lecture transcript (catalog B-34) — INSPIRED.
The lecture's Identity Twin: the user connects with their OWN
permissions to company systems; connectors, skills, knowledge base,
guard rails, and tools are separate components; each user gets a
private workspace; a router directs agent-initiated communication to
that workspace; the gateway is where the agent runs; a managed vault
refreshes credentials.

What this module is (and is not):
- A permission SCOPE the deployment's identity provider issues for one
  user: which servers, which tools, until when. This library ENFORCES
  the scope; it does not AUTHENTICATE the user (no OAuth / JWT / mTLS
  here — same declared-identity boundary as the gateway's trust levels:
  the harness supplies an authenticated scope, this module makes sure
  no call escapes it).
- A CREDENTIAL HANDLE: a reference to a per-user grant, never a key.
  Handles carry no secret material — there is nothing in this module
  to steal, and no shared super-key exists anywhere in the path: the
  vault has no method that mints a credential for more than one user,
  and a handle is bound by fingerprint to exactly one user + one scope.
  Using a handle for another user or a widened scope is refused.
- A CONTEXT the gateway and lifecycle bind to a session: every call
  through an identity-bound gateway is checked (expiry, revocation,
  tool membership) and audited under a one-way hash token for the user,
  so every agent action is attributable to a user permission scope
  without the raw user id ever reaching a log.

Guard rails stay separate from the executor by construction: this
module decides scope membership; ``gateway.py`` executes; the scanner
and fuzzer never import identity. A scope with no tools allows no
tool; a scope with no servers allows no server — deny by default.

Deliberate boundaries (not hidden):
- Revocation is enforced live only when the context carries its vault
  (``IdentityVault.issue_context`` binds it). A context built by hand
  without a vault enforces expiry + membership structurally, but a
  revoke issued after binding is invisible to it until the next bind.
  The gateway CLI always binds through the vault.
- Server names match EXACTLY (the registry is the authority, case
  sensitive); tool names match normalized (strip + lower, the same rule
  as the delegation contract's tool lists — MCP tool names are free
  text, registry names are operator data).
- Scope expiry is wall-clock UTC. The vault does not refresh
  credentials (the lecture's cron refresh is a deployment concern);
  an expired scope refuses until the deployment re-issues it.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

__all__ = [
    "CredentialError",
    "CredentialHandle",
    "IdentityContext",
    "IdentityError",
    "IdentityVault",
    "PermissionScope",
    "ScopeDeniedError",
    "ScopeExpiredError",
]

# Fingerprint domain separator: a scope fingerprint must never collide
# with an unrelated hash of the same fields elsewhere in the codebase.
_FINGERPRINT_DOMAIN = "mcp-guard-identity-scope-v1"
_AUDIT_TOKEN_DOMAIN = "mcp-guard-identity-user-v1"  # nosec B105 - domain separator, not a credential
_VAULT_FILE_VERSION = 1


class IdentityError(Exception):
    """Base class for identity failures (fail-closed, never silent)."""


class ScopeDeniedError(IdentityError):
    """The identity's scope does not cover this tool or server."""

    def __init__(self, what: str, name: str) -> None:
        self.what = what
        self.name = name
        super().__init__(f"{what} {name!r} is outside the identity scope")


class ScopeExpiredError(IdentityError):
    """The identity's scope (or its credential) has expired."""

    def __init__(self, expires_at: datetime) -> None:
        self.expires_at = expires_at
        super().__init__(f"identity scope expired at {expires_at.isoformat()}")


class CredentialError(IdentityError):
    """The credential handle is unknown, revoked, or bound to another
    scope. The message never carries secret material (handles carry
    none) or the raw user id."""


def _normalize_tool(name: str) -> str:
    """Tool names match normalized: strip + lower.

    Same rule as the delegation contract's tool lists (delegation.py):
    MCP tool names are caller-supplied free text, so " Delete_Record "
    must not slip past a scope that grants "delete_record".
    """
    return name.strip().lower()


def _normalize_server(name: str) -> str:
    """Server names match exactly apart from surrounding whitespace.

    Registry names are operator data, case sensitive: "Default" is not
    "default". Only whitespace is stripped, so a padded name cannot
    silently miss its registry entry.
    """
    return name.strip()


def _parse_expires_at(raw: object) -> datetime | None:
    """Parse an expires_at value from a mapping: None stays None, a
    string must be an ISO-8601 timestamp WITH a timezone. A naive
    timestamp raises ValueError: comparing it against aware UTC time
    would fail later as TypeError, so the shape is refused at parse
    time instead. Any other type raises TypeError."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise TypeError(f"expires_at must be an ISO-8601 string or null, got {raw!r}")
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise ValueError("expires_at must carry a timezone (e.g. '2026-11-08T00:00:00Z')")
    return parsed


@dataclass(frozen=True)
class PermissionScope:
    """One user's permission scope: which servers, which tools, until when.

    Empty ``tools`` allows no tool; empty ``servers`` allows no server.
    The scope is frozen: once issued, its grant cannot be widened by
    mutation — a new scope must be issued instead.
    """

    user_id: str
    servers: frozenset[str] = field(default_factory=frozenset)
    tools: frozenset[str] = field(default_factory=frozenset)
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.user_id, str) or not self.user_id.strip():
            raise ValueError("scope user_id must be a non-empty string")
        if not isinstance(self.servers, frozenset):
            raise TypeError("scope servers must be a frozenset of names")
        if not isinstance(self.tools, frozenset):
            raise TypeError("scope tools must be a frozenset of names")
        for name in self.servers:
            if not isinstance(name, str) or not name:
                raise ValueError("scope server names must be non-empty strings")
        for name in self.tools:
            if not isinstance(name, str) or not name:
                raise ValueError("scope tool names must be non-empty strings")
        if self.expires_at is not None and not isinstance(self.expires_at, datetime):
            raise TypeError("scope expires_at must be a datetime or None")

    def allows_tool(self, tool_name: str) -> bool:
        """True when the (normalized) tool is in this scope's grant."""
        if not isinstance(tool_name, str):
            raise TypeError("tool_name must be a string")
        return _normalize_tool(tool_name) in self.tools

    def allows_server(self, server_name: str) -> bool:
        """True when the (exact, case-sensitive) server is in this scope."""
        if not isinstance(server_name, str):
            raise TypeError("server_name must be a string")
        return _normalize_server(server_name) in self.servers

    def is_expired(self, now: datetime | None = None) -> bool:
        """True when the scope has an expiry at or before ``now``."""
        if self.expires_at is None:
            return False
        moment = now if now is not None else datetime.now(UTC)
        return moment >= self.expires_at

    def fingerprint(self) -> str:
        """One-way binding of user + servers + tools + expiry.

        Canonical JSON (sorted keys, sorted sets) so two scopes built
        in different insertion orders fingerprint identically — the
        fingerprint is the scope's identity, not its construction.
        """
        canonical = {
            "user_id": self.user_id,
            "servers": sorted(self.servers),
            "tools": sorted(self.tools),
            "expires_at": self.expires_at.isoformat() if self.expires_at is not None else None,
        }
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{_FINGERPRINT_DOMAIN}:{payload}".encode()).hexdigest()

    def to_mapping(self) -> dict[str, object]:
        """Round-trip mapping (what from_mapping consumes)."""
        data: dict[str, object] = {
            "user_id": self.user_id,
            "servers": sorted(self.servers),
            "tools": sorted(self.tools),
        }
        if self.expires_at is not None:
            data["expires_at"] = self.expires_at.isoformat()
        return data

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> PermissionScope:
        """Parse a scope file mapping.

        Wrong shapes fail closed (TypeError); unknown keys are REJECTED
        (ValueError) — a typo'd scope key must never silently narrow or
        widen a grant, and a scope file is a security boundary, not a
        forward-compatible config. ``user_id`` is required; ``servers``
        / ``tools`` default to empty (deny-by-default); ``expires_at``
        is optional.
        """
        if not isinstance(data, dict):
            raise TypeError("permission scope must be a JSON object")
        known = {"user_id", "servers", "tools", "expires_at"}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(f"permission scope has unknown keys: {unknown}")
        user_id = data.get("user_id")
        if user_id is None:
            raise ValueError("permission scope 'user_id' is required")
        if not isinstance(user_id, str):
            raise TypeError("permission scope 'user_id' must be a string")
        if not user_id.strip():
            raise ValueError("permission scope 'user_id' must be a non-empty string")
        servers_data = data.get("servers", [])
        if not isinstance(servers_data, list) or any(
            not isinstance(name, str) for name in servers_data
        ):
            raise TypeError("permission scope 'servers' must be a list of strings")
        tools_data = data.get("tools", [])
        if not isinstance(tools_data, list) or any(
            not isinstance(name, str) for name in tools_data
        ):
            raise TypeError("permission scope 'tools' must be a list of strings")
        servers = frozenset(_normalize_server(name) for name in servers_data)
        if any(not name for name in servers):
            raise ValueError("permission scope 'servers' entries must be non-empty")
        tools = frozenset(_normalize_tool(name) for name in tools_data)
        if any(not name for name in tools):
            raise ValueError("permission scope 'tools' entries must be non-empty")
        return cls(
            user_id=user_id.strip(),
            servers=servers,
            tools=tools,
            expires_at=_parse_expires_at(data.get("expires_at")),
        )


@dataclass(frozen=True)
class CredentialHandle:
    """A reference to one per-user grant — never a key.

    The handle binds one user to one scope fingerprint. It carries no
    secret material, so it is safe to persist (the vault file holds
    handles only) and safe to audit. ``expires_at`` mirrors the scope
    it was issued for; a handle outlives its scope only on paper —
    checks refuse it either way.
    """

    handle_id: str
    user_id: str
    scope_fingerprint: str
    issued_at: datetime
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.handle_id, str) or not self.handle_id:
            raise ValueError("handle_id must be a non-empty string")
        if not isinstance(self.user_id, str) or not self.user_id:
            raise ValueError("handle user_id must be a non-empty string")
        if not isinstance(self.scope_fingerprint, str) or not self.scope_fingerprint:
            raise ValueError("handle scope_fingerprint must be a non-empty string")
        if not isinstance(self.issued_at, datetime):
            raise TypeError("handle issued_at must be a datetime")
        if self.expires_at is not None and not isinstance(self.expires_at, datetime):
            raise TypeError("handle expires_at must be a datetime or None")

    def is_expired(self, now: datetime | None = None) -> bool:
        """True when the handle has an expiry at or before ``now``."""
        if self.expires_at is None:
            return False
        moment = now if now is not None else datetime.now(UTC)
        return moment >= self.expires_at

    def to_mapping(self) -> dict[str, object]:
        """Round-trip mapping (what from_mapping consumes)."""
        data: dict[str, object] = {
            "handle_id": self.handle_id,
            "user_id": self.user_id,
            "scope_fingerprint": self.scope_fingerprint,
            "issued_at": self.issued_at.isoformat(),
        }
        if self.expires_at is not None:
            data["expires_at"] = self.expires_at.isoformat()
        return data

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> CredentialHandle:
        """Parse a persisted handle mapping. Unknown keys are rejected:
        a handle file is a security record, not a forward-compatible
        config — extra fields must never smuggle a wider grant."""
        if not isinstance(data, dict):
            raise TypeError("credential handle must be a JSON object")
        known = {"handle_id", "user_id", "scope_fingerprint", "issued_at", "expires_at"}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(f"credential handle has unknown keys: {unknown}")
        handle_id = data.get("handle_id")
        if not isinstance(handle_id, str) or not handle_id:
            raise ValueError("credential handle 'handle_id' must be a non-empty string")
        user_id = data.get("user_id")
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("credential handle 'user_id' must be a non-empty string")
        fingerprint = data.get("scope_fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError("credential handle 'scope_fingerprint' must be a non-empty string")
        issued_raw = data.get("issued_at")
        if not isinstance(issued_raw, str):
            raise TypeError("credential handle 'issued_at' must be an ISO-8601 string")
        issued_at = datetime.fromisoformat(issued_raw)
        if issued_at.tzinfo is None:
            raise ValueError("credential handle 'issued_at' must carry a timezone")
        return cls(
            handle_id=handle_id,
            user_id=user_id,
            scope_fingerprint=fingerprint,
            issued_at=issued_at,
            expires_at=_parse_expires_at(data.get("expires_at")),
        )


@dataclass(frozen=True)
class IdentityContext:
    """A bound identity for one session: scope + credential handle.

    Constructed by ``IdentityVault.issue_context`` (which also binds
    the vault, so revocation is enforced live) or directly for tests.
    The constructor validates structural consistency — user match,
    fingerprint match, credential unexpired — so a mismatched pair can
    never be bound by accident. ``check_call`` / ``check_server`` are
    the enforcement points the gateway and lifecycle call before any
    send.
    """

    scope: PermissionScope
    credential: CredentialHandle
    vault: IdentityVault | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scope, PermissionScope):
            raise TypeError("identity scope must be a PermissionScope")
        if not isinstance(self.credential, CredentialHandle):
            raise TypeError("identity credential must be a CredentialHandle")
        if self.credential.user_id != self.scope.user_id:
            raise CredentialError("credential handle belongs to a different user")
        if self.credential.scope_fingerprint != self.scope.fingerprint():
            raise CredentialError("credential handle is bound to a different scope")
        if self.credential.is_expired():
            raise ScopeExpiredError(self.credential.expires_at or datetime.now(UTC))

    @property
    def audit_token(self) -> str:
        """One-way attribution token for the audit log.

        A truncated sha256 of the user id under a domain separator:
        stable across sessions so one user's actions correlate in SIEM,
        irreversible without the user list, and the raw user id never
        reaches any log. (Per-session pseudonyms would hide the very
        attribution the issue demands.)
        """
        digest = hashlib.sha256(f"{_AUDIT_TOKEN_DOMAIN}:{self.scope.user_id}".encode()).hexdigest()
        return f"user-{digest[:16]}"

    def check_handle(self, now: datetime | None = None) -> None:
        """Re-validate the handle against its vault (revocation, live).

        A context without a vault skips this: structural checks ran at
        construction, but a revoke issued after binding is invisible
        until the next bind. The gateway CLI always binds through the
        vault, so its sessions enforce revocation on every call.
        """
        if self.vault is not None:
            self.vault.check(self.credential, self.scope, now)

    def check_call(self, tool_name: str, now: datetime | None = None) -> None:
        """Enforce the scope for one tool call, before any send.

        Order: expiry, then handle validity (revocation), then tool
        membership. A refused call raises; an allowed call returns
        silently — the gateway's trust check still runs after this.
        """
        if self.scope.is_expired(now):
            raise ScopeExpiredError(self.scope.expires_at or datetime.now(UTC))
        if self.credential.is_expired(now):
            raise ScopeExpiredError(self.credential.expires_at or datetime.now(UTC))
        self.check_handle(now)
        if not self.scope.allows_tool(tool_name):
            raise ScopeDeniedError("tool", tool_name)

    def check_server(self, server_name: str, now: datetime | None = None) -> None:
        """Enforce the scope for one server enablement, before any start."""
        if self.scope.is_expired(now):
            raise ScopeExpiredError(self.scope.expires_at or datetime.now(UTC))
        if self.credential.is_expired(now):
            raise ScopeExpiredError(self.credential.expires_at or datetime.now(UTC))
        self.check_handle(now)
        if not self.scope.allows_server(server_name):
            raise ScopeDeniedError("server", server_name)


class IdentityVault:
    """Per-user credential store: issues handles, never keys.

    There is deliberately NO method that mints a credential for more
    than one user, no default scope, and no shared handle: a super-key
    is unrepresentable in this API, not merely discouraged. Handles are
    kept in memory; ``save`` / ``load`` persist handles only (no secret
    material exists to persist) with the file mode locked to 0600 on POSIX.
    """

    def __init__(self) -> None:
        self._handles: dict[str, CredentialHandle] = {}
        self._revoked: set[str] = set()

    def __len__(self) -> int:
        return len(self._handles)

    def issue(
        self, user_id: str, scope: PermissionScope, now: datetime | None = None
    ) -> CredentialHandle:
        """Mint a handle binding ``user_id`` to ``scope``.

        Refuses a scope issued for another user (CredentialError) and
        an expired scope (ScopeExpiredError): the vault never mints a
        handle for a grant the user does not hold.
        """
        if not isinstance(user_id, str) or not user_id:
            raise CredentialError("user_id must be a non-empty string")
        if not isinstance(scope, PermissionScope):
            raise TypeError("scope must be a PermissionScope")
        if scope.user_id != user_id:
            raise CredentialError("scope belongs to a different user")
        moment = now if now is not None else datetime.now(UTC)
        if scope.is_expired(moment):
            raise ScopeExpiredError(scope.expires_at or moment)
        handle = CredentialHandle(
            handle_id=uuid.uuid4().hex,
            user_id=user_id,
            scope_fingerprint=scope.fingerprint(),
            issued_at=moment,
            expires_at=scope.expires_at,
        )
        self._handles[handle.handle_id] = handle
        return handle

    def issue_context(self, scope: PermissionScope, now: datetime | None = None) -> IdentityContext:
        """Mint a handle AND return the bound session context (vault
        attached, so revocation is enforced live on every call)."""
        handle = self.issue(scope.user_id, scope, now)
        return IdentityContext(scope=scope, credential=handle, vault=self)

    def check(
        self, handle: CredentialHandle, scope: PermissionScope, now: datetime | None = None
    ) -> None:
        """Validate a handle against a scope: known, unrevoked, same
        user, same fingerprint, unexpired. Any failure raises; a valid
        handle returns silently."""
        if not isinstance(handle, CredentialHandle):
            raise TypeError("handle must be a CredentialHandle")
        if not isinstance(scope, PermissionScope):
            raise TypeError("scope must be a PermissionScope")
        known = self._handles.get(handle.handle_id)
        if known is None:
            raise CredentialError("unknown credential handle")
        if handle.handle_id in self._revoked:
            raise CredentialError("credential handle has been revoked")
        if known.user_id != scope.user_id or handle.user_id != scope.user_id:
            raise CredentialError("credential handle belongs to a different user")
        if known.scope_fingerprint != scope.fingerprint():
            raise CredentialError("credential handle is bound to a different scope")
        moment = now if now is not None else datetime.now(UTC)
        if handle.is_expired(moment) or scope.is_expired(moment):
            raise ScopeExpiredError(scope.expires_at or handle.expires_at or moment)

    def revoke(self, handle_id: str) -> None:
        """Revoke a handle: every later check refuses it. Revoking an
        unknown id raises — a revoke for a handle that was never issued
        is a caller bug, not a no-op."""
        if not isinstance(handle_id, str) or not handle_id:
            raise CredentialError("handle_id must be a non-empty string")
        if handle_id not in self._handles:
            raise CredentialError("unknown credential handle")
        self._revoked.add(handle_id)

    def handles_for(self, user_id: str) -> tuple[CredentialHandle, ...]:
        """All live (issued, whether or not revoked) handles for a user,
        in handle-id order for determinism."""
        if not isinstance(user_id, str):
            raise TypeError("user_id must be a string")
        return tuple(
            sorted(
                (h for h in self._handles.values() if h.user_id == user_id),
                key=lambda h: h.handle_id,
            )
        )

    def save(self, path: str | Path) -> None:
        """Persist handles + revocations as JSON. Handles carry no secret
        material. The file is created mode 0600 (owner only) on POSIX: a vault
        file other users can read would leak the handle inventory. Windows
        has no POSIX permission bits, so the mode argument is best-effort
        there."""
        target = Path(path)
        payload = {
            "version": _VAULT_FILE_VERSION,
            "handles": [h.to_mapping() for h in self.handles_for_all()],
            "revoked": sorted(self._revoked),
        }
        text = json.dumps(payload, sort_keys=True, indent=2)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        # os.fdopen takes ownership of the fd: it closes on context exit,
        # including on a write error, so no separate close is needed.
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)

    def handles_for_all(self) -> tuple[CredentialHandle, ...]:
        """All issued handles, in handle-id order for determinism."""
        return tuple(sorted(self._handles.values(), key=lambda h: h.handle_id))

    @classmethod
    def load(cls, path: str | Path) -> IdentityVault:
        """Load a vault file written by ``save``. Wrong version,
        malformed shapes, and unknown keys are refused — a tampered
        vault file must never silently resurrect a revoked handle or
        widen a grant."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError("vault file must be a JSON object")
        if set(data) - {"version", "handles", "revoked"}:
            raise ValueError(
                f"vault file has unknown keys: {sorted(set(data) - {'version', 'handles', 'revoked'})}"
            )
        if data.get("version") != _VAULT_FILE_VERSION:
            raise ValueError(f"unsupported vault file version: {data.get('version')!r}")
        handles_data = data.get("handles", [])
        if not isinstance(handles_data, list):
            raise TypeError("vault file 'handles' must be a list")
        revoked_data = data.get("revoked", [])
        if not isinstance(revoked_data, list) or any(
            not isinstance(item, str) for item in revoked_data
        ):
            raise TypeError("vault file 'revoked' must be a list of strings")
        vault = cls()
        for item in handles_data:
            handle = CredentialHandle.from_mapping(item)
            vault._handles[handle.handle_id] = handle
        for handle_id in revoked_data:
            if handle_id not in vault._handles:
                raise CredentialError("vault file revokes an unknown handle")
            vault._revoked.add(handle_id)
        return vault
