"""Deterministic intake normalization: schema-gated entry (rat #76).

Source: ch.3 "Controlling Text-Only LLM Behavior at Inference Time"
(Drive file 1cLNvdiAfD5J, section on input validation and intake
policies) — ADAPTATION. Established: schema validation + deterministic
normalization in API design. Adaptation: intake-as-gate wired into the
agent entry path (``Gateway.call_tool``) with an explicit truncation
policy and a structured fallback.

The intake is the request as the gateway receives it: a tool name, its
arguments, and operator-declared metadata. Before any model or server
sees the input, :func:`normalize_input` either returns a canonical
``NormalizedIntake`` (sorted keys, over-long strings truncated with a
visible marker) or an ``IntakeFailure`` carrying a stable error code.
On failure the gateway returns :func:`structured_fallback` and the
transport is never called — zero malformed inputs reach the model.

Two honest-scope notes, stated here and in the spec section rather than
claimed away:

- "Calibrated against the serving tokenizer" (the issue's phrase): no
  model/serving tokenizer exists in this repo — the PII tokenizer
  tokenizes PII spans, it is not a serving tokenizer. Truncation
  budgets are therefore in CHARACTERS, not tokens: head/tail apply
  per string value by Python ``len()`` (code points), and only
  ``max_arguments_chars`` is measured on the canonical JSON text.
  The numbers below are this unit's calibration, pinned by the
  :data:`CALIBRATION` sets — the set, not the number, is the evidence.
  "Byte-deterministic" means byte-identical across runs (sorted keys,
  fixed budgets, no randomness), not byte-counted budgets — and it
  holds only because the gate refuses text that cannot be encoded to
  bytes at all (a lone surrogate fails as ``INTAKE_NON_JSON_VALUE``).
- "Locale" (the issue's example of pipeline-critical metadata): no
  locale substrate exists anywhere in the repo. It is mapped to
  operator-declared ``IntakePolicy.required_metadata`` (e.g.
  ``"locale"``), supplied per call as ``metadata`` and threaded
  CLI request -> lifecycle -> gateway. It is never invented as a
  built-in field.

Live consumers (a module with zero production consumers is dead
surface): ``Gateway.call_tool`` runs ``normalize_input`` first on every
call with well-typed caller parameters (before the identity check, the
trust check, and the rule of two), records an ``INTAKE`` audit event on
every such call (outcome ok/fail + policy tag + error code +
truncation flags — never content, never metadata values), and returns
the structured fallback on failure. The CLI ``gateway`` subcommand
passes a request's ``"metadata"`` object through, and ``mcp-guard
intake`` is the direct offline audit surface.

Deliberate boundaries (not hidden):
- ``caller_trust`` / ``input_trust`` / ``approval`` stay typed
  parameters of ``call_tool``: a wrong type still raises ``TypeError``
  (the existing contract), before intake runs — so "outcome logged on
  every request" holds for every call that reaches intake, not for a
  programming error that never becomes a request. The intake schema
  covers the REQUEST (tool / arguments / metadata); the
  identity-bound requirement is ``IntakePolicy.require_identity`` —
  when True, a gateway with no identity bound fails intake with
  ``INTAKE_MISSING_IDENTITY``. A bound-but-expired identity passes
  intake and then raises ``ScopeExpiredError`` under #70's raise-based
  identity contract: the split verdict is coherent, and the two
  outcomes are not the same check. A wrong-type caller is a
  programming error, not a malformed request.
- Truncation applies to request string VALUES only, never to keys or
  the tool name (an over-cap name fails, it is not silently renamed)
  and never to the tool RESULT (results reach the model through the
  #72 inbound scan, untouched).
- Control characters are checked only in the tool name. Control
  characters in argument values and keys are valid JSON strings, are
  JSON-escaped on the wire, and pass the gate (argument values never
  appear in the audit log at all): values are the server's problem,
  names are the gate's. The
  truncated-field paths embed raw key text, so a key containing ``.``
  or ``[`` makes a path ambiguous (``"a.b"`` as one key vs nested
  ``a`` -> ``b``) — cosmetic, paths are diagnostics, never lookups.
- Metadata shape is presence-only: a required-metadata value is
  checked for presence as a non-empty string, never walked,
  canonicalized, or surrogate-checked. That is safe by construction:
  metadata values are never forwarded to the transport (only the tool
  name and arguments are sent) and never logged, so an unencodable
  metadata value cannot reach the server or the log — it is out of
  scope for this gate, not an oversight.
- No Unicode canonicalization: composed and decomposed forms of the
  same text normalize differently, and truncation can split a
  grapheme cluster. Unicode-level normalization is #72's job (the
  issue's own duplicate note assigns it there); this gate checks the
  schema and the text's encodability, not its canonical form.
- The fallback dict's marker key (``mcp_guard_intake``) could in
  principle collide with a real server result shape; the authoritative
  signal is the ``INTAKE`` audit event with outcome "fail", which a
  real result never carries. The CLI gateway session marks a fallback
  line with ``"fallback": true`` plus the top-level ``error_code``,
  so a consumer need not parse the result body to tell a fallback
  from a result.

Evidence levels: schema-gating and deterministic normalization are
established API-design practice; the policy shape, the error-code set,
and every budget below are adaptation, calibrated by the in-module
false-positive sets.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from .transport import JsonDict

# Budgets are this unit's calibration (adaptation), not paper numbers and
# not tokenizer measurements: the repo has no serving tokenizer. They
# are tunable through IntakePolicy and pinned by the CALIBRATION sets.
# Module-level constants are not registry-tracked defaults.
_DEFAULT_TAG = "intake-v1"
_DEFAULT_HEAD_CHARS = 1536
_DEFAULT_TAIL_CHARS = 512
_DEFAULT_MARKER = "[TRUNCATED]"
_DEFAULT_MAX_ARGUMENTS_CHARS = 65536
_DEFAULT_MAX_DEPTH = 32
_DEFAULT_MAX_TOOL_NAME_CHARS = 256


class IntakeErrorCode(str, Enum):
    """Stable intake-failure codes — the fallback's routable identity.

    Codes name the schema rule that failed, never the offending value:
    a code is safe to log, route, and audit; the value is not.
    """

    INVALID_TOOL = "INTAKE_INVALID_TOOL"
    INVALID_ARGUMENTS = "INTAKE_INVALID_ARGUMENTS"
    NON_JSON_VALUE = "INTAKE_NON_JSON_VALUE"
    TOO_LARGE = "INTAKE_TOO_LARGE"
    MISSING_METADATA = "INTAKE_MISSING_METADATA"
    MISSING_IDENTITY = "INTAKE_MISSING_IDENTITY"


@dataclass(frozen=True)
class IntakePolicy:
    """Deployment policy for deterministic intake normalization.

    ``tag`` is the policy version carried on every outcome (ok and
    fail), so intake drift is debuggable: two logs with different tags
    were normalized under different policies. ``head_chars`` /
    ``tail_chars`` are the explicit truncation budget: a string longer
    than head + tail becomes head + ``marker`` + tail. ``marker`` is the
    visible truncation signal inside the truncated value itself.
    ``max_arguments_chars`` bounds the canonical JSON length of the
    whole arguments mapping (per-string truncation alone cannot bound
    arg count or total size). ``max_depth`` bounds argument nesting.
    ``max_tool_name_chars`` bounds the tool name (over-cap names fail,
    they are not renamed). ``require_identity`` makes a bound identity
    (rat #70) a required intake field: when True and the gateway has no
    identity bound, intake fails — the identity-bound requirement.
    There is no "tier" concept in #70's identity model (scope +
    credential + vault), so this gates on presence of a bound identity
    only; a bound-but-expired identity passes intake and then raises
    under #70's contract.
    ``required_metadata`` names the operator-declared pipeline-critical
    metadata fields (e.g. ``"locale"``): every call must carry each one
    as a non-empty string, or intake fails. The shipped default is
    empty, so existing callers change nothing except the shape checks.
    """

    tag: str = _DEFAULT_TAG
    head_chars: int = _DEFAULT_HEAD_CHARS
    tail_chars: int = _DEFAULT_TAIL_CHARS
    marker: str = _DEFAULT_MARKER
    max_arguments_chars: int = _DEFAULT_MAX_ARGUMENTS_CHARS
    max_depth: int = _DEFAULT_MAX_DEPTH
    max_tool_name_chars: int = _DEFAULT_MAX_TOOL_NAME_CHARS
    require_identity: bool = False
    required_metadata: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.tag, str) or not self.tag.strip():
            raise ValueError("intake policy tag must be a non-empty string")
        if isinstance(self.head_chars, bool) or not isinstance(self.head_chars, int):
            raise TypeError("intake policy head_chars must be an integer")
        if isinstance(self.tail_chars, bool) or not isinstance(self.tail_chars, int):
            raise TypeError("intake policy tail_chars must be an integer")
        if self.head_chars < 0 or self.tail_chars < 0:
            raise ValueError("intake policy head_chars and tail_chars must be >= 0")
        if self.head_chars + self.tail_chars < 1:
            raise ValueError("intake policy head_chars + tail_chars must be >= 1")
        if not isinstance(self.marker, str) or not self.marker:
            raise ValueError("intake policy marker must be a non-empty string")
        if isinstance(self.max_arguments_chars, bool) or not isinstance(
            self.max_arguments_chars, int
        ):
            raise TypeError("intake policy max_arguments_chars must be an integer")
        if self.max_arguments_chars < 1:
            raise ValueError("intake policy max_arguments_chars must be >= 1")
        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int):
            raise TypeError("intake policy max_depth must be an integer")
        if self.max_depth < 1:
            raise ValueError("intake policy max_depth must be >= 1")
        if isinstance(self.max_tool_name_chars, bool) or not isinstance(
            self.max_tool_name_chars, int
        ):
            raise TypeError("intake policy max_tool_name_chars must be an integer")
        if self.max_tool_name_chars < 1:
            raise ValueError("intake policy max_tool_name_chars must be >= 1")
        if not isinstance(self.require_identity, bool):
            raise TypeError("intake policy require_identity must be a bool")
        if not isinstance(self.required_metadata, tuple) or any(
            not isinstance(name, str) or not name.strip() for name in self.required_metadata
        ):
            raise ValueError("intake policy required_metadata must be a tuple of non-empty strings")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> IntakePolicy:
        """Parse a policy-file ``intake`` mapping.

        Wrong shapes fail closed (TypeError); out-of-range budgets fail
        closed (ValueError); unknown keys are ignored so policy files
        stay forward-compatible. Absent keys take the defaults above.
        """
        if not isinstance(data, Mapping):
            raise TypeError("intake policy must be an object")
        tag_raw = data.get("tag", _DEFAULT_TAG)
        if not isinstance(tag_raw, str):
            raise TypeError("intake policy 'tag' must be a string")
        head_raw = data.get("head_chars", _DEFAULT_HEAD_CHARS)
        if isinstance(head_raw, bool) or not isinstance(head_raw, int):
            raise TypeError("intake policy 'head_chars' must be an integer")
        tail_raw = data.get("tail_chars", _DEFAULT_TAIL_CHARS)
        if isinstance(tail_raw, bool) or not isinstance(tail_raw, int):
            raise TypeError("intake policy 'tail_chars' must be an integer")
        marker_raw = data.get("marker", _DEFAULT_MARKER)
        if not isinstance(marker_raw, str):
            raise TypeError("intake policy 'marker' must be a string")
        max_args_raw = data.get("max_arguments_chars", _DEFAULT_MAX_ARGUMENTS_CHARS)
        if isinstance(max_args_raw, bool) or not isinstance(max_args_raw, int):
            raise TypeError("intake policy 'max_arguments_chars' must be an integer")
        max_depth_raw = data.get("max_depth", _DEFAULT_MAX_DEPTH)
        if isinstance(max_depth_raw, bool) or not isinstance(max_depth_raw, int):
            raise TypeError("intake policy 'max_depth' must be an integer")
        max_tool_raw = data.get("max_tool_name_chars", _DEFAULT_MAX_TOOL_NAME_CHARS)
        if isinstance(max_tool_raw, bool) or not isinstance(max_tool_raw, int):
            raise TypeError("intake policy 'max_tool_name_chars' must be an integer")
        require_raw = data.get("require_identity", False)
        if not isinstance(require_raw, bool):
            raise TypeError("intake policy 'require_identity' must be a bool")
        required: tuple[str, ...] = ()
        if "required_metadata" in data:
            raw_list = data["required_metadata"]
            if not isinstance(raw_list, list) or any(
                not isinstance(item, str) for item in raw_list
            ):
                raise TypeError("intake policy 'required_metadata' must be a list of strings")
            required = tuple(item.strip() for item in raw_list)
        return cls(
            tag=tag_raw,
            head_chars=head_raw,
            tail_chars=tail_raw,
            marker=marker_raw,
            max_arguments_chars=max_args_raw,
            max_depth=max_depth_raw,
            max_tool_name_chars=max_tool_raw,
            require_identity=require_raw,
            required_metadata=required,
        )


@dataclass(frozen=True)
class NormalizedIntake:
    """A request that passed the intake gate, in canonical form.

    ``arguments`` has sorted keys and truncated string values (the
    marker sits inside any truncated value). ``truncated_fields`` are
    the key paths (``a.b[0]``) whose values were truncated — paths,
    never values. ``policy_tag`` names the policy that normalized it.
    """

    tool_name: str
    arguments: JsonDict
    policy_tag: str
    truncated: bool = False
    truncated_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class IntakeFailure:
    """A request the intake gate refused, with its stable error code.

    ``detail`` names the schema rule that failed (e.g. which metadata
    key is missing) — field names only, never values.
    """

    error_code: IntakeErrorCode
    policy_tag: str
    detail: str


def structured_fallback(failure: IntakeFailure) -> JsonDict:
    """The structured fallback a schema failure returns instead of a call.

    Stable error code + policy tag under the namespaced
    ``mcp_guard_intake`` key: loggable, routable, auditable — and the
    transport is never called, so no generation path can see the
    malformed input.
    """
    return {
        "mcp_guard_intake": {
            "status": "fallback",
            "error_code": failure.error_code.value,
            "policy_tag": failure.policy_tag,
        }
    }


def _truncate(value: str, policy: IntakePolicy) -> str:
    """Head + marker + tail, or the value unchanged when it fits."""
    budget = policy.head_chars + policy.tail_chars
    if len(value) <= budget:
        return value
    return value[: policy.head_chars] + policy.marker + value[len(value) - policy.tail_chars :]


def _canonical_json(value: object) -> str:
    """Canonical JSON text: sorted keys, no NaN/Infinity, ASCII kept.

    Raises ``ValueError`` / ``TypeError`` on non-JSON values; callers
    map those to ``INTAKE_NON_JSON_VALUE``. The UTF-8 encode is a
    belt-and-braces check: a lone surrogate passes ``json.dumps`` but
    cannot be encoded to bytes, so the canonical form is only bytes
    when the input is valid Unicode scalar text.
    """
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    text.encode("utf-8")
    return text


def _has_lone_surrogate(text: str) -> bool:
    """True when the text holds a surrogate code point (U+D800–U+DFFF).

    A lone surrogate is not a valid Unicode scalar value and is not
    representable in UTF-8 bytes: ``json.dumps`` accepts it, but the
    canonical form cannot be encoded, so the gate must refuse it
    rather than pass it to the transport.
    """
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


class _Reject(Exception):
    """Internal control flow: the walk hit a schema rule."""

    def __init__(self, code: IntakeErrorCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def _walk(
    raw: object, path: str, depth: int, policy: IntakePolicy, truncated_fields: list[str]
) -> object:
    """Normalize one argument value (recursive, depth-capped at 32).

    Strings truncate in place; mappings rebuild with sorted keys;
    lists/tuples rebuild as lists, preserving order; JSON scalars pass
    through; anything else raises ``_Reject``. The recursion depth is
    bounded by ``max_depth`` (default 32), far below the interpreter
    limit, so a hostile nesting depth fails as a schema error instead
    of a ``RecursionError``.
    """
    if depth > policy.max_depth:
        raise _Reject(IntakeErrorCode.INVALID_ARGUMENTS, "arguments exceed max_depth")
    if isinstance(raw, str):
        if _has_lone_surrogate(raw):
            raise _Reject(IntakeErrorCode.NON_JSON_VALUE, f"lone surrogate in string at {path}")
        value = _truncate(raw, policy)
        if len(raw) > policy.head_chars + policy.tail_chars:
            truncated_fields.append(path)
        return value
    if isinstance(raw, Mapping):
        normalized: dict[str, object] = {}
        for key in sorted(raw.keys(), key=str):
            if not isinstance(key, str) or not key:
                raise _Reject(IntakeErrorCode.INVALID_ARGUMENTS, "arguments holds a non-string key")
            if _has_lone_surrogate(key):
                raise _Reject(IntakeErrorCode.NON_JSON_VALUE, f"lone surrogate in key at {path}")
            normalized[key] = _walk(raw[key], f"{path}.{key}", depth + 1, policy, truncated_fields)
        return normalized
    if isinstance(raw, (list, tuple)):
        return [
            _walk(item, f"{path}[{index}]", depth + 1, policy, truncated_fields)
            for index, item in enumerate(raw)
        ]
    if raw is None or isinstance(raw, (bool, int, float)):
        return raw
    raise _Reject(IntakeErrorCode.NON_JSON_VALUE, f"non-JSON value at {path}")


def normalize_input(
    tool_name: object,
    arguments: object,
    *,
    policy: IntakePolicy | None = None,
    metadata: Mapping[str, object] | None = None,
    identity_bound: bool = False,
) -> NormalizedIntake | IntakeFailure:
    """Schema-gate one intake request, deterministically.

    Pure function: same input twice yields the same outcome, byte for
    byte (sorted keys, fixed budgets, no randomness, no I/O). Checks
    run in a fixed order so a request failing two rules always reports
    the same code: tool name, arguments shape, JSON-serializability,
    total size, required metadata, identity requirement. Truncation is
    applied during the argument walk to every string value longer than
    head + tail.
    """
    effective_policy = policy if policy is not None else IntakePolicy()
    tag = effective_policy.tag
    # (1) Tool name: a non-empty string after strip, bounded, no NUL or
    # control characters. A blank name is malformed input, not a call.
    if not isinstance(tool_name, str):
        return IntakeFailure(IntakeErrorCode.INVALID_TOOL, tag, "tool name is not a string")
    name = tool_name.strip()
    if not name:
        return IntakeFailure(IntakeErrorCode.INVALID_TOOL, tag, "tool name is empty")
    if len(name) > effective_policy.max_tool_name_chars:
        return IntakeFailure(
            IntakeErrorCode.INVALID_TOOL, tag, "tool name exceeds max_tool_name_chars"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return IntakeFailure(
            IntakeErrorCode.INVALID_TOOL, tag, "tool name holds control characters"
        )
    if _has_lone_surrogate(name):
        return IntakeFailure(
            IntakeErrorCode.NON_JSON_VALUE, tag, "tool name holds a lone surrogate"
        )
    # (2) Arguments shape: a mapping with non-empty string keys, walked
    # with a depth cap so a deeply nested input cannot RecursionError
    # its way past the gate.
    if not isinstance(arguments, Mapping):
        return IntakeFailure(IntakeErrorCode.INVALID_ARGUMENTS, tag, "arguments is not an object")
    truncated_fields: list[str] = []
    try:
        normalized: JsonDict = {
            key: _walk(arguments[key], key, 2, effective_policy, truncated_fields)
            for key in sorted(arguments.keys(), key=str)
            if isinstance(key, str) and key
        }
        if len(normalized) != len(arguments):
            return IntakeFailure(
                IntakeErrorCode.INVALID_ARGUMENTS, tag, "arguments holds a non-string key"
            )
    except _Reject as e:
        return IntakeFailure(e.code, tag, e.detail)
    # (3) JSON-serializability of the normalized form (NaN/Infinity are
    # not JSON: allow_nan=False refuses them here, not at the server).
    try:
        canonical = _canonical_json(normalized)
    except (ValueError, TypeError, RecursionError):
        return IntakeFailure(
            IntakeErrorCode.NON_JSON_VALUE, tag, "arguments are not JSON-serializable"
        )
    # (4) Total size: the canonical text is the bounded artifact.
    if len(canonical) > effective_policy.max_arguments_chars:
        return IntakeFailure(IntakeErrorCode.TOO_LARGE, tag, "arguments exceed max_arguments_chars")
    # (5) Required metadata: each declared field must be present as a
    # non-empty string. Values are never inspected beyond that shape —
    # and never recorded anywhere. A metadata value that is not an
    # object at all is malformed, whatever the policy declares.
    if metadata is not None and not isinstance(metadata, Mapping):
        return IntakeFailure(IntakeErrorCode.INVALID_ARGUMENTS, tag, "metadata is not an object")
    if effective_policy.required_metadata:
        if not isinstance(metadata, Mapping):
            return IntakeFailure(
                IntakeErrorCode.MISSING_METADATA,
                tag,
                f"missing metadata field {effective_policy.required_metadata[0]}",
            )
        for name_field in effective_policy.required_metadata:
            value = metadata.get(name_field)
            if not isinstance(value, str) or not value.strip():
                return IntakeFailure(
                    IntakeErrorCode.MISSING_METADATA,
                    tag,
                    f"missing metadata field {name_field}",
                )
    # (6) Identity requirement: the identity-bound requirement.
    if effective_policy.require_identity and not identity_bound:
        return IntakeFailure(
            IntakeErrorCode.MISSING_IDENTITY, tag, "no identity bound to the gateway"
        )
    return NormalizedIntake(
        tool_name=name,
        arguments=normalized,
        policy_tag=tag,
        truncated=bool(truncated_fields),
        truncated_fields=tuple(sorted(truncated_fields)),
    )


#: Calibration sets (adaptation): each adversarial case must fail with
#: its stable code, each benign case must pass. The tests assert every
#: case's expected verdict — the set, not the budget number, is the
#: evidence. Fixtures use example.com / 555 numbers so no real personal
#: data appears anywhere. A case is (name, tool_name, arguments, kwargs,
#: expected error code or None for pass).
CALIBRATION: tuple[tuple[str, object, object, dict[str, object], str | None], ...] = (
    ("blank-tool", "   ", {}, {}, "INTAKE_INVALID_TOOL"),
    ("non-string-tool", 42, {}, {}, "INTAKE_INVALID_TOOL"),
    ("nul-in-tool", "read\x00file", {}, {}, "INTAKE_INVALID_TOOL"),
    ("arguments-not-mapping", "read", ["a", "b"], {}, "INTAKE_INVALID_ARGUMENTS"),
    ("non-string-arg-key", "read", {1: "x"}, {}, "INTAKE_INVALID_ARGUMENTS"),
    ("bytes-value", "read", {"data": b"\x00\x01"}, {}, "INTAKE_NON_JSON_VALUE"),
    ("set-value", "read", {"data": {1, 2}}, {}, "INTAKE_NON_JSON_VALUE"),
    ("nan-value", "read", {"x": float("nan")}, {}, "INTAKE_NON_JSON_VALUE"),
    ("inf-value", "read", {"x": float("inf")}, {}, "INTAKE_NON_JSON_VALUE"),
    ("lone-surrogate-value", "read", {"x": "\ud800"}, {}, "INTAKE_NON_JSON_VALUE"),
    ("lone-surrogate-tool", "re\ud800ad", {}, {}, "INTAKE_NON_JSON_VALUE"),
    (
        "lone-surrogate-nested",
        "read",
        {"a": {"b": ["ok", "\udfff"]}},
        {},
        "INTAKE_NON_JSON_VALUE",
    ),
    ("lone-surrogate-key", "read", {"\ud800": "x"}, {}, "INTAKE_NON_JSON_VALUE"),
    (
        "too-large",
        "read",
        {f"field_{i:04d}": "x" * 100 for i in range(700)},
        {},
        "INTAKE_TOO_LARGE",
    ),
    (
        "missing-locale",
        "read",
        {"path": "notes.txt"},
        {"policy": IntakePolicy(required_metadata=("locale",))},
        "INTAKE_MISSING_METADATA",
    ),
    (
        "missing-identity",
        "read",
        {"path": "notes.txt"},
        {"policy": IntakePolicy(require_identity=True)},
        "INTAKE_MISSING_IDENTITY",
    ),
    ("clean-call", "read", {"path": "notes.txt"}, {}, None),
    ("clean-with-locale", "read", {"path": "notes.txt"}, {"metadata": {"locale": "en-US"}}, None),
    (
        "long-clean-string",
        "read",
        {"text": "a" * 3000},
        {},
        None,
    ),
    ("nested-clean", "read", {"a": {"b": [1, 2, {"c": "x"}]}}, {}, None),
)
