"""CI gate for the defaults registry (mcp-guard#96).

Scans src/mcp_guard via AST for default-like constructs and asserts:
  1. coverage: every construct found in code is registered;
  2. no orphans: every registry entry still exists in code;
  3. value match: registered values match the code (flipping a default
     without updating its registry entry fails);
  4. rationale: every entry carries a non-placeholder rationale.

Key derivation (must match defaults_registry.py):
  cli:{receiver}:{flag}       add_argument, e.g. cli:fuzz_parser:--format
  {module}:{scope}:{key}      .get(key[, default]), e.g. fuzzer:fuzz_tool:name
  {module}:{scope}:param:{a}  signature default, e.g. transport:...:param:timeout
  {module}:{scope}:except:{E} except handler, e.g. cli:_run_fuzz:except:Exception
scope is func or Class.method. Non-constant .get keys use ~unparsed-expr.

Scope decisions (deliberate, documented):
  - `= None` signature defaults are NOT tracked: None means "absent", and the
    real fallback (if any) lives in the body where the AST cannot see it
    reliably. Tracking them would be theater.
  - Plain module-level constants (e.g. _DEFAULT_MAX_TURNS, _MAX_TURNS_LIMIT,
    _SUMMARY_OUTPUT_LIMIT) are NOT tracked: the scanner covers only the four
    construct kinds above, so a constant no scanned construct reads needs no
    entry. Registering one by hand would fail the no-orphans check, by design.
  - argparse `nargs=REMAINDER` without an explicit default is likewise out of
    scope (implicit None, same reason).
  - `action="store_true"` / `"store_false"` ARE tracked (as False / True):
    they are real behavioral defaults.
  - `pyproject.toml` was audited (2026-10-11) and contains no behavioral
    defaults: it holds build metadata, entry points, and linter/test/type
    config — none of which are nudges in the issue's sense
    (default-allow/deny, fallback values, timeout verdicts). All 45
    registered defaults live in Python code, which is what the AST scans.
"""

from __future__ import annotations

import ast
from pathlib import Path

from mcp_guard.defaults_registry import BY_ID

SRC = Path(__file__).resolve().parent.parent / "src" / "mcp_guard"


def _val_repr(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Name):
        return node.id
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001 - unparse is best-effort
        return "?"


class _Extractor(ast.NodeVisitor):
    """Collect (key, kind, value) triples for default-like constructs."""

    def __init__(self, module: str) -> None:
        self.module = module
        self.class_name: str | None = None
        self.func_name: str | None = None
        self.found: list[tuple[str, str, str]] = []

    def _scope(self) -> str:
        if self.class_name and self.func_name:
            return f"{self.class_name}.{self.func_name}"
        return self.func_name or "<module>"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old, self.class_name = self.class_name, node.name
        self.generic_visit(node)
        self.class_name = old

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        old, self.func_name = self.func_name, node.name
        # signature defaults, excluding None ("absent" sentinel, see docstring)
        args = node.args
        defaults = args.defaults
        positional = args.args[-len(defaults) :] if defaults else []
        for arg, d in zip(positional, defaults):
            if isinstance(d, ast.Constant) and d.value is None:
                continue
            key = f"{self.module}:{self._scope()}:param:{arg.arg}"
            self.found.append((key, "param-default", _val_repr(d)))
        # kwonly defaults
        for arg, d in zip(args.kwonlyargs, args.kw_defaults):
            if d is None:
                continue
            if isinstance(d, ast.Constant) and d.value is None:
                continue
            key = f"{self.module}:{self._scope()}:param:{arg.arg}"
            self.found.append((key, "param-default", _val_repr(d)))
        self.generic_visit(node)
        self.func_name = old

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if isinstance(f, ast.Attribute):
            if f.attr == "add_argument":
                self._add_argument(node)
            elif f.attr == "get":
                self._dict_get(node)
        self.generic_visit(node)

    def _add_argument(self, node: ast.Call) -> None:
        recv = (
            node.func.value.id
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
            else "?"
        )
        flag = "?"
        for a in node.args:
            if (
                isinstance(a, ast.Constant)
                and isinstance(a.value, str)
                and a.value.startswith("--")
            ):
                flag = a.value
                break
        if flag == "?" and node.args and isinstance(node.args[0], ast.Constant):
            flag = str(node.args[0].value)
        key = f"{self.module}:{recv}:{flag}"
        default: str | None = None
        action: str | None = None
        for kw in node.keywords:
            if kw.arg == "default":
                default = _val_repr(kw.value)
            elif kw.arg == "action" and isinstance(kw.value, ast.Constant):
                action = str(kw.value.value)
        if default is not None:
            self.found.append((key, "cli-default", default))
        elif action == "store_true":
            self.found.append((key, "cli-default", "False"))
        elif action == "store_false":
            self.found.append((key, "cli-default", "True"))

    def _dict_get(self, node: ast.Call) -> None:
        if not node.args:
            return
        k = node.args[0]
        if isinstance(k, ast.Constant):
            keypart = str(k.value)
        else:
            try:
                keypart = "~" + ast.unparse(k)[:30]
            except Exception:  # noqa: BLE001 - unparse is best-effort
                keypart = "~?"
        default = _val_repr(node.args[1]) if len(node.args) >= 2 else "None"
        key = f"{self.module}:{self._scope()}:{keypart}"
        self.found.append((key, "dict-fallback", default))

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        exc = ast.unparse(node.type) if node.type else "bare"
        key = f"{self.module}:{self._scope()}:except:{exc}"
        self.found.append((key, "except-path", exc))
        self.generic_visit(node)


def _scan_all() -> dict[str, tuple[str, str]]:
    """Map key -> (kind, value) for every default-like construct in src."""
    out: dict[str, tuple[str, str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "defaults_registry.py":
            continue  # the registry describes the code; it is not the code
        ext = _Extractor(path.stem)
        ext.visit(ast.parse(path.read_text(), filename=str(path)))
        for key, kind, value in ext.found:
            # A repeated identical construct (e.g. tool.get("name","unknown")
            # twice in one function) is one default, not two.
            if key in out:
                assert out[key] == (kind, value), (
                    f"conflicting {key}: {out[key]} vs {(kind, value)}"
                )
            out[key] = (kind, value)
    return out


def test_registry_covers_all_code_defaults():
    """Every default-like construct in code must be registered."""
    code = _scan_all()
    missing = sorted(set(code) - set(BY_ID))
    assert not missing, (
        "Undeclared defaults found — add each to defaults_registry.py with a "
        "rationale:\n" + "\n".join(f"  {k} ({code[k][0]} = {code[k][1]})" for k in missing)
    )


def test_registry_has_no_orphans():
    """Every registry entry must still exist in code (nothing stale)."""
    code = _scan_all()
    orphans = sorted(set(BY_ID) - set(code))
    assert not orphans, (
        "Registry entries with no matching code — remove or fix them:\n"
        + "\n".join(f"  {k}" for k in orphans)
    )


def test_registry_values_match_code():
    """A flipped default without a registry update fails."""
    code = _scan_all()
    mismatches = []
    for key, entry in BY_ID.items():
        if key in code and code[key][1] != entry.value:
            mismatches.append(
                f"  {key}: registry says {entry.value!r}, code has {code[key][1]!r} "
                f"— update the registry entry (value AND rationale)"
            )
    assert not mismatches, "Default values drifted from the registry:\n" + "\n".join(mismatches)


def test_registry_kinds_match_code():
    """Registry kind labels must agree with the construct kind found."""
    code = _scan_all()
    mismatches = [
        f"  {k}: registry={BY_ID[k].kind}, code={code[k][0]}"
        for k in BY_ID
        if k in code and BY_ID[k].kind != code[k][0]
    ]
    assert not mismatches, "Kind labels drifted:\n" + "\n".join(mismatches)


def test_every_entry_has_rationale():
    """No placeholder rationales — the registry is documentation."""
    bad = [
        d.id
        for d in BY_ID.values()
        if not d.rationale or len(d.rationale.strip()) < 20 or "TODO" in d.rationale
    ]
    assert not bad, f"Entries with missing/placeholder rationale: {bad}"
