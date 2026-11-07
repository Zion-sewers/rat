"""RED: docs/ARCHITECTURE.md must stay true to the implementation.

mcp-guard#23 asks for an architecture document with sequence diagrams, aligned
with the code. The first version (PR #21) covered the five sections, but
several descriptions drifted from the implementation: the classifier gained
canary-reflection, exfil-channel and evidence-graded default findings, and the
issue explicitly demands sequence diagrams for handshake, fuzz AND scan. These
tests fail CI on any doc/code divergence — the doc is verified against the
code in both directions for everything the code owns (counts via live
generators and, for the no-schema case, via a stub-transport fuzz_tool run;
rule ids via scanner.py AST; CLI flags via cli.py AST; dataclass fields).
The literals 29/37/9/24 are the doc's own table values, asserted equal to the
code — never the other way round.
"""

from __future__ import annotations

import ast
import re
import tomllib
from dataclasses import fields
from pathlib import Path

import pytest

from mcp_guard import payloads
from mcp_guard.fuzzer import FuzzEngine
from mcp_guard.payloads import generate_all_for_param

REPO_ROOT = Path(__file__).resolve().parent.parent
ARCHITECTURE = REPO_ROOT / "docs" / "ARCHITECTURE.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"
SRC = REPO_ROOT / "src" / "mcp_guard"


def _doc() -> str:
    return ARCHITECTURE.read_text(encoding="utf-8")


def _mermaid_blocks(text: str) -> list[str]:
    return re.findall(r"```mermaid\n(.*?)```", text, re.DOTALL)


def _sequence_diagrams(text: str) -> list[str]:
    return [b for b in _mermaid_blocks(text) if "sequenceDiagram" in b]


def _source(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


class _NullTransport:
    """Stub transport: accepts every payload, leaks nothing."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"content": [{"type": "text", "text": "ok"}]}

    def last_exchange(self) -> tuple[dict | None, object]:
        """Flight recorder: exact envelope of the last call + its response id."""
        if not self.calls:
            return None, None
        last = self.calls[-1]
        return (
            {
                "jsonrpc": "2.0",
                "id": len(self.calls),
                "method": "tools/call",
                "params": {"name": last["tool"], "arguments": last["arguments"]},
            },
            len(self.calls),
        )


# --- Issue #23's demanded sections -------------------------------------------

REQUIRED_SECTIONS = [
    "## Transport Layer",
    "## Fuzzing Engine",
    "## Scanner Pipeline",
    "## Report Generation",
    "## CLI Interface",
]


@pytest.mark.parametrize("heading", REQUIRED_SECTIONS)
def test_demanded_sections_present(heading: str) -> None:
    assert heading in _doc(), f"missing section demanded by mcp-guard#23: {heading}"


def test_sequence_diagrams_for_handshake_fuzz_and_scan() -> None:
    """#23 demands sequence diagrams for handshake, fuzz and scan flows."""
    diagrams = _sequence_diagrams(_doc())
    assert len(diagrams) >= 2, "need at least two sequence diagrams"
    joined = "\n".join(diagrams)
    assert "initialize" in joined, "no handshake sequence diagram"
    assert "fuzz_tool" in joined, "no fuzzing sequence diagram"
    assert "scan_tool" in joined, "no static-scan sequence diagram"


# --- Payload counts: doc table vs live generators -----------------------------


def _counts_table() -> dict[str, int]:
    rows: dict[str, int] = {}
    for m in re.finditer(r"^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|$", _doc(), re.MULTILINE):
        rows[m.group(1).strip()] = int(m.group(2))
    return rows


def test_payload_counts_match_live_generators() -> None:
    """The per-input-type table must equal the real generator output."""
    table = _counts_table()
    assert table["String parameter"] == len(generate_all_for_param("q", {"type": "string"})) == 29
    assert (
        table["URI-typed string parameter"]
        == len(generate_all_for_param("url", {"type": "string", "format": "uri"}))
        == 37
    )
    assert (
        table["Integer / number parameter"]
        == len(generate_all_for_param("n", {"type": "integer"}))
        == 9
    )
    # No-schema: through the real firing path, not a re-typed formula — a
    # composition change in _fuzz_no_schema must break this test.
    assert (
        table["No input schema"]
        == len(FuzzEngine(transport=_NullTransport()).fuzz_tool({"name": "t"}))
        == 24
    )


# --- Transport facts -----------------------------------------------------------


def test_handshake_version_and_client_info() -> None:
    """Protocol version and client info must match the live transport."""
    doc = _doc()
    transport_src = _source("transport.py")
    proto = "2024-11-05"
    assert proto in transport_src
    assert proto in doc, "doc does not state the real protocol version"
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    version = project["version"]
    assert f'"version": "{version}"' in transport_src.replace("'", '"')
    assert version in doc, "doc client-info version drifted from pyproject.toml"
    assert "notifications/initialized" in doc
    assert "notifications/initialized" in transport_src


def test_transport_error_semantics_documented() -> None:
    """Doc's error-handling bullets must be true of the code."""
    doc = _doc()
    for term in ("ConnectionError", "RuntimeError", "TimeoutError"):
        assert term in doc, f"doc omits {term} from transport error handling"
        assert term in _source("transport.py")


# --- Classifier: code mechanisms described in the doc ---------------------------


def test_classifier_mechanisms_described() -> None:
    """Canary reflection, exfil channel and evidence-graded default are real
    code paths — the doc must describe all of them, not just the v1 tiers."""
    doc = _doc()
    for mechanism in (
        "INDIRECT_CANARY",
        "EchoLeak",
        "unconfirmed-reflection",
        "no-observable-effect",
        "never SAFE",
    ):
        assert mechanism in doc, f"doc omits classifier mechanism: {mechanism}"


def test_scanner_rule_ids_match_code() -> None:
    """Every rule id emitted by Scanner must appear in the doc's rules table."""
    tree = ast.parse(_source("scanner.py"))
    rule_ids = {
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword)
        and node.arg == "rule_id"
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    assert rule_ids, "could not extract rule ids from scanner.py"
    doc = _doc()
    for rule_id in rule_ids:
        assert rule_id in doc, f"scanner rule id not documented: {rule_id}"


# --- CLI: options and exit codes -------------------------------------------------


def _cli_option_names() -> set[str]:
    tree = ast.parse(_source("cli.py"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.add(node.args[0].value)
    return names


def _cli_exit_codes() -> set[int]:
    tree = ast.parse(_source("cli.py"))
    codes: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "exit"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, int)
        ):
            codes.add(node.args[0].value)
    return codes


def test_cli_options_documented() -> None:
    """Every --flag the parser accepts must be named in the doc."""
    doc = _doc()
    options = _cli_option_names()
    assert options, "could not extract argparse options from cli.py"
    for opt in options:
        if not opt.startswith("--"):
            continue  # positional arguments, documented by prose
        assert opt in doc, f"CLI option not documented: {opt}"


def test_cli_exit_codes_documented() -> None:
    """sys.exit codes in cli.py must match the doc's exit-code table."""
    doc = _doc()
    codes = _cli_exit_codes()
    assert codes == {1, 2}, f"unexpected exit codes in cli.py: {codes}"
    for code in codes | {0}:
        assert f"`{code}`" in doc, f"exit code {code} not in doc's table"


# --- Data model: doc code blocks vs live dataclasses ------------------------------


def test_data_model_fields_match_dataclasses() -> None:
    """The doc's dataclass listings must name the real fields, all of them."""
    doc = _doc()
    import mcp_guard.fuzzer
    import mcp_guard.scanner

    for cls, mod in (
        ("FuzzResult", mcp_guard.fuzzer),
        ("ScanResult", mcp_guard.scanner),
        ("Payload", payloads),
    ):
        for f in fields(getattr(mod, cls)):
            assert re.search(rf"^\s*{f.name}\s*:", doc, re.MULTILINE), (
                f"doc omits dataclass field {cls}.{f.name}"
            )


def test_report_provenance_and_verify_counts_documented() -> None:
    """Load-bearing report mechanisms must be described in the doc."""
    doc = _doc()
    assert "_provenance" in doc, "doc omits the provenance block"
    assert "verify_counts" in doc, "doc omits count verification"
    report_src = _source("report.py")
    assert "_provenance" in report_src and "verify_counts" in report_src


def test_no_placeholder_language() -> None:
    """A mature architecture doc must not ship TODO/FIXME/XXX stubs."""
    for marker in ("TODO", "FIXME", "XXX", "TBD"):
        assert marker not in _doc(), f"doc contains placeholder marker: {marker}"
