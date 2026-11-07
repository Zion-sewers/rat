"""RED: LEADERBOARD.md methodology must match the payload generators.

mcp-guard#12 stayed open for six weeks because the documented payload counts
drifted from the code: generate_indirect_injection() added 4 probes per string
parameter (2026-09-26) and nobody updated the methodology section. These tests
fail CI on any generator change that is not carried into LEADERBOARD.md, and
on any leaderboard edit that is not true of the code — the doc is verified in
both directions. Code and doc are the only two sources of numbers here; the
tests themselves assert equality between them and hold no independent
literals.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest

from mcp_guard.fuzzer import FuzzEngine
from mcp_guard.payloads import (
    Payload,
    Severity,
    generate_all_for_param,
    generate_indirect_injection,
    generate_overflow,
    generate_prompt_injection,
    generate_shell_injection,
    generate_ssrf,
    generate_type_confusion,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
LEADERBOARD = REPO_ROOT / "LEADERBOARD.md"


def _section(text: str, start: str, end: str) -> str:
    """Extract the markdown between two section headings (end exclusive)."""
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


def _two_col_rows(section: str) -> dict[str, int]:
    """Map label -> count for exactly-two-column markdown table rows."""
    rows: dict[str, int] = {}
    for m in re.finditer(r"^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*$", section, re.MULTILINE):
        rows[m.group(1).strip()] = int(m.group(2))
    return rows


def _severity_table(section: str) -> dict[str, int]:
    """Map severity -> weight from the three-column severity table."""
    rows: dict[str, int] = {}
    for m in re.finditer(r"^\|\s*([A-Z]+)\s*\|\s*(\d+)\s*\|[^|]*\|\s*$", section, re.MULTILINE):
        rows[m.group(1).strip()] = int(m.group(2))
    return rows


def _bullet_class_counts(section: str) -> dict[str, int]:
    """Map payload class label -> documented count from the §1 string bullet.

    Parses only the string-parameter breakdown line:
      - String parameters receive shell injection (8), prompt injection (6), ...
    """
    counts: dict[str, int] = {}
    for line in section.splitlines():
        if not line.startswith("- String parameters receive"):
            continue
        items = line.removeprefix("- String parameters receive ").strip()
        for item in re.split(r",\s*(?:and\s+)?", items):
            m = re.fullmatch(r"(.+?)\s*\((\d+)\)\.?", item.strip())
            if m:
                counts[m.group(1).strip()] = int(m.group(2))
    return counts


@pytest.fixture(scope="module")
def doc() -> str:
    assert LEADERBOARD.exists(), "LEADERBOARD.md missing at repo root"
    return LEADERBOARD.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def counts_section(doc: str) -> str:
    return _section(doc, "### 1. Payload Counting", "### 2. Severity Levels")


@pytest.fixture(scope="module")
def severity_section(doc: str) -> str:
    return _section(doc, "### 2. Severity Levels", "### 3. Benchmarking")


# label -> generator expression for the §1 string-parameter breakdown bullets
STRING_CLASS_GENERATORS = {
    "shell injection": lambda: len(generate_shell_injection()),
    "prompt injection": lambda: len(generate_prompt_injection()),
    "indirect-injection probes": lambda: len(generate_indirect_injection()),
    "overflow subset": lambda: len(generate_overflow()[:3]),
    "type confusion": lambda: len(generate_type_confusion("string")),
}


class TestPayloadCountsMatchGenerators:
    """The §1 table is derived from payloads.py, not hand-written."""

    def test_string_parameter_count(self, counts_section: str) -> None:
        documented = _two_col_rows(counts_section)["String parameter"]
        actual = len(generate_all_for_param("name", {"type": "string"}))
        assert actual == documented, (
            f"LEADERBOARD.md says {documented} payloads per string parameter, "
            f"generators produce {actual} — update the doc or the generators"
        )

    def test_string_breakdown_classes_match_generators(self, counts_section: str) -> None:
        """Each documented payload class equals its live generator.

        Names which class drifted, without hard-coding any count in the test:
        both sides of every comparison come from code (generator) or doc.
        """
        bullets = _bullet_class_counts(counts_section)
        for label, count_of in STRING_CLASS_GENERATORS.items():
            assert label in bullets, (
                f"§1 breakdown no longer documents '{label}' — doc and generators have drifted"
            )
            actual = count_of()
            assert bullets[label] == actual, (
                f"doc says {label} contributes {bullets[label]} payloads, "
                f"generator produces {actual}"
            )
        assert sum(count_of() for count_of in STRING_CLASS_GENERATORS.values()) == len(
            generate_all_for_param("name", {"type": "string"})
        )

    def test_uri_string_parameter_count(self, counts_section: str) -> None:
        documented = _two_col_rows(counts_section)["URI-typed string parameter"]
        actual = len(generate_all_for_param("url", {"type": "string", "format": "uri"}))
        assert actual == documented
        assert actual == len(generate_ssrf()) + len(
            generate_all_for_param("name", {"type": "string"})
        )

    def test_integer_parameter_count(self, counts_section: str) -> None:
        documented = _two_col_rows(counts_section)["Integer / number parameter"]
        actual = len(generate_all_for_param("count", {"type": "integer"}))
        assert actual == documented

    def test_no_schema_count(self, counts_section: str) -> None:
        """Drive the real FuzzEngine path so the count can't be hand-rolled."""

        class StubTransport:
            def __init__(self) -> None:
                self.calls: list[dict] = []

            def call_tool(self, tool_name: str, arguments: dict) -> dict:
                self.calls.append({"tool": tool_name, "arguments": arguments})
                return {"isError": True, "content": []}

            def last_exchange(self) -> tuple[dict | None, object]:
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

        engine = FuzzEngine(transport=StubTransport())
        results = engine.fuzz_tool({"name": "no_schema_tool", "inputSchema": {}})
        documented = _two_col_rows(counts_section)["No input schema"]
        assert len(results) == documented


class TestSeverityTableMatchesEnum:
    """Every Severity enum member — including INFO — has a documented weight."""

    def test_all_enum_members_documented(self, severity_section: str) -> None:
        documented = _severity_table(severity_section)
        enum_members = {s.name for s in Severity}
        assert set(documented) == enum_members, (
            f"doc severities {set(documented)} != code enum {enum_members}"
        )

    def test_info_weight_is_zero(self, severity_section: str) -> None:
        # mcp-guard#12 names INFO=0 explicitly as a requirement.
        assert _severity_table(severity_section)["INFO"] == 0

    def test_weights_monotone(self, severity_section: str) -> None:
        w = _severity_table(severity_section)
        assert w["CRITICAL"] > w["HIGH"] > w["MEDIUM"] > w["LOW"] > w["INFO"]


class TestVersionAlignment:
    """mcp-guard#12: the leaderboard header version must equal pyproject's."""

    def test_header_version_matches_pyproject(self, doc: str) -> None:
        import tomllib

        with open(REPO_ROOT / "pyproject.toml", "rb") as f:
            pyproject = tomllib.load(f)
        expected = pyproject["project"]["version"]
        m = re.search(r"\*\*mcp-guard version:\s*([\d.]+)\*\*", doc)
        assert m, "leaderboard header has no mcp-guard version line"
        assert m.group(1) == expected, (
            f"leaderboard says {m.group(1)}, pyproject.toml says {expected}"
        )

    def test_payload_ruleset_version_matches_code(self, doc: str) -> None:
        from mcp_guard.payloads import PAYLOAD_SET_VERSION

        m = re.search(r"\*\*Payload ruleset version:\s*(\d+)\*\*", doc)
        assert m, "leaderboard header has no payload ruleset version line"
        assert m.group(1) == PAYLOAD_SET_VERSION


class TestLegacyRowsAnnotated:
    """The pre-verification rankings rows must not ride under the stamp."""

    def test_rankings_carry_provenance_caveat(self, doc: str) -> None:
        rankings = _section(doc, "## Rankings", "## Key Findings")
        assert "2026-06-03" in rankings, "rankings lost their production date"
        assert "re-run" in rankings, (
            "rankings rows lack the not-re-run caveat — the methodology stamp "
            "would overclaim coverage of legacy rows"
        )


README = REPO_ROOT / "README.md"
SPEC = REPO_ROOT / "docs" / "spec.md"
BLOG = REPO_ROOT / "docs" / "blog.html"

# Canonical inventory of payload-family generators, keyed by module function
# name. Every family-count/coverage test below derives from this registry, and
# test_family_registry_complete enforces it stays in sync with
# mcp_guard.payloads — so a new generate_* family breaks CI with a naming
# message instead of silently going undocumented.
FAMILY_GENERATORS: dict[str, Callable[[], list[Payload]]] = {
    "generate_shell_injection": generate_shell_injection,
    "generate_ssrf": generate_ssrf,
    "generate_overflow": generate_overflow,
    "generate_type_confusion": lambda: generate_type_confusion("string"),
    "generate_prompt_injection": generate_prompt_injection,
    "generate_indirect_injection": generate_indirect_injection,
}


def _family_rule_ids() -> set[str]:
    """rule_ids of every registered family — derived, never literal."""
    return {FAMILY_GENERATORS[name]()[0].rule_id for name in FAMILY_GENERATORS}


def _taxonomy_sections(spec_text: str) -> dict[str, str]:
    """Map rule_id -> section text for every '### Name (`rule_id`)' block
    under ## Payload Taxonomy."""
    taxonomy = _section(spec_text, "## Payload Taxonomy", "## Severity Classification")
    sections: dict[str, str] = {}
    matches = list(re.finditer(r"^### .+?\(`([^`]+)`\)", taxonomy, re.MULTILINE))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(taxonomy)
        # doc headings use underscores (shell_injection); code rule_ids use
        # hyphens (shell-injection) — normalize so the two meet
        sections[m.group(1).replace("_", "-")] = taxonomy[start:end]
    return sections


def _table_data_rows(section: str) -> list[list[str]]:
    """Split markdown table data rows (skip header + separator)."""
    rows: list[list[str]] = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells and cells[0] == "#":
            continue
        if cells and set(cells[0]) <= {"-", ":"}:
            continue
        if cells and cells[0].isdigit():
            rows.append(cells)
    return rows


def _taxonomy_raw_lines(section: str) -> list[str]:
    """Raw data lines of a taxonomy table (same row selection as
    _table_data_rows, unparsed — for pipe-tolerant column access)."""
    lines: list[str] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if cells and cells[0].isdigit():
            lines.append(stripped)
    return lines


def _doc_payload_text(cell: str) -> str:
    """Doc cells wrap payloads in backticks; string payloads carry an extra
    pair of double quotes by doc convention — neither is wire content."""
    return cell.strip().strip("`").strip('"')


class TestPayloadDocSync:
    """mcp-guard#13: README.md, docs/spec.md and docs/blog.html payload claims
    must track the generators the same way LEADERBOARD.md does.

    #12 fixed the leaderboard, but the README still said 25/33, the blog
    said 35/35, and the spec taxonomy was missing the indirect-injection
    family entirely (plus a non-verbatim prompt-injection payload). Every
    number here is parsed from a doc and compared against a generator —
    the tests hold no independent literals.
    """

    @pytest.fixture(scope="class")
    def readme(self) -> str:
        return README.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def spec(self) -> str:
        return SPEC.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def blog(self) -> str:
        return BLOG.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def no_schema_n(self) -> int:
        class StubTransport:
            def __init__(self) -> None:
                self.calls: list[dict] = []

            def call_tool(self, tool_name: str, arguments: dict) -> dict:
                self.calls.append({"tool": tool_name, "arguments": arguments})
                return {"isError": True, "content": []}

            def last_exchange(self) -> tuple[dict | None, object]:
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

        engine = FuzzEngine(transport=StubTransport())
        results = engine.fuzz_tool({"name": "no_schema_tool", "inputSchema": {}})
        return len(results)

    # ---- README.md ----

    def test_readme_what_it_does_counts(self, readme: str) -> None:
        m = re.search(
            r"Fires up to \*\*(\d+) payloads per string parameter\*\* "
            r"\((\d+) for URI-typed",
            readme,
        )
        assert m, "README 'What It Does' lost its payload-count sentence"
        assert int(m.group(1)) == len(generate_all_for_param("name", {"type": "string"}))
        assert int(m.group(2)) == len(
            generate_all_for_param("url", {"type": "string", "format": "uri"})
        )

    def test_readme_methodology_table(self, readme: str, no_schema_n: int) -> None:
        section = _section(readme, "## Methodology", "## License")
        rows = _two_col_rows(section)
        assert rows["String parameter"] == len(generate_all_for_param("name", {"type": "string"}))
        assert rows["URI-typed string parameter"] == len(
            generate_all_for_param("url", {"type": "string", "format": "uri"})
        )
        assert rows["Integer / number parameter"] == len(
            generate_all_for_param("count", {"type": "integer"})
        )
        assert rows["No input schema"] == no_schema_n

    def test_readme_probe_table_family_count(self, readme: str) -> None:
        m = re.search(r"### (\d+) Probe Types", readme)
        assert m, "README lost its probe-types section"
        section = _section(readme, m.group(0), "Payloads are schema-aware")
        # probe table rows are keyed by bold probe names, not digits
        data_rows = [line for line in section.splitlines() if line.strip().startswith("| **")]
        # six generator families: shell, ssrf, overflow, type-confusion,
        # prompt-injection, indirect-injection — derived, not literal:
        n_families = len(_family_rule_ids())
        assert int(m.group(1)) == n_families, (
            f"README heading says {m.group(1)} probe types, generators define {n_families} families"
        )
        assert len(data_rows) == n_families, (
            f"README probe table has {len(data_rows)} rows, generators define "
            f"{n_families} families — a family is undocumented"
        )

    # ---- docs/spec.md ----

    def test_family_registry_complete(self) -> None:
        """Every generate_* in mcp_guard.payloads is in FAMILY_GENERATORS.

        This is the choke point: a new payload family added to the module
        without registry + docs breaks here, naming the unregistered
        generator. generate_all_for_param is the dispatcher, not a family.
        """
        import mcp_guard.payloads as payloads_mod

        module_gens = {
            name
            for name, obj in vars(payloads_mod).items()
            if name.startswith("generate_") and callable(obj)
        } - {"generate_all_for_param"}
        unregistered = module_gens - set(FAMILY_GENERATORS)
        assert not unregistered, (
            f"payloads.py defines unregistered generator(s) "
            f"{sorted(unregistered)} — add to FAMILY_GENERATORS and document "
            f"the family, or the doc-sync tests go stale"
        )
        stale = set(FAMILY_GENERATORS) - module_gens
        assert not stale, f"FAMILY_GENERATORS names removed generator(s) {sorted(stale)}"

    def test_spec_probe_summary_table_family_count(self, spec: str) -> None:
        """The '### Fuzz Probes (v1)' summary table must list every family.

        #13's implementation review caught this table still enumerating 5
        probes after the taxonomy gained its 6th — this test pins it."""
        section = _section(spec, "### Fuzz Probes (v1)", "### Payload Intelligence")
        data_rows = [line for line in section.splitlines() if line.strip().startswith("| **")]
        n_families = len(_family_rule_ids())
        assert len(data_rows) == n_families, (
            f"spec probe summary table has {len(data_rows)} rows, generators "
            f"define {n_families} families"
        )

    def test_spec_taxonomy_covers_all_families(self, spec: str) -> None:
        sections = _taxonomy_sections(spec)
        expected = _family_rule_ids()
        missing = expected - set(sections)
        assert not missing, (
            f"spec taxonomy has no section for rule_id(s) {sorted(missing)} — "
            "a generator family is undocumented"
        )

    def test_spec_taxonomy_row_counts_match_generators(self, spec: str) -> None:
        sections = _taxonomy_sections(spec)
        for rule_id, gen in [
            ("shell-injection", generate_shell_injection),
            ("ssrf", generate_ssrf),
            ("overflow", generate_overflow),
            ("type-confusion", lambda: generate_type_confusion("string")),
            ("prompt-injection", generate_prompt_injection),
            ("indirect-injection", generate_indirect_injection),
        ]:
            documented = len(_table_data_rows(sections[rule_id]))
            actual = len(gen())
            assert documented == actual, (
                f"spec taxonomy '{rule_id}' documents {documented} payloads, "
                f"generator produces {actual}"
            )
        # integer variant of type confusion must also hold 8 (two-column table)
        assert len(generate_type_confusion("integer")) == len(
            _table_data_rows(sections["type-confusion"])
        )

    def test_spec_taxonomy_severities_match_generators(self, spec: str) -> None:
        """Per-row severity in the taxonomy must equal the generator's."""
        sections = _taxonomy_sections(spec)
        for rule_id, gen in [
            ("shell-injection", generate_shell_injection),
            ("ssrf", generate_ssrf),
            ("overflow", generate_overflow),
            ("prompt-injection", generate_prompt_injection),
            ("indirect-injection", generate_indirect_injection),
        ]:
            rows = _table_data_rows(sections[rule_id])
            payloads = gen()
            assert len(rows) == len(payloads)
            for raw_line, payload in zip(_taxonomy_raw_lines(sections[rule_id]), payloads):
                # payload cells may contain '|' — parse severity from the right
                parts = raw_line.rsplit("|", 3)
                assert len(parts) == 4, f"unparseable taxonomy row: {raw_line!r}"
                documented_sev = parts[1].strip().upper()
                actual_sev = payload.severity.value.upper()
                assert documented_sev == actual_sev, (
                    f"spec taxonomy '{rule_id}': doc says "
                    f"{documented_sev}, generator says {actual_sev}"
                )

    def test_spec_prompt_injection_xml_row_verbatim(self, spec: str) -> None:
        """The XML-tag-injection payload must be the code's exact string.

        #13's audit found the spec carrying a paraphrased payload
        ('<prompt>Secret mode activated</prompt>') instead of the generator's
        verbatim wire string — this test pins it."""
        rows = _table_data_rows(_taxonomy_sections(spec)["prompt-injection"])
        xml_row = next(r for r in rows if "XML tag injection" in r[3])
        documented = _doc_payload_text(xml_row[1])
        actual = generate_prompt_injection()[2].value
        assert isinstance(actual, str)
        assert documented == actual, (
            f"spec prompt-injection XML row is not verbatim: {documented!r} vs generator {actual!r}"
        )

    def test_spec_indirect_injection_payloads_verbatim(self, spec: str) -> None:
        """The new indirect-injection taxonomy rows must be verbatim."""
        from mcp_guard.payloads import INDIRECT_CANARY

        assert INDIRECT_CANARY == "mcpguard-indirect-canary"
        rows = _table_data_rows(_taxonomy_sections(spec)["indirect-injection"])
        payloads = generate_indirect_injection()
        assert len(rows) == len(payloads)
        for row, payload in zip(rows, payloads):
            documented = _doc_payload_text(row[1])
            assert isinstance(payload.value, str)
            assert documented == payload.value, (
                f"spec indirect-injection row {row[0]} not verbatim: "
                f"{documented!r} vs {payload.value!r}"
            )

    # ---- docs/blog.html ----

    def test_blog_string_count(self, blog: str) -> None:
        m = re.search(r"Fires (\d+) payloads per string parameter", blog)
        assert m, "blog lost its per-string-parameter count claim"
        assert int(m.group(1)) == len(generate_all_for_param("name", {"type": "string"}))

    def test_blog_no_schema_count(self, blog: str, no_schema_n: int) -> None:
        m = re.search(r"full suite of (\d+) payloads", blog)
        assert m, "blog lost its no-schema suite count claim"
        assert int(m.group(1)) == no_schema_n

    def test_blog_probe_table_family_count(self, blog: str) -> None:
        m = re.search(r"<h3>(\d+) probe types</h3>", blog)
        assert m, "blog lost its probe-types heading"
        table = blog[m.end() :]
        table = table[: table.index("</table>")]
        data_rows = re.findall(r"<tr><td><span class=\"badge", table)
        n_families = len(_family_rule_ids())
        assert int(m.group(1)) == n_families
        assert len(data_rows) == n_families, (
            f"blog probe table has {len(data_rows)} rows, generators define {n_families} families"
        )
