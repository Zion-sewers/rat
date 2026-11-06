"""Adversarial tests for CODEOWNERS (rat#40).

The issue asked for ownership rules per area plus a default owner, on a
file that was once corrupted (binary garbage). That history is established,
not assumed: the original file (2026-07-25, commit 34fad2e) was 309 bytes
containing a NUL byte and garbled owner tokens; it was rewritten as clean
text 2026-09-26 in #49. Two failure modes are pinned here:

1. A corrupt file (non-UTF-8 bytes, NUL bytes) silently breaks GitHub's
   CODEOWNERS parsing, so review routing stops with no failing check.
2. A wrong owner (typo'd user, nonexistent team) or a mis-ordered rule
   (specific rule shadowed by the catch-all) silently routes reviews to
   nobody. The org has a single member, so every owner must be exactly
   @ShovalBenjer.

The matcher below implements the subset of CODEOWNERS semantics this file
uses (`*` catch-all, `/dir/` directory prefix, `/FILE` root file, last
match wins). GitHub's own parser is the final authority; this test pins
the structure GitHub reads. The validator is deliberately stricter than
GitHub in two places, and both are fail-loud by design: a bare pattern
with no owner is rejected here (GitHub treats it as valid with empty
owners, i.e. any user with write access may approve; this validator
fails loud instead), and a pattern outside the three supported forms is
rejected rather than silently mis-evaluated. Inline comments (`# ...`
after the owners) are stripped, matching github.com docs.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CODEOWNERS = REPO_ROOT / "CODEOWNERS"

SOLE_OWNER = "@ShovalBenjer"

# Pattern -> representative repo paths that must resolve to the owner of
# that pattern (not merely to the catch-all default). Every path must exist
# on disk (see test_representative_paths_exist).
REQUIRED_RULES: dict[str, list[str]] = {
    "*": ["README.md", "CHANGELOG.md"],
    "/src/": ["src/mcp_guard/scanner.py", "src/mcp_guard/__init__.py"],
    "/tests/": ["tests/test_scanner.py"],
    "/docs/": ["docs/spec.md", "docs/ARCHITECTURE.md"],
    "/.github/": [".github/workflows/ci.yml", ".github/dependabot.yml"],
    "/SECURITY.md": ["SECURITY.md"],
    "/LICENSE": ["LICENSE"],
    "/pyproject.toml": ["pyproject.toml"],
}

# Paths matched by no specific rule: they must still resolve, via `*`.
DEFAULT_ONLY_PATHS = ["tools/release_notes.py", "AGENTS.md"]


def parse_codeowners(raw: bytes) -> list[tuple[str, list[str]]]:
    """Parse CODEOWNERS bytes into (pattern, owners) rules, fail-closed.

    Raises ValueError on non-UTF-8 bytes or NUL bytes (the corrupted-file
    failure mode), on any rule line with no owner, and on any pattern
    outside the three supported forms (`*`, `/dir/`, `/FILE`).
    """
    if b"\x00" in raw:
        raise ValueError("CODEOWNERS contains NUL bytes: file is corrupted")
    text = raw.decode("utf-8")  # raises UnicodeDecodeError on binary content
    rules: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # `#` always starts a comment in CODEOWNERS (github.com docs show
        # `*.js @js-owner #This is an inline comment.`); strip it so the
        # comment words are never read as owners.
        stripped = stripped.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split()
        pattern, owners = parts[0], parts[1:]
        if not owners:
            raise ValueError(f"CODEOWNERS rule has no owner: {line!r}")
        if not _is_supported_pattern(pattern):
            raise ValueError(f"unsupported CODEOWNERS pattern: {pattern!r}")
        rules.append((pattern, owners))
    return rules


def _is_supported_pattern(pattern: str) -> bool:
    """True for the three pattern forms this file uses, nothing else.

    `*` catch-all, `/dir/` directory prefix, `/FILE` anchored root file.
    Glob forms (`*.js`, `/src/**/*.py`), negation, and character ranges
    are rejected rather than silently mis-evaluated by the matcher below.
    So are degenerate forms: `/` alone, and any pattern containing `!`.
    """
    if "!" in pattern:
        return False
    if pattern == "*":
        return True
    if pattern.startswith("/") and pattern.endswith("/"):
        inner = pattern[1:-1]
        return bool(inner) and "*" not in pattern and "?" not in pattern and "[" not in pattern
    if pattern.startswith("/"):
        return "*" not in pattern and "?" not in pattern and "[" not in pattern
    return False


def _pattern_matches(pattern: str, path: str) -> bool:
    if pattern == "*":
        return True
    if pattern.startswith("/") and pattern.endswith("/"):
        return path.startswith(pattern[1:])
    if pattern.startswith("/"):
        return path == pattern[1:]
    return path == pattern


def resolve_owner(rules: list[tuple[str, list[str]]], path: str) -> str:
    """Owner of the LAST matching rule for `path` (CODEOWNERS semantics)."""
    owner = ""
    for pattern, owners in rules:
        if _pattern_matches(pattern, path):
            owner = owners[-1]
    assert owner, f"no CODEOWNERS rule matches {path!r}"
    return owner


def winning_pattern(rules: list[tuple[str, list[str]]], path: str) -> str:
    """Pattern of the LAST matching rule for `path`."""
    winner = ""
    for pattern, _owners in rules:
        if _pattern_matches(pattern, path):
            winner = pattern
    assert winner, f"no CODEOWNERS rule matches {path!r}"
    return winner


def _load_rules() -> list[tuple[str, list[str]]]:
    assert CODEOWNERS.exists(), "CODEOWNERS file is missing"
    return parse_codeowners(CODEOWNERS.read_bytes())


def test_file_is_clean_utf8_text() -> None:
    raw = CODEOWNERS.read_bytes()
    assert b"\x00" not in raw, "CODEOWNERS contains NUL bytes"
    raw.decode("utf-8")  # raises on binary content


def test_nul_bytes_fail_validation() -> None:
    for bad in (b"\x00\x01\x02binary", b"* @ShovalBenjer\x00\n"):
        try:
            parse_codeowners(bad)
        except ValueError:
            continue
        raise AssertionError(f"NUL bytes accepted: {bad!r}")


def test_non_utf8_bytes_without_nul_fail_validation() -> None:
    # The decode branch: no NUL here, so only the UTF-8 decode can reject
    # these. Deleting the decode would leave this test failing.
    for bad in (b"\xff\xfe* @x\n", b"\x80\x81\x82\n"):
        try:
            parse_codeowners(bad)
        except UnicodeDecodeError:
            continue
        raise AssertionError(f"non-UTF-8 bytes accepted: {bad!r}")


def test_inline_comment_is_stripped_not_read_as_owner() -> None:
    rules = parse_codeowners(b"/src/ @ShovalBenjer #This is an inline comment.\n")
    assert rules == [("/src/", [SOLE_OWNER])]


def test_unsupported_pattern_forms_are_rejected() -> None:
    for bad in (
        b"*.js @ShovalBenjer\n",
        b"/src/**/*.py @ShovalBenjer\n",
        b"docs/*.md @ShovalBenjer\n",
        b"/ @ShovalBenjer\n",
        b"/!foo/ @ShovalBenjer\n",
    ):
        try:
            parse_codeowners(bad)
        except ValueError:
            continue
        raise AssertionError(f"unsupported pattern accepted: {bad!r}")


def test_bare_pattern_without_owner_is_rejected() -> None:
    try:
        parse_codeowners(b"/src/ \n")
    except ValueError:
        return
    raise AssertionError("bare pattern without owner accepted")


def test_every_owner_is_the_sole_org_member() -> None:
    rules = _load_rules()
    assert rules, "CODEOWNERS has no rules"
    for pattern, owners in rules:
        assert owners == [SOLE_OWNER], (
            f"rule {pattern!r} names {owners}, expected [{SOLE_OWNER!r}] "
            "(org has one member; a typo'd user or team silently breaks routing)"
        )


def test_required_rules_present_exactly_once_and_nothing_else() -> None:
    rules = _load_rules()
    patterns = [pattern for pattern, _owners in rules]
    assert len(rules) == len(REQUIRED_RULES), (
        f"CODEOWNERS has {len(rules)} rules, expected exactly {len(REQUIRED_RULES)}: {patterns}"
    )
    for required in REQUIRED_RULES:
        assert patterns.count(required) == 1, (
            f"pattern {required!r} appears {patterns.count(required)} times, expected once"
        )


def test_representative_paths_exist() -> None:
    missing = [
        path
        for paths in list(REQUIRED_RULES.values()) + [DEFAULT_ONLY_PATHS]
        for path in paths
        if not (REPO_ROOT / path).is_file()
    ]
    assert not missing, f"representative paths do not exist on disk: {missing}"


def test_default_rule_is_first() -> None:
    rules = _load_rules()
    assert rules[0][0] == "*", (
        "catch-all `*` must be the FIRST rule: CODEOWNERS is last-match-wins, "
        "a later `*` would shadow every specific rule"
    )


def test_every_required_path_resolves_to_its_own_rule() -> None:
    rules = _load_rules()
    for pattern, paths in REQUIRED_RULES.items():
        for path in paths:
            assert resolve_owner(rules, path) == SOLE_OWNER, (
                f"{path!r} does not resolve to {SOLE_OWNER}"
            )
            assert winning_pattern(rules, path) == pattern, (
                f"{path!r} is won by {winning_pattern(rules, path)!r}, "
                f"not its own rule {pattern!r} (rule is shadowed or mis-ordered)"
            )


def test_unmatched_paths_fall_back_to_default() -> None:
    rules = _load_rules()
    for path in DEFAULT_ONLY_PATHS:
        assert winning_pattern(rules, path) == "*", f"{path!r} should fall back to the `*` default"
        assert resolve_owner(rules, path) == SOLE_OWNER
