"""Adversarial tests for CODEOWNERS (rat#40).

The issue asked for ownership rules per area plus a default owner, on a
file that was once corrupted (binary garbage). Two failure modes are pinned
here:

1. A corrupt file (non-UTF-8 bytes, NUL bytes) silently breaks GitHub's
   CODEOWNERS parsing, so review routing stops with no failing check.
2. A wrong owner (typo'd user, nonexistent team) or a mis-ordered rule
   (specific rule shadowed by the catch-all) silently routes reviews to
   nobody. The org has a single member, so every owner must be exactly
   @ShovalBenjer.

The matcher below implements the subset of CODEOWNERS semantics this file
uses (`*` catch-all, `/dir/` directory prefix, `/FILE` root file, last
match wins). GitHub's own parser is the final authority; this test pins
the structure GitHub reads.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CODEOWNERS = REPO_ROOT / "CODEOWNERS"

SOLE_OWNER = "@ShovalBenjer"

# Pattern -> representative repo paths that must resolve to the owner of
# that pattern (not merely to the catch-all default).
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
    failure mode), and on any rule line with no owner.
    """
    if b"\x00" in raw:
        raise ValueError("CODEOWNERS contains NUL bytes: file is corrupted")
    text = raw.decode("utf-8")  # raises UnicodeDecodeError on binary content
    rules: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        pattern, owners = parts[0], parts[1:]
        if not owners:
            raise ValueError(f"CODEOWNERS rule has no owner: {line!r}")
        rules.append((pattern, owners))
    return rules


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


def test_corrupt_bytes_fail_validation() -> None:
    for bad in (b"\x00\x01\x02binary", b"\xff\xfe\x00* @x\n", b"* @ShovalBenjer\x00\n"):
        try:
            parse_codeowners(bad)
        except (ValueError, UnicodeDecodeError):
            continue
        raise AssertionError(f"corrupt bytes accepted: {bad!r}")


def test_every_owner_is_the_sole_org_member() -> None:
    rules = _load_rules()
    assert rules, "CODEOWNERS has no rules"
    for pattern, owners in rules:
        assert owners == [SOLE_OWNER], (
            f"rule {pattern!r} names {owners}, expected [{SOLE_OWNER!r}] "
            "(org has one member; a typo'd user or team silently breaks routing)"
        )


def test_required_rules_present_exactly_once() -> None:
    rules = _load_rules()
    patterns = [pattern for pattern, _owners in rules]
    for required in REQUIRED_RULES:
        assert patterns.count(required) == 1, (
            f"pattern {required!r} appears {patterns.count(required)} times, expected once"
        )


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


def test_no_rule_without_owner() -> None:
    rules = _load_rules()
    for pattern, owners in rules:
        assert owners, f"rule {pattern!r} has no owner"
