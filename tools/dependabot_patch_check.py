"""Fail-closed patch gate for Dependabot auto-merge (mcp-guard#38).

The dependabot-auto-merge workflow runs when CI completes successfully and
calls this script with the CI head SHA. For every open PR attached to that
SHA, the script merges it only when ALL of the following hold:

- the author is dependabot[bot];
- the PR body lists at least one Dependabot bump line
  (``Bumps [name](url) from X to Y.``) and every listed bump is a patch
  bump (same major.minor, strictly greater patch, numeric versions only).

Anything else is skipped, never merged: minor/major bumps, mixed groups,
unparseable bodies (pre-release versions, missing versions, unexpected
format). There is no silent default and no coercion: unparseable means
"leave it for a human".

Usage (in dependabot-auto-merge.yml):
    python3 tools/dependabot_patch_check.py --sha "$HEAD_SHA"
Reads GITHUB_REPOSITORY from the environment (set automatically in Actions).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping

_BUMP = re.compile(
    r"Bumps \[[^\]]+\]\([^)]+\) from (\S+) to (\S+)\.",
)
_NUMERIC = re.compile(r"^\d+(\.\d+)*$")


def parse_bumps(body: str) -> list[tuple[str, str]] | None:
    """Extract (old, new) version pairs from Dependabot bump lines.

    Returns None when the body contains no bump line at all, so the caller
    can fail closed instead of treating "no bumps found" as "all patch".
    """
    pairs = _BUMP.findall(body or "")
    if not pairs:
        return None
    return [(old, new) for old, new in pairs]


def _version_tuple(version: str) -> tuple[int, int, int] | None:
    """'2.4.1' -> (2, 4, 1); 'v4' -> (4, 0, 0). None when not numeric."""
    cleaned = version.strip().lstrip("vV").rstrip(".,)")
    if not _NUMERIC.match(cleaned):
        return None
    parts = [int(p) for p in cleaned.split(".")]
    if len(parts) > 3:
        return None
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def is_patch_bump(old: str, new: str) -> bool:
    """True only for a strict patch bump: same major.minor, patch greater."""
    old_v = _version_tuple(old)
    new_v = _version_tuple(new)
    if old_v is None or new_v is None:
        return False
    return old_v[0] == new_v[0] and old_v[1] == new_v[1] and new_v[2] > old_v[2]


def all_patch(bumps: list[tuple[str, str]] | None) -> bool:
    """True only when at least one bump exists and every bump is a patch."""
    if not bumps:
        return False
    return all(is_patch_bump(old, new) for old, new in bumps)


def _gh(*args: str) -> str:
    result = subprocess.run(
        ["gh", "api", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh api {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _gh_merge(pr_number: int) -> None:
    result = subprocess.run(
        ["gh", "pr", "merge", str(pr_number), "--squash", "--delete-branch"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh pr merge {pr_number} failed: {result.stderr.strip()}")


def prs_for_sha(repo: str, sha: str) -> list[int]:
    """PR numbers attached to a commit SHA (empty for plain main pushes)."""
    out = _gh(f"repos/{repo}/commits/{sha}/pulls")
    return [int(pr["number"]) for pr in json.loads(out)]


def decide(pr: Mapping[str, object]) -> str:
    """Merge decision for one PR payload: 'merge' or a skip reason."""
    if pr.get("state") != "open":
        return "skip: not open"
    user = pr.get("user")
    author = user.get("login", "") if isinstance(user, Mapping) else ""
    if author != "dependabot[bot]":
        return f"skip: author is {author or 'unknown'}, not dependabot[bot]"
    body = pr.get("body")
    bumps = parse_bumps(body if isinstance(body, str) else "")
    if bumps is None:
        return "skip: no Dependabot bump lines in body (fail-closed)"
    if not all_patch(bumps):
        return f"skip: not every bump is a patch bump: {bumps}"
    return "merge"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True, help="CI head SHA to resolve PRs for")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = parser.parse_args(argv)
    if not args.repo:
        print("GITHUB_REPOSITORY is not set and --repo was not given", file=sys.stderr)
        return 2
    try:
        numbers = prs_for_sha(args.repo, args.sha)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not numbers:
        print(f"no PRs attached to {args.sha}; nothing to do")
        return 0
    for number in numbers:
        try:
            pr = json.loads(_gh(f"repos/{args.repo}/pulls/{number}"))
        except RuntimeError as exc:
            print(f"PR #{number}: {exc}", file=sys.stderr)
            return 2
        verdict = decide(pr)
        print(f"PR #{number} ({pr.get('title', '')}): {verdict}")
        if verdict != "merge":
            continue
        try:
            _gh_merge(number)
        except RuntimeError as exc:
            print(f"PR #{number}: {exc}", file=sys.stderr)
            return 2
        print(f"PR #{number}: merged (squash)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
