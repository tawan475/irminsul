#!/usr/bin/env python3
"""Print the next release version: the Cargo.toml base plus the next -T-N.

Irminsul's releases are `<base>-T-<n>` (e.g. `0.2.3-T-12`): `<base>` is the
`package.version` in Cargo.toml and `<n>` is one running count of this fork's
releases. It never restarts, not even when the base changes: after T-9 comes
10, then 11 (the user's rule, 2026-10-12). The release workflow runs this to
name a release, so nobody types a version and the counter can't be skipped or
reused:

    v0.2.2-T-10, v0.2.3-T.1 exist  ->  0.2.3-T-11
    Cargo.toml bumped to 0.2.4     ->  0.2.4-T-12

`v0.2.3-T.1` is the one release cut as `-T.<n>`, while the count briefly
restarted per base; its number still counts.

The catch with `-T-<n>`: semver compares a pre-release part that holds letters
as text, which is how `0.2.2-T-10` once sorted BELOW `0.2.2-T-9` so the updater
(`self_update::version::bump_is_greater`) never offered T-10 to T-9. Numbers of
the same length compare correctly as text, so the only danger is a base whose
releases gain a digit (99 -> 100). That number is refused here until the base in
Cargo.toml is bumped, because a newer base always wins.

Cargo.toml on main keeps the bare base version. That matters for updates:
`<base>` is a stable semver and every `-T-N` is a pre-release of it, so a
local build never offers itself a release (src/update.rs only walks builds
that are already pre-releases onto pre-releases).

Usage: python next_version.py [--github-output]
  Prints the version; with --github-output, as `version=<v>` for $GITHUB_OUTPUT.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE = re.compile(r"\d+\.\d+\.\d+")
FORK_SUFFIX = re.compile(r"-T[-.]\d+$")
RELEASE_TAG = re.compile(r"v(\d+\.\d+\.\d+)-T([-.])(\d+)")


def base_version(version: str) -> str:
    """The base a Cargo.toml version names; a stray -T-N suffix is ignored."""
    base = FORK_SUFFIX.sub("", version.strip())
    if not BASE.fullmatch(base):
        raise ValueError(f"Cargo.toml version {version!r} is not MAJOR.MINOR.PATCH")
    return base


def next_version(cargo_version: str, tags: list[str]) -> str:
    """The next `<base>-T-<n>` given the repository's existing tags.

    `<n>` continues from the highest release number of any base. Raises
    ValueError when `<n>` would have more digits than an earlier `-T-<n>`
    release of the same base: compared as text it would sort below them (see
    above). The one `-T.<n>` release doesn't count there: its "T" part is a
    prefix of "T-<n>", which always sorts above it.
    """
    base = base_version(cargo_version)
    releases = [
        (m.group(1), m.group(2), int(m.group(3)))
        for tag in tags
        if (m := RELEASE_TAG.fullmatch(tag.strip()))
    ]
    n = max((number for _, _, number in releases), default=0) + 1
    same_base = [number for tag_base, sep, number in releases if tag_base == base and sep == "-"]
    if same_base and len(str(n)) > len(str(max(same_base))):
        raise ValueError(
            f"release {n} of base {base} would sort below {base}-T-{max(same_base)} "
            "(pre-release parts compare as text); bump package.version in Cargo.toml first"
        )
    return f"{base}-T-{n}"


def cargo_version(manifest: Path = ROOT / "Cargo.toml") -> str:
    with manifest.open("rb") as file:
        return tomllib.load(file)["package"]["version"]


def repo_tags() -> list[str]:
    result = subprocess.run(
        ["git", "tag", "--list", "v*"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.split()


def main(argv: list[str]) -> int:
    version = next_version(cargo_version(), repo_tags())
    print(f"version={version}" if "--github-output" in argv else version)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
