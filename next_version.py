#!/usr/bin/env python3
"""Print the next release version: the Cargo.toml base plus the next -T-N.

Irminsul's releases are `<base>-T-<n>` (e.g. `0.2.2-T-3`): `<base>` is the
`package.version` in Cargo.toml and `<n>` counts this fork's releases of that
base. The release workflow runs this to name a release, so nobody types a
version and the counter can't be skipped or reused:

    v0.2.2-T-1, v0.2.2-T-2 exist  ->  0.2.2-T-3
    Cargo.toml bumped to 0.2.3    ->  0.2.3-T-1

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
FORK_SUFFIX = re.compile(r"-T-\d+$")


def base_version(version: str) -> str:
    """The base a Cargo.toml version names; a stray -T-N suffix is ignored."""
    base = FORK_SUFFIX.sub("", version.strip())
    if not BASE.fullmatch(base):
        raise ValueError(f"Cargo.toml version {version!r} is not MAJOR.MINOR.PATCH")
    return base


def next_version(cargo_version: str, tags: list[str]) -> str:
    """The next `<base>-T-<n>` given the repository's existing tags."""
    base = base_version(cargo_version)
    taken = re.compile(rf"v{re.escape(base)}-T-(\d+)")
    used = [int(m.group(1)) for tag in tags if (m := taken.fullmatch(tag.strip()))]
    return f"{base}-T-{max(used, default=0) + 1}"


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
