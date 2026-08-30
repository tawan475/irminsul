#!/usr/bin/env python3
"""Roll every pinned `git = "..."` dependency in a Cargo manifest forward to the
default-branch HEAD of its repository -- and prove the result still builds
before leaving the new pin in place.

Adopting an upstream revision unverified is how a broken dependency ends up in
a release. This script used to rewrite each `rev = "..."` from `git ls-remote`
and then print "Successfully updated" without compiling a single line, so the
sanctioned way to adopt a new `auto-artifactarium` was "take default-branch
HEAD, sight unseen". Two guards now bracket the rewrite:

1. It refuses to run while the manifest has an active `[patch.*]` section.
   A patch redirects the crate to a local path (or another source), so cargo
   never resolves the pin being rewritten -- the verification build in step 2
   would compile the patched code and say nothing at all about the new
   revision.

2. After rewriting it runs a verification build and restores the original
   manifest -- and the Cargo.lock the build rewrote -- byte-for-byte if that
   build fails, so a bad upstream revision never survives the run.

Usage:

    python update_rev.py [Cargo.toml] [--verify {check,full,none}]

    --verify check  (default)  cargo check --no-default-features
    --verify full              python check.py  (fmt, clippy -Dwarnings, test, build)
    --verify none              rewrite only; prints a loud warning
"""

import argparse
import os
import re
import subprocess
import sys

# Same guard as check.py: a Windows console still defaults to a legacy codepage
# that cannot encode the status glyphs below, and an UnicodeEncodeError while
# reporting a failed verification would leave the user with no idea that the
# manifest was restored.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass

GIT_URL_RE = re.compile(r'git\s*=\s*"([^"]+)"')
REV_RE = re.compile(r'rev\s*=\s*"[^"]+"')
REV_SUB_RE = re.compile(r'(rev\s*=\s*")[^"]+(")')
CLOSING_BRACE_RE = re.compile(r"(\s*})\s*$")

# A TOML table header that opens a `[patch...]` section: `[patch.crates-io]`,
# `[patch."https://github.com/owner/repo"]`, or the bare `[patch]`.
PATCH_HEADER_RE = re.compile(r"^\[patch\s*(?:\.|\])")


def active_patch_sections(content):
    """The uncommented `[patch...]` table headers in a manifest, in order.

    Commented-out blocks (the `# Uncomment for local debugging` form) are not
    in effect and are therefore not reported.
    """
    return [
        line.strip()
        for line in content.splitlines()
        if not line.strip().startswith("#") and PATCH_HEADER_RE.match(line.strip())
    ]


def git_ls_remote_head(url):
    """The SHA that `url`'s default branch currently points at, or None."""
    res = subprocess.run(
        ["git", "ls-remote", url, "HEAD"], capture_output=True, text=True, check=True
    )
    if not res.stdout.strip():
        return None
    return res.stdout.split()[0]


def rewrite_pins(content, resolve_head=git_ls_remote_head):
    """Rewrite every `git = "..."` dependency line to its default-branch HEAD.

    Returns `(new_content, updated)`. Line endings are preserved exactly so a
    manifest that only changed a rev does not also show up as a whitespace
    diff. `resolve_head` is injected so the tests can run without a network.
    """
    out = []
    updated = False

    for raw_line in content.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        ending = raw_line[len(line) :]

        # Commented-out lines are skipped deliberately: a disabled dependency
        # or a `[patch]` block kept around for local debugging must not be
        # silently re-pointed at some repository's HEAD.
        if line.strip().startswith("#"):
            out.append(raw_line)
            continue

        match = GIT_URL_RE.search(line)
        if not match:
            out.append(raw_line)
            continue

        url = match.group(1)
        print(f"Fetching latest rev for {url}...")
        try:
            latest_rev = resolve_head(url)
        except Exception as e:  # noqa: BLE001 - network/git failures are all "leave it alone"
            print(f"Failed to fetch rev for {url}: {e}")
            out.append(raw_line)
            continue

        if not latest_rev:
            print(f"Warning: No HEAD found for {url}")
            out.append(raw_line)
            continue

        if REV_RE.search(line):
            new_line = REV_SUB_RE.sub(rf'\g<1>{latest_rev}\g<2>', line)
        else:
            new_line = CLOSING_BRACE_RE.sub(rf', rev = "{latest_rev}"\g<1>', line)

        if new_line != line:
            print(f"Updated {url} to rev {latest_rev[:8]}")
            updated = True
        else:
            print(f"{url} is already up to date at {latest_rev[:8]}")

        out.append(new_line + ending)

    return "".join(out), updated


def verification_command(manifest_dir, mode):
    """The command that decides whether the new pins are adoptable, or None."""
    if mode == "none":
        return None
    if mode == "full":
        check_py = os.path.join(manifest_dir, "check.py")
        if os.path.isfile(check_py):
            return [sys.executable, check_py]
        print(f"⚠️  {check_py} not found; falling back to 'cargo check'.")
    return ["cargo", "check", "--no-default-features"]


def run_verification(manifest_dir, mode):
    """True when the rewritten manifest builds (or verification was waived)."""
    cmd = verification_command(manifest_dir, mode)
    if cmd is None:
        print(
            "\n⚠️  --verify none: the new revisions were NOT built. You are "
            "adopting them unverified; run 'python check.py' before pushing."
        )
        return True

    print(f"\n[Verify] Running: {' '.join(cmd)}")
    try:
        return subprocess.run(cmd, cwd=manifest_dir).returncode == 0
    except FileNotFoundError:
        print(f"❌ [Verify] Command not found: {cmd[0]}. Make sure it is installed.")
        return False
    except KeyboardInterrupt:
        print("\n❌ [Verify] Interrupted.")
        return False


def update_cargo_toml(cargo_toml, verify_mode="check", resolve_head=git_ls_remote_head,
                      verifier=run_verification):
    """Update the pins in `cargo_toml`. Returns a process exit code."""
    cargo_toml = os.path.abspath(cargo_toml)
    if not os.path.exists(cargo_toml):
        print(f"Error: {cargo_toml} not found.")
        return 1

    manifest_dir = os.path.dirname(cargo_toml) or "."

    with open(cargo_toml, "rb") as f:
        original_bytes = f.read()
    content = original_bytes.decode("utf-8")

    # Refuse before touching the network: with a patch in effect the pins this
    # script rewrites are not what cargo resolves, so nothing below could
    # verify them.
    patches = active_patch_sections(content)
    if patches:
        print(f"Error: {cargo_toml} has an active patch section:")
        for header in patches:
            print(f"  {header}")
        print(
            "A [patch] overrides the dependency source, so the revisions this "
            "script pins would never be built and the verification step would "
            "prove nothing. Comment the block out (or remove it) and re-run."
        )
        return 2

    new_content, updated = rewrite_pins(content, resolve_head=resolve_head)

    if not updated:
        print(f"\nEverything is already up-to-date in {cargo_toml}.")
        return 0

    # The verification build rewrites Cargo.lock to match the new pins, so the
    # lockfile has to be rolled back with the manifest. Leaving a lock that
    # names revisions the manifest no longer does is its own failure: every CI
    # leg runs `cargo ... --locked`, which refuses outright when the two
    # disagree.
    lock_path = os.path.join(manifest_dir, "Cargo.lock")
    original_lock = None
    if os.path.isfile(lock_path):
        with open(lock_path, "rb") as f:
            original_lock = f.read()

    with open(cargo_toml, "wb") as f:
        f.write(new_content.encode("utf-8"))

    if not verifier(manifest_dir, verify_mode):
        with open(cargo_toml, "wb") as f:
            f.write(original_bytes)
        if original_lock is not None:
            with open(lock_path, "wb") as f:
                f.write(original_lock)
        elif os.path.isfile(lock_path):
            # There was no lockfile before; the failed build produced this one.
            os.remove(lock_path)
        print(
            f"\n❌ Verification failed; restored {cargo_toml} (and Cargo.lock) "
            "to its previous revisions. The upstream HEAD is not adoptable as-is."
        )
        return 1

    print(f"\n✅ Successfully updated and verified {cargo_toml}!")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Update pinned git revisions in a Cargo manifest, then verify the result builds."
    )
    parser.add_argument(
        "cargo_toml", nargs="?", default="Cargo.toml", help="manifest to update (default: Cargo.toml)"
    )
    parser.add_argument(
        "--verify",
        choices=("check", "full", "none"),
        default="check",
        help="how to verify the new revisions: 'check' runs cargo check --no-default-features "
        "(default), 'full' runs check.py, 'none' skips verification entirely.",
    )
    args = parser.parse_args(argv)

    return update_cargo_toml(args.cargo_toml, verify_mode=args.verify)


if __name__ == "__main__":
    sys.exit(main())
