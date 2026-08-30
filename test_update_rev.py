#!/usr/bin/env python3
"""Tests for update_rev.py's guards.

Run with `python -m unittest discover` (or `python test_update_rev.py`) from
the repository root. Nothing here touches the network or invokes cargo: the
HEAD resolver and the verification step are both injected.
"""

import os
import tempfile
import unittest

import update_rev

MANIFEST = """[package]
name = "irminsul"

[dependencies]
auto-artifactarium = { git = "https://github.com/tawan475/auto-artifactarium", rev = "0000000000000000000000000000000000000000" }
anime-game-data = { git = "https://github.com/konkers/anime-game-data" }

# Uncomment for local debugging
# [patch."https://github.com/konkers/anime-game-data"]
# anime-game-data = { path = "../anime-game-data" }
"""

PATCHED_MANIFEST = MANIFEST + """
[patch."https://github.com/tawan475/auto-artifactarium"]
auto-artifactarium = { path = "../auto-artifactarium" }
"""

NEW_SHA = "1234567890abcdef1234567890abcdef12345678"


def resolve_stub(url):
    return NEW_SHA


class TempManifest:
    """A throwaway directory holding a Cargo.toml, written as raw bytes."""

    def __init__(self, text, lock=None):
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "Cargo.toml")
        self.lock_path = os.path.join(self._dir.name, "Cargo.lock")
        with open(self.path, "wb") as f:
            f.write(text.encode("utf-8"))
        if lock is not None:
            with open(self.lock_path, "wb") as f:
                f.write(lock.encode("utf-8"))

    def read(self):
        with open(self.path, "rb") as f:
            return f.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._dir.cleanup()


class ActivePatchSectionsTest(unittest.TestCase):
    def test_commented_patch_block_is_not_active(self):
        self.assertEqual(update_rev.active_patch_sections(MANIFEST), [])

    def test_uncommented_patch_block_is_reported(self):
        self.assertEqual(
            update_rev.active_patch_sections(PATCHED_MANIFEST),
            ['[patch."https://github.com/tawan475/auto-artifactarium"]'],
        )

    def test_crates_io_and_bare_patch_headers(self):
        self.assertEqual(
            update_rev.active_patch_sections('[patch.crates-io]\nfoo = { path = "x" }\n'),
            ["[patch.crates-io]"],
        )
        self.assertEqual(update_rev.active_patch_sections("[patch]\n"), ["[patch]"])

    def test_unrelated_tables_are_not_patches(self):
        self.assertEqual(update_rev.active_patch_sections("[patches]\n[package]\n"), [])


class RewritePinsTest(unittest.TestCase):
    def test_existing_rev_is_replaced_and_missing_rev_is_appended(self):
        new_content, updated = update_rev.rewrite_pins(MANIFEST, resolve_head=resolve_stub)
        self.assertTrue(updated)
        self.assertIn(
            'auto-artifactarium = { git = "https://github.com/tawan475/auto-artifactarium", rev = "'
            + NEW_SHA
            + '" }',
            new_content,
        )
        # This one had no `rev` at all, so one has to be appended inside the
        # inline table rather than substituted.
        self.assertIn(
            'anime-game-data = { git = "https://github.com/konkers/anime-game-data", rev = "'
            + NEW_SHA
            + '" }',
            new_content,
        )

    def test_commented_dependency_lines_are_left_alone(self):
        line = '# foo = { git = "https://example.com/foo", rev = "deadbeef" }\n'
        new_content, updated = update_rev.rewrite_pins(line, resolve_head=resolve_stub)
        self.assertFalse(updated)
        self.assertEqual(new_content, line)

    def test_line_endings_are_preserved(self):
        crlf = MANIFEST.replace("\n", "\r\n")
        new_content, updated = update_rev.rewrite_pins(crlf, resolve_head=resolve_stub)
        self.assertTrue(updated)
        self.assertEqual(new_content.count("\r\n"), crlf.count("\r\n"))
        self.assertNotIn("\n", new_content.replace("\r\n", ""), "a bare LF was introduced")

    def test_unresolvable_url_leaves_the_line_untouched(self):
        def boom(url):
            raise RuntimeError("network down")

        new_content, updated = update_rev.rewrite_pins(MANIFEST, resolve_head=boom)
        self.assertFalse(updated)
        self.assertEqual(new_content, MANIFEST)

    def test_empty_ls_remote_output_leaves_the_line_untouched(self):
        new_content, updated = update_rev.rewrite_pins(MANIFEST, resolve_head=lambda url: None)
        self.assertFalse(updated)
        self.assertEqual(new_content, MANIFEST)


class UpdateCargoTomlTest(unittest.TestCase):
    def test_refuses_to_run_while_a_patch_is_active(self):
        calls = []
        with TempManifest(PATCHED_MANIFEST) as manifest:
            before = manifest.read()
            code = update_rev.update_cargo_toml(
                manifest.path,
                resolve_head=resolve_stub,
                verifier=lambda *args: calls.append(args),
            )
            self.assertEqual(code, 2)
            self.assertEqual(manifest.read(), before, "manifest must not be rewritten")
            self.assertEqual(calls, [], "verification must not run")

    def test_failed_verification_restores_the_original_manifest(self):
        with TempManifest(MANIFEST) as manifest:
            before = manifest.read()
            code = update_rev.update_cargo_toml(
                manifest.path,
                resolve_head=resolve_stub,
                verifier=lambda *args: False,
            )
            self.assertEqual(code, 1)
            self.assertEqual(
                manifest.read(),
                before,
                "a failing build must not leave the new rev behind",
            )

    def test_successful_verification_keeps_the_new_rev(self):
        seen = []
        with TempManifest(MANIFEST) as manifest:

            def verifier(manifest_dir, mode):
                seen.append((manifest_dir, mode))
                return True

            code = update_rev.update_cargo_toml(
                manifest.path,
                verify_mode="full",
                resolve_head=resolve_stub,
                verifier=verifier,
            )
            self.assertEqual(code, 0)
            self.assertIn(NEW_SHA, manifest.read().decode("utf-8"))
            self.assertEqual(seen, [(os.path.dirname(manifest.path), "full")])

    def test_failed_verification_rolls_the_lockfile_back_too(self):
        lock = 'version = 4\n\n[[package]]\nname = "auto-artifactarium"\n'
        with TempManifest(MANIFEST, lock) as manifest:

            def verifier(manifest_dir, mode):
                # What a real `cargo check` does: rewrite the lock to match the
                # new pins.
                with open(os.path.join(manifest_dir, "Cargo.lock"), "wb") as f:
                    f.write(b"rewritten by the verification build\n")
                return False

            code = update_rev.update_cargo_toml(
                manifest.path, resolve_head=resolve_stub, verifier=verifier
            )
            self.assertEqual(code, 1)
            with open(manifest.lock_path, "rb") as f:
                self.assertEqual(f.read(), lock.encode("utf-8"))

    def test_failed_verification_removes_a_lockfile_the_build_created(self):
        with TempManifest(MANIFEST) as manifest:

            def verifier(manifest_dir, mode):
                with open(os.path.join(manifest_dir, "Cargo.lock"), "wb") as f:
                    f.write(b"created by the verification build\n")
                return False

            code = update_rev.update_cargo_toml(
                manifest.path, resolve_head=resolve_stub, verifier=verifier
            )
            self.assertEqual(code, 1)
            self.assertFalse(os.path.exists(manifest.lock_path))

    def test_successful_verification_keeps_the_lockfile_the_build_wrote(self):
        with TempManifest(MANIFEST, "stale\n") as manifest:

            def verifier(manifest_dir, mode):
                with open(os.path.join(manifest_dir, "Cargo.lock"), "wb") as f:
                    f.write(b"rewritten by the verification build\n")
                return True

            code = update_rev.update_cargo_toml(
                manifest.path, resolve_head=resolve_stub, verifier=verifier
            )
            self.assertEqual(code, 0)
            with open(manifest.lock_path, "rb") as f:
                self.assertEqual(f.read(), b"rewritten by the verification build\n")

    def test_missing_manifest_is_an_error(self):
        self.assertEqual(update_rev.update_cargo_toml("does-not-exist-Cargo.toml"), 1)


class VerificationCommandTest(unittest.TestCase):
    def test_default_mode_runs_cargo_check_without_default_features(self):
        self.assertEqual(
            update_rev.verification_command(".", "check"),
            ["cargo", "check", "--no-default-features"],
        )

    def test_full_mode_runs_check_py_when_present(self):
        repo = os.path.dirname(os.path.abspath(__file__))
        cmd = update_rev.verification_command(repo, "full")
        self.assertEqual(cmd[1], os.path.join(repo, "check.py"))

    def test_full_mode_falls_back_to_cargo_check_without_check_py(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(
                update_rev.verification_command(empty, "full"),
                ["cargo", "check", "--no-default-features"],
            )

    def test_none_mode_has_no_command(self):
        self.assertIsNone(update_rev.verification_command(".", "none"))


class RunVerificationTest(unittest.TestCase):
    """Exercises the real subprocess plumbing, standing a fake check.py in for
    cargo so the test needs no toolchain."""

    def _repo_with_check_py(self, body):
        repo = tempfile.TemporaryDirectory()
        with open(os.path.join(repo.name, "check.py"), "w", encoding="utf-8") as f:
            f.write(body)
        return repo

    def test_a_failing_check_py_is_reported_as_failure(self):
        with self._repo_with_check_py("import sys; sys.exit(3)\n") as repo:
            self.assertFalse(update_rev.run_verification(repo, "full"))

    def test_a_passing_check_py_is_reported_as_success(self):
        with self._repo_with_check_py("import sys; sys.exit(0)\n") as repo:
            self.assertTrue(update_rev.run_verification(repo, "full"))

    def test_check_py_runs_in_the_manifest_directory(self):
        with self._repo_with_check_py(
            "import os, sys\nopen('cwd.txt', 'w').write(os.getcwd())\nsys.exit(0)\n"
        ) as repo:
            self.assertTrue(update_rev.run_verification(repo, "full"))
            with open(os.path.join(repo, "cwd.txt"), encoding="utf-8") as f:
                self.assertEqual(os.path.realpath(f.read()), os.path.realpath(repo))

    def test_waived_verification_succeeds_without_running_anything(self):
        self.assertTrue(update_rev.run_verification(".", "none"))


if __name__ == "__main__":
    unittest.main()
