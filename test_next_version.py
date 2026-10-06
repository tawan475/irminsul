import tempfile
import unittest
from pathlib import Path

from next_version import base_version, cargo_version, next_version


class NextVersionTest(unittest.TestCase):
    def test_counts_up_from_the_highest_release_of_the_base(self):
        tags = ["v0.2.3-T.1", "v0.2.3-T.2", "v0.2.2-T-7"]
        self.assertEqual(next_version("0.2.3", tags), "0.2.3-T.3")

    def test_a_new_base_starts_at_one(self):
        self.assertEqual(next_version("0.2.4", ["v0.2.3-T.5"]), "0.2.4-T.1")

    def test_numbers_compare_as_numbers_not_text(self):
        tags = ["v0.2.3-T.9", "v0.2.3-T.10"]
        self.assertEqual(next_version("0.2.3", tags), "0.2.3-T.11")

    def test_old_dash_tags_count_towards_their_base(self):
        # Releases before the switch were `-T-<n>`; their numbers stay taken.
        tags = ["v0.2.2-T-9", "v0.2.2-T-10"]
        self.assertEqual(next_version("0.2.2", tags), "0.2.2-T.11")
        self.assertEqual(next_version("0.2.3", tags), "0.2.3-T.1")

    def test_a_gap_does_not_reuse_a_number(self):
        self.assertEqual(next_version("0.2.3", ["v0.2.3-T.1", "v0.2.3-T.4"]), "0.2.3-T.5")

    def test_a_suffixed_cargo_version_counts_from_tags_not_from_itself(self):
        # main used to carry the last release's version; the tags are the truth.
        self.assertEqual(next_version("0.2.2-T-1", ["v0.2.2-T-1"]), "0.2.2-T.2")
        self.assertEqual(next_version("0.2.3-T.4", ["v0.2.3-T.4"]), "0.2.3-T.5")

    def test_other_tags_and_lookalikes_are_ignored(self):
        tags = [
            "v0.2.30-T.3",
            "v10.2.3-T.3",
            "v0.2.3-T.3-rc",
            "v0.2.3",
            "x0.2.3-T.9",
            "v0.2.3-T.",
            "v0.2.3-T_4",
        ]
        self.assertEqual(next_version("0.2.3", tags), "0.2.3-T.1")

    def test_a_malformed_base_is_refused(self):
        for version in ["0.2", "v0.2.2", "0.2.2-rc.1", ""]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                base_version(version)

    def test_reads_the_package_version_from_the_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "Cargo.toml"
            manifest.write_text(
                '[workspace]\nmembers = ["crates/x"]\n\n[package]\nname = "irminsul"\nversion = "0.2.3"\n',
                encoding="utf-8",
            )
            self.assertEqual(cargo_version(manifest), "0.2.3")


if __name__ == "__main__":
    unittest.main()
