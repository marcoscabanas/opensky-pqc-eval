"""Restoration must pair exact source releases and never reuse published results."""

import contextlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import restore_artifacts as restore


class RestoreArtifactsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.checkout = self.root / "checkout"
        self.downloads = self.root / "downloads"
        self.checkout.mkdir()
        self.downloads.mkdir()
        self.files = []
        self.add_direct("raw.jsonl", "raw", "data/daytime.jsonl", b"raw recording\n")
        self.add_direct("prepared.jsonl", "prepared", "results/daytime/01_prepared/trace.jsonl", b"prepared\n")
        self.add_direct("signed.jsonl", "signed", "results/daytime/02_signed/key/groups.jsonl", b"signatures\n")
        self.add_archive("metadata-and-results.zip", "metadata_results", {
            "results/daytime/input_audit.json": b'{"timing": "conditional"}\n',
            "results/daytime/01_prepared/manifest.json": b'{"prepared": true}\n',
            "results/daytime/02_signed/key/manifest.json": b'{"signed": true}\n',
            "results/daytime/03_replay/replay_summary.json": b'{"never": "restore"}\n',
            "results/daytime/figures/plot.pdf": b"published figure\n",
        })
        self.code = {
            "README.md": b"matching release\n",
            "run_experiment.py": b"# entry point\n",
            "config/experiment.json": b"{}\n",
            "data/manifest.json": b'{"windows": {}}\n',
            "src/main_experiment.py": b"# implementation\n",
            "scripts/restore_artifacts.py": b"# restoration helper\n",
        }
        for name, content in self.code.items():
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.add_archive("code-snapshot.zip", "code", self.code)
        self.manifest = {"schema_version": 1, "files": self.files}
        self.write_manifest()
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def record(self, path, path_key, relative):
        return {path_key: relative, "bytes": path.stat().st_size, "sha256": restore.digest(path)}

    def add_direct(self, filename, kind, destination, content):
        path = self.downloads / filename
        path.write_bytes(content)
        self.files.append(dict(self.record(path, "filename", filename), kind=kind, restore_path=destination))

    def add_archive(self, filename, kind, contents):
        path = self.downloads / filename
        members = []
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in contents.items():
                archive.writestr(name, content)
                members.append({"path": name, "bytes": len(content),
                                "sha256": restore.hashlib.sha256(content).hexdigest()})
        self.files.append(dict(self.record(path, "filename", filename), kind=kind, members=members))

    def write_manifest(self):
        (self.downloads / "artifact_manifest.json").write_text(json.dumps(self.manifest))

    def run_restore(self, profile="replay", *extra):
        return restore.main(["--artifacts-dir", str(self.downloads), "--destination", str(self.checkout),
                             "--profile", profile, *extra])

    def test_replay_restores_inputs_but_not_code_or_completed_results(self):
        (self.downloads / "code-snapshot.zip").unlink()
        self.assertEqual(self.run_restore(), 0)
        self.assertTrue((self.checkout / "data/daytime.jsonl").is_file())
        self.assertTrue((self.checkout / "results/daytime/input_audit.json").is_file())
        self.assertTrue((self.checkout / "results/daytime/02_signed/key/groups.jsonl").is_file())
        self.assertFalse((self.checkout / "results/daytime/03_replay").exists())
        self.assertFalse((self.checkout / "results/daytime/figures").exists())
        self.assertEqual((self.checkout / "README.md").read_bytes(), self.code["README.md"])

    def test_fresh_needs_only_raw_downloads(self):
        for filename in ("code-snapshot.zip", "prepared.jsonl", "signed.jsonl", "metadata-and-results.zip"):
            (self.downloads / filename).unlink()
        self.assertEqual(self.run_restore("fresh"), 0)
        self.assertTrue((self.checkout / "data/daytime.jsonl").is_file())
        self.assertTrue((self.checkout / "data/manifest.json").is_file())
        self.assertFalse((self.checkout / "results").exists())

    def test_destination_defaults_to_checkout_containing_helper(self):
        with patch.object(restore, "DEFAULT_DESTINATION", self.checkout):
            self.assertEqual(restore.main(["--artifacts-dir", str(self.downloads), "--profile", "fresh"]), 0)
        self.assertTrue((self.checkout / "data/daytime.jsonl").is_file())

    def test_dry_run_checks_checkout_and_lists_missing_downloads_without_writes(self):
        for path in self.downloads.iterdir():
            if path.name != "artifact_manifest.json":
                path.unlink()
        self.assertEqual(self.run_restore("replay", "--dry-run"), 0)
        self.assertIn("Requires raw.jsonl", self.output.getvalue())
        self.assertIn("download bytes", self.output.getvalue())
        self.assertNotIn("Requires code-snapshot.zip", self.output.getvalue())
        self.assertFalse((self.checkout / "data/daytime.jsonl").exists())
        self.assertFalse((self.checkout / "results").exists())

    def test_missing_or_changed_code_fails_before_any_restoration(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                source = self.checkout / "src/main_experiment.py"
                if missing:
                    source.unlink()
                else:
                    source.write_text("# changed\n")
                with self.assertRaisesRegex(ValueError, "Checkout does not match"):
                    self.run_restore()
                self.assertFalse((self.checkout / "data/daytime.jsonl").exists())

    def test_additional_scientific_source_is_not_a_matching_checkout(self):
        (self.checkout / "src/new.py").write_text("# also changes the replay fingerprint\n")
        with self.assertRaisesRegex(ValueError, "Unrecorded scientific source"):
            self.run_restore()

    def test_corrupt_download_fails_before_any_restoration(self):
        (self.downloads / "signed.jsonl").write_bytes(b"corruption\n")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            self.run_restore()
        self.assertFalse((self.checkout / "data/daytime.jsonl").exists())

    def test_missing_required_download_fails_before_any_restoration(self):
        (self.downloads / "signed.jsonl").unlink()
        with self.assertRaisesRegex(FileNotFoundError, "Download signed.jsonl"):
            self.run_restore()
        self.assertFalse((self.checkout / "data/daytime.jsonl").exists())

    def test_interrupted_restore_can_resume_without_overwriting_equal_inputs(self):
        original = restore.clone_or_copy
        copies = 0

        def interrupted(source, destination):
            nonlocal copies
            copies += 1
            if copies == 2:
                raise OSError("simulated interrupted copy")
            original(source, destination)

        with patch.object(restore, "clone_or_copy", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "simulated interrupted"):
                self.run_restore()
        retained = self.checkout / "data/daytime.jsonl"
        self.assertTrue(retained.is_file())
        before = retained.stat().st_mtime_ns
        self.assertFalse(list(self.checkout.rglob(".adsb-restore-*")))
        self.assertEqual(self.run_restore(), 0)
        self.assertEqual(retained.stat().st_mtime_ns, before)
        self.assertEqual(self.run_restore(), 0)

    def test_existing_different_input_is_never_overwritten(self):
        target = self.checkout / "data/daytime.jsonl"
        target.write_bytes(b"different recording\n")
        with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite"):
            self.run_restore()
        self.assertEqual(target.read_bytes(), b"different recording\n")

    def test_abrupt_stop_staging_is_ignored_without_deleting_or_reusing_it(self):
        parent = self.checkout / "results/daytime/02_signed/key"
        empty = parent / ".adsb-restore-abcdefgh"
        incomplete = parent / ".adsb-restore-ijklmnop"
        empty.mkdir(parents=True)
        incomplete.mkdir()
        staged = incomplete / "payload"
        staged.write_bytes(b"interrupted incomplete contents")
        before = staged.stat().st_mtime_ns
        self.assertEqual(self.run_restore(), 0)
        self.assertTrue(empty.is_dir())
        self.assertEqual(staged.stat().st_mtime_ns, before)
        self.assertEqual(staged.read_bytes(), b"interrupted incomplete contents")
        self.assertEqual((parent / "groups.jsonl").read_bytes(), b"signatures\n")
        self.assertEqual(self.run_restore(), 0)

    def test_staging_directory_cannot_hide_symlink_or_other_content(self):
        staging = self.checkout / "results/daytime/02_signed/key/.adsb-restore-abcdefgh"
        staging.mkdir(parents=True)
        unexpected = staging / "unexpected"
        unexpected.write_bytes(b"not a known staging payload")
        with self.assertRaisesRegex(ValueError, "Unexpected content in restore staging"):
            self.run_restore()
        unexpected.unlink()
        payload = staging / "payload"
        payload.symlink_to(self.downloads / "raw.jsonl")
        with self.assertRaisesRegex(ValueError, "Unexpected content in restore staging"):
            self.run_restore()
        payload.unlink()
        payload.mkdir()
        with self.assertRaisesRegex(ValueError, "Unexpected content in restore staging"):
            self.run_restore()

    def test_staging_names_only_allowed_beside_input_files(self):
        staging = self.checkout / "results/.adsb-restore-abcdefgh"
        staging.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "Existing experiment output"):
            self.run_restore()

    def test_existing_replay_output_is_rejected_even_if_matching_published_data(self):
        self.run_restore()
        replay = self.checkout / "results/daytime/03_replay"
        replay.mkdir()
        (replay / "replay_summary.json").write_bytes(b'{"never": "restore"}\n')
        with self.assertRaisesRegex(ValueError, "Existing experiment output"):
            self.run_restore()

    def test_fresh_does_not_accept_already_restored_signed_workloads(self):
        self.run_restore()
        with self.assertRaisesRegex(ValueError, "Existing experiment output"):
            self.run_restore("fresh")

    def test_manifest_traversal_paths_are_rejected_even_when_not_selected(self):
        metadata = next(item for item in self.files if item["kind"] == "metadata_results")
        for bad in ("../outside", "/tmp/outside", "results/../outside", "C:\\outside", "data//file"):
            with self.subTest(bad=bad):
                metadata["members"][-1]["path"] = bad
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, "Unsafe archive path"):
                    self.run_restore("fresh")
                self.assertFalse((self.checkout / "data/daytime.jsonl").exists())

    def test_destination_symlink_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.checkout / "data/manifest.json").unlink()
        (self.checkout / "data").rmdir()
        (self.checkout / "data").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            self.run_restore()
        self.assertEqual(list(outside.iterdir()), [])

    def test_missing_code_inventory_cannot_bypass_compatibility_validation(self):
        self.manifest["files"] = [item for item in self.files if item["kind"] != "code"]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "code snapshot inventory"):
            self.run_restore()

    def test_duplicate_restored_paths_are_rejected(self):
        self.files[1]["restore_path"] = self.files[0]["restore_path"]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Duplicate restored path"):
            self.run_restore()

    def test_manifest_member_checksum_is_checked_before_publication(self):
        item = next(item for item in self.files if item["kind"] == "metadata_results")
        item["members"][0]["sha256"] = "0" * 64
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            self.run_restore()
        self.assertFalse((self.checkout / "results/daytime/input_audit.json").exists())

    def test_symbolic_link_archive_member_is_not_restored(self):
        item = next(item for item in self.files if item["kind"] == "metadata_results")
        archive_path = self.downloads / item["filename"]
        with zipfile.ZipFile(archive_path, "r") as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
        with zipfile.ZipFile(archive_path, "w") as archive:
            for name, content in contents.items():
                info = zipfile.ZipInfo(name)
                if name == "results/daytime/input_audit.json":
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, content)
        item.update(self.record(archive_path, "filename", item["filename"]))
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Invalid archive member"):
            self.run_restore()
        self.assertFalse((self.checkout / "results/daytime/input_audit.json").exists())

    def test_verify_only_checks_unused_code_snapshot_too(self):
        args = ["--artifacts-dir", str(self.downloads), "--verify-only"]
        self.assertEqual(restore.main(args), 0)
        self.assertIn("Verified all 5", self.output.getvalue())
        (self.downloads / "code-snapshot.zip").write_bytes(b"broken")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            restore.main(args)
        self.assertFalse((self.checkout / "data/daytime.jsonl").exists())

    def test_only_two_profiles_are_accepted(self):
        for profile in ("reference", "figures", "everything"):
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, "Unknown reproduction profile"):
                restore.selected(profile, "data/daytime.jsonl", "raw")


if __name__ == "__main__":
    unittest.main()
