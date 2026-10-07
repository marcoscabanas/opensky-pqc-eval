import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.experiment import generate_signatures as experiment


class FakeSigner:
    created = 0
    calls = 0
    fail_on = None

    def __init__(self):
        type(self).created += 1
        self.key = f"key-{type(self).created}".encode()

    @classmethod
    def from_secret_key(cls, secret, public):
        if public != secret:
            raise ValueError("Mismatched keys")
        signer = cls.__new__(cls)
        signer.key = secret
        return signer

    def export_secret_key(self):
        return self.key

    def public_key_bytes(self):
        return self.key

    def sign(self, message):
        type(self).calls += 1
        if type(self).calls == type(self).fail_on:
            raise RuntimeError("Simulated interruption")
        return hashlib.sha256(self.key + message).digest()

    def verify(self, message, signature):
        return signature == hashlib.sha256(self.key + message).digest()

    def metadata(self):
        return {"backend": "test", "maximum_signature_bytes": 32}

    def close(self):
        pass


class SignatureRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.args = SimpleNamespace(
            trace=self.base / "trace.jsonl", groups_dir=self.base / "groups",
            config=self.base / "algorithms.json", output_dir=self.base / "results",
            summary=self.base / "results" / "summary.json", intervals=[1, 2],
            validate_only=False, checkpoint_every=2, progress_seconds=3600,
        )
        self.args.groups_dir.mkdir()
        records = [
            {"trace_id": number, "icao": "AAAAAA" if number < 3 else "BBBBBB",
             "raw_msg": f"{number:028x}"}
            for number in range(1, 5)
        ]
        experiment.write_jsonl(self.args.trace, records)
        for k in self.args.intervals:
            groups = []
            for index in range(0, len(records), k):
                group_records = records[index:index + k]
                groups.append({
                    "group_id": index + 1, "icao": group_records[0]["icao"], "k": k,
                    "complete": True, "message_count": k,
                    "trace_ids": [record["trace_id"] for record in group_records],
                    "group_formation_time_s": float(k - 1),
                })
            experiment.write_jsonl(self.args.groups_dir / f"authentication_groups_k{k}.jsonl", groups)
        self.config = {"TEST": {"module": "test.fake", "enabled": True,
                                "implementation": "test", "expected_signature_bytes": 32}}
        experiment.atomic_json(self.args.config, self.config)
        FakeSigner.created, FakeSigner.calls, FakeSigner.fail_on = 0, 0, None
        self.loader = patch.object(experiment, "load_algorithm_module", return_value=SimpleNamespace(Signer=FakeSigner))
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.quiet = patch("builtins.print")
        self.quiet.start()
        self.addCleanup(self.quiet.stop)

    def run_experiment(self):
        return experiment.run_experiment(self.args)

    def test_interruption_resumes_same_keys_and_preserves_completed_outputs(self):
        FakeSigner.fail_on = 3
        with self.assertRaisesRegex(RuntimeError, "Simulated interruption"):
            self.run_experiment()
        partial = experiment.result_path(self.args, "TEST", 1).with_suffix(".jsonl.partial")
        prefix = partial.read_bytes()
        self.assertEqual(len(prefix.splitlines()), 2)
        self.assertFalse(experiment.result_path(self.args, "TEST", 1).exists())
        manifest_path = experiment.recovery_path(self.args, "TEST")
        manifest = manifest_path.read_bytes()
        self.assertEqual(os.stat(manifest_path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(manifest_path.parent).st_mode & 0o777, 0o700)
        # A power loss can leave a torn, uncommitted tail after the durable prefix.
        with partial.open("ab") as stream:
            stream.write(b'{"torn":')
        FakeSigner.fail_on = None
        summary = self.run_experiment()
        self.assertTrue(summary["complete"])
        self.assertEqual(FakeSigner.created, 2)
        self.assertEqual(manifest_path.read_bytes(), manifest)
        output = experiment.result_path(self.args, "TEST", 1)
        self.assertTrue(output.read_bytes().startswith(prefix))
        self.assertEqual(FakeSigner.calls, 7)  # six successful events plus interrupted call
        self.assertNotIn("secret_key", self.args.summary.read_text())
        calls, content, inode = FakeSigner.calls, output.read_bytes(), output.stat().st_ino
        self.run_experiment()
        self.assertEqual((FakeSigner.calls, output.read_bytes(), output.stat().st_ino), (calls, content, inode))
        fingerprints = {}
        for k in self.args.intervals:
            for record in experiment.load_jsonl(experiment.result_path(self.args, "TEST", k)):
                fingerprints.setdefault(record["icao"], set()).add(record["public_key_sha256"])
        self.assertTrue(all(len(values) == 1 for values in fingerprints.values()))

    def test_config_change_rejected_before_any_signing_or_output_mutation(self):
        self.run_experiment()
        output = experiment.result_path(self.args, "TEST", 1)
        original = output.read_bytes()
        self.config["TEST"]["implementation"] = "different"
        experiment.atomic_json(self.args.config, self.config)
        calls = FakeSigner.calls
        with self.assertRaisesRegex(ValueError, "metadata changed"):
            self.run_experiment()
        self.assertEqual(FakeSigner.calls, calls)
        self.assertEqual(output.read_bytes(), original)

    def test_tampered_committed_prefix_rejected(self):
        FakeSigner.fail_on = 3
        with self.assertRaises(RuntimeError):
            self.run_experiment()
        partial = experiment.result_path(self.args, "TEST", 1).with_suffix(".jsonl.partial")
        records = experiment.load_jsonl(partial)
        records[0]["signature_sha256"] = "0" * 64
        experiment.write_jsonl(partial, records)
        with self.assertRaisesRegex(ValueError, "digest/count mismatch"):
            self.run_experiment()
        self.assertEqual(FakeSigner.calls, 3)

    def test_interrupt_between_digest_and_record_count_keeps_last_checkpoint(self):
        original_sha256 = hashlib.sha256
        updates = 0

        class InterruptingDigest:
            def __init__(self, data=b""):
                self.wrapped = original_sha256(data)

            def __getattr__(self, name):
                return getattr(self.wrapped, name)

            def update(self, raw):
                nonlocal updates
                self.wrapped.update(raw)
                if raw.startswith(b'{"algorithm":'):
                    updates += 1
                    if updates == 3:
                        raise KeyboardInterrupt("Signal between digest/count updates")

        with patch.object(experiment.hashlib, "sha256", InterruptingDigest):
            with self.assertRaises(KeyboardInterrupt):
                self.run_experiment()
        checkpoint = experiment.load_json(experiment.recovery_path(self.args, "TEST", "_k1"))
        self.assertEqual(checkpoint["records"], 2)
        summary = self.run_experiment()
        self.assertTrue(summary["complete"])
        self.assertEqual(FakeSigner.created, 2)
        self.assertEqual(FakeSigner.calls, 7)

    def test_final_record_tampering_rejected_even_when_metadata_remains_valid(self):
        self.run_experiment()
        output = experiment.result_path(self.args, "TEST", 1)
        records = experiment.load_jsonl(output)
        records[0]["signature_sha256"] = "0" * 64
        experiment.write_jsonl(output, records)
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.run_experiment()

    def make_legacy(self, intervals):
        prepared = experiment.prepare_experiment(self.args)
        signers = {icao: FakeSigner() for icao in prepared.aircraft}
        for k in intervals:
            results, _ = experiment.process_interval(
                "TEST", self.config["TEST"], k, prepared.groups[k], prepared.trace, signers,
            )
            experiment.write_jsonl(experiment.result_path(self.args, "TEST", k), results)

    def test_complete_legacy_files_adopted_with_honest_evidence(self):
        self.make_legacy([1, 2])
        experiment.atomic_json(self.args.summary, {"algorithms": {"TEST": {
            "output_files": {"1": {"sha256": "stale"}},
        }}})
        calls = FakeSigner.calls
        summary = self.run_experiment()
        self.assertEqual(FakeSigner.calls, calls)
        self.assertFalse(experiment.recovery_path(self.args, "TEST").exists())
        self.assertIn("legacy recorded verification", summary["algorithms"]["TEST"]["verification_evidence"])
        self.assertFalse(summary["algorithms"]["TEST"]["key_continuity_checkable"])

    def test_incomplete_legacy_files_rejected_without_new_keys(self):
        self.make_legacy([1])
        created = FakeSigner.created
        with self.assertRaisesRegex(ValueError, "incomplete legacy"):
            self.run_experiment()
        self.assertEqual(FakeSigner.created, created)
        self.assertFalse(experiment.recovery_path(self.args, "TEST").exists())

    def test_validate_only_requires_full_coverage_and_never_generates_keys(self):
        self.args.validate_only = True
        with self.assertRaisesRegex(ValueError, "Missing signature outputs"):
            self.run_experiment()
        self.assertEqual(FakeSigner.created, 0)
        self.assertFalse(self.args.summary.exists())
        self.assertFalse((self.args.output_dir / "signature_progress.json").exists())

    def test_failed_verification_is_never_published(self):
        with patch.object(FakeSigner, "verify", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "Verification failed"):
                self.run_experiment()
        self.assertFalse(experiment.result_path(self.args, "TEST", 1).exists())
        checkpoint = experiment.load_json(experiment.recovery_path(self.args, "TEST", "_k1"))
        self.assertEqual(checkpoint["records"], 0)


if __name__ == "__main__":
    unittest.main()
