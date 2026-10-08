import base64
import copy
import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.experiment import signed_workload as workload
from src.experiment.replay_transport import context_bytes, decode_envelope, encode_envelope


def trace_fixture():
    return [{"trace_id": f"m{index}", "relative_time_s": index * 0.2,
             "icao": "40621D", "raw_msg": f"8D40621D58C382D690C8AC2863{0xA7 + index:02X}"}
            for index in range(3)]


def aircraft_trace(count=3, messages=3):
    rows = []
    for aircraft in range(count):
        icao = f"{aircraft + 1:06X}"
        for index, source in enumerate(trace_fixture()[:messages]):
            rows.append({**source, "trace_id": f"{icao}-{index}", "icao": icao,
                         "relative_time_s": source["relative_time_s"] + aircraft * .01,
                         "raw_msg": source["raw_msg"][:2] + icao + source["raw_msg"][8:]})
    return rows


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography is not installed")
class SignedWorkloadTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cache = Path(self.temporary.name)
        self.trace = trace_fixture()

    def build(self, interval=1, max_wait=None, trace=None):
        return workload.build_or_load_workload(self.trace if trace is None else trace,
                                               "ECDSA-P256", interval, max_wait, self.cache)

    def rewrite_groups(self, result, change):
        path = Path(result["evidence"]["cache_dir"])
        rows = [json.loads(line) for line in (path / "groups.jsonl").read_text().splitlines()]
        change(rows)
        (path / "groups.jsonl").write_bytes(b"".join(workload._json_bytes(row) for row in rows))
        manifest = json.loads((path / "manifest.json").read_text())
        manifest["groups_sha256"] = workload.sha256_file(path / "groups.jsonl")
        (path / "manifest.json").write_bytes(workload._json_bytes(manifest))

    def test_actual_context_signatures_are_reused_byte_for_byte(self):
        result = self.build()
        directory = Path(result["evidence"]["cache_dir"])
        snapshots = {path.name: path.read_bytes() for path in directory.iterdir()}
        with patch.object(workload, "make_envelope", side_effect=AssertionError("must reuse")):
            repeated = self.build(trace=list(reversed(self.trace)))
        self.assertEqual(result, repeated)
        self.assertEqual(snapshots, {path.name: path.read_bytes() for path in directory.iterdir()})
        self.assertEqual(result["unsigned_trace_ids"], [])
        self.assertEqual(result["evidence"]["cryptographically_verified_signatures"], 3)
        self.assertEqual(set(snapshots), {"manifest.json", "groups.jsonl", "public_keys.json"})
        self.assertFalse(result["evidence"]["private_keys_persisted"])
        self.assertEqual(len({group["public_key"] for group in result["groups"]}), 1)
        for group in result["groups"]:
            verify = workload.verifier_for("ECDSA-P256", group["public_key"])
            self.addCleanup(verify.close)
            source = next(row for row in self.trace if row["trace_id"] == group["members"][0])
            raw = bytes.fromhex(source["raw_msg"])
            self.assertTrue(verify(context_bytes(group["descriptor"]) + raw, group["envelope"].signature))
            self.assertFalse(verify(raw, group["envelope"].signature))

    def test_fixed_groups_leave_partial_tail_unsigned(self):
        result = self.build(interval=2)
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["groups"][0]["members"], ("m0", "m1"))
        self.assertEqual(result["groups"][0]["formed_s"], 0.2)
        self.assertEqual(result["unsigned_trace_ids"], ["m2"])

    def test_validate_only_never_creates_files_or_signs(self):
        absent = self.cache / "not-created"
        with patch.object(workload, "make_envelope", side_effect=AssertionError("must not sign")):
            with self.assertRaisesRegex(ValueError, "No completed"):
                workload.build_or_load_workload(self.trace, "ECDSA-P256", 1, None, absent,
                                               validate_only=True)
        self.assertFalse(absent.exists())
        result = self.build()
        before = {str(path): (path.read_bytes(), path.stat().st_mtime_ns)
                  for path in self.cache.rglob("*") if path.is_file()}
        with patch.object(workload, "make_envelope", side_effect=AssertionError("must not sign")):
            repeated = workload.build_or_load_workload(self.trace, "ECDSA-P256", 1, None, self.cache,
                                                      validate_only=True)
        self.assertEqual(result, repeated)
        self.assertEqual(before, {str(path): (path.read_bytes(), path.stat().st_mtime_ns)
                                  for path in self.cache.rglob("*") if path.is_file()})

    def test_backend_identity_reports_actual_module_and_implementation(self):
        identity = workload.backend_identity("ECDSA-P256")
        self.assertEqual(identity["module"], "src.crypto.ecdsa_p256")
        self.assertEqual(identity["implementation"], "SECP256R1")
        module = workload.load_algorithm_module(workload._algorithm_config("ECDSA-P256"))
        with patch.object(module, "IMPLEMENTATION", "not-the-configured-implementation"):
            with self.assertRaisesRegex(ValueError, "actual crypto implementation"):
                self.build()

    def test_timeout_policy_and_trace_change_cache_identity(self):
        fixed = self.build(interval=2)
        timeout = self.build(interval=2, max_wait=0.1)
        self.assertNotEqual(fixed["evidence"]["cache_dir"], timeout["evidence"]["cache_dir"])
        self.assertEqual(len(timeout["groups"]), 3)
        self.assertEqual([row["formed_s"] for row in timeout["groups"]], [0.1, 0.30000000000000004, 0.5])
        self.assertEqual(timeout["unsigned_trace_ids"], [])
        changed = copy.deepcopy(self.trace)
        changed[0]["raw_msg"] = changed[0]["raw_msg"][:-2] + "AB"
        different = self.build(interval=2, trace=changed)
        self.assertNotEqual(fixed["evidence"]["cache_identity"], different["evidence"]["cache_identity"])

    def test_timeout_includes_message_at_exact_boundary(self):
        result = self.build(interval=2, max_wait=0.2)
        self.assertEqual(result["groups"][0]["members"], ("m0", "m1"))
        self.assertEqual(result["groups"][1]["members"], ("m2",))
        self.assertAlmostEqual(result["groups"][1]["formed_s"], 0.6)

    def test_signature_tamper_rejected_even_after_rehash(self):
        result = self.build()

        def corrupt(rows):
            envelope = decode_envelope(base64.b64decode(rows[0]["envelope"]))
            altered = dataclasses.replace(envelope, signature=b"\0" * len(envelope.signature))
            rows[0]["envelope"] = base64.b64encode(encode_envelope(altered)).decode("ascii")

        self.rewrite_groups(result, corrupt)
        with self.assertRaisesRegex(ValueError, "cryptographic verification"):
            self.build()

    def test_membership_tamper_rejected_even_after_rehash(self):
        result = self.build()
        self.rewrite_groups(result, lambda rows: rows[0].update(members=["m1"]))
        with self.assertRaisesRegex(ValueError, "membership"):
            self.build()

    def test_context_tamper_rejected_even_after_rehash(self):
        result = self.build()

        def corrupt(rows):
            envelope = decode_envelope(base64.b64decode(rows[0]["envelope"]))
            altered = dataclasses.replace(envelope, descriptor=dataclasses.replace(envelope.descriptor, seq=9))
            rows[0]["envelope"] = base64.b64encode(encode_envelope(altered)).decode("ascii")

        self.rewrite_groups(result, corrupt)
        with self.assertRaisesRegex(ValueError, "context"):
            self.build()

    def test_missing_and_extra_groups_rejected_even_after_rehash(self):
        for alteration in (lambda rows: rows.pop(), lambda rows: rows.append(rows[-1])):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as directory:
                self.cache = Path(directory)
                result = self.build()
                self.rewrite_groups(result, alteration)
                with self.assertRaisesRegex(ValueError, "missing a group|unexpected trailing groups"):
                    self.build()

    def test_checksum_or_manifest_failure_does_not_rebuild_silently(self):
        result = self.build()
        path = Path(result["evidence"]["cache_dir"])
        with (path / "groups.jsonl").open("ab") as stream:
            stream.write(b"\n")
        with patch.object(workload, "make_envelope", side_effect=AssertionError("must not rebuild")):
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.build()
        (path / "manifest.json").unlink()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.build()

    def test_interruption_leaves_only_public_partial_checkpoint_and_rebuilds(self):
        actual = workload.make_envelope
        calls = 0

        def interrupt(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt("simulated interruption")
            return actual(*args, **kwargs)

        with patch.object(workload, "make_envelope", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.build()
        directories = [path for path in self.cache.iterdir() if path.is_dir()]
        self.assertEqual(len(directories), 1)
        self.assertTrue(directories[0].name.endswith(".partial"))
        self.assertEqual([path.name for path in directories[0].iterdir()], ["identity.json"])
        self.assertEqual(len(self.build()["groups"]), 3)

    def test_process_workers_preserve_groups_keys_and_cache_identity(self):
        trace = aircraft_trace()
        result = workload.build_or_load_workload(trace, "ECDSA-P256", 1, None, self.cache, workers=2)
        self.assertEqual(len(result["groups"]), 9)
        self.assertEqual(result["evidence"]["cryptographically_verified_signatures"], 9)
        aircraft_keys = {}
        for group in result["groups"]:
            icao = group["members"][0].split("-")[0]
            aircraft_keys.setdefault(icao, set()).add(group["public_key"])
        self.assertEqual(len(aircraft_keys), 3)
        self.assertTrue(all(len(keys) == 1 for keys in aircraft_keys.values()))
        self.assertEqual(len({next(iter(keys)) for keys in aircraft_keys.values()}), 3)
        with patch.object(workload, "_build_aircraft", side_effect=AssertionError("must reuse")):
            serial = workload.build_or_load_workload(trace, "ECDSA-P256", 1, None, self.cache, workers=1)
        self.assertEqual(result, serial)
        other = workload.build_or_load_workload(trace, "ECDSA-P256", 1, None,
                                                self.cache / "independent", workers=1)
        self.assertEqual(result["evidence"]["cache_identity"], other["evidence"]["cache_identity"])
        self.assertEqual([row["members"] for row in result["groups"]],
                         [row["members"] for row in other["groups"]])
        self.assertEqual([row["formed_s"] for row in result["groups"]],
                         [row["formed_s"] for row in other["groups"]])

    def interrupted_aircraft_build(self):
        trace = aircraft_trace(count=2)
        actual = workload.make_envelope
        count = 0

        def interrupt(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 4:
                raise KeyboardInterrupt("after first complete aircraft")
            return actual(*args, **kwargs)

        with patch.object(workload, "make_envelope", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                workload.build_or_load_workload(trace, "ECDSA-P256", 1, None, self.cache, workers=1)
        checkpoints = next(self.cache.glob("*.partial"))
        return trace, checkpoints / "000001"

    def test_completed_aircraft_checkpoint_is_reused_after_interruption(self):
        trace, shard = self.interrupted_aircraft_build()
        first_rows = [json.loads(line) for line in (shard / "groups.jsonl").read_text().splitlines()]
        first_key = json.loads((shard / "public_keys.json").read_text())["000001"]
        with patch.object(workload, "make_envelope", wraps=workload.make_envelope) as sign:
            result = workload.build_or_load_workload(trace, "ECDSA-P256", 1, None, self.cache, workers=1)
        self.assertEqual(sign.call_count, 3)
        self.assertFalse(shard.parent.exists())
        groups = [row for row in result["groups"] if row["members"][0].startswith("000001-")]
        self.assertEqual(len(groups), 3)
        for row, original in zip(groups, first_rows):
            self.assertEqual(base64.b64encode(encode_envelope(row["envelope"])).decode(), original["envelope"])
            self.assertEqual(base64.b64encode(row["public_key"]).decode(), first_key)

    def test_rehashed_checkpoint_signature_tamper_is_rejected_on_resume(self):
        trace, shard = self.interrupted_aircraft_build()
        rows = [json.loads(line) for line in (shard / "groups.jsonl").read_text().splitlines()]
        envelope = decode_envelope(base64.b64decode(rows[0]["envelope"]))
        corrupted = dataclasses.replace(envelope, signature=b"\0" * 64)
        rows[0]["envelope"] = base64.b64encode(encode_envelope(corrupted)).decode()
        (shard / "groups.jsonl").write_bytes(b"".join(workload._json_bytes(row) for row in rows))
        manifest = json.loads((shard / "manifest.json").read_text())
        manifest["groups_sha256"] = workload.sha256_file(shard / "groups.jsonl")
        (shard / "manifest.json").write_bytes(workload._json_bytes(manifest))
        with patch.object(workload, "make_envelope", side_effect=AssertionError("must not sign")):
            with self.assertRaisesRegex(ValueError, "cryptographic verification"):
                workload.build_or_load_workload(trace, "ECDSA-P256", 1, None, self.cache, workers=1)

    def test_many_aircraft_merge_limits_open_files_and_preserves_order(self):
        trace = aircraft_trace(count=67, messages=1)
        with patch.object(workload, "_merge_group_files", wraps=workload._merge_group_files) as merge:
            result = workload.build_or_load_workload(trace, "ECDSA-P256", 1, None, self.cache, workers=1)
        self.assertEqual(len(result["groups"]), 67)
        self.assertEqual(merge.call_count, 3)
        self.assertTrue(all(len(call.args[0]) <= 64 for call in merge.call_args_list))
        self.assertEqual([group["members"][0] for group in result["groups"]],
                         [row["trace_id"] for row in sorted(trace, key=lambda row: row["relative_time_s"])])

    def test_worker_count_is_explicit_validated_execution_setting(self):
        with patch.dict(os.environ, {"ADSB_SIGNING_WORKERS": "2"}):
            self.assertEqual(workload._worker_count(None), 2)
            self.assertEqual(workload._worker_count(1), 1)
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "positive integer"):
                workload._worker_count(value)
        with patch.dict(os.environ, {"ADSB_SIGNING_WORKERS": "invalid"}):
            with self.assertRaisesRegex(ValueError, "positive integer"):
                workload._worker_count(None)

    def test_group_without_complete_members_has_no_key_or_signature(self):
        result = self.build(interval=4)
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["unsigned_trace_ids"], ["m0", "m1", "m2"])
        self.assertEqual(self.build(interval=4), result)

    def test_invalid_trace_and_batch_policy_are_rejected(self):
        for interval, max_wait in ((0, None), (True, None), (1, 0), (1, float("nan"))):
            with self.subTest(interval=interval, max_wait=max_wait), self.assertRaises(ValueError):
                self.build(interval, max_wait)
        for mutate in (lambda rows: rows.append(rows[0]),
                       lambda rows: rows[0].update(relative_time_s=float("nan")),
                       lambda rows: rows[0].update(icao="FFFFFF"),
                       lambda rows: rows[0].update(raw_msg="5D40621D58C382")):
            rows = copy.deepcopy(self.trace)
            mutate(rows)
            with self.assertRaises(ValueError):
                self.build(trace=rows)


class NativeSignedWorkloadTest(unittest.TestCase):
    def test_spawned_workers_sign_and_verify_native_algorithms(self):
        try:
            oqs = workload._installed_oqs()
        except RuntimeError as exc:
            self.skipTest(str(exc))
        for algorithm in ("ML-DSA-44", "FN-DSA-512"):
            if workload._algorithm_config(algorithm)["implementation"] not in oqs.get_enabled_sig_mechanisms():
                continue
            with self.subTest(algorithm=algorithm), tempfile.TemporaryDirectory() as directory:
                result = workload.build_or_load_workload(aircraft_trace(count=2), algorithm, 2, None,
                                                        directory, workers=2)
                self.assertEqual(result["evidence"]["cryptographically_verified_signatures"], 2)
                self.assertEqual(len(result["unsigned_trace_ids"]), 2)
                self.assertEqual(len({row["public_key"] for row in result["groups"]}), 2)

    def test_real_post_quantum_signatures_verify_from_public_cache(self):
        try:
            oqs = workload._installed_oqs()
        except RuntimeError as exc:
            self.skipTest(str(exc))
        for algorithm in ("ML-DSA-44", "FN-DSA-512", "SLH-DSA-SHA2-128s"):
            if workload._algorithm_config(algorithm)["implementation"] not in oqs.get_enabled_sig_mechanisms():
                continue
            with self.subTest(algorithm=algorithm), tempfile.TemporaryDirectory() as directory:
                trace = trace_fixture()[:2]
                result = workload.build_or_load_workload(trace, algorithm, 2, None, directory)
                self.assertEqual(len(result["groups"]), 1)
                group = result["groups"][0]
                verify = workload.verifier_for(algorithm, group["public_key"])
                try:
                    transcript = context_bytes(group["descriptor"]) + b"".join(bytes.fromhex(row["raw_msg"]) for row in trace)
                    self.assertTrue(verify(transcript, group["envelope"].signature))
                    self.assertFalse(verify(transcript + b"tamper", group["envelope"].signature))
                finally:
                    verify.close()
                with patch.object(workload, "make_envelope", side_effect=AssertionError("must reuse")):
                    self.assertEqual(workload.build_or_load_workload(trace, algorithm, 2, None, directory), result)

    def test_missing_native_library_fails_before_import_or_download(self):
        with patch.dict(workload.sys.modules, {"oqs": None}):
            # Remove the preloaded module only for this guarded call.
            del workload.sys.modules["oqs"]
            with patch.object(workload.importlib.util, "find_spec", return_value=object()), \
                    patch.object(workload.ctypes.util, "find_library", return_value=None), \
                    patch.object(workload.ctypes, "CDLL", side_effect=OSError("missing")), \
                    patch.object(workload.importlib, "import_module", side_effect=AssertionError("must not import")):
                with self.assertRaisesRegex(RuntimeError, "automatic downloading is disabled"):
                    workload._installed_oqs()


if __name__ == "__main__":
    unittest.main()
