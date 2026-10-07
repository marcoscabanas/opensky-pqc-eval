import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.runtime import RunLock, atomic_json


class RuntimeTest(unittest.TestCase):
    def test_other_process_rejected_then_crash_releases_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.lock"
            child = subprocess.Popen(
                [sys.executable, "-u", "-c",
                 "import sys,time; from src.runtime import RunLock; "
                 "lock=RunLock(sys.argv[1]); lock.__enter__(); print('ready'); time.sleep(30)",
                 str(path)], stdout=subprocess.PIPE, text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                with self.assertRaisesRegex(RuntimeError, "Another run"):
                    with RunLock(path):
                        self.fail("Second process obtained the lock")
            finally:
                child.kill()
                child.wait()
                child.stdout.close()
            with RunLock(path):
                self.assertTrue(path.exists())

    def test_failed_atomic_write_keeps_previous_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            atomic_json(path, {"state": "running"})
            with self.assertRaises(TypeError):
                atomic_json(path, {"bad": object()})
            self.assertIn('"running"', path.read_text())
            self.assertEqual(list(Path(directory).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
