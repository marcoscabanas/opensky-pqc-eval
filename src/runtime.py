"""Small POSIX runtime helpers for mutually exclusive, observable runs."""

import fcntl
import json
import os
import tempfile
from pathlib import Path


def atomic_json(path, value, *, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class RunLock:
    """Advisory lock released by the OS on exit, including crashes.

    Keep the lock inode in place: unlinking it would allow concurrent owners.
    The PID is diagnostic; the kernel lock, not PID existence, is authoritative.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.handle.seek(0)
            owner = self.handle.read().strip()
            self.handle.close()
            self.handle = None
            raise RuntimeError(f"Another run owns {self.path}: {owner}") from exc
        try:
            self.handle.seek(0)
            self.handle.truncate()
            json.dump({"pid": os.getpid()}, self.handle)
            self.handle.flush()
        except BaseException:
            self.handle.close()
            self.handle = None
            raise
        return self

    def __exit__(self, *exc):
        if self.handle is not None:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None
