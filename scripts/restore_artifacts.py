#!/usr/bin/env python3
"""Restore Zenodo experiment inputs into the matching GitHub checkout.

Uses only the Python standard library. The code snapshot is a preservation copy;
normal restoration checks the existing checkout and never extracts archived code
or completed replay results.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import zipfile


PROFILES = ("replay", "fresh")
DEFAULT_DESTINATION = Path(__file__).resolve().parents[1]


def digest(path):
    """Return a file's SHA-256 without loading it into memory."""
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def safe_relative(value):
    """Accept normalized, portable relative paths, never archive traversal."""
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError(f"Unsafe archive path: {value!r}")
    path = PurePosixPath(value)
    if (path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/"))
            or any(ord(char) < 32 for char in value)):
        raise ValueError(f"Unsafe archive path: {value!r}")
    return path


def checked_path(root, relative):
    """Refuse symbolic links as well as paths escaping the destination."""
    relative = safe_relative(str(relative))
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"Refusing symbolic link in artifact path: {path}")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes destination: {relative}")
    return path


def _check_record(record, path_key):
    if not isinstance(record, dict):
        raise ValueError("Invalid artifact manifest record")
    safe_relative(record.get(path_key))
    if type(record.get("bytes")) is not int or record["bytes"] < 0:
        raise ValueError(f"Invalid byte count for {record[path_key]}")
    if not isinstance(record.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", record["sha256"]):
        raise ValueError(f"Invalid SHA-256 for {record[path_key]}")


def load_manifest(artifacts_dir):
    """Read and structurally validate the published artifact inventory."""
    path = checked_path(artifacts_dir, "artifact_manifest.json")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1
            or not isinstance(manifest.get("files"), list) or not manifest["files"]):
        raise ValueError("Unsupported or empty artifact manifest")
    filenames, restored_paths, code_items = set(), set(), []
    for item in manifest["files"]:
        _check_record(item, "filename")
        if len(safe_relative(item["filename"]).parts) != 1 or item["filename"] in filenames:
            raise ValueError(f"Invalid or duplicate download filename: {item['filename']}")
        filenames.add(item["filename"])
        if item.get("kind") not in {"raw", "prepared", "signed", "metadata_results", "code", "documentation"}:
            raise ValueError(f"Unknown artifact kind: {item.get('kind')!r}")
        if "restore_path" in item and "members" in item:
            raise ValueError("An artifact cannot be both an archive and a direct file")
        if "members" in item and not isinstance(item["members"], list):
            raise ValueError("Archive members must be a list")
        for entry in entries_for(item):
            _check_record(entry, "path")
            if entry["path"] in restored_paths:
                raise ValueError(f"Duplicate restored path: {entry['path']}")
            restored_paths.add(entry["path"])
        if item["kind"] == "code":
            code_items.append(item)
    if len(code_items) != 1 or not code_items[0].get("members"):
        raise ValueError("The manifest must contain exactly one nonempty code snapshot inventory")
    essential = {"run_experiment.py", "config/experiment.json", "src/main_experiment.py",
                 "scripts/restore_artifacts.py"}
    missing = essential - {entry["path"] for entry in code_items[0]["members"]}
    if missing:
        raise ValueError(f"Code snapshot inventory lacks required files: {', '.join(sorted(missing))}")
    return manifest


def entries_for(item):
    if "restore_path" in item:
        return [{"path": item["restore_path"], "bytes": item["bytes"], "sha256": item["sha256"]}]
    return item.get("members", [])


def selected(profile, path, kind):
    """Select inputs only; no profile restores code or completed outputs."""
    if profile not in PROFILES:
        raise ValueError(f"Unknown reproduction profile: {profile}")
    if kind == "code":
        return False
    parts = safe_relative(path).parts
    if parts[0] == "data":
        return True
    return profile == "replay" and len(parts) > 2 and parts[0] == "results" and (
        parts[1] in ("daytime", "nighttime") and (
            parts[2] in ("01_prepared", "02_signed")
            or (len(parts) == 3 and parts[2] == "input_audit.json")))


def verify_file(path, record):
    if not path.is_file():
        raise FileNotFoundError(f"Missing file: {path}")
    if path.stat().st_size != record["bytes"] or digest(path) != record["sha256"]:
        raise ValueError(f"Checksum mismatch: {path}")


def validate_checkout(destination, manifest):
    """Check every archived source file without downloading the code ZIP."""
    if not destination.is_dir():
        raise ValueError(f"Clone or unpack the matching code release first: {destination}")
    entries = next(item["members"] for item in manifest["files"] if item["kind"] == "code")
    for entry in entries:
        path = checked_path(destination, entry["path"])
        try:
            verify_file(path, entry)
        except (OSError, ValueError) as error:
            raise ValueError(
                f"Checkout does not match the Zenodo code snapshot: {entry['path']}. "
                "Use a clean checkout of the matching release; no files were restored."
            ) from error
    recorded = {entry["path"] for entry in entries}
    for path in (destination / "src").rglob("*.py"):
        if path.relative_to(destination).as_posix() not in recorded:
            raise ValueError(f"Unrecorded scientific source file in checkout: {path}")
    return len(entries)


def make_plan(manifest, profile):
    plan = [(item, entry) for item in manifest["files"] for entry in entries_for(item)
            if selected(profile, entry["path"], item["kind"])]
    if not plan:
        raise ValueError(f"No inputs found for profile {profile}")
    required = {item["filename"]: item for item, _ in plan}
    return plan, required


def validate_existing_inputs(destination, plan):
    """Allow interrupted restores to resume, but reject existing experiment output."""
    allowed = {entry["path"] for _, entry in plan}
    allowed_directories = {str(parent) for path in allowed for parent in PurePosixPath(path).parents}
    staging_parents = {str(PurePosixPath(path).parent) for path in allowed}
    results = checked_path(destination, "results")
    if results.exists():
        if not results.is_dir():
            raise ValueError(f"Results path is not a directory: {results}")
        for parent, directories, filenames in os.walk(results, topdown=True, followlinks=False):
            for name in list(directories) + filenames:
                path = Path(parent) / name
                relative = path.relative_to(destination).as_posix()
                checked_path(destination, relative)
                if (name in directories and re.fullmatch(r"\.adsb-restore-[a-z0-9_]{8}", name)
                        and path.parent.relative_to(destination).as_posix() in staging_parents):
                    contents = list(path.iterdir())
                    if any(child.name != "payload" or not stat.S_ISREG(child.lstat().st_mode)
                           for child in contents):
                        raise ValueError(f"Unexpected content in restore staging directory: {relative}")
                    # A killed process may leave an incomplete payload. Never
                    # reuse or remove it: another restore could still own it.
                    directories.remove(name)
                    continue
                expected = relative in (allowed_directories if path.is_dir() else allowed)
                if not expected:
                    raise ValueError(
                        f"Existing experiment output or unexpected result file: {relative}. "
                        "Use a new clean checkout; restoration never reuses completed replay outputs."
                    )
    existing = 0
    for _, entry in plan:
        path = checked_path(destination, entry["path"])
        if path.exists():
            try:
                verify_file(path, entry)
            except (OSError, ValueError) as error:
                raise FileExistsError(f"Refusing to overwrite different file: {path}") from error
            existing += 1
    return existing


def clone_or_copy(source, target):
    """Use an independent copy-on-write file when macOS supports it."""
    if sys.platform == "darwin":
        function = ctypes.CDLL(None, use_errno=True).clonefile
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        function.restype = ctypes.c_int
        if function(os.fsencode(source), os.fsencode(target), 0) == 0:
            return
    if shutil.disk_usage(target.parent).free < source.stat().st_size + 100 * 1024**2:
        raise OSError(f"Insufficient free space to restore {target.name}")
    shutil.copy2(source, target)


def restore_file(artifacts_dir, destination, item, entry):
    target = checked_path(destination, entry["path"])
    if target.exists():
        verify_file(target, entry)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    source = checked_path(artifacts_dir, item["filename"])
    # A complete, verified sibling is published atomically, with no overwrite.
    with tempfile.TemporaryDirectory(prefix=".adsb-restore-", dir=target.parent) as temporary:
        staged = Path(temporary) / "payload"
        if "restore_path" in item:
            clone_or_copy(source, staged)
        else:
            with zipfile.ZipFile(source) as archive:
                matches = [info for info in archive.infolist() if info.filename == entry["path"]]
                if len(matches) != 1:
                    raise ValueError(f"Missing or duplicate archive member: {entry['path']}")
                info = matches[0]
                mode = info.external_attr >> 16
                if (info.is_dir() or stat.S_ISLNK(mode)
                        or (stat.S_IFMT(mode) and not stat.S_ISREG(mode))
                        or info.file_size != entry["bytes"]):
                    raise ValueError(f"Invalid archive member: {entry['path']}")
                with archive.open(info) as input_stream, staged.open("xb") as output_stream:
                    shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
        verify_file(staged, entry)
        try:
            os.link(staged, target)
        except FileExistsError:
            # Another concurrent restore may have published the identical file.
            verify_file(target, entry)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, required=True,
                        help="download directory containing artifact_manifest.json and selected Zenodo files")
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION,
                        help="matching checkout root (default: this script's repository)")
    parser.add_argument("--profile", choices=PROFILES,
                        help="replay: use saved signatures; fresh: start from raw recordings")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true", help="check checkout and list downloads without writing")
    modes.add_argument("--verify-only", action="store_true", help="verify every upload; requires the complete package")
    args = parser.parse_args(argv)
    artifacts_dir = args.artifacts_dir.resolve()
    manifest = load_manifest(artifacts_dir)
    if args.verify_only:
        for item in manifest["files"]:
            verify_file(checked_path(artifacts_dir, item["filename"]), item)
            print("OK", item["filename"], flush=True)
        print(f"Verified all {len(manifest['files'])} manifest-listed uploads.")
        return 0
    if args.profile is None:
        parser.error("--profile replay or --profile fresh is required for restoration")
    destination = args.destination.resolve()
    code_count = validate_checkout(destination, manifest)
    plan, required = make_plan(manifest, args.profile)
    existing = validate_existing_inputs(destination, plan)
    print(f"Checkout matches all {code_count} code files in the Zenodo snapshot.")
    print(f"Profile {args.profile}: {len(plan)} input files ({existing} already restored), "
          f"{len(required)} downloads, {sum(item['bytes'] for item in required.values()):,} download bytes, "
          f"{sum(entry['bytes'] for _, entry in plan):,} restored bytes.")
    print("The code snapshot ZIP is not required; completed results are never restored.")
    for name in sorted(required):
        print("Requires", name)
    if args.dry_run:
        print("Dry run: no files written. Download checksums are checked during restoration.")
        return 0
    # Verify every required download before writing any input files.
    for name, item in required.items():
        source = checked_path(artifacts_dir, name)
        if not source.exists():
            raise FileNotFoundError(f"Download {name} into {artifacts_dir} first")
        verify_file(source, item)
    for item, entry in plan:
        restore_file(artifacts_dir, destination, item, entry)
    print(f"Restored and verified {len(plan)} input files in {destination}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
