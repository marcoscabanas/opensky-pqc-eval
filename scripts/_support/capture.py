#!/usr/bin/env python3
"""Record a receiver's TCP bytes unchanged, without decoding or replacing timestamps.

The binary stream needs offline format/timestamp validation and an adapter before
it can enter the experiment. Run this command yourself after connecting the VPN.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import time


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def capture(output, *, host="airsquitter.lr.tudelft.nl", port=10004, duration_s=4260):
    """Return a metadata record; interrupted or failed captures remain incomplete."""
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a nonempty hostname.")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535.")
    if (isinstance(duration_s, bool) or not isinstance(duration_s, (int, float))
            or not math.isfinite(duration_s) or duration_s <= 0):
        raise ValueError("duration-s must be a finite positive number.")
    output = Path(output).expanduser().absolute()
    if output.suffix != ".beast":
        raise ValueError("output must have the .beast extension.")
    sidecar = output.with_suffix(output.suffix + ".json")
    for path in (output, sidecar):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing path: {path}")
    info = {
        "schema_version": 1, "host": host, "port": port,
        "raw_file": output.name, "requested_duration_s": duration_s,
        "host_clock_started_utc": _utc_now(), "host_clock_connected_utc": None,
        "host_clock_finished_utc": None, "network_elapsed_s": None,
        "network_duration_completed": False, "complete": False,
        "stop_reason": "not_connected", "error": None,
        "byte_count": 0, "sha256": None,
        "raw_format_assumption": "Beast binary, inferred from the endpoint; not verified by this recorder.",
        "host_clock_note": "Host clock fields describe recording activity; they are NOT radio reception timestamps.",
        "capture_scope": "Unmodified TCP bytes, including whatever the receiver exports; "
                         "this does not establish complete capture of all 1090 MHz transmissions.",
        "offline_validation_required": "Validate stream format, receiver timestamps, drops and coverage "
                                       "before adapting this recording for the experiment.",
    }
    connected_at = None
    # Both exclusive reservations precede the network connection. 'x' also
    # rejects a file or symlink created between the precheck and opening.
    with output.open("xb") as raw, sidecar.open("x", encoding="utf-8") as metadata:
        try:
            with socket.create_connection((host, port), timeout=10) as stream:
                connected_at = time.monotonic()
                info["host_clock_connected_utc"] = _utc_now()
                deadline = connected_at + duration_s
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        info["network_duration_completed"] = True
                        info["stop_reason"] = "requested_duration_elapsed"
                        break
                    stream.settimeout(min(1.0, remaining))
                    try:
                        block = stream.recv(65536)
                    except socket.timeout:
                        continue
                    if not block:
                        info["stop_reason"] = "remote_eof"
                        break
                    raw.write(block)
                    info["byte_count"] += len(block)
        except KeyboardInterrupt:
            info["stop_reason"] = "interrupted"
        except OSError as error:
            info["stop_reason"] = "io_error"
            info["error"] = f"{type(error).__name__}: {error}"
        finally:
            if connected_at is not None:
                info["network_elapsed_s"] = time.monotonic() - connected_at
            info["host_clock_finished_utc"] = _utc_now()
            try:
                raw.flush()
                os.fsync(raw.fileno())
            except OSError as error:
                info["stop_reason"] = "persistence_error"
                info["error"] = f"{type(error).__name__}: {error}"
            # Hash the saved file itself, including any partial write on error.
            digest = hashlib.sha256()
            with output.open("rb") as saved:
                for block in iter(lambda: saved.read(1024 * 1024), b""):
                    digest.update(block)
            info["sha256"] = digest.hexdigest()
            info["byte_count"] = output.stat().st_size
            if info["stop_reason"] == "requested_duration_elapsed" and not info["byte_count"]:
                info["stop_reason"] = "no_bytes_received"
            info["complete"] = (info["stop_reason"] == "requested_duration_elapsed"
                                and info["byte_count"] > 0)
            json.dump(info, metadata, indent=2, allow_nan=False)
            metadata.write("\n")
            metadata.flush()
            os.fsync(metadata.fileno())
    return info


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="airsquitter.lr.tudelft.nl")
    parser.add_argument("--port", type=int, default=10004)
    parser.add_argument("--duration-s", type=float, default=4260,
                        help="Recording duration after connecting (default: 4260 seconds / 71 minutes).")
    parser.add_argument("--output", type=Path, required=True,
                        help="New .beast file; metadata is saved as <output>.json. Neither is overwritten.")
    args = parser.parse_args(argv)
    print("Recording unchanged TCP bytes. Host clock times are not RF reception timestamps.", flush=True)
    try:
        info = capture(args.output, host=args.host, port=args.port, duration_s=args.duration_s)
    except (OSError, ValueError) as error:
        parser.exit(2, f"ERROR: {error}\n")
    print(f"{'COMPLETE' if info['complete'] else 'INCOMPLETE'}: {info['byte_count']} bytes; "
          f"{info['stop_reason']}. Metadata: {args.output}.json", flush=True)
    print("Offline stream and timestamp validation is required before the experiment.", flush=True)
    return 0 if info["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
