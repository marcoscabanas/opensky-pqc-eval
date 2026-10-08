# Native cryptography setup

Run these commands from the repository root. The native dependency is **liboqs
0.16.0**, pinned to release commit
[`5a1a854b0dc9f2141bdc771c555ee60c37950183`](https://github.com/open-quantum-safe/liboqs/commit/5a1a854b0dc9f2141bdc771c555ee60c37950183).
Use **liboqs-python 0.16.0.1**, whose maintenance release targets native 0.16.0.
[Wrapper release notes](https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0.1).

Install prerequisites on macOS (with Homebrew and Xcode command line tools):

```bash
xcode-select --install  # Only if the command line tools are absent.
brew install cmake openssl@3 python@3.13
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

On Ubuntu/Debian Linux:

```bash
sudo apt-get update
sudo apt-get install build-essential git cmake libssl-dev python3 python3-venv
```

Use Python 3.13 for the pinned environment; the recorded development environment used 3.13.3. The package minimum of 3.11 does not apply to every pinned dependency.
Other Linux distributions need equivalent C compiler, Make, Git, CMake, OpenSSL
development headers, Python, and venv packages. These prerequisites follow the
[native library build instructions](https://github.com/open-quantum-safe/liboqs/blob/0.16.0/README.md).

Build the native library before importing `oqs`:

```bash
./scripts/bootstrap_liboqs.sh --dry-run
./scripts/bootstrap_liboqs.sh
export OQS_INSTALL_PATH="$PWD/.deps/liboqs"
./scripts/bootstrap_liboqs.sh --check
```

The script builds only the shared library, in Release mode with distribution
dispatch and OpenSSL enabled. Stateful algorithms remain disabled because this
study uses stateless signatures. The flags follow the wrapper's installer and
the [native build options](https://github.com/open-quantum-safe/liboqs/blob/0.16.0/CONFIGURE.md).
Source, build, and install directories stay under `.deps/`; no home-directory or
system installation is changed. Set `LIBOQS_BUILD_JOBS=2` before running the script
to reduce build parallelism. `--dry-run` and `--check` perform no downloads or
writes. An existing local installation with the correct version and all three PQ
mechanisms is reused. An incomplete or incompatible prefix causes an error;
preserve or move that directory aside explicitly before retrying. There is no
automatic cleanup. The installed `source-commit.txt`, `configure-arguments.txt`,
and `build-CMakeCache.txt` record a new build's source and configuration. Matching
source versions does not promise identical timings across CPUs, compilers, or
OpenSSL versions.

Install the pinned Python cryptography dependencies in a virtual environment. If you already created and activated `.venv` from the main README, skip the first two lines:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r config/requirements/crypto.txt
```

Set the platform's library lookup path in every experiment shell, before starting
Python:

```bash
export OQS_INSTALL_PATH="$PWD/.deps/liboqs"
# Linux:
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# macOS (use this instead of the Linux line):
export DYLD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
```

The wrapper can find a system library before considering `OQS_INSTALL_PATH`. If
no library can be loaded, importing `oqs` attempts an automatic native build; its
default prefix is `~/_oqs` when `OQS_INSTALL_PATH` is unset. The explicit bootstrap
and check above prevent reliance on that behavior. The
[wrapper source](https://github.com/open-quantum-safe/liboqs-python/blob/0.16.0.1/oqs/oqs.py)
defines this lookup order. On macOS, protected system launchers can strip `DYLD_*`
variables; use the virtual environment's Python from the configured shell.

Verify both versions and the loaded path, then run the real sign/verify smoke
test. The path assertion intentionally fails if a system library wins lookup:

```bash
python - <<'PY'
import ctypes
import ctypes.util
import os
from pathlib import Path
import sys

prefix = Path(os.environ["OQS_INSTALL_PATH"]).resolve()
suffix = "dylib" if sys.platform == "darwin" else "so"
expected = prefix / "lib" / f"liboqs.{suffix}"
ctypes.CDLL(str(expected))  # Fail before wrapper import if native loading is broken.
import oqs

# Resolve the loaded symbol's image, including a bare Linux soname lookup.
class DlInfo(ctypes.Structure):
    _fields_ = [("dli_fname", ctypes.c_char_p), ("dli_fbase", ctypes.c_void_p),
                ("dli_sname", ctypes.c_char_p), ("dli_saddr", ctypes.c_void_p)]

loader = ctypes.CDLL(ctypes.util.find_library("dl") or None)
loader.dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(DlInfo)]
loader.dladdr.restype = ctypes.c_int
info = DlInfo()
assert loader.dladdr(ctypes.cast(oqs.oqs.native().OQS_version, ctypes.c_void_p),
                     ctypes.byref(info)), "Cannot identify the loaded library"
loaded = Path(os.fsdecode(info.dli_fname)).resolve()
print("Native:", oqs.oqs_version(), "Wrapper:", oqs.oqs_python_version())
print("Loaded library:", loaded)
assert oqs.oqs_version() == "0.16.0"
assert oqs.oqs_python_version() == "0.16.0.1"
assert loaded == expected.resolve(), (
    "Resolve system-library lookup before recording benchmark results."
)
required = {"ML-DSA-44", "Falcon-512", "SLH_DSA_PURE_SHA2_128S"}
assert required.issubset(oqs.get_enabled_sig_mechanisms())
PY
python -m tests.test_crypto
```

The smoke test generates ephemeral keys, signs and verifies one message with
each of ECDSA P-256, ML-DSA-44, Falcon-512, and SLH-DSA-SHA2-128s, and rejects a
modified message. Its historical `FN-DSA-512` label denotes the `Falcon-512`
backend; it does not establish a finalized FN-DSA implementation. No keys are
written. Library setup and smoke testing are separate from the replay's published
embedded timing profiles; rebuilding the host library does not remeasure those
profiles.
