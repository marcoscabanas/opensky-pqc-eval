#!/usr/bin/env bash
# Project-local native dependency; never installs into $HOME/_oqs or /usr/local.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./scripts/bootstrap_liboqs.sh [--dry-run | --check | --help]

Build liboqs 0.16.0 under this checkout's .deps/liboqs.
--dry-run  Check prerequisites and print commands; no writes or network access.
--check    Check the existing local library only; no writes or network access.

Optional environment: LIBOQS_BUILD_JOBS (default 4), OPENSSL_ROOT_DIR.
Use liboqs-python==0.16.0.1 in the project's Python virtual environment.
EOF
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
bootstrap_mode=install
case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --dry-run) bootstrap_mode=dry-run ;;
    --check) bootstrap_mode=check ;;
    '') ;;
    *) usage >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { usage >&2; exit 2; }

bootstrap_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
bootstrap_deps="$bootstrap_root/.deps"
bootstrap_prefix="$bootstrap_deps/liboqs"
bootstrap_source="$bootstrap_deps/liboqs-source-0.16.0"
bootstrap_build="$bootstrap_deps/liboqs-build-0.16.0"
bootstrap_commit=5a1a854b0dc9f2141bdc771c555ee60c37950183
bootstrap_url=https://github.com/open-quantum-safe/liboqs.git
bootstrap_jobs=${LIBOQS_BUILD_JOBS:-4}
[[ "$bootstrap_jobs" =~ ^[1-9][0-9]*$ ]] || fail 'LIBOQS_BUILD_JOBS must be a positive integer.'

for bootstrap_path in "$bootstrap_deps" "$bootstrap_prefix" "$bootstrap_source" "$bootstrap_build"; do
    [[ ! -L "$bootstrap_path" ]] || fail "Refusing a symbolic-link destination: $bootstrap_path"
    [[ ! -e "$bootstrap_path" || -d "$bootstrap_path" ]] || fail "Expected a directory: $bootstrap_path"
done
command -v python3 >/dev/null || fail 'Install Python 3 first.'
case "$(uname -s)" in
    Darwin) bootstrap_library="$bootstrap_prefix/lib/liboqs.dylib" ;;
    Linux) bootstrap_library="$bootstrap_prefix/lib/liboqs.so" ;;
    *) fail 'This bootstrap supports macOS and Linux.' ;;
esac

check_native() {
    # ctypes loads this exact path; importing oqs could trigger its auto-installer.
    python3 - "$bootstrap_library" "$bootstrap_prefix" <<'PY'
import ctypes
from pathlib import Path
import sys

library_path, prefix = map(Path, sys.argv[1:])
if not library_path.is_file():
    sys.exit(f"Missing native library: {library_path}")
if prefix.resolve() not in library_path.resolve().parents:
    sys.exit(f"Library resolves outside its local prefix: {library_path}")
try:
    native = ctypes.CDLL(str(library_path))
    native.OQS_version.restype = ctypes.c_char_p
    version = native.OQS_version().decode("ascii")
    if version != "0.16.0":
        sys.exit(f"Expected liboqs 0.16.0, found {version}")
    native.OQS_SIG_alg_is_enabled.argtypes = [ctypes.c_char_p]
    native.OQS_SIG_alg_is_enabled.restype = ctypes.c_int
    required = ("ML-DSA-44", "Falcon-512", "SLH_DSA_PURE_SHA2_128S")
    missing = [name for name in required if not native.OQS_SIG_alg_is_enabled(name.encode())]
    if missing:
        sys.exit(f"Required mechanisms are unavailable: {', '.join(missing)}")
except (OSError, AttributeError) as exc:
    sys.exit(f"Cannot load compatible native library: {exc}")
print(f"Verified liboqs {version}: {library_path.resolve()}")
PY
}

if [[ -e "$bootstrap_prefix" ]]; then
    if check_native; then
        printf 'Compatible local installation exists; no files changed.\n'
        printf 'export OQS_INSTALL_PATH=%q\n' "$bootstrap_prefix"
        exit 0
    fi
    fail "Existing prefix is incomplete or incompatible; preserve or move it aside before retrying: $bootstrap_prefix"
fi
[[ "$bootstrap_mode" != check ]] || fail "Local installation is absent: $bootstrap_prefix"

for bootstrap_tool in git cmake make cc; do
    command -v "$bootstrap_tool" >/dev/null || fail "Missing prerequisite: $bootstrap_tool (see README.md)."
done
bootstrap_openssl=${OPENSSL_ROOT_DIR:-}
if [[ -z "$bootstrap_openssl" && "$(uname -s)" == Darwin ]] && command -v brew >/dev/null; then
    bootstrap_openssl=$(brew --prefix openssl@3 2>/dev/null || true)
fi
if [[ -n "$bootstrap_openssl" ]]; then
    [[ -f "$bootstrap_openssl/include/openssl/ssl.h" ]] || fail "OpenSSL headers missing under OPENSSL_ROOT_DIR: $bootstrap_openssl"
elif [[ ! -f /usr/include/openssl/ssl.h && ! -f /usr/local/include/openssl/ssl.h ]]; then
    fail 'Install OpenSSL development headers, or set OPENSSL_ROOT_DIR (see README.md).'
fi

# Preserve interrupted work. An existing source checkout must be the pinned,
# unmodified release. An existing build directory must have our ownership marker.
if [[ -e "$bootstrap_source" ]]; then
    [[ -d "$bootstrap_source/.git" ]] || fail "Unexpected source directory: $bootstrap_source"
    [[ "$(git -C "$bootstrap_source" rev-parse HEAD)" == "$bootstrap_commit" ]] || fail 'Existing source revision differs from the pinned release.'
    [[ -z "$(GIT_OPTIONAL_LOCKS=0 git -C "$bootstrap_source" status --porcelain --untracked-files=all)" ]] || fail 'Existing source checkout contains changes; preserve them before retrying.'
fi
if [[ -e "$bootstrap_build" ]]; then
    [[ -f "$bootstrap_build/.opensky-bootstrap-commit" ]] || fail "Unrecognized build directory: $bootstrap_build"
    [[ "$(cat "$bootstrap_build/.opensky-bootstrap-commit")" == "$bootstrap_commit" ]] || fail 'Existing build marker differs from the pinned release.'
fi

bootstrap_configure=(cmake -S "$bootstrap_source" -B "$bootstrap_build" -G 'Unix Makefiles'
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
    -DOQS_DIST_BUILD=ON -DOQS_USE_OPENSSL=ON -DOQS_ALGS_ENABLED=All
    -DOQS_ENABLE_SIG_STFL_LMS=OFF -DOQS_ENABLE_SIG_STFL_XMSS=OFF
    -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=OFF
    "-DCMAKE_INSTALL_PREFIX=$bootstrap_prefix" -DCMAKE_INSTALL_LIBDIR=lib)
if [[ -n "$bootstrap_openssl" ]]; then
    bootstrap_configure+=("-DOPENSSL_ROOT_DIR=$bootstrap_openssl")
fi
print_command() { printf '  '; printf '%q ' "$@"; printf '\n'; }
if [[ "$bootstrap_mode" == dry-run ]]; then
    printf 'Dry run: no files will be created; no commands below will run.\n'
    print_command git clone --depth 1 --branch 0.16.0 "$bootstrap_url" "$bootstrap_source"
    printf '  Require source commit %s\n' "$bootstrap_commit"
    print_command "${bootstrap_configure[@]}"
    print_command cmake --build "$bootstrap_build" --parallel "$bootstrap_jobs"
    print_command cmake --install "$bootstrap_build" --config Release
    printf '  Verify local native version and required signature mechanisms.\n'
    exit 0
fi

mkdir -p "$bootstrap_deps"
if [[ ! -d "$bootstrap_source" ]]; then
    git clone --depth 1 --branch 0.16.0 "$bootstrap_url" "$bootstrap_source"
fi
[[ "$(git -C "$bootstrap_source" rev-parse HEAD)" == "$bootstrap_commit" ]] || fail 'Downloaded release does not match the pinned commit.'
mkdir -p "$bootstrap_build"
printf '%s\n' "$bootstrap_commit" > "$bootstrap_build/.opensky-bootstrap-commit"
"${bootstrap_configure[@]}"
cmake --build "$bootstrap_build" --parallel "$bootstrap_jobs"
cmake --install "$bootstrap_build" --config Release
check_native

# Retain configure arguments and CMakeCache.txt for environment provenance.
printf '%s\n' "$bootstrap_commit" > "$bootstrap_prefix/source-commit.txt"
printf '%s\n' "${bootstrap_configure[@]}" > "$bootstrap_prefix/configure-arguments.txt"
cp "$bootstrap_build/CMakeCache.txt" "$bootstrap_prefix/build-CMakeCache.txt"
printf 'Installed native dependency. In the shell used to run experiments:\n'
printf 'export OQS_INSTALL_PATH=%q\n' "$bootstrap_prefix"
printf 'Then verify Python library selection as documented in README.md.\n'
