#!/usr/bin/env bash
#
# liboqs/mayhem/build.sh — build open-quantum-safe/liboqs' four OSS-Fuzz harnesses as sanitized
# libFuzzer targets (+ standalone reproducers), and build liboqs' OWN KAT test programs (test_kem /
# test_sig) with normal flags so mayhem/test.sh can RUN them.
#
# The fuzzed surface is liboqs' post-quantum KEM / signature primitives driven on attacker-controlled
# bytes. Every harness reads a small header (uint32 random_seed + uint32 algorithm_index) off the
# front of the input, picks a PQC algorithm by index (mod the algorithm count), seeds a deterministic
# RNG with the seed, then runs the full keygen -> encaps/sign -> decaps/verify cycle, feeding the rest
# of the input bytes into the shared-secret / message buffer:
#   fuzz_test_kem          — OQS_KEM keypair/encaps/decaps round-trip (KEM decapsulation surface).
#   fuzz_test_sig          — OQS_SIG keypair/sign/verify round-trip (signature verification surface).
#   fuzz_test_sig_stfl_lms — stateful LMS hash-based signature import/verify surface.
#   fuzz_test_sig_stfl_xmss— stateful XMSS hash-based signature import/verify surface.
# Inputs are NOT files of a fixed format — they are raw byte blobs; the leading 8 bytes select the
# algorithm + RNG seed and the remainder is fed to the crypto buffers.
#
# liboqs already wires the fuzzers in tests/CMakeLists.txt under -DOQS_BUILD_FUZZ_TESTS=ON and honors
# the OSS-Fuzz $LIB_FUZZING_ENGINE env (CMakeLists.txt:59). We build the WHOLE library + harnesses with
# $SANITIZER_FLAGS injected as CMAKE_C_FLAGS so the PQC code (not just the harness) is instrumented.
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN/
# SRC. $OUT defaults to /mayhem.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem triage can read symbols (clang-19 plain -g emits DWARF-5).
# Threaded AFTER $SANITIZER_FLAGS so it wins over any -g already in SANITIZER_FLAGS.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${OUT:=/mayhem}"

# Inject -fsanitize=fuzzer-no-link when SANITIZER_FLAGS does not already carry any fuzzer variant.
# This flag is required so that the liboqs library objects (compiled via CMAKE_C_FLAGS=$SANITIZER_FLAGS)
# are instrumented with SanCov edge counters.  Without it the library is uninstrumented and Mayhem
# sees 0 edges on all four targets even though the harnesses link successfully and the fuzz-smoke
# startup test passes.  -fsanitize=fuzzer-no-link adds instrumentation but does NOT pull in the
# libFuzzer driver runtime (that comes separately at link time via $LIB_FUZZING_ENGINE), so it is
# safe to put in CFLAGS passed to every TU including the library.
# Guard: skip if the caller already baked a fuzzer variant into SANITIZER_FLAGS.
case "$SANITIZER_FLAGS" in
  *fuzzer*) ;;
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac

# Relax ONE benign UBSan check: -fsanitize=function. liboqs' KEM/SIG dispatch tables store algorithm
# entry points behind generic function-pointer types and call them through a single uniform prototype
# (e.g. src/kem/kem.c:637 calls OQS_KEM_bike_l1_keypair via a (unsigned char*, unsigned char*) ptr).
# That is a deliberate, well-defined-in-practice indirection, but -fsanitize=function flags the
# pointer-type mismatch and halts (-fno-sanitize-recover) on the very first input, so EVERY run aborts.
# We drop only the `function` sub-check; ASan + the rest of UBSan stay on and halting. Appended LAST so
# it wins over the inherited -fsanitize=...,undefined.
case "$SANITIZER_FLAGS" in
  *undefined*|*function*) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=function" ;;
esac
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS OUT

# SRC defaults to the repo root (the dir holding this mayhem/ dir's parent).
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export SRC
cd "$SRC"

HARNESSES="fuzz_test_kem fuzz_test_sig fuzz_test_sig_stfl_lms fuzz_test_sig_stfl_xmss"

# ── 1) Build liboqs + the libFuzzer harnesses (sanitized) ──────────────────────────────────────────
# CMakeLists.txt picks up $LIB_FUZZING_ENGINE for the harness link flags; we add $SANITIZER_FLAGS as
# CMAKE_C_FLAGS so the library code is also instrumented. The fuzz harnesses are gated on Clang.
BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"; mkdir -p "$BUILD"
cmake -GNinja -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DOQS_BUILD_FUZZ_TESTS=ON \
  -DOQS_ENABLE_SIG_STFL_LMS=ON \
  -DOQS_ENABLE_SIG_STFL_XMSS=ON \
  -DOQS_BUILD_ONLY_LIB=OFF
ninja -C "$BUILD" -j"$MAYHEM_JOBS" $HARNESSES

for h in $HARNESSES; do
  bin="$BUILD/tests/$h"
  [ -x "$bin" ] || { echo "ERROR: expected libFuzzer harness $bin not built" >&2; exit 1; }
  cp "$bin" "$OUT/$h"
  echo "built $h -> $OUT/$h"
done

# ── 2) Standalone reproducers (no libFuzzer runtime; reads one input file) ──────────────────────────
# Rebuild each harness object against the standalone driver, linking the sanitized liboqs static lib.
STANDALONE_SRC="$SRC/mayhem/harnesses/standalone_main.c"
LIBOQS_A="$BUILD/lib/liboqs.a"
[ -f "$LIBOQS_A" ] || LIBOQS_A="$(find "$BUILD" -name 'liboqs.a' | head -1)"
[ -f "$LIBOQS_A" ] || { echo "ERROR: could not find liboqs.a under $BUILD" >&2; exit 1; }

# liboqs copies its public headers (oqs/oqs.h, oqs/kem.h, ...) into <build>/include/oqs at configure.
INC="-I$BUILD/include"
for h in $HARNESSES; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -DOQS_FUZZ_STANDALONE $INC \
      "$SRC/tests/$h.c" "$STANDALONE_SRC" "$LIBOQS_A" \
      $(pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto) -lm -lpthread \
      -o "$OUT/$h-standalone" \
    && echo "built $h-standalone -> $OUT/$h-standalone" \
    || echo "WARNING: standalone build of $h failed (libFuzzer target still ships)" >&2
done

# ── 3) Build liboqs' OWN KAT test programs with NORMAL flags (clean tree) for mayhem/test.sh. ───────
# test_kem / test_sig run self-contained known-answer + round-trip correctness tests per algorithm.
TESTS="$SRC/mayhem-tests"
rm -rf "$TESTS"; mkdir -p "$TESTS"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS -u LIB_FUZZING_ENGINE \
  cmake -GNinja -S "$SRC" -B "$TESTS" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DOQS_BUILD_FUZZ_TESTS=OFF
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS -u LIB_FUZZING_ENGINE \
  ninja -C "$TESTS" -j"$MAYHEM_JOBS" test_kem test_sig
echo "built liboqs KAT test programs (test_kem/test_sig) in mayhem-tests/"

echo "build.sh complete:"
ls -la $(for h in $HARNESSES; do echo "$OUT/$h"; done) 2>&1 || true
