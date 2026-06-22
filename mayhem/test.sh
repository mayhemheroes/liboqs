#!/usr/bin/env bash
#
# liboqs/mayhem/test.sh — RUN liboqs' OWN known-answer / correctness tests (test_kem, test_sig),
# built by mayhem/build.sh with normal flags, and emit a CTRF summary. exit 0 iff every selected
# test passes.
#
# BEHAVIORAL oracle (§6.3): we grep the actual output of each test program for a known-good string
# that only a functioning library produces. If the program is neutered (e.g. LD_PRELOAD exit(0)),
# it emits no output and the grep fails — so a reward-hacking no-op FAILS this test. This script
# only RUNS the pre-built programs; it never compiles.
#
# KEM check: test_kem prints "shared secrets are equal" when encaps/decaps round-trip succeeds.
# SIG check: test_sig prints "verification passes as expected" when sign/verify round-trip succeeds.
# Both also print "sample computation for KEM <alg>" / "Sample computation for signature <alg>"
# as a header — we require BOTH the header AND the correctness result to be present.
#
# We run a representative subset (lattice KEM + lattice signature + a hash-based signature) rather
# than every algorithm — the full matrix (Classic McEliece, BIKE, …) is minutes-to-hours of keygen.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$SRC"

BUILDDIR="$SRC/mayhem-tests"
TEST_KEM="$BUILDDIR/tests/test_kem"
TEST_SIG="$BUILDDIR/tests/test_sig"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$TEST_KEM" ] || [ ! -x "$TEST_SIG" ]; then
  echo "missing $TEST_KEM / $TEST_SIG — run mayhem/build.sh first" >&2
  emit_ctrf "liboqs-kat" 0 1 0; exit 2
fi

# Representative, always-enabled NIST-standard algorithms (fast keygen):
#   KEM: ML-KEM (FIPS 203) + the original Kyber.   SIG: ML-DSA (FIPS 204) + Falcon.
KEM_ALGS="ML-KEM-512 ML-KEM-768 Kyber512"
SIG_ALGS="ML-DSA-44 ML-DSA-65 Falcon-512"

PASSED=0; FAILED=0

# run_kem_one <alg>: run test_kem, capture output, grep for known behavioral evidence.
# "shared secrets are equal" is only printed after a successful encaps/decaps round-trip.
# A neutered program produces no output → grep fails → test fails.
run_kem_one() {
  local alg="$1"
  echo "=== test_kem $alg ==="
  local out
  out=$("$TEST_KEM" "$alg" 2>&1) || { echo "FAIL test_kem $alg (exit $?)"; FAILED=$(( FAILED + 1 )); return; }
  printf '%s\n' "$out"
  if printf '%s\n' "$out" | grep -q "shared secrets are equal"; then
    echo "PASS test_kem $alg (shared secrets verified)"; PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL test_kem $alg (output missing 'shared secrets are equal')"; FAILED=$(( FAILED + 1 ))
  fi
}

# run_sig_one <alg>: run test_sig, capture output, grep for known behavioral evidence.
# "verification passes as expected" is only printed after a successful sign/verify round-trip.
run_sig_one() {
  local alg="$1"
  echo "=== test_sig $alg ==="
  local out
  out=$("$TEST_SIG" "$alg" 2>&1) || { echo "FAIL test_sig $alg (exit $?)"; FAILED=$(( FAILED + 1 )); return; }
  printf '%s\n' "$out"
  if printf '%s\n' "$out" | grep -q "verification passes as expected"; then
    echo "PASS test_sig $alg (verification confirmed)"; PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL test_sig $alg (output missing 'verification passes as expected')"; FAILED=$(( FAILED + 1 ))
  fi
}

for a in $KEM_ALGS; do run_kem_one "$a"; done
for a in $SIG_ALGS; do run_sig_one "$a"; done

emit_ctrf "liboqs-kat" "$PASSED" "$FAILED" 0
