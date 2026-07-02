#!/usr/bin/env bash
# Conformance runner for the independent Go verifier (axm-verify-go).
#
# Reproduces, in order:
#   1. go test ./...            — identity.json and merkle.json vectors
#   2. the gold shard           — must PASS with keys/gold-v2-provisional.pub
#   3. every row of tests/vectors/shards/EXPECTED.md — same exit code,
#      status, sorted error-code set, and profile arrays
#   4. tamper trio on a copy of the gold shard — content byte flip
#      (E_MERKLE_MISMATCH, exit 1), Ed25519 half corrupted (exit 1),
#      ML-DSA half corrupted (exit 1)
#
# CI-runnable: exits non-zero on the first divergence.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GO="${GO:-go}"
command -v "$GO" >/dev/null 2>&1 || GO=/usr/local/go/bin/go

BIN="$(mktemp -d)/axm-verify-go"
WORK="$(mktemp -d)"
trap 'rm -rf "$(dirname "$BIN")" "$WORK"' EXIT

FAILURES=0
note() { printf '%s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAILURES=$((FAILURES+1)); }

# ---------------------------------------------------------------- 1. go test
note "== go test ./... (identity + merkle vectors) =="
if (cd "$SCRIPT_DIR" && "$GO" test ./...); then
    note "unit tests: ok"
else
    fail "go test ./..."
fi

note "== build =="
(cd "$SCRIPT_DIR" && "$GO" build -o "$BIN" ./cmd/axm-verify-go) || { fail "build"; exit 1; }

# run_case <shard_dir> <key> <want_exit> <want_status> <want_codes> <want_checked> <want_unchecked> <label>
# want_codes / profiles: ';'- or ','-separated sorted, '-' for empty.
run_case() {
    local shard="$1" key="$2" want_exit="$3" want_status="$4" \
          want_codes="$5" want_checked="$6" want_unchecked="$7" label="$8"
    local out ec
    out="$("$BIN" shard "$shard" --trusted-key "$key" 2>/dev/null)"
    ec=$?
    local parsed
    parsed="$(printf '%s' "$out" | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except Exception:
    print("BADJSON"); sys.exit(0)
codes = ";".join(sorted(set(e["code"] for e in r["errors"]))) or "-"
pc = ";".join(r["profiles_checked"]) or "-"
pu = ";".join(r["profiles_unchecked"]) or "-"
print(r["status"] + "|" + codes + "|" + pc + "|" + pu)
')"
    if [ "$parsed" = "BADJSON" ]; then fail "$label: stdout is not valid JSON: $out"; return; fi
    local status codes pc pu
    IFS='|' read -r status codes pc pu <<< "$parsed"
    local bad=""
    [ "$ec" = "$want_exit" ]      || bad="$bad exit=$ec(want $want_exit)"
    [ "$status" = "$want_status" ] || bad="$bad status=$status(want $want_status)"
    [ "$codes" = "$want_codes" ]   || bad="$bad codes=$codes(want $want_codes)"
    if [ "$want_checked" != "*" ]; then
        [ "$pc" = "$want_checked" ] || bad="$bad profiles_checked=$pc(want $want_checked)"
    fi
    if [ "$want_unchecked" != "*" ]; then
        [ "$pu" = "$want_unchecked" ] || bad="$bad profiles_unchecked=$pu(want $want_unchecked)"
    fi
    if [ -n "$bad" ]; then fail "$label:$bad"; else note "ok: $label (exit $ec, $codes)"; fi
}

# ------------------------------------------------------------- 2. gold shard
note "== gold shard =="
run_case "$REPO_ROOT/shards/gold/fm21-11-hemorrhage-v2" \
         "$REPO_ROOT/keys/gold-v2-provisional.pub" \
         0 PASS - - - "gold shard"

# ------------------------------------------------- 3. EXPECTED.md vector table
note "== tests/vectors/shards/EXPECTED.md =="
EXPECTED="$REPO_ROOT/tests/vectors/shards/EXPECTED.md"
CI_KEY="$REPO_ROOT/tests/keys/ci_test_publisher.pub"
ROWS=0
while IFS='|' read -r _ vector shard exit_code status error_codes checked unchecked _; do
    vector="$(echo "$vector" | xargs)"; shard="$(echo "$shard" | xargs)"
    exit_code="$(echo "$exit_code" | xargs)"; status="$(echo "$status" | xargs)"
    error_codes="$(echo "$error_codes" | xargs)"
    checked="$(echo "$checked" | xargs)"; unchecked="$(echo "$unchecked" | xargs)"
    case "$vector" in ""|vector|----*|--------*) continue ;; esac
    [ -n "$exit_code" ] || continue
    ROWS=$((ROWS+1))
    run_case "$REPO_ROOT/tests/vectors/shards/$shard" "$CI_KEY" \
             "$exit_code" "$status" "$error_codes" "$checked" "$unchecked" \
             "vector $vector"
done < <(grep -E '^\|' "$EXPECTED")
note "vector rows executed: $ROWS"
[ "$ROWS" -ge 16 ] || fail "expected at least 16 EXPECTED.md rows, got $ROWS"

# ---------------------------------------------------------- 4. tamper trio
note "== tamper trio (copies of the gold shard) =="
GOLD="$REPO_ROOT/shards/gold/fm21-11-hemorrhage-v2"
GOLD_KEY="$REPO_ROOT/keys/gold-v2-provisional.pub"

flip_byte() { # file offset
    python3 -c '
import sys
path, off = sys.argv[1], int(sys.argv[2])
data = bytearray(open(path, "rb").read())
data[off] ^= 0x01
open(path, "wb").write(bytes(data))
' "$1" "$2"
}

# 4a. content byte flip -> E_MERKLE_MISMATCH, exit 1
cp -r "$GOLD" "$WORK/tamper_content"
flip_byte "$WORK/tamper_content/content/source.txt" 100
run_case "$WORK/tamper_content" "$GOLD_KEY" 1 FAIL E_MERKLE_MISMATCH - - \
         "tamper: content byte flip"

# 4b. Ed25519 half corrupted (byte 0 of manifest.sig) -> exit 1
cp -r "$GOLD" "$WORK/tamper_ed25519"
flip_byte "$WORK/tamper_ed25519/sig/manifest.sig" 0
run_case "$WORK/tamper_ed25519" "$GOLD_KEY" 1 FAIL E_SIG_INVALID - - \
         "tamper: ed25519 signature half"

# 4c. ML-DSA half corrupted (byte 1064 of manifest.sig) -> exit 1
cp -r "$GOLD" "$WORK/tamper_mldsa"
flip_byte "$WORK/tamper_mldsa/sig/manifest.sig" 1064
run_case "$WORK/tamper_mldsa" "$GOLD_KEY" 1 FAIL E_SIG_INVALID - - \
         "tamper: ml-dsa signature half"

# --------------------------------------------------------------------- result
if [ "$FAILURES" -gt 0 ]; then
    printf '\nCONFORMANCE: FAIL (%d divergence(s))\n' "$FAILURES" >&2
    exit 1
fi
printf '\nCONFORMANCE: PASS (unit vectors, gold shard, %d table rows, tamper trio)\n' "$ROWS"
