#!/usr/bin/env bash
# AXM spoke drift check — the boundary lint every spoke's CI runs.
#
# It catches the cardinal violations that let a spoke silently diverge from the
# frozen kernel: a hardcoded signing key, reimplementing a frozen kernel surface
# (signing / Merkle / manifest encoding), storing a derived identity, shipping
# Parquet shard tables, or naming a retired crypto suite. Every one of these is
# something the reconciliation of 2026-07 had to rip out of a real spoke.
#
# This script lives in axm-genesis so it is itself a single source of truth: a
# spoke's CI checks out the kernel and runs THIS file against its own tree, so
# the lint can never drift from the contract it enforces.
#
# Usage:   bash drift-check.sh [SPOKE_DIR]      (default: current directory)
# Exit:    0 clean, 1 on any finding.
set -uo pipefail

ROOT="${1:-.}"
status=0

# Scan the spoke's own source/docs only — never a vendored kernel checkout,
# build output, or virtualenv. The first arg is the grep pattern; any further
# args are extra `--include` globs (default: the full doc+code set).
scan() {
  local pat="$1"; shift
  local includes=("$@")
  if [ "${#includes[@]}" -eq 0 ]; then
    includes=(--include='*.py' --include='*.md' --include='*.html' --include='*.jsx'
              --include='*.toml' --include='*.go' --include='*.txt' --include='*.yml')
  fi
  grep -rIniE "$pat" "$ROOT" "${includes[@]}" \
    2>/dev/null \
    | grep -vE '/(\.git|axm-genesis|node_modules|\.venv|venv|__pycache__|dist|build)/' \
    | grep -vE '\.egg-info/' \
    | grep -vF 'drift-ok'
}
# Suppression: a line containing the token `drift-ok` is skipped. Use it
# sparingly and always with a reason — e.g. a doc that *names* a forbidden
# symbol to explain the rule, or a committed test key documented as proving
# nothing (tests/keys/README.md-style). In Markdown/HTML use an invisible
# comment: <!-- drift-ok: documenting the rule -->.

check() {  # check <slug> <why> <pattern> [include-glob ...]
  local slug="$1" why="$2" pat="$3"; shift 3
  local hits
  hits="$(scan "$pat" "$@")"
  if [ -n "$hits" ]; then
    echo "❌ DRIFT [$slug]: $why"
    echo "$hits" | sed 's/^/     /'
    echo
    status=1
  fi
}

# A. Hardcoded key material. A signing key comes from `axm-build keygen`, never
#    the source tree; tests use throwaway keypairs (hybrid1_keygen()).
check hardcoded-key \
  "a signing key/seed is hardcoded in source — keys come from axm-build keygen, never the tree" \
  '(seed|key|publisher|signing|secret)[a-z0-9_]* *= *bytes\.fromhex\('

# B. Reimplementing frozen kernel surfaces (Python seal path only — shard
#    sealing is always Python; a daemon's local segment Merkle or a demo's
#    client-side simulation is a different thing). A spoke calls
#    compile_generic_shard and verify_shard; it must never sign, hash, build a
#    Merkle tree, or encode a manifest itself (axm-sfn's two-pass reseal did).
check kernel-surface \
  "a spoke must not sign, hash, Merkle, or encode manifests in its compile path — use compile_generic_shard / verify_shard only" \
  '\b(compute_merkle_root|mldsa44_sign|mldsa44_keygen|manifest_signing_message|signing_key_from_private_key_bytes)\b' \
  --include='*.py'

# C. Stored / pre-v1 identity. Identity is DERIVED — sh1_ + BLAKE3(manifest) —
#    and never stored; use axm_verify.crypto.derive_shard_id.
check stored-identity \
  "identity is derived (sh1_ + BLAKE3 of the manifest), never stored — use derive_shard_id" \
  'shard_blake3_|\[.shard_id.\] *='

# D. Parquet shard tables. v1 core and extension tables are canonical JSONL.
check parquet-tables \
  "shard tables are canonical JSONL, not Parquet" \
  '@[0-9]+\.parquet|(entities|claims|provenance|spans)\.parquet'

# E. Retired suite labels. There is one suite: axm-hybrid1 (Ed25519 ‖ ML-DSA-44).
check retired-suite \
  "the only suite is axm-hybrid1; SUITE_ED25519 / SUITE_MLDSA44 / axm-blake3-mldsa44 are pre-reset" \
  'axm-blake3-mldsa44|\bSUITE_ED25519\b|\bSUITE_MLDSA44\b'

if [ "$status" -eq 0 ]; then
  echo "✓ drift-check: clean — no kernel-boundary violations in ${ROOT}"
fi
exit $status
