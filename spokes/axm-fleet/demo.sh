#!/usr/bin/env bash
# The four-beat sustainment demo.
#
#   1. RECORD    compile a node record, verify it offline with the trusted key
#   2. PATCH     compile a successor record that supersedes it — the kernel
#                seals the lineage (manifest.supersedes + ext/lineage@1)
#   3. TAMPER    flip one sealed byte -> E_MERKLE_MISMATCH; wrong key -> E_SIG_INVALID
#   4. REMOVE    verify the same shard with the independent Go verifier,
#                built from the spec and vectors alone. Remove the reference
#                implementation and the record still proves out.
#
# Requires: pip install -e <kernel>[mldsa-compat] && pip install -e . ;
# beat 4 additionally requires a Go toolchain and the in-repo verifiers/go.
#
# Keys generated here are throwaway: they prove the pipeline, never
# authenticity. Real publisher keys come from an offline ceremony.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
POOL="$WORK/pool"
mkdir -p "$POOL"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

say "0. throwaway publisher identity (axm-build keygen)"
axm-build keygen "$WORK/keys" --name publisher
KEY="$WORK/keys/publisher.key"
PUB="$WORK/keys/publisher.pub"

say "1. RECORD — compile the deploy record, verify offline with the trusted key"
DEPLOY_ID=$(axm-fleet record "$HERE/examples/node-0042.deploy.json" "$POOL/deploy" --key "$KEY")
echo "deploy record: $DEPLOY_ID"
axm-verify shard "$POOL/deploy" --trusted-key "$PUB"

say "2. PATCH — a new record that supersedes the old; the kernel seals the lineage"
PATCH_ID=$(axm-fleet record "$HERE/examples/node-0042.patch.json" "$POOL/patch" \
  --key "$KEY" --supersedes "$DEPLOY_ID")
echo "patch record:  $PATCH_ID"
echo "--- manifest.supersedes:"
python3 -c "import json,sys; print(json.load(open('$POOL/patch/manifest.json'))['supersedes'])"
echo "--- ext/lineage@1.jsonl:"
cat "$POOL/patch/ext/lineage@1.jsonl"
echo "--- chain:"
axm-fleet history "$POOL"

say "3. TAMPER — flip one sealed byte, then try the wrong trusted key"
cp -r "$POOL/deploy" "$WORK/tampered"
python3 - "$WORK/tampered/content/source.txt" <<'EOF'
import sys
p = sys.argv[1]
raw = bytearray(open(p, "rb").read()); raw[0] ^= 1
open(p, "wb").write(bytes(raw))
EOF
axm-verify shard "$WORK/tampered" --trusted-key "$PUB" && exit 1 || echo "(FAIL as required — E_MERKLE_MISMATCH)"
axm-build keygen "$WORK/other" --name other >/dev/null
axm-verify shard "$POOL/deploy" --trusted-key "$WORK/other/other.pub" && exit 1 || echo "(FAIL as required — E_SIG_INVALID)"

say "4. REMOVE THE VENDOR — verify with the independent Go verifier"
if command -v go >/dev/null 2>&1 && [ -d "$REPO_ROOT/verifiers/go" ]; then
  (cd "$REPO_ROOT/verifiers/go" && go build -o "$WORK/axm-verify-go" ./cmd/axm-verify-go)
  "$WORK/axm-verify-go" shard "$POOL/patch" --trusted-key "$PUB"
  echo "(second implementation, built from the spec alone: PASS)"
else
  echo "(skipped: Go toolchain or verifiers/go not available)"
fi

say "verdict"
echo "The fleet is sovereign when the vendor can be removed and the record still verifies."
