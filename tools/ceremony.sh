#!/usr/bin/env bash
# ceremony.sh — one-click AXM Genesis v1.0.0 release ceremony (RELEASE.md steps 0-6).
#
# Run from the axm-genesis repository root, on a clean `main` checkout:
#
#   bash tools/ceremony.sh                # real ceremony (asks once before pushing)
#   bash tools/ceremony.sh --simulate     # full dry-run: throwaway keys, no push
#
# What it does, in runbook order:
#   step 0   rename stale prototype tags (v1.0.0 v1.0.2 v1.1.0 v1.2.0 -> prototype/*)
#   step 1   mint the publisher keypair OUTSIDE the repo; install the .pub;
#            retire the provisional key; append an HONEST custody statement
#   step 2   re-mint gold v2 from the committed source (wrapped automatically),
#            PROVE byte-determinism outside sig/, swap in, regen CHECKSUMS,
#            run the three gates (checksums, verify, full test suite)
#   step 5   flip 1.0.0rc1 -> 1.0.0 and run the version gate
#   step 6   commit, cut the SIGNED v1.0.0 tag, verify it, and (real mode)
#            push after one typed confirmation
#   steps 3-4 (RFC 3161 / OpenTimestamps / Software Heritage) are network
#            attestations printed as post-push follow-ups; they never gate the tag.
#
# CUSTODY HONESTY: this script generates the key on THIS machine. That is
# workstation-grade custody, not the air-gapped ceremony RELEASE.md describes.
# The custody statement it writes says exactly that and nothing stronger. If
# you want air-gap grade, run RELEASE.md by hand on an offline machine — or
# mint now and rotate keys later by RFC when adoption justifies it. This
# script never claims a ceremony grade that did not happen.
set -euo pipefail

SIMULATE=0
REMOTE="origin"
for arg in "$@"; do
  case "$arg" in
    --simulate) SIMULATE=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[32m   ✓ %s\033[0m\n' "$*"; }
die() { printf '\033[31m   ✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Loud gate: run the command, show its tail and die on failure. Never lets a
# failed gate scroll past (a `cmd && ok` chain would — set -e ignores it).
gate() { # gate "<description>" cmd args...
  local desc="$1"; shift
  local out
  if out=$("$@" 2>&1); then
    ok "$desc"
  else
    printf '%s\n' "$out" | tail -20 >&2
    die "$desc — FAILED (last 20 lines above)"
  fi
}

# ---------------------------------------------------------------- preflight
say "preflight"
[ -f "spec/v1/SPECIFICATION.md" ] && [ -d "shards/gold" ] || die "run from the axm-genesis repo root"
for t in git python3 axm-build axm-verify; do command -v "$t" >/dev/null || die "missing tool: $t"; done
BRANCH=$(git branch --show-current)
[ "$BRANCH" = "main" ] || die "on branch '$BRANCH' — the ceremony runs from main"
[ -z "$(git status --porcelain)" ] || die "working tree not clean"
grep -q '__version__ = "1.0.0rc1"' src/axm_verify/__init__.py || die "version is not 1.0.0rc1 (already released?)"
GOLD="shards/gold/fm21-11-hemorrhage-v2"
[ -d "$GOLD" ] || die "gold shard missing: $GOLD"

# Key material lives OUTSIDE the repo tree, always.
if [ "$SIMULATE" = 1 ]; then
  CEREMONY_DIR=$(mktemp -d "${TMPDIR:-/tmp}/axm-ceremony-sim.XXXXXX")
  KEY_NAME="sim_publisher"
  ok "SIMULATION: throwaway keys in $CEREMONY_DIR — nothing will be pushed"
else
  CEREMONY_DIR="${AXM_CEREMONY_DIR:-$HOME/axm-ceremony}"
  KEY_NAME="canonical_publisher"
  mkdir -p "$CEREMONY_DIR"; chmod 700 "$CEREMONY_DIR"
  ok "real mode: key material goes to $CEREMONY_DIR (outside the repo; back it up offline after)"
fi

# --- tag-signing identity -----------------------------------------------
# The release tag MUST be signed and locally verifiable before push.
if [ "$SIMULATE" = 1 ]; then
  export GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/axm-gnupg-sim.XXXXXX"); chmod 700 "$GNUPGHOME"
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
      "AXM Ceremony Simulation <sim@invalid>" ed25519 sign never >/dev/null 2>&1
  GPG_KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/{print $5; exit}')
  git config gpg.format openpgp          # repo-local; overrides any ssh-signing default
  git config user.signingkey "$GPG_KEYID"
  ok "throwaway GPG signing key (simulation): $GPG_KEYID"
else
  FMT=$(git config gpg.format || echo openpgp)
  if [ "$FMT" = "ssh" ]; then
    # ssh signing: `git tag -v` needs an allowed-signers file. Provision one
    # locally from the configured signing key so verification can run.
    SIGNKEY=$(git config user.signingkey || true)
    [ -n "$SIGNKEY" ] || die "gpg.format=ssh but no user.signingkey configured"
    if ! git config gpg.ssh.allowedSignersFile >/dev/null; then
      ALLOWED="$CEREMONY_DIR/allowed_signers"
      KEYTEXT="$SIGNKEY"; [ -f "$SIGNKEY" ] && KEYTEXT=$(cat "$SIGNKEY")
      SIGNER_ID=$(git config user.email || echo maintainer)
      printf '%s %s\n' "$SIGNER_ID" "$KEYTEXT" > "$ALLOWED"
      git config gpg.ssh.allowedSignersFile "$ALLOWED"
      ok "provisioned allowed-signers file for ssh tag verification: $ALLOWED"
    fi
  else
    gpg --list-secret-keys 2>/dev/null | grep -q sec \
      || die "no GPG secret key available and gpg.format is not ssh — configure signing first"
  fi
fi

# ------------------------------------------------------- step 0: stale tags
say "step 0 — rename stale prototype tags"
STALE_RENAMED=()
for t in v1.0.0 v1.0.2 v1.1.0 v1.2.0; do
  if git rev-parse -q --verify "refs/tags/$t" >/dev/null; then
    git tag -f "prototype/$t" "$t" >/dev/null
    git tag -d "$t" >/dev/null
    STALE_RENAMED+=("$t")
    ok "$t -> prototype/$t (local; remote updated at push)"
  fi
done
[ ${#STALE_RENAMED[@]} -gt 0 ] || ok "no stale tags present locally"

# ---------------------------------------------------- step 1: publisher key
say "step 1 — mint publisher keypair (on THIS machine — see custody note)"
if [ ! -f "$CEREMONY_DIR/$KEY_NAME.key" ]; then
  gate "axm-build keygen" axm-build keygen "$CEREMONY_DIR" --name "$KEY_NAME"
else
  ok "reusing existing keypair in $CEREMONY_DIR"
fi
KEYLEN=$(wc -c < "$CEREMONY_DIR/$KEY_NAME.key"); PUBLEN=$(wc -c < "$CEREMONY_DIR/$KEY_NAME.pub")
[ "$KEYLEN" -eq 3904 ] && [ "$PUBLEN" -eq 1344 ] || die "unexpected key sizes (sk=$KEYLEN pub=$PUBLEN; want 3904/1344)"
chmod 600 "$CEREMONY_DIR/$KEY_NAME.key"
ok "keypair: $CEREMONY_DIR/$KEY_NAME.{key,pub} (sk 3904 B, pub 1344 B)"

cp "$CEREMONY_DIR/$KEY_NAME.pub" keys/canonical_publisher.pub
if [ -f keys/gold-v2-provisional.pub ]; then
  mkdir -p archive/v0/keys
  git mv keys/gold-v2-provisional.pub archive/v0/keys/gold-v2-provisional.pub
  ok "provisional key retired to archive/v0/keys/"
fi

CUSTODY_DATE=$(date -u +%Y-%m-%d)
if [ "$SIMULATE" = 1 ]; then CUSTODY_MODE="SIMULATION — throwaway key, not a trust anchor"; else CUSTODY_MODE="workstation ceremony (networked machine)"; fi
cat >> keys/README.md <<EOF

## Custody statement — canonical_publisher.pub ($CUSTODY_DATE)

- Ceremony mode: $CUSTODY_MODE.
- The keypair was generated with \`axm-build keygen\` on the maintainer's
  machine; the secret key was written only to a directory outside the
  repository and never committed. This is workstation-grade custody: the
  key HAS existed on a networked machine. It is NOT the air-gapped ceremony
  described in RELEASE.md; a future key rotation (by RFC) can upgrade the
  custody grade if adoption warrants it.
- Git-URL pins to \`refs/tags/v1.0.0\` give a stable source ref, but pip
  does not verify the tag signature during installation; authenticity of
  the release tag is a maintainer/repository inspection concern, not a
  property of pip resolution.
- The provisional key (gold-v2-provisional.pub) is retired under
  archive/v0/keys/ and remains valid only as history.
EOF
ok "custody statement appended to keys/README.md (honest grade: $CUSTODY_MODE)"

# -------------------------------------------------- step 2: re-mint gold v2
say "step 2 — re-mint gold v2 and prove determinism"
# The wrapped input is the committed section text under its original heading;
# regenerate it instead of requiring an out-of-band file (see RELEASE.md).
python3 - "$GOLD/content/source.txt" "$CEREMONY_DIR/fm21-11-wrapped.md" <<'PY'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
open(sys.argv[2], "w", encoding="utf-8").write("# STOP THE BLEEDING\n\n" + src)
PY
export AXM_SIGNING_KEY_HEX=$(python3 -c "import sys;print(open(sys.argv[1],'rb').read().hex())" "$CEREMONY_DIR/$KEY_NAME.key")
rm -rf "$CEREMONY_DIR/gold-v2"
gate "gold re-mint (axm-build gold-fm21-11)" axm-build gold-fm21-11 "$CEREMONY_DIR/fm21-11-wrapped.md" "$CEREMONY_DIR/gold-v2"
unset AXM_SIGNING_KEY_HEX

gate "determinism: every byte outside sig/ reproduces the committed mint" \
  diff -r --exclude=sig "$CEREMONY_DIR/gold-v2" "$GOLD"
gate "manifest byte-identical (sh1_ shard identity unchanged)" \
  cmp "$CEREMONY_DIR/gold-v2/manifest.json" "$GOLD/manifest.json"

rm -rf "$GOLD"
cp -r "$CEREMONY_DIR/gold-v2" "$GOLD"
find "$GOLD" -type f | LC_ALL=C sort | xargs sha256sum > shards/gold/CHECKSUMS.sha256
gate "gate 1/3: frozen-bytes checksums" sha256sum -c shards/gold/CHECKSUMS.sha256
gate "gate 2/3: axm-verify PASS against the ceremony key" \
  axm-verify shard "$GOLD" --trusted-key keys/canonical_publisher.pub
gate "gate 3/3: full test suite" python3 -m pytest tests/ -q

# --------------------------------------------------- step 5: version 1.0.0
say "step 5 — flip version 1.0.0rc1 -> 1.0.0"
python3 - <<'PY'
from pathlib import Path
p = Path("src/axm_verify/__init__.py")
p.write_text(p.read_text().replace('__version__ = "1.0.0rc1"', '__version__ = "1.0.0"'))
PY
grep -q '__version__ = "1.0.0"' src/axm_verify/__init__.py || die "version flip failed"
ok "version flipped"
if [ "$SIMULATE" = 1 ]; then
  # Simulation shares the host's installed package; check single-sourcing
  # against this tree's code without touching the host install.
  gate "version gate (single-sourced, this tree)" \
    env PYTHONPATH=src python3 -m pytest tests/test_compatibility_contract.py -q -k single_sourced
else
  gate "reinstall (pip install -e .)" python3 -m pip install -e . -q
  gate "version gate (single-sourced + installed match)" \
    python3 -m pytest tests/test_compatibility_contract.py -q -k version
fi

# ---------------------------------------------- step 6: commit + signed tag
say "step 6 — commit and cut the signed v1.0.0 tag"
git add -A
git commit -q -m "release: v1.0.0 — ceremony key, re-signed gold v2, version flip

- keys/canonical_publisher.pub installed; provisional key retired
- gold v2 re-minted with the ceremony key: byte-deterministic outside sig/,
  manifest byte-identical (sh1_ identity unchanged)
- CHECKSUMS regenerated; verify + full suite green
- custody statement (honest grade) appended to keys/README.md"
gate "signed annotated tag created" git tag -s v1.0.0 -m "AXM Genesis v1.0.0 — the frozen kernel (RFC 0002)"
gate "tag verifies locally (git tag -v)" git tag -v v1.0.0
[ "$(git cat-file -t "$(git rev-parse v1.0.0)")" = "tag" ] || die "v1.0.0 is not an annotated tag object"
ok "v1.0.0 is a signed, locally-verified annotated tag"

say "result"
git log --oneline -1

if [ "$SIMULATE" = 1 ]; then
  say "SIMULATION complete — nothing pushed, nothing minted"
  echo "   This clone now holds the full post-ceremony state for inspection."
  echo "   Throwaway material: $CEREMONY_DIR and \$GNUPGHOME (delete freely)."
  exit 0
fi

say "push (the only irreversible step)"
echo "   Will push to '$REMOTE': main, v1.0.0, prototype/* tags, and DELETE the stale originals."
read -r -p "   Type 'mint' to push, anything else aborts: " CONFIRM
[ "$CONFIRM" = "mint" ] || { echo "   aborted — nothing pushed; local state is ready when you are."; exit 0; }
if [ ${#STALE_RENAMED[@]} -gt 0 ]; then
  git push "$REMOTE" 'refs/tags/prototype/*'
  for t in "${STALE_RENAMED[@]}"; do git push "$REMOTE" ":refs/tags/$t"; done
fi
git push "$REMOTE" main v1.0.0
ok "pushed. The anchor exists."

say "post-push follow-ups (RELEASE.md steps 3-4: network attestations)"
cat <<'EOF'
   cp shards/gold/fm21-11-hemorrhage-v2/manifest.json attestations/gold-v2-manifest.json
   openssl ts -query -data attestations/gold-v2-manifest.json -no_nonce -sha256 -out attestations/gold-v2-manifest.tsq
   curl -sS -H "Content-Type: application/timestamp-query" --data-binary @attestations/gold-v2-manifest.tsq https://freetsa.org/tsr -o attestations/gold-v2-manifest.tsr
   ots stamp attestations/gold-v2-manifest.json     # `ots upgrade` + `ots verify` the next day
   curl -X POST "https://archive.softwareheritage.org/api/1/origin/save/git/url/https://github.com/BigBirdReturns/axm-genesis/"
   # commit the proofs — then tell the propagation session: run the propagation wave
EOF
