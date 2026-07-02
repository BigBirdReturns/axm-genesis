# RELEASE.md — the v1.0.0 runbook

This is the checklist for the steps **only the maintainer can perform**:
the key ceremony, the ceremony re-mint of the gold shard, the timestamp
attestations, and the actual release. Everything else on the RFC 0002
branch (spec, code, vectors, provisional gold v2, CI) is already in place;
`make test`, `make verify-frozen`, and verification of the provisional gold
shard all pass before this runbook begins.

Every command is copy-pasteable from the repository root. Steps are in
execution order.

---

## 0. Rename the stale prototype tags

The repository carries four pre-reset tags — `v1.0.0`, `v1.0.2`, `v1.1.0`,
`v1.2.0` — all pointing at v0.x prototype commits. The first one collides
with the release tag this runbook cuts in step 6, and all four claim
version numbers the RFC 0002 reset reclassified. Nothing depends on them
(no PyPI releases exist; axm-core and axm-chat pin commit SHAs). Preserve
every pointer under an honest name, then delete the originals:

```bash
for t in v1.0.0 v1.0.2 v1.1.0 v1.2.0; do
  git tag "prototype/$t" "$t"          # same commit, honest name
done
git push origin 'refs/tags/prototype/*'
for t in v1.0.0 v1.0.2 v1.1.0 v1.2.0; do
  git push origin ":refs/tags/$t"      # remove the originals
  git tag -d "$t"
done
```

(This must run from a normally-authenticated clone; the sandboxed
sessions that produced this branch can only push `claude/*` branches.)

---

## 1. Key ceremony — generate the canonical publisher keypair (OFFLINE)

Run on an **offline machine** (no network; a live-boot system is ideal).
The private key never enters the repository, never touches a cloud
session, and never crosses the network — there are no exceptions.

```bash
# On the OFFLINE machine:
axm-build keygen /secure/axm-ceremony --name canonical_publisher
# writes:
#   /secure/axm-ceremony/canonical_publisher.key  (3904-byte hybrid secret blob)
#   /secure/axm-ceremony/canonical_publisher.pub  (1344-byte hybrid public key)
```

Then:

- Store `canonical_publisher.key` on offline media (at least two copies,
  separate locations). Record where, and who holds them.
- Carry **only** `canonical_publisher.pub` to the online machine.
- Update the custody statement in `keys/README.md`: date of ceremony,
  machine class used, storage locations (in general terms), and the
  explicit sentence "the private key has never entered a networked
  environment". Replace the provisional-key section: move
  `keys/gold-v2-provisional.pub` under the "Retired / test keys" list.

```bash
# On the ONLINE machine, in the repo:
cp /media/ceremony/canonical_publisher.pub keys/canonical_publisher.pub
git mv keys/gold-v2-provisional.pub archive/v0/keys/gold-v2-provisional.pub  # retire
```

(`make verify-gold` and the CI gold-shard job already expect the ceremony
key at `keys/canonical_publisher.pub`.)

## 2. Re-mint gold v2 with the ceremony key; regenerate CHECKSUMS

Signing requires the secret blob, so this build runs on the **offline**
machine too (the builder needs no network). The mint is deterministic:
built from the same wrapped FM 21-11 source (see
`shards/gold/README.md` → Reproduction), every byte outside `sig/` —
including `manifest.json` — must reproduce the provisional mint exactly;
only the key material and signature change.

```bash
# OFFLINE — never run a build against shards/gold/ in the repo; build aside and compare:
export AXM_SIGNING_KEY_HEX=$(xxd -p -c 10000 /secure/axm-ceremony/canonical_publisher.key)
axm-build gold-fm21-11 /secure/axm-ceremony/fm21-11-wrapped.md /secure/axm-ceremony/gold-v2
unset AXM_SIGNING_KEY_HEX

# Confirm determinism against the committed provisional mint (only sig/ may differ):
diff -r --exclude=sig /secure/axm-ceremony/gold-v2 shards/gold/fm21-11-hemorrhage-v2 && echo DETERMINISTIC
```

Back in the repo, swap in the ceremony-signed bytes and re-pin:

```bash
rm -rf shards/gold/fm21-11-hemorrhage-v2
cp -r /secure/axm-ceremony/gold-v2 shards/gold/fm21-11-hemorrhage-v2

find shards/gold/fm21-11-hemorrhage-v2 -type f | LC_ALL=C sort | xargs sha256sum > shards/gold/CHECKSUMS.sha256

# The three gates that must pass before committing:
sha256sum -c shards/gold/CHECKSUMS.sha256
axm-verify shard shards/gold/fm21-11-hemorrhage-v2 --trusted-key keys/canonical_publisher.pub
make test
```

Update `shards/gold/README.md`: delete the PROVISIONAL section, record the
ceremony date, and restate the derived `sh1_` identity (it is unchanged if
the manifest reproduced byte-identically — verify, don't assume). From
this commit on, the "never recompiled" pledge attaches to these bytes.

## 3. Re-attest: RFC 3161 + OpenTimestamps + Software Heritage over the v2 manifest

Same commands as `attestations/README.md`, pointed at the ceremony-signed
v2 manifest:

```bash
# A byte-identical copy of the attested manifest lives in attestations/:
cp shards/gold/fm21-11-hemorrhage-v2/manifest.json attestations/gold-v2-manifest.json

# RFC 3161 (freetsa.org):
openssl ts -query -data attestations/gold-v2-manifest.json -no_nonce -sha256 \
  -out attestations/gold-v2-manifest.tsq
curl -sS -H "Content-Type: application/timestamp-query" \
  --data-binary @attestations/gold-v2-manifest.tsq \
  https://freetsa.org/tsr -o attestations/gold-v2-manifest.tsr
openssl ts -verify \
  -queryfile attestations/gold-v2-manifest.tsq \
  -in attestations/gold-v2-manifest.tsr \
  -CAfile attestations/freetsa-cacert.pem \
  -untrusted attestations/freetsa-tsa.crt

# OpenTimestamps (creates attestations/gold-v2-manifest.json.ots, pending):
ots stamp attestations/gold-v2-manifest.json

# Software Heritage archival of the repo at this state:
curl -X POST "https://archive.softwareheritage.org/api/1/origin/save/git/url/https://github.com/BigBirdReturns/axm-genesis/"
```

Commit the new proof files and update `attestations/README.md` with the
anchor timestamps. Keep the v1 (v0.x-era) proofs — they attest the
archived prototype and remain valid history.

## 4. Upgrade the pending OpenTimestamps proofs

The `.ots` files are pending until the calendars anchor into a Bitcoin
block (typically within hours; check back the next day):

```bash
ots upgrade attestations/gold-manifest.json.ots       # the v0.x proof, still pending
ots upgrade attestations/gold-v2-manifest.json.ots    # the new v2 proof (step 3)
ots verify  attestations/gold-manifest.json.ots
ots verify  attestations/gold-v2-manifest.json.ots
git add attestations/*.ots && git commit -m "attest: upgrade OTS proofs to Bitcoin-anchored"
```

## 5. Flip the version: 1.0.0rc1 → 1.0.0

The version is single-sourced from `axm_verify.__version__` (pyproject
reads it dynamically); this is the only edit:

```bash
sed -i 's/__version__ = "1.0.0rc1"/__version__ = "1.0.0"/' src/axm_verify/__init__.py
pip install -e . && pytest tests/test_compatibility_contract.py -k version  # version-match test
git commit -am "release: v1.0.0"
```

## 6. Tag v1.0.0 (signed) and cut the GitHub release

```bash
git tag -s v1.0.0 -m "AXM Genesis v1.0.0 — the frozen kernel (RFC 0002)"
git push origin main v1.0.0

# Release checksums: the gold-shard pins plus the sdist/wheel digests
python -m build
sha256sum dist/* > dist/SHA256SUMS

gh release create v1.0.0 \
  --title "AXM Genesis v1.0.0" \
  --notes-file CHANGELOG.md \
  dist/axm_genesis-1.0.0.tar.gz \
  dist/axm_genesis-1.0.0-py3-none-any.whl \
  dist/SHA256SUMS \
  shards/gold/CHECKSUMS.sha256
```

From this tag onward the CONTRIBUTING.md freeze rules apply with full
force: the next breaking change costs a major version and a migration
path.

## 7. Publish to PyPI

```bash
python -m pip install --upgrade build twine
python -m build
twine check dist/*
twine upload dist/*
```

Preferred over a long-lived API token: configure **PyPI trusted
publishing** (PyPI → project → Publishing → add GitHub
`BigBirdReturns/axm-genesis` with a release workflow) so future uploads
run from CI via OIDC with no stored credential; `twine upload` is the
manual bootstrap for this first release.

## 8. Zenodo deposit (DOI)

Via the GitHub integration (once per repository):

1. Log in at <https://zenodo.org/> with the GitHub account.
2. Profile → GitHub → flip the switch for `BigBirdReturns/axm-genesis`.
3. If the switch was flipped **before** step 6, the v1.0.0 release has
   already been deposited automatically; otherwise create a new GitHub
   release (e.g. `v1.0.0-zenodo` is unnecessary — re-publish the release,
   or use Zenodo's "upload" with the release tarball).
4. Record the minted DOI badge in README.md and `attestations/README.md`
   ("Still open" section — close it).

## Done — declare the freeze

All eight steps complete means: canonical key with custody, ceremony-signed
gold shard, independent existence proofs, signed tag, installable package,
archived and DOI'd release. Update `rfcs/README.md` status for RFC 0002 to
IMPLEMENTED (ceremony and tag no longer pending) and the corresponding
rows in `docs/DURABILITY.md`.
