# Keys

Public key material trusted by this repository. Private keys never enter
the repository — there are no exceptions.

## `gold-v2-provisional.pub`

The `axm-hybrid1` public key (1344 bytes: `pk_ed25519 (32) ‖ pk_mldsa44
(1312)`) that verifies the **provisional** gold shard
`shards/gold/fm21-11-hemorrhage-v2/`:

```bash
axm-verify shard shards/gold/fm21-11-hemorrhage-v2 --trusted-key keys/gold-v2-provisional.pub
```

Custody statement: the keypair was generated with `axm-build keygen` inside
a cloud coding session on 2026-07-02, used to sign the v2 gold shard once,
and the private half was then destroyed (`shred -u`) without ever being
written to the repository or leaving session-local temporary storage. No
copy of the private key exists. This key can therefore never sign anything
again — which also means it cannot be part of a long-term custody story.

It is a placeholder pending the RFC 0002 D7 **offline key ceremony**, which
will generate the canonical publisher keypair with documented custody,
re-mint the gold shard under it (procedure in `RELEASE.md`), and record
timestamp attestations under `attestations/`. Until then, treat signatures
under this key as pinning integrity of the committed bytes, with
authenticity resting on this repository's git history.

## Retired / test keys

- `archive/v0/keys/canonical_test_publisher.pub` — the v0.x gold-shard
  Ed25519 key. Its private half was historically published in this
  repository, so it never proved authenticity. Archived history; do not
  trust it for anything new.
- `tests/keys/ci_test_publisher.pub` (and `.key`) — the CI test keypair,
  committed **including its private half** on purpose. It signs the
  conformance vectors under `tests/vectors/shards/` and proves nothing.
  See `tests/keys/README.md`.

## Generating your own publisher key

```bash
axm-build keygen <outdir> --name <publisher-name>
```

writes `<name>.key` (3904-byte hybrid secret blob — keep it offline) and
`<name>.pub` (1344-byte public key — the only half that ever belongs near a
repository). The builder deliberately has no default signing key: a
signature made with a published key proves integrity only, never
authenticity.

## Custody statement — canonical_publisher.pub (2026-07-06)

- Ceremony mode: **cloud-session ceremony** (Claude Code remote sandbox,
  executed with the maintainer's explicit authorization). This is the
  lowest custody grade in this ledger and it is recorded as such — it is
  NOT the air-gapped ceremony RELEASE.md describes, and NOT a local
  workstation ceremony.
- The keypair was generated with `axm-build keygen` inside the session
  container, outside the repository tree, and was never committed. The
  session container is ephemeral: unless the maintainer exports the secret
  key before the container is reclaimed, the key is destroyed with it and
  this publisher identity can never sign again (supersession then requires
  a new key by RFC — the verification of everything already signed is
  unaffected, since verification needs only this public key).
- The v1.0.0 release tag is **annotated but not maintainer-GPG-signed**:
  the maintainer's signing key was never in the session (correctly). The
  maintainer may re-sign the same commit in place
  (`git tag -sf v1.0.0 <commit> && git push -f origin v1.0.0`).
- Git-URL pins to `refs/tags/v1.0.0` give a stable source ref, but pip
  does not verify tag signatures during installation; authenticity of the
  release is anchored by this repository's history, CI, the gold-shard
  checksums, and the independent timestamp attestations — not by pip
  resolution.
- The provisional key (gold-v2-provisional.pub) is retired under
  archive/v0/keys/ and remains valid only as history.

### Custody amendment (2026-07-06, same day)

The publisher secret key was **deliberately destroyed** (`shred`) at the end
of the ceremony session, before the container was reclaimed. This publisher
identity is single-use by design: nothing can ever be signed under it again.
Verification is unaffected — it requires only `canonical_publisher.pub`,
committed above. Any future signing requires a new keypair adopted by RFC'd
rotation. This is the strongest custody statement available for this grade:
the key cannot be exfiltrated because it no longer exists.
