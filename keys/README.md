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
