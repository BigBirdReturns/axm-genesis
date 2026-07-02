# Gold Shard v2 — fm21-11-hemorrhage-v2

The gold shard (`fm21-11-hemorrhage-v2/`) is the reference artifact of AXM
Genesis v1 (`spec/v1/CONFORMANCE.md` section 5): a real shard, minted under
the `axm-hybrid1` suite from the same FM 21-11 hemorrhage-control source
text as the retired v0.x gold shard. Its `content/source.txt` is
byte-identical to `archive/v0/gold/fm21-11-hemorrhage-v1/content/source.txt`
(SHA-256 `b5f9d284…bb04c` in both checksum files).

Derived identity (v1 rule — `sh1_` + BLAKE3 of the canonical manifest bytes):

```
sh1_ec77b88475889e48a7cd6d87103b729c7b27b846683cc6e279141f2c40c643fd
```

## PROVISIONAL status — read before trusting the signature

**This v2 mint is PROVISIONAL.** It was signed with a fresh `axm-hybrid1`
keypair generated inside a cloud coding session on 2026-07-02, **not** under
the offline key ceremony that RFC 0002 D7 requires. The private key was used
once, held only in session-local temporary storage, never written to the
repository, and destroyed (`shred -u`) immediately after signing. The public
half is committed at `keys/gold-v2-provisional.pub`.

What that means:

- **Integrity is fully meaningful.** Verification against
  `keys/gold-v2-provisional.pub` and the byte pins in `CHECKSUMS.sha256`
  detect any modification to these bytes. Unlike the v0 key, this key's
  private half was never published, so no third party can re-sign altered
  bytes — but a cloud session is not a custody story.
- **Authenticity awaits the ceremony.** Before the v1.0.0 freeze is
  declared, the gold shard will be re-minted and signed with the canonical
  publisher key generated at the RFC 0002 offline key ceremony (custody
  documented in `keys/README.md`), and timestamp attestations over the new
  manifest will land under `attestations/`. The re-mint procedure is in
  `RELEASE.md`. Only that ceremony mint inherits the "never recompiled"
  pledge.

Because the mint is deterministic (canonical JSONL, deterministic ML-DSA
signing, fixed `created_at`), the ceremony re-mint from the same source will
reproduce every byte outside `sig/`, and the manifest is expected to be
byte-identical; only the key material and signature change.

## Verify

```bash
axm-verify shard shards/gold/fm21-11-hemorrhage-v2 --trusted-key keys/gold-v2-provisional.pub
# exit 0, status PASS
sha256sum -c shards/gold/CHECKSUMS.sha256
```

## Reproduction

The shard was built with the reference builder from the archived source
text (the extractor and claim set are unchanged from the v0 gold builder,
ported to the v1 kernel):

```bash
# wrap the archived section text under its original heading, then:
axm-build gold-fm21-11 <wrapped-fm21-11.md> <outdir> --private-key <hex>
```

Never run any build command against `shards/gold/` itself. Reproduce into a
different directory and compare.

The v0.x gold shard (`fm21-11-hemorrhage-v1`, legacy Ed25519 suite, Parquet
tables) is archived history at `archive/v0/gold/` and is no longer
normative.
