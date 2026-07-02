# Keys

## `canonical_test_publisher.pub`

Ed25519 public key used by `make verify-gold` and the test suite to verify the
frozen gold shard (`shards/gold/fm21-11-hemorrhage-v1/`).

**This key pins integrity, not authenticity.** Its private half was
historically published in this repository (it was once the hardcoded default
signing key of the builder CLI), so anyone can produce signatures that
validate against it. A signature under this key proves the signed bytes have
not changed since signing; it does not prove who signed them. Authenticity of
the gold shard rests on this repository's git history.

Never sign anything new with the corresponding private key, and never treat a
signature under this key as evidence of origin.

## Supplying your own signing key

The builder CLI deliberately has no default signing key. Provide one via
`--private-key <64-hex-chars>` or the `AXM_SIGNING_KEY_HEX` environment
variable. Generate a fresh Ed25519 seed with:

```bash
python -c "from nacl.signing import SigningKey; print(bytes(SigningKey.generate()).hex())"
```

Keep private keys out of this repository. See `docs/DURABILITY.md` for the
planned detached attestation / timestamping of the gold shard.
