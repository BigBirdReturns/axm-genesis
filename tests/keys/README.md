# tests/keys — CI test keypair

**This keypair proves nothing.** Both halves are committed to the
repository on purpose.

| File | Contents |
|------|----------|
| `ci_test_publisher.key` | axm-hybrid1 secret key blob, 3904 bytes: `ed25519_seed (32) ‖ sk_mldsa44 (2560) ‖ pk_mldsa44 (1312)` |
| `ci_test_publisher.pub` | axm-hybrid1 public key, 1344 bytes: `pk_ed25519 (32) ‖ pk_mldsa44 (1312)` |

It was generated with `axm-build keygen tests/keys --name ci_test_publisher`
and exists solely so that the test suite and CI can compile, sign, mutate,
and verify the shard vectors under `tests/vectors/shards/` (see
`tests/vectors/shards/EXPECTED.md`) deterministically.

Because the private half is public, a signature under this key
demonstrates the signing/verification pipeline and pins bytes — it can
never establish authenticity or origin. Never sign a real artifact with
it, never add it to any trust store, and never treat a signature that
validates against `ci_test_publisher.pub` as evidence of who produced the
signed bytes.

Real publisher keys live outside the repository; see `keys/README.md`.
