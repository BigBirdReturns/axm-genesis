# Shard vector expectations (v1)

Machine-readable ground truth for every shard vector in this directory.
Each row records the outcome OBSERVED by running the reference verifier on
the vector at generation time; the conformance suite consumes this table
and must reproduce it exactly.

- Verifier invocation: `axm-verify shard <shard> --trusted-key tests/keys/ci_test_publisher.pub`
- `shard` paths are relative to `tests/vectors/shards/`.
- `error_codes` is `;`-separated and sorted; `-` means none.
- Exit codes (frozen contract): 0 = PASS; 2 = FAIL where every error code is in
  {E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING} (or the path is missing);
  1 = any other FAIL.
- Each vector directory has a README.md documenting the exact mutation.
- `invalid/invalid_embodied_gap` is binding only for verifiers implementing
  the `embodied@1` profile; a verifier without it must report the profile
  under `profiles_unchecked` (and would PASS that shard).

| vector | shard | exit_code | status | error_codes | profiles_checked | profiles_unchecked |
|--------|-------|-----------|--------|-------------|------------------|--------------------|
| valid/minimal | valid/minimal/shard | 0 | PASS | - | - | - |
| valid/valid_embodied | valid/valid_embodied/shard | 0 | PASS | - | embodied@1 | - |
| invalid/bad_signature_ed25519_half | invalid/bad_signature_ed25519_half/shard | 1 | FAIL | E_SIG_INVALID | - | - |
| invalid/bad_signature_mldsa_half | invalid/bad_signature_mldsa_half/shard | 1 | FAIL | E_SIG_INVALID | - | - |
| invalid/dup_primary_key | invalid/dup_primary_key/shard | 1 | FAIL | E_SCHEMA_READ | - | - |
| invalid/invalid_embodied_gap | invalid/invalid_embodied_gap/shard | 1 | FAIL | E_BUFFER_DISCONTINUITY | embodied@1 | - |
| invalid/manifest_shard_id_present | invalid/manifest_shard_id_present/shard | 1 | FAIL | E_MANIFEST_SCHEMA | - | - |
| invalid/merkle_mismatch | invalid/merkle_mismatch/shard | 1 | FAIL | E_MERKLE_MISMATCH | - | - |
| invalid/missing_field | invalid/missing_field/shard | 1 | FAIL | E_SCHEMA_NULL | - | - |
| invalid/missing_manifest | invalid/missing_manifest/shard | 2 | FAIL | E_LAYOUT_MISSING | - | - |
| invalid/orphan_claim | invalid/orphan_claim/shard | 1 | FAIL | E_REF_ORPHAN | - | - |
| invalid/sources_bijection_extra_file | invalid/sources_bijection_extra_file/shard | 1 | FAIL | E_MANIFEST_SCHEMA | - | - |
| invalid/sources_bijection_missing_entry | invalid/sources_bijection_missing_entry/shard | 1 | FAIL | E_MANIFEST_SCHEMA | - | - |
| invalid/statistics_mismatch | invalid/statistics_mismatch/shard | 1 | FAIL | E_MANIFEST_SCHEMA | - | - |
| invalid/unknown_suite | invalid/unknown_suite/shard | 1 | FAIL | E_MANIFEST_SCHEMA | - | - |
| invalid/unsorted_rows | invalid/unsorted_rows/shard | 1 | FAIL | E_SCHEMA_READ | - | - |
