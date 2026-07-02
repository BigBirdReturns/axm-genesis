# invalid/unknown_suite

Mutation from valid/minimal: set `suite` to `"axm-mldsa44"` (a plausible
but non-existent suite identifier), re-encoded canonically and re-signed.
v1 defines exactly one suite, `axm-hybrid1`; the `suite` field is required
and must equal it. Suite detection by key size does not exist in v1.

Expected: exit 1, E_MANIFEST_SCHEMA.
