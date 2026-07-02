# invalid/manifest_shard_id_present

Mutation from valid/minimal: add a `shard_id` field to the manifest (set to
the value a v0.x-style publisher would plausibly write — the derived id of
the valid manifest, `sh1_d0fcd5ca31ce75b9207f...`), re-encoded canonically
and re-signed with the CI test key so the forbidden field is the ONLY
defect. In v1 shard identity is DERIVED (`sh1_` + BLAKE3 of the canonical
manifest bytes); a `shard_id` key in the manifest is a schema violation.

Expected: exit 1, E_MANIFEST_SCHEMA.
