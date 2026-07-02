# invalid/missing_field

Mutation from valid/minimal: delete the required `entity_type` key from the
first record of `graph/entities.jsonl` (the line re-encoded canonically so
canonical-encoding checks still pass), Merkle root recomputed, manifest
re-signed — so the missing record key is the ONLY defect.

Expected: exit 1, E_SCHEMA_NULL (missing/null required field).
