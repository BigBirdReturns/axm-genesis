# invalid/orphan_claim

Mutation from valid/minimal: delete the `headache` entity row from
`graph/entities.jsonl`, then repair everything downstream so the orphan is
the ONLY defect: `statistics.entities` updated to the new row count, the
Merkle root recomputed, the manifest re-signed with the CI test key.

The claim `aspirin treats headache` now references an entity_id that does
not exist in the entities table.

Expected: exit 1, E_REF_ORPHAN.
