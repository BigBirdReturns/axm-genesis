# invalid/dup_primary_key

Mutation from valid/minimal: duplicate the first line of
`graph/entities.jsonl` verbatim (identical primary key twice, canonical
encoding and byte order otherwise intact), Merkle root recomputed, manifest
re-signed. `statistics.entities` is deliberately left at the original value:
table validation stops at the duplicate before statistics are compared.

Expected: exit 1, E_SCHEMA_READ (duplicate primary key).
