# invalid/unsorted_rows

Mutation from valid/minimal: swap the first two lines of
`graph/entities.jsonl` (each line still canonical; the file no longer
sorted bytewise ascending by primary key), Merkle root recomputed, manifest
re-signed — so row order is the ONLY defect.

Expected: exit 1, E_SCHEMA_READ (rows out of order).
