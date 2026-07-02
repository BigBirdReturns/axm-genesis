# invalid/sources_bijection_missing_entry

Mutation from valid/minimal: append a `sources` entry for
`content/ghost.txt` (with a syntactically valid SHA-256) although no such
file exists in the shard, re-encoded canonically and re-signed — the
dangling sources entry is the ONLY defect.

Expected: exit 1, E_MANIFEST_SCHEMA.
