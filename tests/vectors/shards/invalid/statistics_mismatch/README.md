# invalid/statistics_mismatch

Mutation from valid/minimal: increment `statistics.claims` by one (now 3;
`graph/claims.jsonl` has 2 rows), re-encoded canonically and re-signed —
so the statistics/row-count disagreement is the ONLY defect. Every earlier
stage (layout, manifest schema, signature, Merkle, bijection, tables,
identities, references) passes.

Expected: exit 1, E_MANIFEST_SCHEMA.
