# invalid/sources_bijection_extra_file

Mutation from valid/minimal: add `content/extra.txt` WITHOUT listing it in
`sources`, recompute the Merkle root (so the tree commits to the new file)
and re-sign — so the broken bijection is the ONLY defect: a file under
`content/` that `sources` does not declare.

Expected: exit 1, E_MANIFEST_SCHEMA.
