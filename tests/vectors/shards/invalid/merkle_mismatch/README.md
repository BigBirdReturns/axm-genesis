# invalid/merkle_mismatch

Mutation from valid/minimal: XOR the second-to-last byte of
`content/doc.txt` with 0x01. Nothing else changes: the manifest (and thus
the signature over it) is intact, but the recomputed Merkle root no longer
equals `integrity.merkle_root`. (The `sources` hash is also stale, but the
Merkle check runs first and the verifier stops at the first failing stage.)

Expected: exit 1, E_MERKLE_MISMATCH.
