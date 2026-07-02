# invalid/bad_signature_mldsa_half

Mutation from valid/minimal: XOR byte 1064 of `sig/manifest.sig` with 0x01.
Byte 1064 lies in the ML-DSA-44 component (bytes 64..2483 of the hybrid
signature). The Ed25519 component is untouched and still verifies —
hybrid verification must fail because BOTH components must verify.

Expected: exit 1, E_SIG_INVALID.
