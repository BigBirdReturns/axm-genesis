# invalid/bad_signature_ed25519_half

Mutation from valid/minimal: XOR byte 0 of `sig/manifest.sig` with 0x01.
Byte 0 lies in the Ed25519 component (bytes 0..63 of the 2484-byte hybrid
signature). The ML-DSA-44 component is untouched and still verifies —
hybrid verification must fail because BOTH components must verify.

Expected: exit 1, E_SIG_INVALID.
