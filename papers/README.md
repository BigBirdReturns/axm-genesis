# Papers

Design documents and theory for AXM Genesis. These are explanatory, not normative —
the repository manifest, the committed shard files, and the specification under
[`spec/v1.0`](../spec/v1.0) remain the source of truth for anything stated here.

| Paper | Description |
|-------|-------------|
| [AXM Genesis: A Frozen Cryptographic Kernel for Verified Knowledge Reconstruction](axm-genesis-frozen-cryptographic-kernel-v0.6.pdf) (draft v0.6, June 2026) | Defines Verifiable Reconstruction Architectures (VRA), frames RAG as a degenerate runtime-generation special case of a general reconstruction pipeline, and presents AXM Genesis — signed shards, BLAKE3 Merkle integrity, ML-DSA-44 post-quantum signatures, and deterministic query-time execution — as a proof-by-construction alternative. References commit `6fa74b6d8de87bf8e4f3cc00309e409704b806e4`. |

## Errata

Published PDFs cannot be edited, so known errors are corrected in the
repository's errata register: [`docs/ERRATA.md`](../docs/ERRATA.md).

Known errata for the v0.6 draft:

- **Erratum 1** — Section 6.3.3 misdescribes the Merkle construction
  (odd-node handling, BLAKE3 "PARENT flag", dotfile exclusion). The normative
  definition is [`spec/v1.0/SPECIFICATION.md`](../spec/v1.0/SPECIFICATION.md)
  section 4 plus the reference implementation
  [`src/axm_build/merkle.py`](../src/axm_build/merkle.py); the erratum
  reproduces the correct construction in full. See
  [`docs/ERRATA.md`](../docs/ERRATA.md), Erratum 1.
