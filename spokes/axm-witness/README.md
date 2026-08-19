# AXM Witness bootstrap transport

This directory stages the qualified `axm-witness` v0.1 source tree for extraction into a dedicated repository. It is a transport object, not the intended long-term repository layout and not a municipal deployment.

The connected GitHub path available during bootstrap could create a governed branch and pull request in AXM Genesis, but it could not create a new repository or push a local checkout. The source tree is therefore carried as a deterministic archive split into independently hashed text fragments. CI reconstructs the archive, verifies the exact SHA-256 identity, extracts the spoke into a clean directory, and reruns the Python, Go, mutation, and cross-language qualification campaigns.

## Transport identity

- Source archive: `axm-witness-bootstrap.tar.gz`
- Archive SHA-256: `f8d60bbf18f14167186ef71e256e0d855817bfeb272b7a25c30230e1c0c77f56`
- Base64 SHA-256: `8a3cfa1a05dc0846de8ca6222591c1a01681d0f4e2ee0b3584a825b16e987044`
- Fragments: 10, sorted lexically from `part00` through `part09`
- Source status: laboratory bootstrap, not deployed

Reconstruct the exact tree with:

```bash
spokes/axm-witness/bootstrap/extract.sh /tmp/axm-witness
cd /tmp/axm-witness/axm-witness
python -m pip install -e '.[dev]'
make qualify
```

`bootstrap/TRANSPORT.json` binds every fragment name, size, file SHA-256, and Git blob identity. `bootstrap/SHA256SUMS` binds the reconstructed base64 and archive objects.

## Qualified mechanism

The staged source contains an append-only SQLite WAL ledger, exact raw-byte custody, deterministic canonical JSON, Ed25519 event signatures, a chained record digest, gap and quarantine faults, HMAC commitments for enumerable identifiers, four municipal event schemas, signed segment manifests, aggregate public receipts, a detached Python verifier, a separately implemented Go verifier, a file-backed acquisition aperture, and planted mutation campaigns.

The retained local campaign passed 21 of 21 Python tests, 3 of 3 Go tests, 12 of 12 Python mutation and evidence-boundary cases, and 9 of 9 cross-language replay cases. GitHub CI repeats those checks from the reconstructed transport object.

## Claim boundary

Version 0.1 proves integrity and continuity after an event enters agency custody. It does not prove that Flock Safety or another exclusive source disclosed every event before agency receipt. Tier 2 remains a synthetic cursor and inventory fixture. Tier 3 remains a schema-level origin-commitment contract without a camera-side or dual-publish implementation.

No live PSPD identity provider, Flock API, retention policy, redaction policy, key ceremony, encrypted municipal storage profile, TPM quote, RFC 3161 timestamp, Genesis hybrid seal, Console driver, or Fleet appliance record has been qualified. The dedicated repository should be created only after this bootstrap object is admitted and extracted without changing the archive identity.
