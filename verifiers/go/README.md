# axm-verify-go — independent Go verifier for AXM Genesis v1

A second, independent implementation of the AXM Genesis v1 shard verifier,
written in Go. It exists to test the project's core durability claim: that
a stranger with the specification, the conformance vectors, and standard
crypto libraries can build a conformant verifier with zero access to the
reference code.

## Purity statement

This verifier was built **exclusively** from:

- `spec/v1/SPECIFICATION.md`
- `spec/v1/CONFORMANCE.md`
- `spec/profiles/embodied@1.md`
- `COMPATIBILITY.md`
- `tests/vectors/**` (identity.json, merkle.json, the shard vectors and
  their READMEs, EXPECTED.md)
- the artifact bytes of `shards/gold/**`, `keys/*.pub`, `tests/keys/*.pub`

No reference source (`src/**`, `tools/**`, `tests/*.py`, `archive/**`, or
any Python in this repository) was read at any point. Every ambiguity in
the prose was resolved empirically against the conformance vectors; the
gaps and their resolutions are catalogued in [`FINDINGS.md`](FINDINGS.md).

## Build

Requires Go >= 1.24.

```sh
cd verifiers/go
go build ./cmd/axm-verify-go
```

## Run

The CLI implements the frozen contract of spec section 13 and
COMPATIBILITY.md section 4:

```sh
axm-verify-go shard <shard_dir> --trusted-key <publisher_pubkey>
```

- stdout: one line of machine-readable JSON —
  `{"shard":...,"status":"PASS"|"FAIL","error_count":N,"errors":[{"code":...,"message":...}],"profiles_checked":[...],"profiles_unchecked":[...]}`
- stderr: one `CODE: message` line per error
- exit 0 = PASS; exit 2 = FAIL where every error code is in
  `{E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}`, or the shard path
  is missing, or a command-line usage error; exit 1 = any other FAIL

Example (from the repository root):

```sh
verifiers/go/axm-verify-go shard shards/gold/fm21-11-hemorrhage-v2 \
    --trusted-key keys/gold-v2-provisional.pub
```

Implemented profiles: `embodied@1` (hot-stream continuity). Any other
manifest-declared profile is reported in `profiles_unchecked` — unchecked
is not passed.

## Conformance

```sh
verifiers/go/run_conformance.sh
```

runs, and fails on the first divergence:

1. `go test ./...` — reproduces every case of `tests/vectors/identity.json`
   (canonicalization, entity/claim/provenance/span id derivations) and
   `tests/vectors/merkle.json` (leaves, node, empty root, whole trees).
2. The gold shard `shards/gold/fm21-11-hemorrhage-v2` with
   `keys/gold-v2-provisional.pub` — must PASS, exit 0.
3. Every row of `tests/vectors/shards/EXPECTED.md` — exit code, status,
   sorted error-code set, and `profiles_checked`/`profiles_unchecked` must
   all match.
4. A tamper trio on copies of the gold shard: content byte flip
   (`E_MERKLE_MISMATCH`, exit 1), corrupted Ed25519 signature half
   (exit 1), corrupted ML-DSA signature half (exit 1).

## Dependencies and rationale

| Dependency | Used for | Why |
|---|---|---|
| Go stdlib `crypto/ed25519` | first hybrid signature component | RFC 8032 plain Ed25519, exactly what spec section 3 requires |
| Go stdlib `crypto/sha256` | content hashes, identifier digests | FIPS 180-4 |
| Go stdlib `encoding/json` | JSON *parsing* only | canonical **encoding** is hand-written (`internal/axm/canonical.go`) because Go's encoder escapes HTML characters, uses uppercase `\uXXXX` hex, and does not match the spec's byte rules; the verifier re-encodes every parsed document and compares bytes |
| `lukechampine.com/blake3` | Merkle tree, shard identity | pure-Go BLAKE3 v1 with 32-byte default output |
| `github.com/cloudflare/circl` (`sign/mldsa/mldsa44`) | second hybrid signature component | FIPS 204 final ML-DSA-44, pure (non-pre-hashed) mode with empty context — verified empirically against the gold shard (see FINDINGS.md finding 1) |
| `golang.org/x/text/unicode/norm` | NFC in `canonicalize()` | the Go standard library has no Unicode normalization; x/text is the Go project's own supplementary repository, and any NFC implementation at Unicode >= 15.1.0 is conformant per the spec's stability-policy pin |

## Layout

```
cmd/axm-verify-go/      CLI (frozen contract)
internal/axm/
  canonical.go          canonical JSON encoding (spec section 5) + strict parse
  ids.go                canonicalize(), e1_/c1_/p1_/s1_ derivations (spec 10)
  merkle.go             domain-separated BLAKE3 Merkle tree (spec 8)
  verify.go             staged verification procedure (spec 13.2), layout,
                        signature, Merkle, sources bijection, statistics
  manifest.go           manifest schema (spec 6)
  tables.go             canonical JSONL core tables, ids, references (11-12)
  embodied.go           embodied@1 profile (hot-stream continuity)
  *_test.go             identity.json and merkle.json vector tests
run_conformance.sh      full conformance runner (CI-entrypoint)
FINDINGS.md             spec gaps found and their empirical resolutions
```
