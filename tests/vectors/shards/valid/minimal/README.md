# valid/minimal

The smallest fully-conforming v1 shard: one content file, three entities,
two claims with provenance and evidence spans, canonical JSONL tables,
`axm-hybrid1` signature by the CI test key.

Built (not mutated) with:

    axm-build compile candidates.jsonl content/ shard/ \
        --private-key tests/keys/ci_test_publisher.key \
        --namespace test/minimal --title "Minimal Valid Shard" \
        --created-at 2026-07-02T00:00:00Z --license-spdx CC0-1.0

Every invalid vector is a surgical mutation of a byte-identical copy of
this shard (see each vector's README).

Expected: exit 0, status PASS.
