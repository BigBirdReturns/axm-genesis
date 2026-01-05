# AXM Genesis Conformance Profile v1.0.0 (Frozen)

This document defines the minimum requirements for a conforming AXM Genesis shard and verifier.

## 1. Conforming Shard

A shard conforms if it satisfies all requirements in:

- spec/v1.0/SPECIFICATION.md, Sections 2 through 9

In addition, a conforming shard must:

- use UTF-8 for `manifest.json`
- ensure all required Parquet columns contain no null values
- ensure object_type is one of: `entity`, `literal:string`
- ensure tier is an integer in the range 0 to 2

## 2. Conforming Verifier

A verifier conforms if it:

- emits a machine-readable JSON result
- returns PASS only when the shard conforms
- returns FAIL with one or more error codes when the shard does not conform

The reference error codes are defined in `axm_verify.const.ErrorCode`.

## 3. Gold Shard

This repository includes a gold shard at:

`shards/gold/fm21-11-hemorrhage-v1/`

A change that causes the gold shard to fail verification is rejected.
