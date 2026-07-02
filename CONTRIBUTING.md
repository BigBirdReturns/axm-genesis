# Contributing to AXM Genesis

## Code Changes

1. Fork the repository
2. Create a branch
3. Make changes
4. Ensure `make test` passes
5. Submit a pull request

Maintainers may merge code PRs that do not change the frozen specification.

## Specification Changes

The published specification is frozen. Changes to `spec/v1.0/` are never accepted after release.

To propose changes:

1. Create a file in `rfcs/` named `NNNN-short-title.md`
2. Use the RFC template below
3. Submit a pull request for discussion
4. If accepted, changes go into a new spec version (for example, `spec/v1.1/`)

## RFC Template

```
# RFC NNNN: Title

## Summary
One paragraph.

## Motivation
Why is this needed?

## Specification
Exact changes to spec language.

## Backwards Compatibility
Does this break existing shards?

## Reference Implementation
Link to code or PR.
```

## Gold Shard Policy

The gold shard in `shards/gold/` is never regenerated.

- The gold shard is the definition of correctness
- CI enforces this on every push and pull request via the **CI** workflow
  (`.github/workflows/ci.yml`), whose `gold-shard` job:
  1. Checks the committed bytes against the pinned checksums with
     `sha256sum -c shards/gold/CHECKSUMS.sha256` (locally: `make verify-frozen`).
     Any change to the frozen bytes fails this guard.
  2. Runs `make verify-gold` (the reference verifier against the gold shard
     with the canonical trusted key) and requires exit code 0.
- If a verifier change breaks the gold shard, the `gold-shard` job fails and
  the verifier change is rejected
- To merge, `make test` (the conformance suite, run by the workflow's `test`
  job on Python 3.11 and 3.12) and the frozen-bytes check above are required
  to pass
