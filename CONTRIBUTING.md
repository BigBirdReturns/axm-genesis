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

- CI verifies the committed bytes pass verification
- If a verifier change breaks the gold shard, the verifier change is rejected
- The gold shard is the definition of correctness
