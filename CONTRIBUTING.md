# Contributing to AXM Genesis

## Code Changes

1. Fork the repository
2. Create a branch
3. Make changes
4. Ensure `make test` passes
5. Submit a pull request

Maintainers may merge code PRs that do not change the frozen specification.

Building a downstream spoke rather than changing Genesis itself? See
[docs/ADOPTING.md](docs/ADOPTING.md) and [templates/spoke-template/](templates/spoke-template/).

## Specification Changes

The specification is `spec/v1/` (SPECIFICATION.md + CONFORMANCE.md). It is
frozen: **from the v1.0.0 tag onward, changes to `spec/v1/` are never
accepted.** Until that tag lands (the pending steps are the key ceremony
and the release itself — see [RELEASE.md](RELEASE.md)), spec fixes are
possible but each one requires an RFC, exactly like a post-freeze change
would.

The former `spec/v1.0/` documents are the v0.x prototype lineage, archived
at `archive/v0/spec/` — historical, not normative, and not a valid target
for changes of any kind.

To propose changes:

1. Create a file in `rfcs/` named `NNNN-short-title.md`
2. Use the RFC template below
3. Submit a pull request for discussion
4. If accepted, changes go into a new spec version — after v1.0.0, a
   breaking change means a new major format (new `spec_version`, new suite
   identifier, new identifier prefixes), never a mutation of `spec/v1/`.
   Profiles (`spec/profiles/`) and extensions version independently and
   are the additive path.

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

The gold shard is `shards/gold/fm21-11-hemorrhage-v2/` (`axm-hybrid1`,
canonical JSONL). It is never regenerated — with one scheduled exception:
the RFC 0002 key ceremony re-mint ([RELEASE.md](RELEASE.md) step 2), which
replaces only the signature material of the current provisional mint. From
the v1.0.0 tag onward, the "never recompiled" pledge is absolute.

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
  job) and the frozen-bytes check above are required to pass
- The v0.x gold shard (`fm21-11-hemorrhage-v1`) is archived at
  `archive/v0/gold/` with its own checksum pins; it is history, not an
  oracle, and must not verify under the v1 kernel

## Test Vector Policy

`tests/vectors/` is conformance ground truth (COMPATIBILITY.md §8): vectors
are frozen once added, new vectors may be added in minor versions, existing
vectors are never modified or removed.
