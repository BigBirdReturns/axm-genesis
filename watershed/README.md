# Watershed

What is deliberately centralized is the one thing that must be: the meaning of verification. Everything above the basin is replaceable, forkable, and incapable of capturing its peers.

A registry of repositories assigned to layers, with one rule enforced mechanically: dependencies flow downhill only, toward a frozen basin. Sideways and uphill dependencies fail CI. The manifest is the durable surface; any ecosystem it describes is an instance.

Watershed exists because growing ecosystems recreate the failure they were built to attack: authority scattered across repos, no repo owning the whole invariant, every fix touching three ledger formats. The check makes the illegal dependency a build failure instead of a discovery.

## The rule

A repo may depend only on repos in strictly lower layers. Layer 0, the basin layer, is internally stratified (kernel < format < verification) and permits acyclic intra-layer dependencies; all layers above it are flat. The basin repo is frozen and depends on nothing. Shared needs between same-layer repos go down into layer 0 as versioned extensions, never sideways.

## The layers (canonical four; instances may rename, not reorder)

| Index | Name | Rule |
|-------|------|------|
| 0 | protocol | Defines vocabulary and verification. Extensions live here and only here. |
| 1 | attention | Orchestrates and observes through ledgers at runtime. Non-dependable: no code dependency may point into it, from anywhere. |
| 2 | instruments | Produce ledgers from protocol vocabulary. Never depend on each other. |
| 3 | publications | Cite instrument outputs by hash and version. Depended on by nothing. |

A layer may declare `dependable: false` when its repos interact with the ecosystem only through ledgers at runtime (observers, orchestrators). Its position in the ordering then grants no code-dependency rights in either direction — the checker forbids every edge into it. Layer 0 must be dependable.

## Extensions

Versioned, immutable vocabulary objects (`temporal@1`, `evidence-tiers@1`). A version bump is a new id. Extensions are the growth mechanism: when two instruments need the same thing, the question is which extension it becomes, not which repo to copy from. Consuming an extension is the only legal sideways-looking relationship, and it resolves downhill because extensions are defined at layer 0.

## Statuses

frozen (normative surface immutable — the spec, vocabulary, and signature roots, anything a downstream verifier's result depends on; no dependencies; conformance fixtures, CI config, and tooling changes are permitted, because they are the frozen thing's immune system, not the frozen thing), active, incubating (layer provisional; not yet a legal dependency target), legacy (may be depended on, may not add dependencies), archived (nothing may depend on it).

## Target edges (forecast, not state)

A `depends_on` entry may be written as `{ "repo": "axm-core", "target": true }`: a declared target state, not yet an actual import. The edge must still be legal — an aspiration to violate the invariant fails now — but the manifest stops asserting a present-tense fact that is not true. The checker labels any manifest containing target edges `FORECAST` in its output. Remove the flag when the dependency becomes real. Until a receipt-level check exists that reads each repo's actual imports and lockfiles and fails on divergence from the manifest, declared non-target edges are themselves self-reported; treat the manifest accordingly.

## Usage

```bash
# validate manifest shape
npx ajv-cli validate --spec=draft2020 -s schema/watershed.schema.json -d your.watershed.json

# enforce flow direction (wire into CI on every manifest change)
node ci/watershed-check.js your.watershed.json
```

Exit 0: all flows downhill. Exit 1: violations listed flat, one per line, including sideways, uphill, self, cycles, archived targets, incubating targets, edges into non-dependable layers, and frozen repos claiming dependencies.

## Files

```
schema/watershed.schema.json    Manifest schema (JSON Schema draft 2020)
ci/watershed-check.js           The enforcement. Node, no dependencies.
example/axm.watershed.json      Populated instance: the AXM ecosystem, 11 repos, 4 layers.
test/watershed-check.test.js    Negative tests: every rule has a fixture that violates it.
```

## Forking the shape

Any ecosystem with a frozen root and a proliferation problem bears this shape. Copy the schema, write your manifest, name your basin, wire the check into CI. The layers generalize: protocol becomes "spec," instruments become "services," publications become "clients." The rule does not change. Water does not flow uphill.
