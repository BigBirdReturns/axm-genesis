# AXM Three-Layer Architecture

**Status**: Normative
**Date**: 2026-02-21

---

## Overview

AXM operates across three layers that share one container format (Genesis) but
serve different temporal purposes. The protocol does not distinguish between
layers — all shards are structurally identical. The distinction is semantic,
enforced by convention, and critical for understanding the system's behavior.

```
Layer           Crypto overhead    Mutability    Purpose
──────────────  ─────────────────  ────────────  ──────────────────────────
Knowledge       Build-time         Immutable     Reference material
Journal         Session-boundary   Immutable     Decision traces
Hot Buffer      None               Append-only   Working memory
```

---

## Layer 1: Knowledge Shards

Knowledge shards contain compiled reference material. They are what Forge
produces and Genesis seals.

**Contents**: Entities (nouns), claims (SPO triples), evidence (byte-range
spans into source text), provenance (source hash + byte offsets). Optionally:
ext/locators (page/paragraph positions), ext/coords (semantic coordinates),
ext/temporal (validity windows), ext/references (cross-shard links).

**Lifecycle**: A document enters Forge. The extraction pipeline segments it,
extracts claims (tier 0–3), binds evidence to byte ranges, and emits
candidates.jsonl. Genesis compiles this into parquet tables, computes the
Merkle root, and signs with ML-DSA-44. The shard is sealed. It never changes.

**Examples**:
- FM 21-11 (military field medicine) → hemorrhage treatment claims
- California Family Code §§ 2030–2032 → spousal support statutes
- SEC 10-K filing → financial claims at tier-0 (structured extraction)
- XBRL financial data → direct candidates, no LLM involved

**Identity**: A knowledge shard's identity is its Merkle root. Same content,
same key, same root. Different content, different root. This is the anchor
that journal shards point back to.

---

## Layer 2: Journal Shards

Journal shards record what happened when knowledge shards were used. They
capture the full decision trace: what was queried, what was retrieved, what
was evaluated, what was rejected, and what was concluded.

**Contents**: Same parquet tables as knowledge shards, but the entities and
claims encode operational events instead of reference facts.

Entity examples:
- `query:2026-02-21T03:00:00Z:tourniquet-application`
- `gate:retrieval:fm21-11:3-claims-returned`
- `gate:threshold:confidence-0.85:passed`
- `gate:constraint:roe-check:permitted`
- `gate:rejection:claim-xyz:below-threshold`

Claim examples:
- `query:abc → retrieved → claim:def FROM shard:merkle_root_xyz`
- `gate:threshold → evaluated → claim:def WITH score 0.92`
- `gate:constraint → permitted → action:apply-tourniquet`
- `gate:rejection → rejected → claim:ghi REASON score 0.31 < threshold 0.5`

**The rejection record is the critical field.** For legal, medical, and
compliance domains, what was considered and discarded matters as much as what
was used. A journal shard proves not just the conclusion but the reasoning
path, including the dead ends.

**Cross-shard references**: Each journal entry points back to the knowledge
shard(s) consulted via ext/references@1.parquet:

```
src_claim_id    relation_type    dst_shard_id           dst_object_type  dst_object_id
claim:abc       retrieved_from   shard_blake3_<root>    claim            claim:def
```

This creates a verifiable chain: journal shard → knowledge shard → source
document → specific byte range. The entire provenance path is cryptographically
sealed at every link.

**Lifecycle**: A session produces trace events (see Layer 3). When the session
ends — or when a size/time/event threshold is reached — the accumulated events
are compiled into a journal shard using the same Forge → Genesis pipeline.
The entities are operational events. The claims are decision records. The
evidence is the query/response text. The provenance points to the hot buffer
records that generated each claim.

**Compounding**: Journal shards are mountable in Spectra like any other shard.
Future queries can reference past decisions. The LLM sees both the doctrine
(knowledge shard) and the history of how that doctrine was applied (journal
shards). Over time, the system accumulates institutional knowledge — not just
what the manual says, but how the manual has been applied in practice.

---

## Layer 3: Hot Buffer

The hot buffer is not a shard. It is the working memory that exists between
journal shard compilations.

**Format**: Append-only structured records. No cryptographic overhead. No
hashing, no signing, no Merkle computation. The format is implementation-
specific: JSONL on disk, ring buffer in memory, WAL file, SQLite — the
protocol does not prescribe it.

**Contents**: Raw trace events as they happen:

```jsonl
{"ts": 1740100800.123, "type": "query", "text": "How do I stop arterial bleeding?", "session": "s:abc"}
{"ts": 1740100800.456, "type": "retrieval", "shard": "shard_blake3_...", "claims": ["c:1", "c:2", "c:3"]}
{"ts": 1740100800.789, "type": "gate", "gate_type": "threshold", "claim": "c:1", "score": 0.92, "threshold": 0.5, "result": "pass"}
{"ts": 1740100800.890, "type": "gate", "gate_type": "threshold", "claim": "c:3", "score": 0.31, "threshold": 0.5, "result": "reject"}
{"ts": 1740100801.234, "type": "gate", "gate_type": "constraint", "rule": "roe:medical", "action": "apply-tourniquet", "result": "permit"}
{"ts": 1740100801.567, "type": "emission", "answer": "Apply tourniquet above wound...", "citations": ["c:1", "c:2"]}
```

**Performance**: Nanosecond writes. No proof-of-work. No per-event signing.
The cost of recording a trace event is a structured append — the same cost
as writing a log line.

**Seal trigger**: The hot buffer is compiled into a journal shard when:
- The session ends (user closes the app, device disconnects)
- A time threshold passes (e.g., every 15 minutes)
- A size threshold passes (e.g., every 1000 events)
- An explicit seal command is issued
- The device is about to lose power

The trigger policy is a configuration decision, not a protocol decision.

**Failure mode**: If the device loses power before sealing, the hot buffer
is recoverable from disk (it's append-only). On next boot, the recovery
process reads the buffer, validates structural integrity (no torn writes),
and compiles whatever is salvageable into a journal shard. Events that were
in-flight at crash time are lost. Events that were flushed to disk survive.

---

## Gate Registry

Journal shards use a fixed set of gate types to classify decision points.
Each gate type has defined inputs, outputs, and semantics:

| Gate Type       | Input                          | Output                        | Records                |
|-----------------|--------------------------------|-------------------------------|------------------------|
| `retrieval`     | Query + mounted shards         | Candidate claims              | What was found         |
| `semantic`      | Claims + query                 | Relevance scores              | How relevant each was  |
| `threshold`     | Scores + threshold value       | Pass/reject per claim         | What was kept/dropped  |
| `rule`          | Action + constraint shards     | Permit/deny/conditional       | What rules applied     |
| `llm_inference` | Context + prompt               | Generated text                | What the LLM produced  |
| `aggregation`   | Multiple claim sets            | Merged result                 | How results combined   |
| `contradiction` | Claim pairs                    | Conflict detection            | What conflicted        |
| `emission`      | Final answer + citations       | Output to user                | What was delivered     |
| `rejection`     | Claim + reason                 | Exclusion record              | What was discarded why |

---

## How It Maps to Existing Components

| Component          | Layer 1 (Knowledge)           | Layer 2 (Journal)              | Layer 3 (Hot Buffer)       |
|--------------------|-------------------------------|--------------------------------|----------------------------|
| Forge              | Document extraction pipeline  | Trace → candidates conversion  | N/A                        |
| Genesis            | Compile + sign shard          | Compile + sign shard           | N/A                        |
| Spectra            | Mount + query                 | Mount + query                  | N/A                        |
| Decision Logger    | N/A                           | N/A                            | Append trace events        |
| DecisionForgeAdapter | N/A                         | Export candidates.jsonl        | Read hot buffer            |
| Hallucination Firewall | N/A                       | Gate: emission validation      | Record pass/fail           |
| Constraint Engine  | N/A                           | Gate: rule evaluation          | Record permit/deny         |
| Nodal Flow         | Mount + query UI              | Mount + query decision history | Display live trace         |

---

## What the Protocol Does NOT Define

- Hot buffer format (JSONL, SQLite, ring buffer — implementation choice)
- Seal trigger policy (time, size, event, explicit — configuration choice)
- Gate evaluation order (pipeline-specific)
- Which knowledge shards to mount (user/application decision)
- How to display journal traces in the UI (presentation concern)

The protocol defines ONE thing: how to seal a collection of facts (whatever
their semantic type) into a cryptographically verified, content-addressed
container. Knowledge shards, journal shards, and future shard types all use
the same container. The three-layer distinction is a convention, not a
protocol feature.
