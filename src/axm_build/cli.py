"""
AXM Genesis — Builder CLI

Commands:
  axm-build gold-fm21-11 <source-md> <outdir>   Build the gold shard (Ed25519, frozen)
  axm-build compile <candidates> <content-dir> <outdir> [--suite ...]  Generic compile
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import unicodedata
from pathlib import Path
from typing import Any, Dict, List

import click
import pyarrow as pa
import pyarrow.parquet as pq
from nacl.signing import SigningKey

from axm_verify.identity import recompute_entity_id, recompute_claim_id
from axm_verify.const import ENTITIES_SCHEMA, CLAIMS_SCHEMA, PROVENANCE_SCHEMA, SPANS_SCHEMA
from axm_build.manifest import dumps_canonical_json
from axm_build.merkle import compute_merkle_root

HASH_CHUNK_SIZE = 64 * 1024
CANONICAL_TEST_PRIVATE_KEY = bytes.fromhex("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ── Gold Shard Builder (FM 21-11, Ed25519 only) ─────────────────────────────

def _normalize_markdown(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    lines = text.splitlines()
    out: List[str] = []
    for line in lines:
        stripped = line.rstrip()
        stripped = re.sub(r"\s+", " ", stripped)
        out.append(stripped)
    return "\n".join(out) + "\n"


def _extract_section(source: str, heading: str) -> str:
    pattern = rf"^(#{1,6})\s+{re.escape(heading)}\s*$"
    m = re.search(pattern, source, re.MULTILINE)
    if not m:
        raise ValueError(f"Heading not found: {heading}")
    level = len(m.group(1))
    start = m.end()
    end_pat = rf"^#{{{1},{level}}}\s"
    m2 = re.search(end_pat, source[start:], re.MULTILINE)
    end = start + m2.start() if m2 else len(source)
    return source[start:end].strip()


def _build_gold_shard(source_md: Path, outdir: Path, private_key_hex: str) -> Dict[str, Any]:
    """Build the FM 21-11 hemorrhage gold shard (Ed25519)."""
    raw = source_md.read_text(encoding="utf-8")

    # Try both heading patterns
    section = None
    for pattern in [r"Measure B\b.*", r"STOP THE BLEEDING"]:
        try:
            section = _extract_section(raw, pattern)
            break
        except ValueError:
            continue

    if section is None:
        raise click.ClickException("Cannot find hemorrhage section in source markdown")

    normalized = _normalize_markdown(section)

    shard_dir = outdir
    shard_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("content", "graph", "evidence", "sig"):
        (shard_dir / sub).mkdir(exist_ok=True)

    content_path = shard_dir / "content" / "source.txt"
    content_path.write_text(normalized, encoding="utf-8")
    source_hash = _sha256_file(content_path)

    namespace = "survival/medical"
    entities_data: List[Dict[str, str]] = []
    claims_data: List[Dict[str, Any]] = []
    provenance_data: List[Dict[str, Any]] = []
    spans_data: List[Dict[str, Any]] = []

    # Entity extraction
    keywords = [
        "tourniquet", "pressure dressing", "severe bleeding",
        "broken bone", "elevation", "direct pressure",
        "hemorrhage control", "field dressing",
    ]
    source_bytes = normalized.encode("utf-8")

    for kw in keywords:
        eid = recompute_entity_id(namespace, kw)
        entities_data.append({
            "entity_id": eid,
            "namespace": namespace,
            "label": kw,
            "entity_type": "concept",
        })

    # Claim extraction
    claim_specs = [
        ("tourniquet", "treats", "severe bleeding", "entity"),
        ("pressure dressing", "treats", "severe bleeding", "entity"),
        ("elevation", "supports", "hemorrhage control", "entity"),
        ("direct pressure", "treats", "severe bleeding", "entity"),
        ("tourniquet", "contraindicated_for", "broken bone", "entity"),
        ("field dressing", "supports", "hemorrhage control", "entity"),
    ]

    for subj_label, pred, obj_label, obj_type in claim_specs:
        subj_eid = recompute_entity_id(namespace, subj_label)
        obj_eid = recompute_entity_id(namespace, obj_label)
        cid = recompute_claim_id(subj_eid, pred, obj_eid, obj_type)
        claims_data.append({
            "claim_id": cid,
            "subject": subj_eid,
            "predicate": pred,
            "object": obj_eid,
            "object_type": obj_type,
            "tier": 3,
        })

        kw_lower = subj_label.lower()
        idx = normalized.lower().find(kw_lower)
        if idx >= 0:
            byte_start = len(normalized[:idx].encode("utf-8"))
            span_end = min(idx + 200, len(normalized))
            byte_end = len(normalized[:span_end].encode("utf-8"))
            span_text = source_bytes[byte_start:byte_end].decode("utf-8")

            prov_id = hashlib.sha256(f"{cid}:{source_hash}:{byte_start}".encode()).hexdigest()[:24]
            provenance_data.append({
                "provenance_id": f"p_{prov_id}",
                "claim_id": cid,
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
            })

            span_id = hashlib.sha256(f"s:{source_hash}:{byte_start}:{byte_end}".encode()).hexdigest()[:24]
            spans_data.append({
                "span_id": f"s_{span_id}",
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
                "text": span_text,
            })

    # Write parquet tables
    ent_table = pa.table(
        {f.name: [r[f.name] for r in entities_data] for f in ENTITIES_SCHEMA},
        schema=ENTITIES_SCHEMA,
    )
    pq.write_table(ent_table, shard_dir / "graph" / "entities.parquet")

    clm_table = pa.table(
        {f.name: [r[f.name] for r in claims_data] for f in CLAIMS_SCHEMA},
        schema=CLAIMS_SCHEMA,
    )
    pq.write_table(clm_table, shard_dir / "graph" / "claims.parquet")

    prv_table = pa.table(
        {f.name: [r[f.name] for r in provenance_data] for f in PROVENANCE_SCHEMA},
        schema=PROVENANCE_SCHEMA,
    )
    pq.write_table(prv_table, shard_dir / "graph" / "provenance.parquet")

    spn_table = pa.table(
        {f.name: [r[f.name] for r in spans_data] for f in SPANS_SCHEMA},
        schema=SPANS_SCHEMA,
    )
    pq.write_table(spn_table, shard_dir / "evidence" / "spans.parquet")

    # Compute Merkle root (legacy Ed25519 suite)
    merkle_root = compute_merkle_root(shard_dir, suite="ed25519")

    # Build manifest
    manifest = {
        "spec_version": "1.0.0",
        "shard_id": f"shard_blake3_{merkle_root}",
        "metadata": {
            "title": "FM 21-11 Hemorrhage Control (Measure B)",
            "namespace": namespace,
            "created_at": "2026-01-01T00:00:00Z",
        },
        "publisher": {
            "name": "AXM Genesis Canonical Test Publisher",
            "id": "@axm_genesis_test",
        },
        "sources": [{"path": "content/source.txt", "hash": source_hash}],
        "integrity": {
            "algorithm": "blake3",
            "merkle_root": merkle_root,
        },
        "statistics": {
            "entities": len(entities_data),
            "claims": len(claims_data),
        },
        "license": {
            "spdx": "CC0-1.0",
            "notes": "US Government work",
        },
    }

    manifest_bytes = dumps_canonical_json(manifest)
    (shard_dir / "manifest.json").write_bytes(manifest_bytes)

    # Sign
    sk = SigningKey(bytes.fromhex(private_key_hex))
    sig = sk.sign(manifest_bytes).signature
    (shard_dir / "sig" / "manifest.sig").write_bytes(sig)
    (shard_dir / "sig" / "publisher.pub").write_bytes(bytes(sk.verify_key))

    return manifest


# ── Generic Compiler (suite-aware, v1.1) ─────────────────────────────────────

def _compile_from_candidates(
    candidates_path: Path,
    content_dir: Path,
    outdir: Path,
    suite: str = "axm-blake3-mldsa44",
    private_key_path: Path | None = None,
    namespace: str = "default",
    title: str = "Untitled Shard",
) -> Dict[str, Any]:
    """Generic shard compiler. Reads candidates.jsonl + content → signed shard.

    candidates.jsonl format (one JSON object per line):
      {"type":"entity", "namespace":"...", "label":"...", "entity_type":"..."}
      {"type":"claim", "subject_label":"...", "predicate":"...", "object_label":"...",
       "object_type":"entity|literal:...", "tier":0-4,
       "evidence":{"source_file":"...", "byte_start":N, "byte_end":N, "text":"..."}}
    """
    from axm_build.sign import (
        SUITE_ED25519, SUITE_MLDSA44,
        signing_key_from_private_key_bytes, mldsa44_sign,
    )

    shard_dir = outdir
    shard_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("content", "graph", "evidence", "sig"):
        (shard_dir / sub).mkdir(exist_ok=True)

    # Copy content files
    content_hashes: Dict[str, str] = {}
    for f in sorted(content_dir.iterdir()):
        if f.is_file():
            dest = shard_dir / "content" / f.name
            shutil.copy2(f, dest)
            content_hashes[f.name] = _sha256_file(dest)

    # Parse candidates
    candidates = []
    with candidates_path.open("r") as fh:
        for line in fh:
            line = line.strip()
            if line:
                candidates.append(json.loads(line))

    entities_data: List[Dict[str, str]] = []
    claims_data: List[Dict[str, Any]] = []
    provenance_data: List[Dict[str, Any]] = []
    spans_data: List[Dict[str, Any]] = []

    entity_map: Dict[str, str] = {}

    # Pass 1: entities
    for c in candidates:
        if c["type"] == "entity":
            ns = c.get("namespace", namespace)
            label = c["label"]
            eid = recompute_entity_id(ns, label)
            if eid not in entity_map.values():
                entity_map[label] = eid
                entities_data.append({
                    "entity_id": eid,
                    "namespace": ns,
                    "label": label,
                    "entity_type": c.get("entity_type", "concept"),
                })

    # Pass 2: claims + evidence
    for c in candidates:
        if c["type"] != "claim":
            continue

        subj_label = c["subject_label"]
        obj_label = c["object_label"]
        obj_type = c.get("object_type", "entity")
        pred = c["predicate"]
        tier = int(c.get("tier", 3))

        for lbl in (subj_label, obj_label if obj_type == "entity" else None):
            if lbl and lbl not in entity_map:
                eid = recompute_entity_id(namespace, lbl)
                entity_map[lbl] = eid
                entities_data.append({
                    "entity_id": eid,
                    "namespace": namespace,
                    "label": lbl,
                    "entity_type": "concept",
                })

        subj_eid = entity_map[subj_label]
        obj_val = entity_map[obj_label] if obj_type == "entity" else obj_label

        cid = recompute_claim_id(subj_eid, pred, obj_val, obj_type)
        claims_data.append({
            "claim_id": cid,
            "subject": subj_eid,
            "predicate": pred,
            "object": obj_val,
            "object_type": obj_type,
            "tier": tier,
        })

        ev = c.get("evidence")
        if ev:
            source_file = ev["source_file"]
            source_hash = content_hashes.get(source_file, "")
            byte_start = int(ev["byte_start"])
            byte_end = int(ev["byte_end"])
            text = ev.get("text", "")

            prov_id = hashlib.sha256(f"{cid}:{source_hash}:{byte_start}".encode()).hexdigest()[:24]
            provenance_data.append({
                "provenance_id": f"p_{prov_id}",
                "claim_id": cid,
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
            })

            span_id = hashlib.sha256(f"s:{source_hash}:{byte_start}:{byte_end}".encode()).hexdigest()[:24]
            spans_data.append({
                "span_id": f"s_{span_id}",
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
                "text": text,
            })

    # Write parquet
    pq.write_table(
        pa.table({f.name: [r[f.name] for r in entities_data] for f in ENTITIES_SCHEMA}, schema=ENTITIES_SCHEMA),
        shard_dir / "graph" / "entities.parquet",
    )
    pq.write_table(
        pa.table({f.name: [r[f.name] for r in claims_data] for f in CLAIMS_SCHEMA}, schema=CLAIMS_SCHEMA),
        shard_dir / "graph" / "claims.parquet",
    )
    pq.write_table(
        pa.table({f.name: [r[f.name] for r in provenance_data] for f in PROVENANCE_SCHEMA}, schema=PROVENANCE_SCHEMA),
        shard_dir / "graph" / "provenance.parquet",
    )
    pq.write_table(
        pa.table({f.name: [r[f.name] for r in spans_data] for f in SPANS_SCHEMA}, schema=SPANS_SCHEMA),
        shard_dir / "evidence" / "spans.parquet",
    )

    # ext/
    ext_dir = shard_dir / "ext"
    extensions = []
    if ext_dir.exists() and any(ext_dir.iterdir()):
        for f in sorted(ext_dir.iterdir()):
            if f.is_file():
                extensions.append(f.name)

    # Merkle root
    merkle_root = compute_merkle_root(shard_dir, suite=suite)

    # Manifest
    sources = [{"path": f"content/{name}", "hash": h} for name, h in sorted(content_hashes.items())]
    manifest: Dict[str, Any] = {
        "spec_version": "1.1.0",
        "suite": suite,
        "shard_id": f"shard_blake3_{merkle_root}",
        "metadata": {
            "title": title,
            "namespace": namespace,
            "created_at": "2026-01-01T00:00:00Z",
        },
        "publisher": {
            "name": "AXM Genesis Builder",
            "id": "@axm_builder",
        },
        "sources": sources,
        "integrity": {
            "algorithm": "blake3",
            "merkle_root": merkle_root,
        },
        "statistics": {
            "entities": len(entities_data),
            "claims": len(claims_data),
        },
    }
    if extensions:
        manifest["extensions"] = extensions

    manifest_bytes = dumps_canonical_json(manifest)
    (shard_dir / "manifest.json").write_bytes(manifest_bytes)

    # Sign
    if private_key_path:
        key_bytes = private_key_path.read_bytes()
        if suite == SUITE_MLDSA44:
            sig = mldsa44_sign(key_bytes, manifest_bytes)
            pk_path = private_key_path.parent / "publisher.pub"
            pk_bytes = pk_path.read_bytes()
        else:
            sk = signing_key_from_private_key_bytes(key_bytes[:32])
            sig = sk.sign(manifest_bytes).signature
            pk_bytes = bytes(sk.verify_key)

        (shard_dir / "sig" / "manifest.sig").write_bytes(sig)
        (shard_dir / "sig" / "publisher.pub").write_bytes(pk_bytes)

    return manifest


# ── CLI ──────────────────────────────────────────────────────────────────────

@click.group()
def main() -> None:
    """AXM Genesis shard builder."""
    pass


@main.command("gold-fm21-11")
@click.argument("source_md", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("outdir", type=click.Path(path_type=Path))
@click.option("--private-key", default="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
def gold_cmd(source_md: Path, outdir: Path, private_key: str) -> None:
    """Build the FM 21-11 gold shard (Ed25519, frozen)."""
    manifest = _build_gold_shard(source_md, outdir, private_key)
    click.echo(json.dumps(manifest, indent=2, ensure_ascii=False))
    click.echo(f"\nGold shard written to {outdir}")


@main.command("compile")
@click.argument("candidates", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("content_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("outdir", type=click.Path(path_type=Path))
@click.option("--suite", default="axm-blake3-mldsa44", type=click.Choice(["ed25519", "axm-blake3-mldsa44"]))
@click.option("--private-key", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None)
@click.option("--namespace", default="default")
@click.option("--title", default="Untitled Shard")
def compile_cmd(
    candidates: Path,
    content_dir: Path,
    outdir: Path,
    suite: str,
    private_key: Path | None,
    namespace: str,
    title: str,
) -> None:
    """Compile candidates.jsonl + content files into a signed shard."""
    manifest = _compile_from_candidates(
        candidates_path=candidates,
        content_dir=content_dir,
        outdir=outdir,
        suite=suite,
        private_key_path=private_key,
        namespace=namespace,
        title=title,
    )
    click.echo(json.dumps(manifest, indent=2, ensure_ascii=False))
    click.echo(f"\nShard written to {outdir}")


if __name__ == "__main__":
    main()
