"""AXM Genesis — Builder CLI.

Commands:
  axm-build keygen <outdir>                          Generate an axm-hybrid1 keypair
  axm-build compile <candidates> <content-dir> <outdir>  Compile a signed shard
  axm-build gold-fm21-11 <source-md> <outdir>        Build the FM 21-11 gold shard
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

from axm_verify.const import SPEC_VERSION, SUITE_HYBRID1
from axm_verify.identity import (
    derive_provenance_id,
    derive_span_id,
    recompute_claim_id,
    recompute_entity_id,
)

from .jsonl import canonical_json_bytes, write_table
from .merkle import compute_merkle_root
from .schemas import CLAIMS_SCHEMA, ENTITIES_SCHEMA, PROVENANCE_SCHEMA, SPANS_SCHEMA
from .sign import (
    HYBRID1_SK_LEN,
    hybrid1_keygen,
    hybrid1_public_key,
    hybrid1_sign,
    manifest_signing_message,
)

HASH_CHUNK_SIZE = 64 * 1024
_KEY_HEX_LEN = HYBRID1_SK_LEN * 2

_NO_KEY_MSG = (
    "No signing key provided. Pass --private-key <{n}-hex-chars> or set the "
    "AXM_SIGNING_KEY_HEX environment variable.\n"
    "There is no default signing key: a key with a published private half "
    "proves integrity, never authenticity. Generate your own keypair with:\n"
    "  axm-build keygen <outdir>"
).format(n=_KEY_HEX_LEN)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _parse_key_hex(private_key: str | None) -> bytes:
    if not private_key:
        raise click.ClickException(_NO_KEY_MSG)
    private_key = private_key.strip()
    if len(private_key) != _KEY_HEX_LEN:
        raise click.ClickException(
            f"--private-key must be exactly {_KEY_HEX_LEN} hex characters "
            f"({HYBRID1_SK_LEN}-byte hybrid1 secret key blob), got {len(private_key)} characters."
        )
    try:
        return bytes.fromhex(private_key)
    except ValueError:
        raise click.ClickException(
            f"--private-key is not valid hex: expected exactly {_KEY_HEX_LEN} "
            "hexadecimal characters."
        )


def _sign_and_seal(shard_dir: Path, manifest: Dict[str, Any], secret_key: bytes) -> None:
    """Write manifest.json and the hybrid signature files."""
    manifest_bytes = canonical_json_bytes(manifest)
    (shard_dir / "manifest.json").write_bytes(manifest_bytes)
    (shard_dir / "sig").mkdir(exist_ok=True)
    (shard_dir / "sig" / "publisher.pub").write_bytes(hybrid1_public_key(secret_key))
    (shard_dir / "sig" / "manifest.sig").write_bytes(
        hybrid1_sign(secret_key, manifest_signing_message(manifest_bytes))
    )


# ── Gold Shard Builder v2 (FM 21-11, axm-hybrid1) ────────────────────────────

def _normalize_markdown(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    out: List[str] = []
    for line in text.splitlines():
        stripped = line.rstrip()
        stripped = re.sub(r"\s+", " ", stripped)
        out.append(stripped)
    return "\n".join(out) + "\n"


def _extract_section(source: str, heading: str) -> str:
    pattern = rf"^(#{{1,6}})\s+{heading}\s*$"
    m = re.search(pattern, source, re.MULTILINE)
    if not m:
        raise ValueError(f"Heading not found: {heading}")
    level = len(m.group(1))
    start = m.end()
    end_pat = rf"^#{{1,{level}}}\s"
    m2 = re.search(end_pat, source[start:], re.MULTILINE)
    end = start + m2.start() if m2 else len(source)
    return source[start:end].strip()


def _build_gold_shard(source_md: Path, outdir: Path, secret_key: bytes) -> Dict[str, Any]:
    """Build the FM 21-11 hemorrhage gold shard v2 (axm-hybrid1)."""
    raw = source_md.read_text(encoding="utf-8")

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
    if shard_dir.exists():
        shutil.rmtree(shard_dir)
    for sub in ("content", "graph", "evidence", "sig"):
        (shard_dir / sub).mkdir(parents=True, exist_ok=True)

    content_path = shard_dir / "content" / "source.txt"
    content_path.write_text(normalized, encoding="utf-8")
    source_hash = _sha256_file(content_path)
    source_bytes = normalized.encode("utf-8")

    namespace = "survival/medical"
    entities_data: List[Dict[str, Any]] = []
    claims_data: List[Dict[str, Any]] = []
    provenance_data: List[Dict[str, Any]] = []
    spans_by_id: Dict[str, Dict[str, Any]] = {}

    keywords = [
        "tourniquet", "pressure dressing", "severe bleeding",
        "broken bone", "elevation", "direct pressure",
        "hemorrhage control", "field dressing",
    ]
    for kw in keywords:
        entities_data.append({
            "entity_id": recompute_entity_id(namespace, kw),
            "namespace": namespace,
            "label": kw,
            "entity_type": "concept",
        })

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

        idx = normalized.lower().find(subj_label.lower())
        if idx < 0:
            continue
        byte_start = len(normalized[:idx].encode("utf-8"))
        span_end = min(idx + 200, len(normalized))
        byte_end = len(normalized[:span_end].encode("utf-8"))
        span_text = source_bytes[byte_start:byte_end].decode("utf-8")

        provenance_data.append({
            "provenance_id": derive_provenance_id(cid, source_hash, byte_start, byte_end),
            "claim_id": cid,
            "source_hash": source_hash,
            "byte_start": byte_start,
            "byte_end": byte_end,
        })
        span_id = derive_span_id(source_hash, byte_start, byte_end, span_text)
        spans_by_id[span_id] = {
            "span_id": span_id,
            "source_hash": source_hash,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "text": span_text,
        }

    write_table(shard_dir / "graph" / "entities.jsonl", entities_data, ENTITIES_SCHEMA, "entity_id")
    write_table(shard_dir / "graph" / "claims.jsonl", claims_data, CLAIMS_SCHEMA, "claim_id")
    write_table(shard_dir / "graph" / "provenance.jsonl", provenance_data, PROVENANCE_SCHEMA, "provenance_id")
    write_table(shard_dir / "evidence" / "spans.jsonl", list(spans_by_id.values()), SPANS_SCHEMA, "span_id")

    merkle_root = compute_merkle_root(shard_dir)

    manifest = {
        "spec_version": SPEC_VERSION,
        "suite": SUITE_HYBRID1,
        "metadata": {
            "title": "FM 21-11 Hemorrhage Control (Measure B)",
            "namespace": namespace,
            "created_at": "2026-01-01T00:00:00Z",
        },
        "publisher": {
            "name": "AXM Genesis Canonical Publisher",
            "id": "@axm_genesis",
        },
        "sources": [{"path": "content/source.txt", "hash": source_hash}],
        "integrity": {"algorithm": "blake3", "merkle_root": merkle_root},
        "statistics": {"entities": len(entities_data), "claims": len(claims_data)},
        "license": {"spdx": "CC0-1.0", "notes": "US Government work"},
    }
    _sign_and_seal(shard_dir, manifest, secret_key)
    return manifest


# ── Generic candidate compiler ───────────────────────────────────────────────

def _compile_from_candidates(
    candidates_path: Path,
    content_dir: Path,
    outdir: Path,
    secret_key: bytes,
    namespace: str = "default",
    title: str = "Untitled Shard",
    created_at: str = "2026-01-01T00:00:00Z",
    license_spdx: str = "UNLICENSED",
) -> Dict[str, Any]:
    """Compile candidates.jsonl + content files into a signed v1 shard.

    candidates.jsonl format (one JSON object per line):
      {"type":"entity", "namespace":"...", "label":"...", "entity_type":"..."}
      {"type":"claim", "subject_label":"...", "predicate":"...", "object_label":"...",
       "object_type":"entity|literal:...", "tier":0-4,
       "evidence":{"source_file":"...", "byte_start":N, "byte_end":N, "text":"..."}}
    """
    shard_dir = outdir
    if shard_dir.exists():
        shutil.rmtree(shard_dir)
    for sub in ("content", "graph", "evidence", "sig"):
        (shard_dir / sub).mkdir(parents=True, exist_ok=True)

    # Copy content files
    content_hashes: Dict[str, str] = {}
    for f in sorted(content_dir.iterdir()):
        if f.is_file():
            dest = shard_dir / "content" / f.name
            shutil.copy2(f, dest)
            content_hashes[f.name] = _sha256_file(dest)

    candidates = []
    with candidates_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                candidates.append(json.loads(line))

    entities_data: List[Dict[str, Any]] = []
    claims_data: List[Dict[str, Any]] = []
    provenance_data: List[Dict[str, Any]] = []
    spans_by_id: Dict[str, Dict[str, Any]] = {}
    entity_map: Dict[str, str] = {}

    def add_entity(ns: str, label: str, entity_type: str = "concept") -> str:
        eid = recompute_entity_id(ns, label)
        if label not in entity_map:
            entity_map[label] = eid
            entities_data.append({
                "entity_id": eid,
                "namespace": ns,
                "label": label,
                "entity_type": entity_type,
            })
        return entity_map[label]

    # Pass 1: entities
    for c in candidates:
        if c["type"] == "entity":
            add_entity(c.get("namespace", namespace), c["label"], c.get("entity_type", "concept"))

    # Pass 2: claims + evidence
    for c in candidates:
        if c["type"] != "claim":
            continue
        subj_label = c["subject_label"]
        obj_label = c["object_label"]
        obj_type = c.get("object_type", "entity")
        pred = c["predicate"]
        tier = int(c.get("tier", 3))

        subj_eid = add_entity(namespace, subj_label)
        obj_val = add_entity(namespace, obj_label) if obj_type == "entity" else obj_label

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
            source_hash = content_hashes.get(ev["source_file"], "")
            byte_start = int(ev["byte_start"])
            byte_end = int(ev["byte_end"])
            text = ev.get("text", "")

            provenance_data.append({
                "provenance_id": derive_provenance_id(cid, source_hash, byte_start, byte_end),
                "claim_id": cid,
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
            })
            span_id = derive_span_id(source_hash, byte_start, byte_end, text)
            spans_by_id[span_id] = {
                "span_id": span_id,
                "source_hash": source_hash,
                "byte_start": byte_start,
                "byte_end": byte_end,
                "text": text,
            }

    write_table(shard_dir / "graph" / "entities.jsonl", entities_data, ENTITIES_SCHEMA, "entity_id")
    write_table(shard_dir / "graph" / "claims.jsonl", claims_data, CLAIMS_SCHEMA, "claim_id")
    write_table(shard_dir / "graph" / "provenance.jsonl", provenance_data, PROVENANCE_SCHEMA, "provenance_id")
    write_table(shard_dir / "evidence" / "spans.jsonl", list(spans_by_id.values()), SPANS_SCHEMA, "span_id")

    merkle_root = compute_merkle_root(shard_dir)

    sources = [{"path": f"content/{name}", "hash": h} for name, h in sorted(content_hashes.items())]
    manifest: Dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "suite": SUITE_HYBRID1,
        "metadata": {
            "title": title,
            "namespace": namespace,
            "created_at": created_at,
        },
        "publisher": {"name": "AXM Genesis Builder", "id": "@axm_builder"},
        "license": {"spdx": license_spdx},
        "sources": sources,
        "integrity": {"algorithm": "blake3", "merkle_root": merkle_root},
        "statistics": {"entities": len(entities_data), "claims": len(claims_data)},
    }
    _sign_and_seal(shard_dir, manifest, secret_key)
    return manifest


# ── CLI ──────────────────────────────────────────────────────────────────────

@click.group()
def main() -> None:
    """AXM Genesis shard builder."""
    pass


@main.command("keygen")
@click.argument("outdir", type=click.Path(file_okay=False, path_type=Path))
@click.option("--name", default="publisher", show_default=True,
              help="Base name for the key files.")
def keygen_cmd(outdir: Path, name: str) -> None:
    """Generate an axm-hybrid1 keypair.

    Writes <outdir>/<name>.key (3904-byte secret key blob: ed25519 seed ||
    ML-DSA-44 sk || ML-DSA-44 pk) and <outdir>/<name>.pub (1344-byte hybrid
    public key). Refuses to overwrite existing files. Keep the .key file
    offline; only the .pub file belongs anywhere near a repository.
    """
    sk_path = outdir / f"{name}.key"
    pk_path = outdir / f"{name}.pub"
    for p in (sk_path, pk_path):
        if p.exists():
            raise click.ClickException(f"Refusing to overwrite existing file: {p}")
    public_key, secret_key = hybrid1_keygen()
    outdir.mkdir(parents=True, exist_ok=True)
    sk_path.touch(mode=0o600)
    sk_path.write_bytes(secret_key)
    pk_path.write_bytes(public_key)
    click.echo(f"Secret key ({len(secret_key)} bytes): {sk_path}")
    click.echo(f"Public key ({len(public_key)} bytes): {pk_path}")


@main.command("compile")
@click.argument("candidates", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("content_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("outdir", type=click.Path(path_type=Path))
@click.option("--private-key", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help=f"Path to the {HYBRID1_SK_LEN}-byte hybrid1 secret key blob (axm-build keygen).")
@click.option("--namespace", default="default", show_default=True)
@click.option("--title", default="Untitled Shard", show_default=True)
@click.option("--created-at", default="2026-01-01T00:00:00Z", show_default=True,
              help="RFC 3339 UTC timestamp (Z suffix) for metadata.created_at.")
@click.option("--license-spdx", default="UNLICENSED", show_default=True)
def compile_cmd(
    candidates: Path,
    content_dir: Path,
    outdir: Path,
    private_key: Path,
    namespace: str,
    title: str,
    created_at: str,
    license_spdx: str,
) -> None:
    """Compile candidates.jsonl + content files into a signed shard."""
    secret_key = private_key.read_bytes()
    if len(secret_key) != HYBRID1_SK_LEN:
        raise click.ClickException(
            f"--private-key file must contain exactly {HYBRID1_SK_LEN} bytes "
            f"(hybrid1 secret key blob), got {len(secret_key)}."
        )
    manifest = _compile_from_candidates(
        candidates_path=candidates,
        content_dir=content_dir,
        outdir=outdir,
        secret_key=secret_key,
        namespace=namespace,
        title=title,
        created_at=created_at,
        license_spdx=license_spdx,
    )
    click.echo(json.dumps(manifest, indent=2, ensure_ascii=False))
    click.echo(f"\nShard written to {outdir}")


@main.command("gold-fm21-11")
@click.argument("source_md", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("outdir", type=click.Path(path_type=Path))
@click.option(
    "--private-key",
    envvar="AXM_SIGNING_KEY_HEX",
    show_envvar=True,
    default=None,
    metavar=f"HEX{_KEY_HEX_LEN}",
    help=(
        f"REQUIRED. axm-hybrid1 secret key blob as exactly {_KEY_HEX_LEN} hex "
        "characters. Falls back to the AXM_SIGNING_KEY_HEX environment "
        "variable. There is deliberately no default: a signature made with a "
        "published key proves integrity only, never authenticity."
    ),
)
def gold_cmd(source_md: Path, outdir: Path, private_key: str | None) -> None:
    """Build the FM 21-11 gold shard v2 (axm-hybrid1)."""
    secret_key = _parse_key_hex(private_key)
    manifest = _build_gold_shard(source_md, outdir, secret_key)
    click.echo(json.dumps(manifest, indent=2, ensure_ascii=False))
    click.echo(f"\nGold shard written to {outdir}")


if __name__ == "__main__":
    main()
