from __future__ import annotations

import base64
import hashlib
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import click
import pyarrow as pa
import pyarrow.parquet as pq

from axm_verify.identity import recompute_entity_id, recompute_claim_id

from .merkle import compute_merkle_root
from .manifest import dumps_canonical_json
from .sign import signing_key_from_private_key_bytes
from .schemas import (
    ENTITIES_SCHEMA,
    CLAIMS_SCHEMA,
    PROVENANCE_SCHEMA,
    SPANS_SCHEMA,
)

from .compiler_generic import CompilerConfig, compile_generic_shard

CANONICAL_TEST_PRIVATE_KEY = bytes.fromhex(
    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
)
GOLD_CREATED_AT = "2026-01-01T00:00:00Z"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _write_parquet_deterministic(path: Path, rows: List[Dict[str, Any]], schema: pa.Schema, sort_key: str) -> None:
    """Write Parquet deterministically as far as PyArrow permits.

    - Explicit schema
    - Rows sorted by primary key
    - No compression, no dictionaries, no statistics
    """
    rows_sorted = sorted(rows, key=lambda r: r[sort_key])
    table = pa.Table.from_pylist(rows_sorted, schema=schema)

    path.parent.mkdir(parents=True, exist_ok=True)
    writer = pq.ParquetWriter(
        path,
        schema=schema,
        compression="NONE",
        use_dictionary=False,
        write_statistics=False,
    )
    try:
        writer.write_table(table)
    finally:
        writer.close()


def _find_span_bytes(content_bytes: bytes, needle: str) -> Tuple[int, int, str]:
    """Return UTF-8 byte offsets for the first occurrence of needle in content_bytes."""
    content_text = content_bytes.decode("utf-8")
    idx = content_text.find(needle)
    if idx < 0:
        raise ValueError(f"Evidence substring not found in content: {needle!r}")
    end = idx + len(needle)

    byte_start = len(content_text[:idx].encode("utf-8"))
    byte_end = len(content_text[:end].encode("utf-8"))
    return byte_start, byte_end, needle


def _normalize_source_text(s: str) -> str:
    """Normalize extracted source text for canonical shards.

    Rules:
    - LF line endings
    - strip trailing whitespace
    - unwrap hard-wrapped lines into paragraphs
    - de-hyphenate words split across line breaks
    - ensure a single final newline
    """
    import re

    s = s.replace("\r\n", "\n").replace("\r", "\n")
    raw_lines = [ln.rstrip() for ln in s.split("\n")]

    # Trim leading/trailing empty lines
    while raw_lines and raw_lines[0] == "":
        raw_lines.pop(0)
    while raw_lines and raw_lines[-1] == "":
        raw_lines.pop()

    out: list[str] = []
    i = 0
    while i < len(raw_lines):
        line = raw_lines[i]
        if line == "":
            # If a blank line splits a sentence, treat it as a soft wrap.
            j = i + 1
            while j < len(raw_lines) and raw_lines[j] == "":
                j += 1
            if out and j < len(raw_lines):
                prev = out[-1]
                nxt = raw_lines[j].lstrip()
                if prev and prev[-1] not in ".:;!?)" and (nxt[:1].islower() or nxt[:1].isdigit()):
                    out[-1] = prev + " " + nxt
                    i = j + 1
                    continue

            out.append("")
            i += 1
            continue

        buf = line
        i += 1
        while i < len(raw_lines):
            nxt = raw_lines[i]
            if nxt == "":
                break

            # If previous line ends with a hyphen, de-hyphenate and join.
            if buf.endswith("-"):
                buf = buf[:-1] + nxt.lstrip()
                i += 1
                continue

            # Heuristic unwrap: join with space unless the current line looks like a heading/list item.
            looks_like_heading = buf.isupper() or buf.endswith(":")
            looks_like_list = nxt.strip().startswith(("-", "*")) or re.match(r"^\(?\d+\)?\.?\s+", nxt) is not None
            if looks_like_heading or looks_like_list:
                break

            buf = buf + " " + nxt.lstrip()
            i += 1

        out.append(buf)


    # Collapse multiple blank lines to a single blank line
    cleaned: list[str] = []
    for ln in out:
        if ln == "" and cleaned and cleaned[-1] == "":
            continue
        cleaned.append(ln)

    normalized = "\n".join(cleaned) + "\n"

    # Targeted OCR repairs required for the canonical gold shard evidence substrings.
    # These edits affect only the gold text normalization path.
    normalized = normalized.replace("pi'essure", "pressure").replace("pi’essure", "pressure")
    normalized = normalized.replace("bleed-\ning", "bleeding")

    return normalized


def _extract_measure_b_from_fm_markdown(fm_md_path: Path) -> str:
    """Extract the Stop the Bleeding (Measure B) section from the FM markdown.

    The provided markdown may include a table of contents. This extractor searches
    for candidate occurrences and selects the one that contains expected body text.
    """
    import re

    raw = fm_md_path.read_text(encoding="utf-8", errors="ignore")
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")

    pat = re.compile(r"STOP\s+THE\s+BLEEDING\s*\(\s*MEASURE\s*B\s*\)", flags=re.IGNORECASE)
    matches = list(pat.finditer(raw))
    if not matches:
        raise ValueError("Could not locate Stop the Bleeding (Measure B) marker in the FM markdown.")

    def score(pos: int) -> int:
        window = raw[pos : pos + 12000].lower()
        s = 0
        for term in ["pressure dressing", "tourniquet", "digital pressure", "elevation"]:
            if term in window:
                s += 1
        # Prefer longer sections that look like prose, not TOC
        if "\n\n" in window:
            s += 1
        return s

    best = max(matches, key=lambda m: score(m.start()))
    start = best.start()
    tail = raw[start:]

    stop = len(tail)
    for pat_stop in [
        r"\n\s*PREVENT\s+SHOCK\s*\(\s*MEASURE\s*C\s*\)",
        r"\n\s*CHAPTER\s+5\b",
    ]:
        m = re.search(pat_stop, tail, flags=re.IGNORECASE)
        if m:
            stop = min(stop, m.start())

    section = tail[:stop]
    return _normalize_source_text(section)



def _build_gold_shard(out_dir: Path, fm_md_path: Path) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "sig").mkdir(parents=True)
    (out_dir / "content").mkdir(parents=True)
    (out_dir / "graph").mkdir(parents=True)
    (out_dir / "evidence").mkdir(parents=True)

    # 1) Content
    source_text = _extract_measure_b_from_fm_markdown(fm_md_path)
    source_path = out_dir / "content" / "source.txt"
    source_path.write_text(source_text, encoding="utf-8", newline="\n")
    content_bytes = source_path.read_bytes()
    source_hash = sha256_file(source_path)

    namespace = "survival/medical"

    # 2) Entities (minimum required by prompt)
    entity_specs = [
        ("pressure dressing", "procedure"),
        ("digital pressure", "procedure"),
        ("tourniquet", "procedure"),
        ("elevation", "procedure"),
        ("severe bleeding", "condition"),
        ("arterial bleeding", "condition"),
        ("broken bone", "condition"),
        ("shock", "condition"),
    ]
    ent_rows: List[Dict[str, Any]] = []
    ent_id_by_label: Dict[str, str] = {}
    for label, etype in entity_specs:
        eid = recompute_entity_id(namespace, label)
        ent_id_by_label[label] = eid
        ent_rows.append(
            {
                "entity_id": eid,
                "namespace": namespace,
                "label": label,
                "entity_type": etype,
            }
        )

    # 3) Claims with required evidence substrings (exact match)
    claim_specs = [
        (
            "pressure dressing",
            "treats",
            "severe bleeding",
            "entity",
            0,
            "pressure dressing is the preferred method for controlling severe bleeding",
        ),
        (
            "tourniquet",
            "treats",
            "severe bleeding",
            "entity",
            0,
            "tourniquet can be used to control bleeding from a limb",
        ),
        (
            "digital pressure",
            "treats",
            "arterial bleeding",
            "entity",
            0,
            "digital pressure can be used to control the bleeding",
        ),
        (
            "broken bone",
            "contraindicates",
            "elevation",
            "entity",
            0,
            "Elevation must not be used if there is a broken bone",
        ),
        (
            "tourniquet",
            "warns",
            "do not loosen",
            "literal:string",
            0,
            "Do not loosen a tourniquet",
        ),
        (
            "tourniquet",
            "precondition",
            "pressure dressing failed",
            "literal:string",
            0,
            "unless a pressure dressing has failed to stop the bleeding",
        ),
    ]

    claim_rows: List[Dict[str, Any]] = []
    prov_rows: List[Dict[str, Any]] = []
    span_rows: List[Dict[str, Any]] = []

    for subj_label, pred, obj_value, obj_type, tier, evidence in claim_specs:
        subj = ent_id_by_label[subj_label]
        if obj_type == "entity":
            obj = ent_id_by_label[obj_value]
        else:
            obj = obj_value

        cid = recompute_claim_id(subj, pred, obj, obj_type)

        byte_start, byte_end, span_text = _find_span_bytes(content_bytes, evidence)

        # Deterministic IDs for provenance/span (sha256-based, same as prior generator conventions but aligned)
        # These IDs are not currently verified by axm_verify, but we keep them deterministic for reimplementation.
        def _b32_id(prefix: str, canonical: str) -> str:

            digest = hashlib.sha256(canonical.encode("utf-8")).digest()
            return prefix + base64.b32encode(digest[:15]).decode("ascii").lower().rstrip("=")

        provenance_id = _b32_id("p_", f"{source_hash}\x00{byte_start}\x00{byte_end}")
        span_id = _b32_id("s_", f"{source_hash}\x00{byte_start}\x00{byte_end}\x00{span_text}")

        claim_rows.append(
            {
                "claim_id": cid,
                "subject": subj,
                "predicate": pred,
                "object": obj,
                "object_type": obj_type,
                "tier": int(tier),
            }
        )
        prov_rows.append(
            {
                "provenance_id": provenance_id,
                "claim_id": cid,
                "source_hash": source_hash,
                "byte_start": int(byte_start),
                "byte_end": int(byte_end),
            }
        )
        span_rows.append(
            {
                "span_id": span_id,
                "source_hash": source_hash,
                "byte_start": int(byte_start),
                "byte_end": int(byte_end),
                "text": span_text,
            }
        )

    # 4) Parquet (sorted)
    _write_parquet_deterministic(out_dir / "graph" / "entities.parquet", ent_rows, ENTITIES_SCHEMA, "entity_id")
    _write_parquet_deterministic(out_dir / "graph" / "claims.parquet", claim_rows, CLAIMS_SCHEMA, "claim_id")
    _write_parquet_deterministic(out_dir / "graph" / "provenance.parquet", prov_rows, PROVENANCE_SCHEMA, "provenance_id")
    _write_parquet_deterministic(out_dir / "evidence" / "spans.parquet", span_rows, SPANS_SCHEMA, "span_id")

    # 5) Manifest (canonical JSON, fixed timestamp, deterministic pubkey/signature)
    merkle_root = compute_merkle_root(out_dir)
    manifest: Dict[str, Any] = {
        "spec_version": "1.0.0",
        "shard_id": f"shard_blake3_{merkle_root}",
        "metadata": {
            "title": "FM 21-11 Hemorrhage Control (Measure B)",
            "namespace": namespace,
            "created_at": GOLD_CREATED_AT,
        },
        "publisher": {
            "id": "@axm_genesis_test",
            "name": "AXM Genesis Canonical Test Publisher",
        },
        "license": {"spdx": "CC0-1.0", "notes": "US Government work"},
        "sources": [{"path": "content/source.txt", "hash": source_hash}],
        "integrity": {"algorithm": "blake3", "merkle_root": merkle_root},
        "statistics": {"entities": len(ent_rows), "claims": len(claim_rows)},
    }

    manifest_bytes = dumps_canonical_json(manifest)
    (out_dir / "manifest.json").write_bytes(manifest_bytes)

    sk = signing_key_from_private_key_bytes(CANONICAL_TEST_PRIVATE_KEY)
    vk = sk.verify_key
    (out_dir / "sig" / "publisher.pub").write_bytes(bytes(vk))
    sig = sk.sign(manifest_bytes).signature
    (out_dir / "sig" / "manifest.sig").write_bytes(sig)


@click.group()
def main() -> None:
    """AXM Genesis shard builder."""


@main.command("gold-fm21-11")
@click.argument("fm_markdown", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("out_dir", type=click.Path(dir_okay=True, file_okay=False, path_type=Path))
def gold_fm21_11(fm_markdown: Path, out_dir: Path) -> None:
    """Build the canonical gold shard from the FM 21-11 markdown source."""
    _build_gold_shard(out_dir, fm_markdown)
    click.echo(f"Wrote gold shard to: {out_dir}")


@main.command("compile")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--candidates",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSONL extracted claims",
)
@click.option(
    "--out",
    "out_dir",
    required=True,
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help="Output directory",
)
@click.option(
    "--key",
    default=None,
    envvar="AXM_PRIVATE_KEY",
    help="Publisher Ed25519 private key hex (32 bytes). If unset, uses the canonical test key.",
)
@click.option(
    "--namespace",
    default="generic/import",
    show_default=True,
    help="Entity namespace for this shard.",
)
@click.option(
    "--publisher-id",
    default="@cli_builder",
    show_default=True,
)
@click.option(
    "--publisher-name",
    default="AXM CLI Builder",
    show_default=True,
)
@click.option(
    "--created-at",
    required=True,
    help="ISO8601 timestamp.",
)
def compile_cmd(
    source: Path,
    candidates: Path,
    out_dir: Path,
    key: str | None,
    namespace: str,
    publisher_id: str,
    publisher_name: str,
    created_at: str,
) -> None:
    """Compile a canonical source + candidates.jsonl into a verified AXM shard."""

    if key is None:
        priv_bytes = CANONICAL_TEST_PRIVATE_KEY
    else:
        try:
            priv_bytes = bytes.fromhex(key)
        except ValueError as e:
            raise click.ClickException("Invalid private key hex") from e
        if len(priv_bytes) != 32:
            raise click.ClickException("Private key must be 32 bytes (64 hex chars)")

    cfg = CompilerConfig(
        source_path=source,
        candidates_path=candidates,
        out_dir=out_dir,
        private_key=priv_bytes,
        publisher_id=publisher_id,
        publisher_name=publisher_name,
        namespace=namespace,
        created_at=created_at,
    )

    ok = compile_generic_shard(cfg)
    if not ok:
        raise SystemExit(1)
    click.echo(f"Wrote shard to: {out_dir}")

if __name__ == "__main__":
    main()
