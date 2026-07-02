#!/usr/bin/env python3
"""
axm-fleet/src/axm_fleet/record_compile.py

Node Record Compiler
====================

Compiles a node_record.json into a genesis-verifiable shard.

The spoke owns exactly three things (docs/ADOPTING.md): domain extraction,
its CLI, and its dependency declarations. Compilation, signing, Merkle
construction, identity derivation, and lineage emission are the kernel's.

The sustainment loop this spoke exists for:

  deploy   -> compile a record shard, verify with the escrowed key
  patch    -> compile a NEW record shard that `supersedes` the old one;
              the kernel emits manifest.supersedes + ext/lineage@1.jsonl
  audit    -> anyone with the trusted public key (supplied out of band)
              can prove what is running, who built it, who signed it,
              when it changed, and what authorized the change — offline,
              with no vendor infrastructure in the loop.

There is deliberately no default signing key. A signature under a
published key proves integrity, never authenticity.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import blake3

from axm_build.common import normalize_source_text
from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.sign import HYBRID1_SK_LEN

from axm_fleet.record_schema import validate_node_record

_NAMESPACE = "fleet/node"
_PUBLISHER_ID = "@axm_fleet"
_PUBLISHER_NAME = "AXM Fleet Record Compiler"


# ---------------------------------------------------------------------------
# Candidate extraction
# ---------------------------------------------------------------------------

def _extract_candidates(record: dict, source_text: str) -> list[dict]:
    """Extract genesis-compatible candidates from a node record.

    Evidence strings are key:value fragments of the normalized source JSON;
    the kernel requires each to occur exactly once (ambiguous evidence
    fails the build, missing evidence drops the candidate).
    """
    candidates: list[dict] = []

    asset = record.get("asset", {})
    image = record.get("image", {})
    components = record.get("components", {})
    event = record.get("event", {})
    asset_id = asset["asset_id"]

    def _add(subj: str, pred: str, obj: str, obj_type: str, tier: int, evidence: str) -> None:
        if evidence in source_text:
            candidates.append({
                "subject": subj,
                "predicate": pred,
                "object": obj,
                "object_type": obj_type,
                "tier": tier,
                "evidence": evidence,
            })

    # --- Asset ---
    _add(asset_id, "program", asset["program"], "literal:string", 0,
         f'"program": "{asset["program"]}"')
    _add(asset_id, "platform", asset["platform"], "literal:string", 1,
         f'"platform": "{asset["platform"]}"')
    # The substitutable surface: which compute the node carries is
    # configuration (tier 1), never architecture.
    _add(asset_id, "compute_module", asset["compute_module"], "literal:string", 1,
         f'"compute_module": "{asset["compute_module"]}"')

    # --- Image: integrity facts (tier 0) ---
    subj_image = f"{asset_id}/image"
    _add(subj_image, "image_digest", image["image_digest"], "literal:string", 0,
         f'"image_digest": "{image["image_digest"]}"')
    _add(subj_image, "sbom_digest", image["sbom_digest"], "literal:string", 0,
         f'"sbom_digest": "{image["sbom_digest"]}"')
    if image.get("provenance_digest"):
        _add(subj_image, "provenance_digest", image["provenance_digest"],
             "literal:string", 0,
             f'"provenance_digest": "{image["provenance_digest"]}"')
    _add(subj_image, "signing_key_id", image["signing_key_id"], "literal:string", 0,
         f'"signing_key_id": "{image["signing_key_id"]}"')

    # --- Image: configuration (tier 1) ---
    _add(subj_image, "build_id", image["build_id"], "literal:string", 1,
         f'"build_id": "{image["build_id"]}"')
    _add(subj_image, "sbom_format", image["sbom_format"], "literal:string", 1,
         f'"sbom_format": "{image["sbom_format"]}"')
    _add(subj_image, "built_at_utc", image["built_at_utc"], "literal:string", 1,
         f'"built_at_utc": "{image["built_at_utc"]}"')
    _add(subj_image, "builder", image["builder"], "literal:string", 1,
         f'"builder": "{image["builder"]}"')

    # --- Components ---
    # The digest fragment is unique per component (schema enforces pairwise
    # distinct digests); the name fragment is unique because component names
    # are object keys. Both anchor evidence for that component's claims.
    for name, comp in components.items():
        subj = f"{asset_id}/{name}"
        name_evidence = f'"{name}": {{'
        _add(subj, "component_digest", comp["digest"], "literal:string", 0,
             f'"digest": "{comp["digest"]}"')
        _add(subj, "component_version", comp["version"], "literal:string", 1,
             name_evidence)
        _add(subj, "component_kind", comp["kind"], "literal:string", 1,
             name_evidence)

    # --- Event (tier 2) ---
    subj_event = f"{asset_id}/event"
    _add(subj_event, "event_type", event["event_type"], "literal:string", 2,
         f'"event_type": "{event["event_type"]}"')
    _add(subj_event, "event_time_utc", event["event_time_utc"], "literal:string", 2,
         f'"event_time_utc": "{event["event_time_utc"]}"')
    _add(subj_event, "authorized_by", event["authorized_by"], "literal:string", 2,
         f'"authorized_by": "{event["authorized_by"]}"')
    if event.get("note"):
        _add(subj_event, "note", event["note"], "literal:string", 2,
             f'"note": "{event["note"]}"')

    return candidates


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def _load_secret_key(key_path: "Path | None", secret_key: "bytes | None") -> bytes:
    if secret_key is None:
        if key_path is None:
            raise ValueError(
                "A signing key is required: pass key_path (the 3904-byte "
                "axm-hybrid1 secret key blob written by `axm-build keygen`) "
                "or secret_key bytes. There is deliberately no default key."
            )
        secret_key = Path(key_path).read_bytes()
    if len(secret_key) != HYBRID1_SK_LEN:
        raise ValueError(
            f"Signing key is not a {HYBRID1_SK_LEN}-byte axm-hybrid1 secret "
            f"key blob (got {len(secret_key)} bytes). Generate one with: "
            f"axm-build keygen <outdir> --name <publisher>"
        )
    return secret_key


def compile_record(
    record_path: "Path | None",
    out_path: Path,
    key_path: "Path | None" = None,
    *,
    secret_key: "bytes | None" = None,
    supersedes: "tuple[str, ...]" = (),
    lineage_action: str = "supersede",
    lineage_note: str = "",
    created_at: "str | None" = None,
    _record_raw: "dict | None" = None,
) -> str:
    """Compile a node_record.json into a genesis-verifiable shard.

    Returns the derived shard identity ("sh1_" + BLAKE3 of the manifest
    bytes — spec §9: identity is derived, never stored).

    Args:
        record_path:    Path to node_record.json. Ignored if _record_raw given.
        key_path:       Path to the 3904-byte axm-hybrid1 secret key blob.
        secret_key:     The key blob itself, for callers holding it in memory.
        supersedes:     Derived sh1_ id(s) of the record(s) this one replaces.
                        The kernel emits manifest.supersedes and one
                        ext/lineage@1.jsonl row per predecessor.
        lineage_action: supersede | amend | retract.
        lineage_note:   Human note on the lineage row. Defaults to
                        "<event_type> <build_id>" from the record.
        created_at:     RFC 3339 UTC with Z suffix. Defaults to now; pass a
                        fixed value for reproducible builds.
    """
    if _record_raw is not None:
        record = _record_raw
    else:
        with open(record_path, "r", encoding="utf-8") as f:
            record = json.load(f)

    key_blob = _load_secret_key(key_path, secret_key)

    errors = validate_node_record(record)
    if errors:
        for e in errors:
            print(f"  VALIDATION ERROR: {e}")
        raise ValueError(f"Node record validation failed with {len(errors)} errors")

    if created_at is None:
        created_at = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    # The record document itself is the sealed source; every claim cites a
    # fragment of it, and its digests bind the external artifacts (image,
    # SBOM, models, firmware) by content address. Normalize exactly as the
    # kernel will so evidence uniqueness is checked against sealed bytes.
    source_text = normalize_source_text(
        json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True)
    )

    candidates = _extract_candidates(record, source_text)
    if not candidates:
        raise ValueError("No candidates extracted from node record")

    asset_id = record["asset"]["asset_id"]
    build_id = record["image"]["build_id"]
    event_type = record["event"]["event_type"]
    if supersedes and not lineage_note:
        lineage_note = f"{event_type} {build_id}"

    out_path = Path(out_path)

    with tempfile.TemporaryDirectory(prefix="axm_fleet_") as tmp:
        work_dir = Path(tmp)
        source_path = work_dir / "source.txt"
        source_path.write_text(source_text, encoding="utf-8")

        candidates_path = work_dir / "candidates.jsonl"
        with candidates_path.open("w", encoding="utf-8") as f:
            for c in candidates:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")

        cfg = CompilerConfig(
            source_path=source_path,
            candidates_path=candidates_path,
            out_dir=out_path,
            private_key=key_blob,
            publisher_id=_PUBLISHER_ID,
            publisher_name=_PUBLISHER_NAME,
            namespace=_NAMESPACE,
            created_at=created_at,
            title=f"{asset_id} · {build_id} · {event_type}",
            supersedes=tuple(supersedes),
            lineage_action=lineage_action,
            lineage_note=lineage_note,
        )

        # compile_generic_shard writes the shard AND self-verifies it against
        # the publisher key; False means the kernel rejected its own output.
        if not compile_generic_shard(cfg):
            raise RuntimeError(f"Shard failed kernel self-verification: {out_path}")

    manifest_bytes = (out_path / "manifest.json").read_bytes()
    return "sh1_" + blake3.blake3(manifest_bytes).hexdigest()
