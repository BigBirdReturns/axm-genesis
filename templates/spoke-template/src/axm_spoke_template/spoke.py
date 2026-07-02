"""The one function a spoke owns: turn domain input into claim candidates,
then hand them to the axm-genesis kernel to compile, sign, and self-verify.

This template's "domain" is deliberately trivial — a plain text file, one
claim per usable line — so that everything else (candidates, CompilerConfig,
compile, derived shard identity) is visible with no domain noise. Replace
``extract_candidates`` with your real extraction; do not touch the rest.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import blake3

from axm_build.common import normalize_source_text
from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.sign import HYBRID1_SK_LEN

MAX_CANDIDATES = 2  # template keeps the shard tiny; raise freely


def extract_candidates(source_text: str, doc_label: str) -> List[Dict[str, Any]]:
    """Emit claim candidates from raw text. THIS is the part you replace.

    The kernel compiler locates each ``evidence`` quote as a unique byte
    substring of the normalized source (ambiguous evidence fails the build),
    so we only emit lines that occur exactly once.
    """
    normalized = normalize_source_text(source_text)
    candidates: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for line in normalized.splitlines():
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        if normalized.count(line) != 1:
            continue  # ambiguous evidence would (correctly) fail the compile
        candidates.append({
            "subject": doc_label,
            "predicate": "contains_line",
            "object": line,
            "object_type": "literal:string",
            "tier": 0,
            "evidence": line,
        })
        if len(candidates) >= MAX_CANDIDATES:
            break
    return candidates


def build_shard(
    source_path: Path,
    out_dir: Path,
    key_path: Path,
    namespace: str,
    *,
    publisher_id: str = "@axm_spoke_template",
    publisher_name: str = "AXM Spoke Template",
    created_at: str = "2026-01-01T00:00:00Z",
    license_spdx: str = "UNLICENSED",
) -> str:
    """Compile ``source_path`` into a signed shard; return the derived sh1_ id.

    ``key_path`` is the 3904-byte axm-hybrid1 secret key blob written by
    ``axm-build keygen``. It stays outside your repository; only the .pub
    file is ever committed or distributed.
    """
    source_path = Path(source_path)
    out_dir = Path(out_dir)

    secret_key = Path(key_path).read_bytes()
    if len(secret_key) != HYBRID1_SK_LEN:
        raise ValueError(
            f"{key_path} is not a {HYBRID1_SK_LEN}-byte axm-hybrid1 secret key "
            f"blob (got {len(secret_key)} bytes). Generate one with: "
            f"axm-build keygen <outdir> --name <publisher>"
        )

    text = source_path.read_text(encoding="utf-8")
    candidates = extract_candidates(text, doc_label=source_path.stem)
    if not candidates:
        raise ValueError(f"No usable claim candidates extracted from {source_path}")

    with tempfile.TemporaryDirectory() as tmp:
        candidates_path = Path(tmp) / "candidates.jsonl"
        with candidates_path.open("w", encoding="utf-8") as f:
            for c in candidates:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")

        cfg = CompilerConfig(
            source_path=source_path,
            candidates_path=candidates_path,
            out_dir=out_dir,
            private_key=secret_key,
            publisher_id=publisher_id,
            publisher_name=publisher_name,
            namespace=namespace,
            created_at=created_at,
            title=source_path.name,
            license_spdx=license_spdx,
        )
        # compile_generic_shard writes the shard AND self-verifies it against
        # the publisher key; False means the kernel rejected its own output.
        if not compile_generic_shard(cfg):
            raise RuntimeError(f"Shard failed kernel self-verification: {out_dir}")

    # Shard identity is derived, never stored (spec section 9):
    #   shard_id = "sh1_" + hex(BLAKE3(manifest bytes))
    manifest_bytes = (out_dir / "manifest.json").read_bytes()
    return "sh1_" + blake3.blake3(manifest_bytes).hexdigest()
