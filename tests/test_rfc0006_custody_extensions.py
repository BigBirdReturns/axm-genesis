"""RFC 0006: custody-evidence extensions — packets@1 and tpm-attestation@1.

Both are ordinary registered extension tables fed through the one-pass
compiler's extra_content / extra_ext path (no reseal, no post-compile
injection). The verbatim packet bytes and every TPM blob live in content/
as Merkle leaves; the JSONL rows only INDEX them by (file, offset, length)
+ sha256. This is what lets axm-sfn stop reimplementing kernel surfaces.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.ext_schemas import EXTENSION_REGISTRY
from axm_build.jsonl import read_table
from axm_verify.logic import verify_shard
from helpers import requires_mldsa_backend

pytestmark = requires_mldsa_backend

DOC_TEXT = (
    "Custody session log\n"
    "packet 0 sealed under TPM signing key\n"
    "packet 1 sealed under TPM signing key\n"
)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _write_inputs(base: Path) -> tuple[Path, Path]:
    source = base / "source.txt"
    source.write_text(DOC_TEXT, encoding="utf-8")
    candidates = base / "candidates.jsonl"
    rows = [
        {
            "subject": "node-001",
            "predicate": "sealed",
            "object": f"packet-{seq}",
            "object_type": "entity",
            "tier": 1,
            "evidence": f"packet {seq} sealed under TPM signing key",
        }
        for seq in (0, 1)
    ]
    candidates.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return source, candidates


def _cfg(base: Path, ci_secret_key: bytes, **overrides) -> CompilerConfig:
    source, candidates = _write_inputs(base)
    defaults = dict(
        source_path=source,
        candidates_path=candidates,
        out_dir=base / "shard",
        private_key=ci_secret_key,
        publisher_id="@ci_test",
        publisher_name="CI Test Publisher",
        namespace="test/custody",
        created_at="2026-07-03T00:00:00Z",
        title="RFC 0006 custody extensions test",
        license_spdx="CC0-1.0",
    )
    defaults.update(overrides)
    return CompilerConfig(**defaults)


def _custody_shard(base: Path, ci_secret_key: bytes) -> CompilerConfig:
    """Two packets + one TPM signing key + one quote, indexed into content/."""
    # Verbatim canonical packet bytes concatenated into one content leaf.
    p0, p1 = b"PKT-zero-canonical-bytes", b"PKT-one-canonical-bytes"
    packets_bin = base / "packets.bin"
    packets_bin.write_bytes(p0 + p1)
    packets_rows = [
        {"seq": 0, "file": "content/packets.bin", "offset": 0,
         "length": len(p0), "packet_sha256": _sha(p0)},
        {"seq": 1, "file": "content/packets.bin", "offset": len(p0),
         "length": len(p1), "packet_sha256": _sha(p1)},
    ]

    # TPM blobs concatenated into one content leaf, one row per blob.
    sig0 = b"tpmt-signature-over-packet-0"
    pubk = b"tpm2b-public-signing-key-area"
    qsig = b"tpmt-signature-over-attest"
    qatt = b"tpm2b-attest-pcr-digest+nonce"
    qnon = b"qualifying-data-nonce-32bytes-xx"
    blob = bytearray()
    def _put(b: bytes) -> tuple[int, int]:
        off = len(blob)
        blob.extend(b)
        return off, len(b)
    o_sig, l_sig = _put(sig0)
    o_pub, l_pub = _put(pubk)
    o_qsig, l_qsig = _put(qsig)
    o_qatt, l_qatt = _put(qatt)
    o_qnon, l_qnon = _put(qnon)
    att_bin = base / "tpm-attestation.bin"
    att_bin.write_bytes(bytes(blob))
    key_fp = _sha(pubk)
    F = "content/tpm-attestation.bin"
    tpm_rows = [
        {"kind": "packet_sig", "seq": 0, "field": "signature",
         "alg": "tpm2:rsapss-2048-sha256:tpmt-signature", "key_fingerprint": key_fp,
         "file": F, "offset": o_sig, "length": l_sig, "sha256": _sha(sig0), "pcrs": ""},
        {"kind": "sign_pub", "seq": 0, "field": "public",
         "alg": "tpm2:tpm2b-public", "key_fingerprint": key_fp,
         "file": F, "offset": o_pub, "length": l_pub, "sha256": _sha(pubk), "pcrs": ""},
        {"kind": "quote", "seq": 1, "field": "signature",
         "alg": "tpm2:rsapss-2048-sha256:tpmt-signature", "key_fingerprint": key_fp,
         "file": F, "offset": o_qsig, "length": l_qsig, "sha256": _sha(qsig), "pcrs": ""},
        {"kind": "quote", "seq": 1, "field": "attest",
         "alg": "tpm2:rsapss-2048-sha256:tpmt-signature", "key_fingerprint": key_fp,
         "file": F, "offset": o_qatt, "length": l_qatt, "sha256": _sha(qatt),
         "pcrs": "[0,1,2,7]"},
        {"kind": "quote", "seq": 1, "field": "nonce",
         "alg": "tpm2:rsapss-2048-sha256:tpmt-signature", "key_fingerprint": key_fp,
         "file": F, "offset": o_qnon, "length": l_qnon, "sha256": _sha(qnon), "pcrs": ""},
    ]

    return _cfg(
        base,
        ci_secret_key,
        extra_content=(("packets.bin", packets_bin), ("tpm-attestation.bin", att_bin)),
        extra_ext={"packets@1": packets_rows, "tpm-attestation@1": tpm_rows},
    )


def test_custody_extensions_registered():
    for ext_id in ("packets@1", "tpm-attestation@1"):
        reg = EXTENSION_REGISTRY[ext_id]
        assert reg["file"] == ext_id + ".jsonl"
        assert isinstance(reg["unique"], bool)


def test_custody_shard_compiles_and_verifies(tmp_path, ci_secret_key):
    cfg = _custody_shard(tmp_path, ci_secret_key)
    assert compile_generic_shard(cfg)

    shard = cfg.out_dir
    manifest = json.loads((shard / "manifest.json").read_bytes())
    assert {"packets@1", "tpm-attestation@1"} <= set(manifest["extensions"])
    # The indexed bytes are real content leaves in the sources bijection.
    paths = {s["path"] for s in manifest["sources"]}
    assert {"content/packets.bin", "content/tpm-attestation.bin"} <= paths

    result = verify_shard(shard, trusted_key_path=shard / "sig" / "publisher.pub")
    assert result["status"] == "PASS", result["errors"]


def test_custody_tables_are_canonical_and_ordered(tmp_path, ci_secret_key):
    """Round-trip each table through the strict reader: canonical + ordered."""
    cfg = _custody_shard(tmp_path, ci_secret_key)
    assert compile_generic_shard(cfg)

    for ext_id in ("packets@1", "tpm-attestation@1"):
        reg = EXTENSION_REGISTRY[ext_id]
        rows = read_table(cfg.out_dir / "ext" / reg["file"], reg["schema"], reg["sort_key"])
        assert rows, ext_id

    # Indexed offsets/lengths/hashes actually match the stored content bytes.
    pkt_rows = read_table(
        cfg.out_dir / "ext" / "packets@1.jsonl",
        EXTENSION_REGISTRY["packets@1"]["schema"],
        EXTENSION_REGISTRY["packets@1"]["sort_key"],
    )
    for row in pkt_rows:
        stored = (cfg.out_dir / row["file"]).read_bytes()[
            row["offset"]:row["offset"] + row["length"]
        ]
        assert _sha(stored) == row["packet_sha256"]


def test_custody_evidence_survives_tamper_as_merkle_leaf(tmp_path, ci_secret_key):
    """Flipping an indexed content byte breaks the seal (E_MERKLE_MISMATCH)."""
    cfg = _custody_shard(tmp_path, ci_secret_key)
    assert compile_generic_shard(cfg)

    target = cfg.out_dir / "content" / "packets.bin"
    b = bytearray(target.read_bytes())
    b[0] ^= 0xFF
    target.write_bytes(bytes(b))

    result = verify_shard(cfg.out_dir, trusted_key_path=cfg.out_dir / "sig" / "publisher.pub")
    assert result["status"] == "FAIL"
    assert any(e["code"] == "E_MERKLE_MISMATCH" for e in result["errors"])
