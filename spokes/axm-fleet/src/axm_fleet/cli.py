"""Fleet spoke CLI — the click.Group that axm-core mounts via the
``axm.spokes`` entry point (and that also runs standalone as ``axm-fleet``).

Commands:
    record   node_record.json -> signed shard (optionally superseding a prior record)
    verify   kernel verifier passthrough, trusted key supplied out of band
    history  walk the supersedes chains across a directory of record shards
"""
from __future__ import annotations

import json
from pathlib import Path

import blake3
import click

from axm_verify.const import MALFORMED_SHARD_CODES
from axm_verify.logic import verify_shard

from .record_compile import compile_record


@click.group("fleet")
def fleet_group() -> None:
    """Fleet sustainment records: node_record.json in, signed AXM shard out."""


@fleet_group.command("record")
@click.argument("record", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("outdir", type=click.Path(file_okay=False, path_type=Path))
@click.option("--key", "key_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="3904-byte axm-hybrid1 secret key blob (axm-build keygen). "
                   "No default: a shard signed with a published key proves "
                   "integrity, never authenticity.")
@click.option("--supersedes", "supersedes", multiple=True, metavar="SH1_ID",
              help="Derived sh1_ id of the record this one replaces. "
                   "Repeatable. Emits manifest.supersedes + ext/lineage@1.")
@click.option("--lineage-action", default="supersede", show_default=True,
              type=click.Choice(["supersede", "amend", "retract"]))
@click.option("--lineage-note", default="",
              help="Note on the lineage row (default: '<event_type> <build_id>').")
@click.option("--created-at", "created_at", default=None,
              help="RFC 3339 UTC with Z suffix (default: now). "
                   "Pass a fixed value for reproducible builds.")
def record_cmd(record: Path, outdir: Path, key_path: Path,
               supersedes: "tuple[str, ...]", lineage_action: str,
               lineage_note: str, created_at: "str | None") -> None:
    """Compile RECORD into a signed shard at OUTDIR; print the derived id."""
    shard_id = compile_record(
        record, outdir, key_path,
        supersedes=supersedes,
        lineage_action=lineage_action,
        lineage_note=lineage_note,
        created_at=created_at,
    )
    click.echo(shard_id)


@fleet_group.command("verify")
@click.argument("shard", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--trusted-key", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Trusted 1344-byte hybrid publisher public key, supplied "
                   "out of band — never the key embedded in the shard.")
def verify_cmd(shard: Path, trusted_key: Path) -> None:
    """Verify SHARD with the kernel verifier (passthrough to axm-verify).

    Honors the frozen exit-code contract: 0 = PASS, 2 = structurally
    malformed shard, 1 = any other failure.
    """
    result = verify_shard(shard, trusted_key_path=trusted_key)
    click.echo(json.dumps(result, ensure_ascii=False))
    if result.get("status") == "PASS":
        return
    errors = result.get("errors", [])
    for err in errors:
        click.echo(f"{err.get('code', 'E_UNKNOWN')}: {err.get('message', '')}", err=True)
    codes = {e.get("code") for e in errors}
    raise SystemExit(2 if codes and codes <= MALFORMED_SHARD_CODES else 1)


@fleet_group.command("history")
@click.argument("pool", type=click.Path(exists=True, file_okay=False, path_type=Path))
def history_cmd(pool: Path) -> None:
    """Walk supersedes chains across a directory of record shards.

    POOL is a directory whose subdirectories are record shards. Identity is
    derived from manifest bytes (never stored), so the chain is
    reconstructed purely by reading — the spoke never re-derives kernel
    state, it only follows the manifest.supersedes edges the kernel sealed.
    """
    shards: dict[str, dict] = {}  # sh1_id -> {dir, manifest, lineage_rows}
    for manifest_path in sorted(pool.glob("*/manifest.json")):
        shard_dir = manifest_path.parent
        manifest_bytes = manifest_path.read_bytes()
        sid = "sh1_" + blake3.blake3(manifest_bytes).hexdigest()
        lineage_rows = []
        lineage_file = shard_dir / "ext" / "lineage@1.jsonl"
        if lineage_file.exists():
            lineage_rows = [
                json.loads(line)
                for line in lineage_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        shards[sid] = {
            "dir": shard_dir,
            "manifest": json.loads(manifest_bytes),
            "lineage": lineage_rows,
        }

    if not shards:
        click.echo(f"No record shards found under {pool}")
        raise SystemExit(1)

    superseded = {
        pred for info in shards.values()
        for pred in info["manifest"].get("supersedes", [])
    }
    heads = [sid for sid in shards if sid not in superseded]

    for head in sorted(heads):
        sid: "str | None" = head
        depth = 0
        while sid is not None:
            info = shards.get(sid)
            if info is None:
                click.echo(f"{'  ' * depth}└─ {sid}  (not in pool)")
                break
            m = info["manifest"]
            marker = "●" if depth == 0 else "└─"
            title = m.get("metadata", {}).get("title", "?")
            created = m.get("metadata", {}).get("created_at", "?")
            click.echo(f"{'  ' * depth}{marker} {sid}")
            click.echo(f"{'  ' * depth}  {title}  ·  {created}  ·  {info['dir']}")
            preds = m.get("supersedes", [])
            for row in info["lineage"]:
                click.echo(
                    f"{'  ' * depth}  {row.get('action', '?')} "
                    f"{row.get('supersedes_shard_id', '?')[:24]}…  "
                    f"— {row.get('note', '')}"
                )
            sid = preds[0] if preds else None
            depth += 1
        click.echo()


if __name__ == "__main__":
    fleet_group()
