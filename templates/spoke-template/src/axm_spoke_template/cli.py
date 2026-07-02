"""Spoke CLI — the click.Group that axm-core mounts via the ``axm.spokes``
entry point (and that also runs standalone as ``axm-spoke-template``).

Rename ``spoke_template_group`` together with the entry-point key in
pyproject.toml; the group name is what appears under ``axm <name>``.
"""
from __future__ import annotations

import json
from pathlib import Path

import click

from axm_verify.const import MALFORMED_SHARD_CODES
from axm_verify.logic import verify_shard

from .spoke import build_shard


@click.group("spoke-template")
def spoke_template_group() -> None:
    """Template spoke: text file in, signed AXM shard out."""


@spoke_template_group.command("build")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("outdir", type=click.Path(file_okay=False, path_type=Path))
@click.option("--key", "key_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="3904-byte axm-hybrid1 secret key blob (axm-build keygen). "
                   "No default: a shard signed with a published key proves "
                   "integrity, never authenticity.")
@click.option("--namespace", required=True,
              help="metadata.namespace; part of every entity-id derivation.")
def build_cmd(source: Path, outdir: Path, key_path: Path, namespace: str) -> None:
    """Compile SOURCE into a signed shard at OUTDIR; print the derived id."""
    shard_id = build_shard(source, outdir, key_path, namespace)
    click.echo(shard_id)


@spoke_template_group.command("verify")
@click.argument("shard", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--trusted-key", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Trusted 1344-byte hybrid publisher public key, supplied "
                   "out of band.")
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


if __name__ == "__main__":
    spoke_template_group()
