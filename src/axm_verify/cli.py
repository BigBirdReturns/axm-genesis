from __future__ import annotations

import json
from pathlib import Path
import click

from .const import MALFORMED_SHARD_CODES
from .logic import verify_shard


@click.group()
def main() -> None:
    pass


@main.command("shard")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
@click.option(
    "--trusted-key",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to the trusted publisher public key.",
)
def shard_cmd(path: Path, trusted_key: Path) -> None:
    """Verify an AXM shard at PATH.

    Exit-code contract (frozen — see COMPATIBILITY.md section 4):

    \b
      0  shard is valid
      1  verification failed (stderr carries one reason line per error)
      2  shard directory is malformed: missing required files/dirs
         (click usage errors — e.g. PATH does not exist — also exit 2)

    The machine-readable JSON result is always printed to stdout.
    """
    result = verify_shard(path, trusted_key_path=trusted_key)
    click.echo(json.dumps(result, ensure_ascii=False))
    if result.get("status") == "PASS":
        return

    errors = result.get("errors", [])
    for err in errors:
        click.echo(f"{err.get('code', 'E_UNKNOWN')}: {err.get('message', '')}", err=True)

    codes = {e.get("code") for e in errors}
    # Exit 2 iff the shard is structurally malformed: every reported error
    # is a missing-required-file/dir error. Anything else (bad signature,
    # Merkle mismatch, schema/manifest violations, ...) exits 1.
    if codes and codes <= MALFORMED_SHARD_CODES:
        raise SystemExit(2)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
