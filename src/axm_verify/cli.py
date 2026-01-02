from __future__ import annotations

import json
from pathlib import Path
import click

from .logic import verify_shard

@click.group()
def main() -> None:
    pass

@main.command("shard")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
def shard_cmd(path: Path) -> None:
    """Verify an AXM shard at PATH."""
    result = verify_shard(path)
    click.echo(json.dumps(result, ensure_ascii=False))
    if result.get("status") != "PASS":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
