from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .api import extract_to_canonical_text


@click.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--out",
    "out_dir",
    required=True,
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help="Output directory for extraction artifacts",
)
def main(input_file: Path, out_dir: Path) -> None:
    """Extract canonical text and chunk metadata from a document (PDF/DOCX).

    Writes:
      - source.txt: canonical UTF-8 text (input to axm-build compile)
      - chunks.json: chunk locator/span metadata
    """
    try:
        click.echo(f"Extracting: {input_file.name}...")
        canonical_text, chunks = extract_to_canonical_text(input_file)

        out_dir.mkdir(parents=True, exist_ok=True)
        source_path = out_dir / "source.txt"
        chunks_path = out_dir / "chunks.json"

        source_path.write_text(canonical_text, encoding="utf-8")
        chunks_path.write_text(json.dumps(chunks, indent=2, default=str), encoding="utf-8")

        click.echo("Success")
        click.echo(f"  Text:   {source_path} ({len(canonical_text)} chars)")
        click.echo(f"  Chunks: {chunks_path} ({len(chunks)} items)")

    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1) from e
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
