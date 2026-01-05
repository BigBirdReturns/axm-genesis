from __future__ import annotations

from pathlib import Path

from axm_build.cli import _extract_measure_b_from_fm_markdown


def main() -> None:
    import sys

    if len(sys.argv) != 3:
        raise SystemExit("Usage: python generators/fm21_11/extract.py <fm21-11.md> <out_source.txt>")

    fm = Path(sys.argv[1])
    out = Path(sys.argv[2])

    out.write_text(_extract_measure_b_from_fm_markdown(fm), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
