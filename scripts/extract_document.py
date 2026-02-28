import argparse
import json
from pathlib import Path

from axm_extract.api import extract_to_canonical_text


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract PDF/DOCX to canonical text + chunks")
    ap.add_argument("src", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    text, chunks = extract_to_canonical_text(args.src)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "source.txt").write_text(text, encoding="utf-8")
    (args.out / "chunks.json").write_text(json.dumps(chunks, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {args.out}/source.txt and {len(chunks)} chunks")


if __name__ == "__main__":
    main()
