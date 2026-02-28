import argparse
import json
import subprocess
from pathlib import Path

from axm_extract.api import extract_to_canonical_text


def main() -> None:
    ap = argparse.ArgumentParser(description="Bridge: extract -> candidates.jsonl -> axm-build compile")
    ap.add_argument("src", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    work = args.out.parent / f"temp_{args.src.stem}"
    work.mkdir(parents=True, exist_ok=True)

    # 1) Extract
    text, _chunks = extract_to_canonical_text(args.src)
    source_path = work / "source.txt"
    source_path.write_text(text, encoding="utf-8")

    # 2) Candidate generation stub
    words = text.split()
    if len(words) < 5:
        raise SystemExit("Text too short to generate stub candidate")

    evidence = " ".join(words[:5])
    cand = {
        "subject": "Document",
        "predicate": "starts_with",
        "object": "text",
        "object_type": "literal",
        "evidence": evidence,
        "tier": 1,
    }
    candidates_path = work / "candidates.jsonl"
    candidates_path.write_text(json.dumps(cand) + "\n", encoding="utf-8")

    # 3) Compile
    cmd = [
        "axm-build",
        "compile",
        str(source_path),
        "--candidates",
        str(candidates_path),
        "--out",
        str(args.out),
    ]
    subprocess.check_call(cmd)


if __name__ == "__main__":
    main()
