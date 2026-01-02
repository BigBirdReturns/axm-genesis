from __future__ import annotations

import sys
from pathlib import Path

import duckdb


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python examples/query_shard.py <shard_dir>")

    shard = Path(sys.argv[1])
    entities = shard / "graph" / "entities.parquet"
    claims = shard / "graph" / "claims.parquet"
    prov = shard / "graph" / "provenance.parquet"
    spans = shard / "evidence" / "spans.parquet"

    con = duckdb.connect(database=":memory:")

    con.execute(f"CREATE VIEW entities AS SELECT * FROM read_parquet('{entities}')")
    con.execute(f"CREATE VIEW claims AS SELECT * FROM read_parquet('{claims}')")
    con.execute(f"CREATE VIEW provenance AS SELECT * FROM read_parquet('{prov}')")
    con.execute(f"CREATE VIEW spans AS SELECT * FROM read_parquet('{spans}')")

    # Example query: show each claim with human-readable labels and evidence text
    q = """
    SELECT
      c.claim_id,
      es.label AS subject_label,
      c.predicate,
      CASE WHEN c.object_type = 'entity' THEN eo.label ELSE c.object END AS object_value,
      s.text AS evidence
    FROM claims c
    LEFT JOIN entities es ON es.entity_id = c.subject
    LEFT JOIN entities eo ON eo.entity_id = c.object
    LEFT JOIN provenance p ON p.claim_id = c.claim_id
    LEFT JOIN spans s ON s.source_hash = p.source_hash AND s.byte_start = p.byte_start AND s.byte_end = p.byte_end
    ORDER BY c.claim_id
    """
    rows = con.execute(q).fetchall()
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
