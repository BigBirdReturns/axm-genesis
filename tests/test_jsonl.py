"""Canonical JSONL tables (spec sections 5 and 11).

One byte encoding: json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False) as UTF-8 + exactly one newline per record; the file is
the exact concatenation, no BOM, no trailing blank line; rows sorted
bytewise ascending by primary key; duplicate primary keys rejected.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from axm_build.jsonl import canonical_json_bytes, encode_table, read_table, write_table
from axm_verify.const import CLAIMS_SCHEMA, ENTITIES_SCHEMA

_E = {"namespace": "test/ns", "entity_type": "concept"}


def _entity(entity_id: str, label: str = "label") -> dict:
    return {"entity_id": entity_id, "label": label, **_E}


# ── Canonical encoding of a single value ─────────────────────────────────────

def test_keys_sorted_and_separators_tight() -> None:
    assert canonical_json_bytes({"b": 1, "z": 2, "a": 3}) == b'{"a":3,"b":1,"z":2}'


def test_ensure_ascii_false_emits_raw_utf8() -> None:
    got = canonical_json_bytes({"label": "café ﬁ Straße"})
    assert got == '{"label":"café ﬁ Straße"}'.encode("utf-8")
    assert b"\\u" not in got


def test_encoding_is_deterministic_and_roundtrips() -> None:
    obj = {"tier": 3, "label": "naïve", "n": 0}
    once = canonical_json_bytes(obj)
    assert canonical_json_bytes(obj) == once
    assert canonical_json_bytes(json.loads(once)) == once


# ── Table encoding ───────────────────────────────────────────────────────────

def test_golden_bytes_for_a_two_row_table() -> None:
    rows = [_entity("e1_bb", "naïve"), _entity("e1_aa", "plain")]
    got = encode_table(rows, ENTITIES_SCHEMA, "entity_id")
    expected = (
        '{"entity_id":"e1_aa","entity_type":"concept","label":"plain","namespace":"test/ns"}\n'
        '{"entity_id":"e1_bb","entity_type":"concept","label":"naïve","namespace":"test/ns"}\n'
    ).encode("utf-8")
    assert got == expected


def test_rows_sorted_bytewise_by_primary_key() -> None:
    # 'Z' (0x5A) sorts before 'a' (0x61): bytewise, not case-insensitive.
    rows = [_entity("e1_a"), _entity("e1_Z"), _entity("e1_0")]
    got = encode_table(rows, ENTITIES_SCHEMA, "entity_id")
    order = [json.loads(line)["entity_id"] for line in got.decode().splitlines()]
    assert order == ["e1_0", "e1_Z", "e1_a"]


def test_file_shape_invariants() -> None:
    got = encode_table([_entity("e1_x")], ENTITIES_SCHEMA, "entity_id")
    assert got.endswith(b"\n")
    assert not got.endswith(b"\n\n")       # no trailing blank line
    assert not got.startswith(b"\xef\xbb\xbf")  # no BOM
    assert b"\r" not in got


def test_zero_rows_is_a_zero_byte_file(tmp_path: Path) -> None:
    assert encode_table([], ENTITIES_SCHEMA, "entity_id") == b""
    p = tmp_path / "empty.jsonl"
    write_table(p, [], ENTITIES_SCHEMA, "entity_id")
    assert p.read_bytes() == b""
    assert read_table(p, ENTITIES_SCHEMA, "entity_id") == []


def test_duplicate_primary_key_rejected() -> None:
    rows = [_entity("e1_dup", "one"), _entity("e1_dup", "two")]
    with pytest.raises(ValueError, match="duplicate primary key"):
        encode_table(rows, ENTITIES_SCHEMA, "entity_id")
    # Fully identical rows are also rejected (a duplicate is a duplicate).
    with pytest.raises(ValueError, match="duplicate"):
        encode_table([_entity("e1_dup"), _entity("e1_dup")], ENTITIES_SCHEMA, "entity_id")


def test_nonunique_sort_key_mode_still_rejects_identical_rows() -> None:
    # Extension tables may share a sort key but never a full row.
    schema = {"k": "string", "v": "string"}
    ok = encode_table(
        [{"k": "a", "v": "1"}, {"k": "a", "v": "2"}], schema, "k", unique=False
    )
    assert ok.count(b"\n") == 2
    with pytest.raises(ValueError, match="duplicate row"):
        encode_table([{"k": "a", "v": "1"}, {"k": "a", "v": "1"}], schema, "k", unique=False)


# ── Schema enforcement at write time ─────────────────────────────────────────

def test_exact_key_set_enforced() -> None:
    row = _entity("e1_x")
    with pytest.raises(ValueError, match="unexpected keys"):
        encode_table([{**row, "extra": "no"}], ENTITIES_SCHEMA, "entity_id")
    missing = dict(row)
    del missing["label"]
    with pytest.raises(ValueError, match="missing or null"):
        encode_table([missing], ENTITIES_SCHEMA, "entity_id")


def test_nulls_forbidden() -> None:
    row = _entity("e1_x")
    row["label"] = None
    with pytest.raises(ValueError, match="missing or null"):
        encode_table([row], ENTITIES_SCHEMA, "entity_id")


def _claim(**overrides) -> dict:
    row = {
        "claim_id": "c1_x",
        "subject": "e1_s",
        "predicate": "treats",
        "object": "e1_o",
        "object_type": "entity",
        "tier": 3,
    }
    row.update(overrides)
    return row


@pytest.mark.parametrize(
    "bad, match",
    [
        ({"tier": "3"}, "must be an integer"),
        ({"tier": True}, "must be an integer"),
        ({"tier": 3.0}, "must be an integer"),
        ({"tier": -1}, "out of range"),
        ({"tier": 2**63}, "out of range"),
        ({"predicate": 7}, "must be a string"),
    ],
    ids=["str-int", "bool-int", "float-int", "negative", "overflow", "int-str"],
)
def test_type_discipline(bad: dict, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        encode_table([_claim(**bad)], CLAIMS_SCHEMA, "claim_id")


def test_strings_must_be_nfc() -> None:
    # "e" + COMBINING ACUTE is not NFC; the canonical form is precomposed é.
    with pytest.raises(ValueError, match="NFC"):
        encode_table([_entity("e1_x", "Café")], ENTITIES_SCHEMA, "entity_id")
    encode_table([_entity("e1_x", "Café")], ENTITIES_SCHEMA, "entity_id")


# ── Read path (builder-side) ─────────────────────────────────────────────────

def test_write_read_roundtrip(tmp_path: Path) -> None:
    rows = [_entity("e1_b", "two"), _entity("e1_a", "oné")]
    p = tmp_path / "entities.jsonl"
    write_table(p, rows, ENTITIES_SCHEMA, "entity_id")
    back = read_table(p, ENTITIES_SCHEMA, "entity_id")
    assert [r["entity_id"] for r in back] == ["e1_a", "e1_b"]
    assert back[0]["label"] == "oné"
    # Re-encoding what was read reproduces the exact bytes.
    assert encode_table(back, ENTITIES_SCHEMA, "entity_id") == p.read_bytes()


@pytest.mark.parametrize(
    "raw, match",
    [
        (b'{"entity_id":"e1_a","entity_type":"concept","label":"x","namespace":"n"}',
         "newline"),
        (b'{"entity_id": "e1_a", "entity_type": "concept", "label": "x", "namespace": "n"}\n',
         "canonical"),
        (b'{"entity_type":"concept","entity_id":"e1_a","label":"x","namespace":"n"}\n',
         "canonical"),
        (b'["e1_a"]\n', "not a JSON object"),
    ],
    ids=["missing-final-newline", "spaced", "unsorted-keys", "non-object"],
)
def test_read_rejects_non_canonical_files(tmp_path: Path, raw: bytes, match: str) -> None:
    p = tmp_path / "t.jsonl"
    p.write_bytes(raw)
    with pytest.raises(ValueError, match=match):
        read_table(p, ENTITIES_SCHEMA, "entity_id")


def test_read_rejects_out_of_order_and_duplicate_rows(tmp_path: Path) -> None:
    a = canonical_json_bytes(_entity("e1_a"))
    b = canonical_json_bytes(_entity("e1_b"))
    p = tmp_path / "t.jsonl"
    p.write_bytes(b + b"\n" + a + b"\n")
    with pytest.raises(ValueError, match="out of order"):
        read_table(p, ENTITIES_SCHEMA, "entity_id")
    p.write_bytes(a + b"\n" + a + b"\n")
    with pytest.raises(ValueError, match="out of order or duplicate"):
        read_table(p, ENTITIES_SCHEMA, "entity_id")
