"""Shared Clifford Number fixture, checked without a sibling checkout.

The fixture is identical to Clifford Number PR #2604 at a10b9e85863358ffd871f21f3611c74674f580cf,
path test/fixtures/axm-identity-reconciliation.json. It preserves Genesis
reference blob 64f1b2182474d34bd600512d3d6ef2012c080cc2, including CRLF bytes.
These checks pin serialization and bytes, not real-world entity equivalence.
"""
import hashlib
import json
from pathlib import Path

import pytest

from axm_verify.identity import canonicalize, recompute_claim_id, recompute_entity_id

FIXTURE = Path(__file__).parent / "vectors" / "identity-reconciliation-clifford.json"
SHARED_SHA256 = "b35fe3625e3dd48859f8a13d19daf8e03522ffd6dfb3d135e614ce441a79518a"


def _load(path=FIXTURE):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHARED_SHA256, "shared fixture byte drift"
    return json.loads(raw)


def test_entity_rows_reproduce():
    body = _load()
    assert len(body["entities"]) == 14
    for row in body["entities"]:
        assert canonicalize(row["namespace"]) == row["canonical_namespace"]
        assert canonicalize(row["label"]) == row["canonical_label"]
        assert recompute_entity_id(row["namespace"], row["label"]) == row["entity_id"]


def test_claim_rows_reproduce():
    body = _load()
    assert len(body["claims"]) == 2
    for c in body["claims"]:
        assert recompute_claim_id(
            c["subject_id"], c["predicate"], c["object"], c["object_type"]
        ) == c["claim_id"]


def test_exact_shared_fixture_bytes():
    _load()


@pytest.mark.parametrize("mutation", ["lf_normalization", "trailing_byte", "metadata"])
def test_byte_drift_is_rejected(tmp_path, mutation):
    raw = FIXTURE.read_bytes()
    altered = {
        "lf_normalization": raw.replace(b"\r\n", b"\n"),
        "trailing_byte": raw + b" ",
        "metadata": raw.replace(b"CN-P0-1", b"CN-P0-X", 1),
    }[mutation]
    assert altered != raw
    path = tmp_path / "changed-fixture.json"
    path.write_bytes(altered)
    with pytest.raises(AssertionError, match="shared fixture byte drift"):
        _load(path)
