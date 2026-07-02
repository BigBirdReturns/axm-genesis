"""Identity layer (spec section 10): canonicalize() and the four ID kinds.

Locks the frozen behavior in three ways:
1. The committed vectors in tests/vectors/identity.json must reproduce.
2. The ASCII-only-lowercasing semantics (RFC 0002 D4) are asserted directly
   against the casefold alternatives they replaced.
3. One vector is recomputed from primitives (hashlib + base32) so the test
   does not merely compare the library with itself.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from axm_verify.const import (
    CLAIM_ID_RE,
    ENTITY_ID_RE,
    PROVENANCE_ID_RE,
    SPAN_ID_RE,
)
from axm_verify.identity import (
    canonicalize,
    derive_provenance_id,
    derive_span_id,
    recompute_claim_id,
    recompute_entity_id,
)
from helpers import VECTORS_DIR

VECTORS = json.loads((VECTORS_DIR / "identity.json").read_text(encoding="utf-8"))

_CANON_OK = [c for c in VECTORS["canonicalization"] if "expected" in c]
_CANON_ERR = [c for c in VECTORS["canonicalization"] if "expected_error" in c]


def _case_id(case: dict) -> str:
    return ascii(case["input"])[1:-1][:48]


# ── Vector reproduction ──────────────────────────────────────────────────────

@pytest.mark.parametrize("case", _CANON_OK, ids=_case_id)
def test_canonicalization_vectors(case: dict) -> None:
    assert canonicalize(case["input"]) == case["expected"]


@pytest.mark.parametrize("case", _CANON_ERR, ids=_case_id)
def test_canonicalization_error_vectors(case: dict) -> None:
    assert case["expected_error"] == "ValueError"
    with pytest.raises(ValueError):
        canonicalize(case["input"])


@pytest.mark.parametrize(
    "case", VECTORS["entity_ids"], ids=lambda c: f"{c['namespace']}/{ascii(c['label'])[1:-1]}"
)
def test_entity_id_vectors(case: dict) -> None:
    eid = recompute_entity_id(case["namespace"], case["label"])
    assert eid == case["expected_id"]
    assert ENTITY_ID_RE.match(eid)


@pytest.mark.parametrize("case", VECTORS["claim_ids"], ids=lambda c: c["expected_id"][-8:])
def test_claim_id_vectors(case: dict) -> None:
    cid = recompute_claim_id(
        case["subject"], case["predicate"], case["object"], case["object_type"]
    )
    assert cid == case["expected_id"]
    assert CLAIM_ID_RE.match(cid)


@pytest.mark.parametrize("case", VECTORS["provenance_ids"], ids=lambda c: c["expected_id"][-8:])
def test_provenance_id_vectors(case: dict) -> None:
    pid = derive_provenance_id(
        case["claim_id"], case["source_hash"], case["byte_start"], case["byte_end"]
    )
    assert pid == case["expected_id"]
    assert PROVENANCE_ID_RE.match(pid)


@pytest.mark.parametrize("case", VECTORS["span_ids"], ids=lambda c: c["expected_id"][-8:])
def test_span_id_vectors(case: dict) -> None:
    sid = derive_span_id(
        case["source_hash"], case["byte_start"], case["byte_end"], case["text"]
    )
    assert sid == case["expected_id"]
    assert SPAN_ID_RE.match(sid)


# ── Construction locked against primitives (not the library itself) ─────────

def test_entity_id_recomputed_from_primitives() -> None:
    """id = e1_ + base32lower(full SHA-256 digest), no padding, no truncation."""
    namespace, label = "survival/medical", "tourniquet"
    preimage = (canonicalize(namespace) + "\x00" + canonicalize(label)).encode("utf-8")
    digest = hashlib.sha256(preimage).digest()
    assert len(digest) == 32  # the FULL digest — digest[:15] is v0.x history
    expected = "e1_" + base64.b32encode(digest).decode("ascii").lower().rstrip("=")
    assert len(expected) == len("e1_") + 52
    assert recompute_entity_id(namespace, label) == expected
    assert expected == VECTORS["entity_ids"][0]["expected_id"]


def test_id_prefixes_are_versioned() -> None:
    eid = recompute_entity_id("ns", "x")
    cid = recompute_claim_id(eid, "p", eid, "entity")
    pid = derive_provenance_id(cid, "0" * 64, 0, 1)
    sid = derive_span_id("0" * 64, 0, 1, "t")
    for value, prefix in ((eid, "e1_"), (cid, "c1_"), (pid, "p1_"), (sid, "s1_")):
        assert value.startswith(prefix)
        assert len(value) == len(prefix) + 52


# ── ASCII-lower semantics (RFC 0002 D4: NOT casefold) ───────────────────────

def test_ascii_only_lowercasing_versus_casefold() -> None:
    # Every case below is one where str.casefold() (or str.lower()) differs.
    assert canonicalize("ß") == "ß"          # casefold -> "ss"
    assert canonicalize("ﬁle") == "ﬁle"      # casefold -> "file"
    assert canonicalize("İ") == "İ"          # casefold/lower -> "i" + U+0307
    assert canonicalize("Σ") == "Σ"          # casefold -> "σ"
    assert canonicalize("Ä") == "Ä"          # lower -> "ä"
    # ASCII is still lowered.
    assert canonicalize("ABCXYZ") == "abcxyz"
    assert canonicalize("MiXeD 123") == "mixed 123"


def test_non_ascii_case_variants_are_distinct_entities() -> None:
    ns = "test/unicode"
    assert recompute_entity_id(ns, "Straße") != recompute_entity_id(ns, "STRASSE")
    assert recompute_entity_id(ns, "İstanbul") != recompute_entity_id(ns, "Istanbul")
    assert recompute_entity_id(ns, "ıstanbul") != recompute_entity_id(ns, "istanbul")


def test_cyrillic_confusables_are_distinct_entities() -> None:
    ns = "test/unicode"
    assert recompute_entity_id(ns, "Маma") != recompute_entity_id(ns, "Mama")
    assert recompute_entity_id(ns, "АXM") != recompute_entity_id(ns, "AXM")


def test_nfc_unifies_combining_sequences() -> None:
    ns = "test/unicode"
    combining = "Café"    # e + COMBINING ACUTE ACCENT
    precomposed = "Café"   # é
    assert canonicalize(combining) == canonicalize(precomposed)
    assert recompute_entity_id(ns, combining) == recompute_entity_id(ns, precomposed)


# ── Adversarial cases ────────────────────────────────────────────────────────

def test_control_characters_stripped_not_treated_as_whitespace() -> None:
    assert canonicalize("a\tb") == "ab"        # TAB is Cc: stripped
    assert canonicalize("a\nb") == "ab"        # LF is Cc: stripped
    assert canonicalize("a\rb") == "ab"        # CR is Cc: stripped
    assert canonicalize("a\x07b") == "ab"      # BEL is Cc: stripped
    assert canonicalize("a\x9fb") == "ab"      # APC (C1 range) is Cc: stripped


def test_whitespace_collapse_and_trim() -> None:
    assert canonicalize("  a   b  ") == "a b"
    assert canonicalize("a  b") == "a b"   # NBSP + EM SPACE collapse
    assert canonicalize("　") == ""              # whitespace-only trims empty
    assert canonicalize("") == ""


def test_format_characters_preserved() -> None:
    # ZERO WIDTH SPACE is category Cf, not Cc and not whitespace: preserved.
    assert canonicalize("a​b") == "a​b"


def test_nul_rejected_everywhere() -> None:
    with pytest.raises(ValueError):
        canonicalize("a\x00b")
    with pytest.raises(ValueError):
        recompute_entity_id("ns", "a\x00b")
    with pytest.raises(ValueError):
        recompute_claim_id("e1_x", "p\x00q", "v", "literal:string")


def test_canonicalize_is_idempotent() -> None:
    for case in _CANON_OK:
        once = canonicalize(case["input"])
        assert canonicalize(once) == once


# ── Claim identity semantics ─────────────────────────────────────────────────

def test_literal_objects_canonicalized_object_type_in_preimage() -> None:
    subj = VECTORS["claim_ids"][0]["subject"]
    # Literal object values pass through canonicalize(): "  5  " == "5".
    a = recompute_claim_id(subj, "has_width_cm", "  5  ", "literal:integer")
    b = recompute_claim_id(subj, "has_width_cm", "5", "literal:integer")
    assert a == b
    # object_type participates in the preimage.
    c = recompute_claim_id(subj, "has_width_cm", "5", "literal:string")
    assert c != b


def test_predicate_is_canonicalized() -> None:
    subj = VECTORS["claim_ids"][0]["subject"]
    obj = VECTORS["claim_ids"][0]["object"]
    assert recompute_claim_id(subj, "Treats", obj, "entity") == recompute_claim_id(
        subj, "treats", obj, "entity"
    )
