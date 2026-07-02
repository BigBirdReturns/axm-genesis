"""AXM Genesis v1 — canonicalization and identifier derivations (spec section 10).

All four identifier kinds share one shape:

    id = prefix + base32lower( SHA-256( preimage_utf8 ) )

The full 32-byte digest is encoded (never truncated), yielding exactly 52
base32 characters after the versioned prefix (e1_ / c1_ / p1_ / s1_).
"""
from __future__ import annotations

import base64
import hashlib
import unicodedata

# The frozen whitespace set WS (spec section 10.1): the non-Cc Unicode
# whitespace characters, enumerated so canonicalize() is independent of
# future Unicode changes. Tabs/newlines are category Cc and are removed in
# step 3, before whitespace collapsing.
_WS = frozenset(
    "\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)

_ASCII_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)


def canonicalize(text: str) -> str:
    """Frozen text canonicalization (spec section 10.1).

    1. NFC-normalize.
    2. ASCII-only lowercasing (A-Z -> a-z; deliberately NOT casefold).
    3. Strip Unicode category-Cc control characters.
    4. Collapse runs of frozen-set whitespace to a single ASCII space; trim.

    Raises ValueError on NUL input (NUL is the preimage field separator).
    """
    if "\x00" in text:
        raise ValueError("Input contains illegal NUL byte")
    t = unicodedata.normalize("NFC", text)
    t = t.translate(_ASCII_LOWER)
    t = "".join(c for c in t if unicodedata.category(c) != "Cc")
    out: list[str] = []
    in_ws = False
    for c in t:
        if c in _WS:
            in_ws = True
            continue
        if in_ws and out:
            out.append(" ")
        in_ws = False
        out.append(c)
    return "".join(out)


def _derive_id(prefix: str, preimage: str) -> str:
    digest = hashlib.sha256(preimage.encode("utf-8")).digest()
    return prefix + base64.b32encode(digest).decode("ascii").lower().rstrip("=")


def recompute_entity_id(namespace: str, label: str) -> str:
    """entity_id = e1_ + b32(SHA-256(canon(namespace) || 0x00 || canon(label)))."""
    return _derive_id("e1_", canonicalize(namespace) + "\x00" + canonicalize(label))


def recompute_claim_id(subject: str, predicate: str, obj: str, object_type: str) -> str:
    """claim_id over subject-id, canonical predicate, object_type, object value.

    The object value is the entity_id verbatim when object_type is "entity",
    otherwise the canonicalized literal.
    """
    pred_c = canonicalize(predicate)
    obj_value = obj if object_type == "entity" else canonicalize(obj)
    return _derive_id(
        "c1_", subject + "\x00" + pred_c + "\x00" + object_type + "\x00" + obj_value
    )


def derive_provenance_id(claim_id: str, source_hash: str, byte_start: int, byte_end: int) -> str:
    """RECOMMENDED provenance_id derivation (spec section 10.6)."""
    return _derive_id(
        "p1_", f"{claim_id}\x00{source_hash}\x00{byte_start}\x00{byte_end}"
    )


def derive_span_id(source_hash: str, byte_start: int, byte_end: int, text: str) -> str:
    """RECOMMENDED span_id derivation (spec section 10.6)."""
    return _derive_id(
        "s1_", f"{source_hash}\x00{byte_start}\x00{byte_end}\x00{text}"
    )
