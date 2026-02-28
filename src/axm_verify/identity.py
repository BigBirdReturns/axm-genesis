from __future__ import annotations

import base64
import hashlib
import unicodedata


def canonicalize(text: str) -> str:
    if "\x00" in text:
        raise ValueError("Identifier contains illegal null byte")
    t = unicodedata.normalize("NFC", text)
    t = t.casefold()
    parts = []
    for chunk in t.split():
        cleaned = "".join(c for c in chunk if unicodedata.category(c) != "Cc")
        if cleaned:
            parts.append(cleaned)
    return " ".join(parts)


def recompute_entity_id(namespace: str, label: str) -> str:
    canonical = canonicalize(namespace) + "\x00" + canonicalize(label)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return "e_" + base64.b32encode(digest[:15]).decode("ascii").lower().rstrip("=")


def recompute_claim_id(subject: str, predicate: str, obj: str, object_type: str) -> str:
    pred_canon = canonicalize(predicate)
    obj_value = obj if object_type == "entity" else canonicalize(obj)
    canonical = subject + "\x00" + pred_canon + "\x00" + object_type + "\x00" + obj_value
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return "c_" + base64.b32encode(digest[:15]).decode("ascii").lower().rstrip("=")
