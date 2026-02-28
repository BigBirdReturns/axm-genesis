from __future__ import annotations

import hashlib
import re
from typing import Optional

def norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def make_content_anchored_chunk_id(doc_id: str, kind: str, locator_key: str, text: str) -> str:
    t = norm_ws(text)
    if not t:
        t = ""
    first = t[:50]
    last = t[-50:] if len(t) > 50 else t
    payload = f"{doc_id}|{kind}|{locator_key}|{first}|{last}"
    return "chk:sha256:" + sha256_hex(payload)
