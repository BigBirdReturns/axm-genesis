"""
Minimal pure-Python stubs for offline test environments.
Import this ONLY in test conftest when real deps are missing.
These stubs do NOT produce correct outputs — they exist to let
logic and schema tests run without binary deps installed.
"""
import hashlib


class _Blake3Stub:
    def __init__(self, data=b""):
        self._h = hashlib.sha256()
        if data:
            self._h.update(data)
    def update(self, data):
        self._h.update(data)
    def digest(self):
        return self._h.digest()  # 32 bytes
    def hexdigest(self):
        return self._h.hexdigest()

def _blake3_stub(data=b""):
    h = _Blake3Stub()
    if data:
        h.update(data)
    return h


def install_stubs():
    """Inject stubs into sys.modules so imports succeed."""
    import sys
    import types
    if "blake3" not in sys.modules:
        m = types.ModuleType("blake3")
        m.blake3 = _blake3_stub
        sys.modules["blake3"] = m
    if "nacl" not in sys.modules:
        nacl = types.ModuleType("nacl")
        nacl_sig = types.ModuleType("nacl.signing")
        nacl_exc = types.ModuleType("nacl.exceptions")
        class BadSig(Exception):
            pass
        nacl_exc.BadSignatureError = BadSig
        sys.modules["nacl"] = nacl
        sys.modules["nacl.signing"] = nacl_sig
        sys.modules["nacl.exceptions"] = nacl_exc
