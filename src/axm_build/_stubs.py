"""
Minimal pure-Python stubs for offline test environments.
Import this ONLY in test conftest when real deps are missing.
These stubs do NOT produce correct outputs — they exist to let
logic and schema tests run without binary deps installed.
"""
import hashlib
import json
import struct
import sqlite3
from pathlib import Path


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


class _DuckDBStub:
    """Minimal sqlite3-backed DuckDB stub for tests."""
    def __init__(self):
        self._con = sqlite3.connect(":memory:")
    def execute(self, sql, params=None):
        # Strip DuckDB-specific syntax
        sql2 = sql.replace("read_parquet", "_PARQUET")
        try:
            cur = self._con.execute(sql2, params or [])
        except Exception:
            cur = self._con.execute("SELECT 1 WHERE 0")  # empty result
        return cur
    def fetchall(self):
        return []
    def close(self):
        self._con.close()
    @staticmethod
    def connect(*a, **kw):
        return _DuckDBStub()


def install_stubs():
    """Inject stubs into sys.modules so imports succeed."""
    import sys
    if "blake3" not in sys.modules:
        import types
        m = types.ModuleType("blake3")
        m.blake3 = _blake3_stub
        sys.modules["blake3"] = m
    if "duckdb" not in sys.modules:
        import types
        m = types.ModuleType("duckdb")
        m.connect = _DuckDBStub.connect
        sys.modules["duckdb"] = m
    if "pyarrow" not in sys.modules:
        import types
        pa = types.ModuleType("pyarrow")
        pa.schema = lambda *a, **kw: None
        pa.field = lambda *a, **kw: None
        pa.string = lambda: "string"
        pa.int64 = lambda: "int64"
        pa.float64 = lambda: "float64"
        pa.Table = type("Table", (), {})
        sys.modules["pyarrow"] = pa
        sys.modules["pyarrow.parquet"] = types.ModuleType("pyarrow.parquet")
    if "nacl" not in sys.modules:
        import types
        nacl = types.ModuleType("nacl")
        nacl_sig = types.ModuleType("nacl.signing")
        nacl_exc = types.ModuleType("nacl.exceptions")
        class BadSig(Exception): pass
        nacl_exc.BadSignatureError = BadSig
        sys.modules["nacl"] = nacl
        sys.modules["nacl.signing"] = nacl_sig
        sys.modules["nacl.exceptions"] = nacl_exc
