"""
Genesis test conftest — install offline stubs if real deps missing.
"""
import sys

def _try_import(mod):
    try:
        __import__(mod)
        return True
    except ImportError:
        return False

missing = [m for m in ("blake3", "duckdb", "pyarrow", "nacl") if not _try_import(m)]

if missing:
    import warnings
    warnings.warn(
        f"Missing deps for full test run: {missing}. "
        "Installing offline stubs — Merkle/crypto tests will be SKIPPED.",
        RuntimeWarning,
    )
    from axm_build._stubs import install_stubs
    install_stubs()
