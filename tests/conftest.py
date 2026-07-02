"""Conformance-suite fixtures (v1, RFC 0002).

Path constants and pure helpers live in tests/helpers.py; this module
only wires them into pytest fixtures.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
_SRC = _TESTS_DIR.parent / "src"
for _p in (str(_SRC), str(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import (  # noqa: E402
    CI_KEY_PATH,
    CI_PUB_PATH,
    EMBODIED_GAP_SHARD,
    EMBODIED_SHARD,
    MINIMAL_SHARD,
    copy_shard,
)


@pytest.fixture(scope="session")
def ci_secret_key() -> bytes:
    """The committed CI test secret key (3904-byte hybrid1 blob; proves nothing)."""
    key = CI_KEY_PATH.read_bytes()
    assert len(key) == 3904
    return key


@pytest.fixture(scope="session")
def ci_public_key_path() -> Path:
    return CI_PUB_PATH


@pytest.fixture()
def minimal_shard(tmp_path: Path) -> Path:
    """A mutable copy of the valid/minimal vector shard."""
    return copy_shard(MINIMAL_SHARD, tmp_path / "minimal_shard")


@pytest.fixture()
def embodied_shard(tmp_path: Path) -> Path:
    """A mutable copy of the valid embodied@1 profile vector shard."""
    return copy_shard(EMBODIED_SHARD, tmp_path / "embodied_shard")


@pytest.fixture()
def embodied_gap_shard(tmp_path: Path) -> Path:
    """A mutable copy of the invalid embodied@1 gap vector shard."""
    return copy_shard(EMBODIED_GAP_SHARD, tmp_path / "embodied_gap_shard")
