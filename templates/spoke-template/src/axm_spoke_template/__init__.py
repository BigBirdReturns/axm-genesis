"""axm_spoke_template — a minimal, working AXM spoke.

Domain extraction is the only thing a spoke owns. Compilation, signing,
Merkle construction, identity derivation, and verification all belong to
axm-genesis and are imported, never reimplemented (SPOKE_API.md).
"""
from .spoke import build_shard

__all__ = ["build_shard"]
__version__ = "0.1.0"
