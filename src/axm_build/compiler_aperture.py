"""One-pass AXM Aperture package compiler (RFC 0009)."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping, Sequence

from .aperture_bundle import validate_aperture_bundle
from .aperture_ext_schemas import register_aperture_extensions

register_aperture_extensions()

from .compiler_generic import CompilerConfig, compile_generic_shard  # noqa: E402


def compile_aperture_shard(
    cfg: CompilerConfig,
    extension_rows: Mapping[str, Sequence[Mapping[str, Any]]],
) -> bool:
    """Validate a complete package and delegate one-pass custody to Genesis.

    This function does not write, hash, Merkle, sign, or reseal extension
    files itself.  It normalizes the RFC 0009 rows, supplies them through the
    existing ``extra_ext`` compiler seam, and returns the generic compiler's
    ordinary self-verification result.
    """
    if cfg.extra_ext:
        raise ValueError(
            "compile_aperture_shard receives extension_rows separately; "
            "CompilerConfig.extra_ext must be empty"
        )
    normalized = validate_aperture_bundle(extension_rows)
    return compile_generic_shard(replace(cfg, extra_ext=normalized))
