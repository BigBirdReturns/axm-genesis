"""AXM Genesis reference shard builder."""

from .aperture_ext_schemas import register_aperture_extensions

# RFC 0009 registration is idempotent and occurs before any axm_build
# submodule imports compiler_generic's reference to EXTENSION_REGISTRY.
register_aperture_extensions()
