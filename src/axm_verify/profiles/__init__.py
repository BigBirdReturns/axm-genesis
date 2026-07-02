"""AXM Genesis — profile registry (spec section 15).

A profile is a named, versioned check-set over content/ and ext/, defined
in its own normative document under spec/profiles/. The kernel knows
nothing about any application domain; this registry maps the profile
identifiers this verifier implements to their check functions.

Each check function has the signature:

    check(shard_root: Path, errors: list[dict]) -> None

appending {"code": ..., "message": ...} dicts for every violation.
"""
from __future__ import annotations

from . import embodied_v1

# profile identifier -> check function
IMPLEMENTED_PROFILES = {
    embodied_v1.PROFILE_ID: embodied_v1.check,
}
