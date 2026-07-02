# invalid/missing_manifest

Mutation from valid/minimal: delete `manifest.json`.

Expected: exit 2 (structurally malformed — every reported error is in
{E_LAYOUT_MISSING, E_SCHEMA_MISSING, E_SIG_MISSING}), E_LAYOUT_MISSING.
