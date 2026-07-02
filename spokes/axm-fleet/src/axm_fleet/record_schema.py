"""
axm-fleet/src/axm_fleet/record_schema.py

Node Record Schema Contract
===========================

This file defines the interface between any fleet-management surface
(CI/CD pipeline, depot tooling, CLI) and the record compiler. It is the
frozen contract.

A node_record is a JSON document with four sections:

  asset       -> what physical node this record describes
  image       -> the deployed software image and its supply-chain digests
  components  -> the pinned models and firmware the image carries
  event       -> why this record exists (deploy | patch | rollback | recovery)

The record compiler validates a node_record against this schema, extracts
candidates, and delegates to compile_generic_shard. The output is a
genesis-verifiable shard. An update is a NEW shard that supersedes the old
one — records are never mutated, they are succeeded.

Claim tiers:

  Tier 0 -> integrity facts: content digests (image, SBOM, provenance,
            components) and the signing key id. These bind the record to
            external artifacts by hash; they are facts, not choices.
  Tier 1 -> configuration: build id, versions, platform, compute module.
            The substitutable surface — what a rehost changes.
  Tier 2 -> event: what happened, when, and who authorized it.

Example node_record.json:
{
  "schema_version": "1.0.0",
  "asset": {
    "asset_id": "node-0042",
    "platform": "small-uas-quadrotor",
    "program": "FLEET-DEMO",
    "compute_module": "som-vendor-a"
  },
  "image": {
    "build_id": "2026.07.02-r1",
    "image_digest": "sha256:…",
    "sbom_digest": "sha256:…",
    "sbom_format": "spdx-2.3",
    "provenance_digest": "sha256:…",
    "signing_key_id": "fleet-release-2026",
    "built_at_utc": "2026-07-01T18:00:00Z",
    "builder": "ci.fleet.example/build/8841"
  },
  "components": {
    "detect-model":  {"kind": "model",    "version": "4.2.1", "digest": "sha256:…"},
    "autopilot-fw":  {"kind": "firmware", "version": "1.9.3", "digest": "sha256:…"}
  },
  "event": {
    "event_type": "deploy",
    "event_time_utc": "2026-07-02T00:00:00Z",
    "authorized_by": "release-officer@fleet.example",
    "note": "initial fielding"
  }
}
"""
from __future__ import annotations

import re
from typing import Any

VALID_EVENT_TYPES = {"deploy", "patch", "rollback", "recovery"}
VALID_COMPONENT_KINDS = {"model", "firmware", "os", "application"}

# Content digests are explicit about their algorithm.
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_REQUIRED_ASSET = ("asset_id", "platform", "program", "compute_module")
_REQUIRED_IMAGE = ("build_id", "image_digest", "sbom_digest", "sbom_format",
                   "signing_key_id", "built_at_utc", "builder")
_REQUIRED_EVENT = ("event_type", "event_time_utc", "authorized_by")
_REQUIRED_COMPONENT = ("kind", "version", "digest")


def validate_node_record(raw: dict[str, Any]) -> list[str]:
    """Validate a raw JSON dict against the node-record schema.

    Returns a list of error strings. Empty list means valid.
    """
    errors: list[str] = []

    if "schema_version" not in raw:
        errors.append("Missing schema_version")

    asset = raw.get("asset", {})
    if not asset:
        errors.append("Missing asset section")
        return errors
    for key in _REQUIRED_ASSET:
        if not asset.get(key):
            errors.append(f"Missing asset.{key}")

    image = raw.get("image", {})
    if not image:
        errors.append("Missing image section")
        return errors
    for key in _REQUIRED_IMAGE:
        if not image.get(key):
            errors.append(f"Missing image.{key}")
    for key in ("image_digest", "sbom_digest", "provenance_digest"):
        val = image.get(key)
        if val and not DIGEST_RE.match(val):
            errors.append(f"image.{key} is not a sha256:<64-hex> digest: {val}")
    for key in ("built_at_utc",):
        val = image.get(key)
        if val and not UTC_RE.match(val):
            errors.append(f"image.{key} is not RFC 3339 UTC with Z suffix: {val}")

    components = raw.get("components", {})
    if not isinstance(components, dict) or not components:
        errors.append("Missing or empty components section (name -> component map)")
        return errors
    seen_digests: dict[str, str] = {}
    for name, comp in components.items():
        if not isinstance(comp, dict):
            errors.append(f"components.{name} must be an object")
            continue
        for key in _REQUIRED_COMPONENT:
            if not comp.get(key):
                errors.append(f"Missing components.{name}.{key}")
        kind = comp.get("kind", "")
        if kind and kind not in VALID_COMPONENT_KINDS:
            errors.append(f"Invalid components.{name}.kind: {kind}")
        digest = comp.get("digest", "")
        if digest:
            if not DIGEST_RE.match(digest):
                errors.append(f"components.{name}.digest is not a sha256:<64-hex> digest")
            elif digest in seen_digests:
                # Digest fragments are the evidence anchors for component
                # claims; two components with one digest would make the
                # evidence ambiguous (and is nonsensical anyway).
                errors.append(
                    f"components.{name}.digest duplicates components.{seen_digests[digest]}.digest"
                )
            else:
                seen_digests[digest] = name

    event = raw.get("event", {})
    if not event:
        errors.append("Missing event section")
        return errors
    for key in _REQUIRED_EVENT:
        if not event.get(key):
            errors.append(f"Missing event.{key}")
    if event.get("event_type") and event["event_type"] not in VALID_EVENT_TYPES:
        errors.append(f"Invalid event.event_type: {event['event_type']}")
    if event.get("event_time_utc") and not UTC_RE.match(event["event_time_utc"]):
        errors.append("event.event_time_utc is not RFC 3339 UTC with Z suffix")

    return errors
