"""Whole-bundle semantic validation for RFC 0009 Aperture extensions."""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .aperture_ext_schemas import APERTURE_EXTENSION_IDS
from .aperture_rows import ApertureExtensionError, canonical_array, validate_rows


def validate_aperture_bundle(
    raw_bundle: Mapping[str, Sequence[Mapping[str, Any]]],
) -> Dict[str, List[Dict[str, str]]]:
    supplied = set(raw_bundle)
    required = set(APERTURE_EXTENSION_IDS)
    if supplied != required:
        raise ApertureExtensionError(
            "Aperture package compilation requires the complete RFC 0009 bundle: "
            f"missing={sorted(required - supplied)} extra={sorted(supplied - required)}"
        )
    bundle = {
        extension_id: validate_rows(extension_id, raw_bundle[extension_id])
        for extension_id in APERTURE_EXTENSION_IDS
    }

    revisions = {
        (row["package_id"], row["revision"]): row
        for row in bundle["aperture-package-revisions@1"]
    }
    positions: Dict[Tuple[str, str], set[str]] = {}
    for row in bundle["aperture-positions@1"]:
        key = (row["package_id"], row["revision"])
        _known_revision(key, revisions, "position")
        positions.setdefault(key, set()).add(row["position_id"])
    for row in bundle["aperture-positions@1"]:
        key = (row["package_id"], row["revision"])
        if row["parent_id"] and row["parent_id"] not in positions[key]:
            raise ApertureExtensionError(
                f"position {row['position_id']!r} references an unknown parent"
            )

    sources: Dict[Tuple[str, str], set[str]] = {}
    for row in bundle["aperture-sources@1"]:
        key = (row["package_id"], row["revision"])
        _known_revision(key, revisions, "source")
        sources.setdefault(key, set()).add(row["source_id"])
    for key in revisions:
        if not sources.get(key):
            raise ApertureExtensionError(f"package revision {key!r} has no source custody")

    facts: Dict[Tuple[str, str], set[str]] = {}
    for row in bundle["aperture-facts@1"]:
        key = (row["package_id"], row["revision"])
        _known_revision(key, revisions, "fact")
        if row["first_reveal_position_id"] not in positions.get(key, set()):
            raise ApertureExtensionError(
                f"fact {row['fact_id']!r} references an unknown first reveal position"
            )
        _provenance(row["provenance_refs_json"], sources.get(key, set()), row["fact_id"])
        facts.setdefault(key, set()).add(row["fact_id"])

    for row in bundle["aperture-causal-edges@1"]:
        key = (row["package_id"], row["revision"])
        _known_revision(key, revisions, "causal edge")
        known = facts.get(key, set())
        _, causes = canonical_array(
            row["cause_fact_ids_json"], "cause_fact_ids_json", minimum=1
        )
        if any(fact_id not in known for fact_id in causes):
            raise ApertureExtensionError(
                f"causal edge {row['edge_id']!r} references an unknown cause fact"
            )
        if row["effect_fact_id"] not in known:
            raise ApertureExtensionError(
                f"causal edge {row['edge_id']!r} references an unknown effect fact"
            )
        if row["effect_fact_id"] in causes:
            raise ApertureExtensionError(
                f"causal edge {row['edge_id']!r} is self-causal"
            )
        _provenance(row["provenance_refs_json"], sources.get(key, set()), row["edge_id"])

    reveal_pairs: set[Tuple[str, str, str, str]] = set()
    for row in bundle["aperture-reveals@1"]:
        key = (row["package_id"], row["revision"])
        _known_revision(key, revisions, "reveal")
        if row["fact_id"] not in facts.get(key, set()):
            raise ApertureExtensionError(
                f"reveal {row['reveal_id']!r} references an unknown fact"
            )
        if row["position_id"] not in positions.get(key, set()):
            raise ApertureExtensionError(
                f"reveal {row['reveal_id']!r} references an unknown position"
            )
        _provenance(row["provenance_refs_json"], sources.get(key, set()), row["reveal_id"])
        reveal_pairs.add((*key, row["fact_id"], row["position_id"]))
    for row in bundle["aperture-facts@1"]:
        identity = (
            row["package_id"],
            row["revision"],
            row["fact_id"],
            row["first_reveal_position_id"],
        )
        if identity not in reveal_pairs:
            raise ApertureExtensionError(
                f"fact {row['fact_id']!r} lacks its declared reveal record"
            )

    maps: Dict[str, List[Dict[str, str]]] = {}
    for row in bundle["aperture-edition-maps@1"]:
        maps.setdefault(row["map_id"], []).append(row)
    _validate_map_segments(maps)
    for key, revision in revisions.items():
        _, map_ids = canonical_array(
            revision["edition_time_map_refs_json"],
            "edition_time_map_refs_json",
            minimum=1,
        )
        for map_id in map_ids:
            rows = maps.get(map_id)
            if not rows:
                raise ApertureExtensionError(
                    f"package revision {key!r} references unknown TimeMap {map_id!r}"
                )
            first = rows[0]
            if (
                first["work_id"] != revision["work_id"]
                or first["canonical_edition_id"]
                != revision["canonical_edition_id"]
            ):
                raise ApertureExtensionError(
                    f"TimeMap {map_id!r} is incompatible with package revision {key!r}"
                )
    return bundle


def _known_revision(
    key: Tuple[str, str],
    revisions: Mapping[Tuple[str, str], Mapping[str, str]],
    label: str,
) -> None:
    if key not in revisions:
        raise ApertureExtensionError(f"{label} references unknown package revision {key!r}")


def _provenance(value: str, known_sources: set[str], identity: str) -> None:
    _, refs = canonical_array(value, "provenance_refs_json", minimum=1)
    unknown = set(refs) - known_sources
    if unknown:
        raise ApertureExtensionError(
            f"record {identity!r} references unknown package sources {sorted(unknown)}"
        )


def _validate_map_segments(
    maps: Mapping[str, Sequence[Mapping[str, str]]],
) -> None:
    for map_id, rows in maps.items():
        first = rows[0]
        invariant = (
            first["work_id"],
            first["provider_edition_id"],
            first["canonical_edition_id"],
            first["review_state"],
            first["source_digests_json"],
        )
        provider_ranges: List[Tuple[int, int]] = []
        canonical_ranges: List[Tuple[int, int]] = []
        for row in rows:
            current = (
                row["work_id"],
                row["provider_edition_id"],
                row["canonical_edition_id"],
                row["review_state"],
                row["source_digests_json"],
            )
            if current != invariant:
                raise ApertureExtensionError(
                    f"TimeMap {map_id!r} changes edition or review identity between segments"
                )
            if row["provider_start_us"]:
                provider_ranges.append(
                    (int(row["provider_start_us"]), int(row["provider_end_us"]))
                )
            if row["canonical_start_us"]:
                canonical_ranges.append(
                    (int(row["canonical_start_us"]), int(row["canonical_end_us"]))
                )
        _nonoverlap(provider_ranges, f"TimeMap {map_id!r} provider")
        _nonoverlap(canonical_ranges, f"TimeMap {map_id!r} canonical")


def _nonoverlap(ranges: Sequence[Tuple[int, int]], label: str) -> None:
    ordered = sorted(ranges)
    for previous, current in zip(ordered, ordered[1:]):
        if current[0] < previous[1]:
            raise ApertureExtensionError(f"{label} intervals overlap")
