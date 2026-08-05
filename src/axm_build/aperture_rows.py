"""Row-level validation and normalization for RFC 0009 Aperture extensions."""
from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .aperture_ext_schemas import APERTURE_EXTENSION_REGISTRY

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_ID_RE = re.compile(r"^storypkg1_[0-9a-f]{64}$")
MAP_ID_RE = re.compile(r"^timemap1_[0-9a-f]{64}$")
NONNEGATIVE_RE = re.compile(r"^(0|[1-9][0-9]*)$")
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
INTEGER_RE = re.compile(r"^(0|-?[1-9][0-9]*)$")

REVIEW_STATES = {"candidate", "reviewed", "published", "superseded"}
POSITION_KINDS = {"sequence", "scene", "beat", "event"}
EDGE_STRENGTHS = {"necessary", "strong", "contextual"}
REVEAL_MODES = {"seen", "heard", "explained", "outcome-spoiled"}
SEGMENT_KINDS = {"mapped", "provider_only", "canonical_only"}
CUSTODY_STATES = {"public", "holder_controlled", "derived"}


class ApertureExtensionError(ValueError):
    """A supplied Aperture extension bundle violates RFC 0009."""


def _require(value: str, field: str) -> None:
    if not value:
        raise ApertureExtensionError(f"{field} must be non-empty")


def _pattern(value: str, pattern: re.Pattern[str], field: str) -> None:
    if not pattern.fullmatch(value):
        raise ApertureExtensionError(f"{field} has invalid canonical form")


def canonical_array(
    value: str,
    field: str,
    *,
    minimum: int = 0,
    sort_values: bool = True,
) -> Tuple[str, List[str]]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ApertureExtensionError(f"{field} must be a JSON array string") from exc
    if not isinstance(parsed, list) or len(parsed) < minimum:
        raise ApertureExtensionError(f"{field} must contain at least {minimum} values")
    if any(not isinstance(item, str) or not item for item in parsed):
        raise ApertureExtensionError(f"{field} must contain non-empty strings only")
    if len(set(parsed)) != len(parsed):
        raise ApertureExtensionError(f"{field} must contain unique values")
    normalized_values = sorted(parsed) if sort_values else list(parsed)
    normalized = json.dumps(
        normalized_values,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return normalized, normalized_values


def canonical_confidence(value: str, field: str) -> str:
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise ApertureExtensionError(f"{field} must be a decimal string") from exc
    if not number.is_finite() or number < 0 or number > 1:
        raise ApertureExtensionError(f"{field} must be in [0,1]")
    plain = format(number, "f")
    if "." in plain:
        plain = plain.rstrip("0").rstrip(".")
    return plain or "0"


def canonical_rate(numerator: str, denominator: str, field: str) -> Tuple[str, str]:
    _pattern(numerator, INTEGER_RE, f"{field}.numerator")
    _pattern(denominator, POSITIVE_RE, f"{field}.denominator")
    value = Fraction(int(numerator), int(denominator))
    if value < 0:
        raise ApertureExtensionError(f"{field} must be nonnegative")
    return str(value.numerator), str(value.denominator)


def _shape(extension_id: str, row: Mapping[str, Any], index: int) -> Dict[str, str]:
    registration = APERTURE_EXTENSION_REGISTRY[extension_id]
    expected = set(registration["schema"])
    actual = set(row)
    if actual != expected:
        raise ApertureExtensionError(
            f"{extension_id} row {index} key mismatch: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )
    if any(not isinstance(row[key], str) for key in registration["schema"]):
        raise ApertureExtensionError(
            f"{extension_id} row {index} must use JSON strings only"
        )
    return {key: str(row[key]) for key in registration["schema"]}


def validate_rows(
    extension_id: str,
    rows: Sequence[Mapping[str, Any]],
) -> List[Dict[str, str]]:
    if extension_id not in APERTURE_EXTENSION_REGISTRY:
        raise ApertureExtensionError(f"unregistered Aperture extension {extension_id!r}")
    if not rows:
        raise ApertureExtensionError(f"{extension_id} must contain at least one row")
    registration = APERTURE_EXTENSION_REGISTRY[extension_id]
    sort_key = registration["sort_key"]
    key_columns = (sort_key,) if isinstance(sort_key, str) else tuple(sort_key)
    normalized: List[Dict[str, str]] = []
    identities: set[Tuple[str, ...]] = set()

    for index, raw in enumerate(rows):
        row = _shape(extension_id, raw, index)
        prefix = f"{extension_id} row {index}"
        if "package_id" in row:
            _pattern(row["package_id"], PACKAGE_ID_RE, f"{prefix}.package_id")
        if "revision" in row:
            _pattern(row["revision"], POSITIVE_RE, f"{prefix}.revision")
        if "map_id" in row:
            _pattern(row["map_id"], MAP_ID_RE, f"{prefix}.map_id")
        if "canonical_story_digest" in row:
            _pattern(
                row["canonical_story_digest"],
                SHA256_RE,
                f"{prefix}.canonical_story_digest",
            )
        if "sha256" in row:
            _pattern(row["sha256"], SHA256_RE, f"{prefix}.sha256")
        if "review_state" in row and row["review_state"] not in REVIEW_STATES:
            raise ApertureExtensionError(f"{prefix}.review_state is unsupported")
        for field in (
            "work_id",
            "canonical_edition_id",
            "provider_edition_id",
            "position_id",
            "fact_id",
            "edge_id",
            "reveal_id",
            "segment_id",
            "source_id",
        ):
            if field in row:
                _require(row[field], f"{prefix}.{field}")

        if extension_id == "aperture-package-revisions@1":
            if row["supersedes"]:
                _pattern(row["supersedes"], PACKAGE_ID_RE, f"{prefix}.supersedes")
            row["edition_time_map_refs_json"], _ = canonical_array(
                row["edition_time_map_refs_json"],
                f"{prefix}.edition_time_map_refs_json",
                minimum=1,
            )
        elif extension_id == "aperture-positions@1":
            _pattern(row["canonical_start_us"], NONNEGATIVE_RE, f"{prefix}.canonical_start_us")
            _pattern(row["canonical_end_us"], POSITIVE_RE, f"{prefix}.canonical_end_us")
            if int(row["canonical_end_us"]) <= int(row["canonical_start_us"]):
                raise ApertureExtensionError(f"{prefix} must have a positive interval")
            if row["kind"] not in POSITION_KINDS:
                raise ApertureExtensionError(f"{prefix}.kind is unsupported")
            _require(row["label"], f"{prefix}.label")
        elif extension_id == "aperture-facts@1":
            _require(row["proposition"], f"{prefix}.proposition")
            _require(row["first_reveal_position_id"], f"{prefix}.first_reveal_position_id")
            row["subject_ids_json"], _ = canonical_array(
                row["subject_ids_json"], f"{prefix}.subject_ids_json"
            )
            row["provenance_refs_json"], _ = canonical_array(
                row["provenance_refs_json"],
                f"{prefix}.provenance_refs_json",
                minimum=1,
            )
        elif extension_id == "aperture-causal-edges@1":
            row["cause_fact_ids_json"], _ = canonical_array(
                row["cause_fact_ids_json"],
                f"{prefix}.cause_fact_ids_json",
                minimum=1,
            )
            _require(row["effect_fact_id"], f"{prefix}.effect_fact_id")
            if row["strength"] not in EDGE_STRENGTHS:
                raise ApertureExtensionError(f"{prefix}.strength is unsupported")
            row["provenance_refs_json"], _ = canonical_array(
                row["provenance_refs_json"],
                f"{prefix}.provenance_refs_json",
                minimum=1,
            )
        elif extension_id == "aperture-reveals@1":
            _require(row["position_id"], f"{prefix}.position_id")
            if row["mode"] not in REVEAL_MODES:
                raise ApertureExtensionError(f"{prefix}.mode is unsupported")
            row["provenance_refs_json"], _ = canonical_array(
                row["provenance_refs_json"],
                f"{prefix}.provenance_refs_json",
                minimum=1,
            )
        elif extension_id == "aperture-edition-maps@1":
            _validate_time_map(row, prefix)
        elif extension_id == "aperture-sources@1":
            if row["custody"] not in CUSTODY_STATES:
                raise ApertureExtensionError(f"{prefix}.custody is unsupported")
            if row["contains_redistributable_text"] not in {"true", "false"}:
                raise ApertureExtensionError(
                    f"{prefix}.contains_redistributable_text must be true or false"
                )

        identity = tuple(row[column] for column in key_columns)
        if identity in identities:
            raise ApertureExtensionError(
                f"{extension_id} has duplicate primary key {identity!r}"
            )
        identities.add(identity)
        normalized.append(row)
    return normalized


def _validate_time_map(row: Dict[str, str], prefix: str) -> None:
    if row["kind"] not in SEGMENT_KINDS:
        raise ApertureExtensionError(f"{prefix}.kind is unsupported")
    for field in (
        "provider_start_us",
        "provider_end_us",
        "canonical_start_us",
        "canonical_end_us",
    ):
        if row[field]:
            _pattern(row[field], NONNEGATIVE_RE, f"{prefix}.{field}")
    if bool(row["provider_start_us"]) != bool(row["provider_end_us"]):
        raise ApertureExtensionError(f"{prefix} has an incomplete provider interval")
    if bool(row["canonical_start_us"]) != bool(row["canonical_end_us"]):
        raise ApertureExtensionError(f"{prefix} has an incomplete canonical interval")
    provider_pair = bool(row["provider_start_us"])
    canonical_pair = bool(row["canonical_start_us"])
    if provider_pair and int(row["provider_end_us"]) <= int(row["provider_start_us"]):
        raise ApertureExtensionError(f"{prefix} provider interval must be positive")
    if canonical_pair and int(row["canonical_end_us"]) <= int(row["canonical_start_us"]):
        raise ApertureExtensionError(f"{prefix} canonical interval must be positive")
    expected = {
        "mapped": (True, True),
        "provider_only": (True, False),
        "canonical_only": (False, True),
    }
    if (provider_pair, canonical_pair) != expected[row["kind"]]:
        raise ApertureExtensionError(
            f"{prefix} interval presence contradicts segment kind"
        )
    row["rate_numerator"], row["rate_denominator"] = canonical_rate(
        row["rate_numerator"], row["rate_denominator"], f"{prefix}.rate"
    )
    row["evidence_refs_json"], _ = canonical_array(
        row["evidence_refs_json"], f"{prefix}.evidence_refs_json"
    )
    row["source_digests_json"], source_digests = canonical_array(
        row["source_digests_json"],
        f"{prefix}.source_digests_json",
        minimum=1,
    )
    for digest in source_digests:
        _pattern(digest, SHA256_RE, f"{prefix}.source_digests_json")
    row["confidence"] = canonical_confidence(
        row["confidence"], f"{prefix}.confidence"
    )
