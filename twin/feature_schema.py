"""Canonical twin feature schema (must match production FEATURE_NAMES)."""

from __future__ import annotations

import hashlib
from typing import List, Sequence

from ml_models.feature_builder import FEATURE_NAMES
from twin.validate import TwinValidationError

FEATURE_SCHEMA_VERSION = "FEATURE_NAMES_v1"
EXPECTED_FEATURE_DIM = len(FEATURE_NAMES)


def feature_schema_hash(names: Sequence[str] | None = None) -> str:
    """SHA-256 of canonical ordered feature names."""
    ordered = list(names) if names is not None else list(FEATURE_NAMES)
    blob = "|".join(ordered).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def canonical_feature_schema() -> dict:
    return {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_dim": EXPECTED_FEATURE_DIM,
        "feature_names": list(FEATURE_NAMES),
        "feature_schema_hash": feature_schema_hash(),
    }


def assert_compatible_feature_vector(vector: Sequence[float]) -> List[float]:
    if len(vector) != EXPECTED_FEATURE_DIM:
        raise TwinValidationError(
            f"feature schema mismatch: got dim={len(vector)}, "
            f"expected {EXPECTED_FEATURE_DIM} ({FEATURE_SCHEMA_VERSION})"
        )
    out: List[float] = []
    for i, v in enumerate(vector):
        try:
            out.append(float(v))
        except (TypeError, ValueError) as exc:
            raise TwinValidationError(
                f"non-numeric feature at index {i} ({FEATURE_NAMES[i]})"
            ) from exc
    return out


def assert_compatible_feature_names(names: Sequence[str]) -> None:
    expected = list(FEATURE_NAMES)
    got = list(names)
    if got != expected:
        raise TwinValidationError(
            "feature schema mismatch: names/order differ from "
            f"{FEATURE_SCHEMA_VERSION} (hash {feature_schema_hash(got)} != "
            f"{feature_schema_hash(expected)})"
        )
