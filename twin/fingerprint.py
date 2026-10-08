"""Config fingerprint for TwinProfile reproducibility metadata."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from shared_contracts.models import TwinProfile
from shared_contracts.serialize import to_dict


def _stable_payload(profile: TwinProfile) -> Dict[str, Any]:
    """Fields that define reproducible configuration (exclude timestamps/ids noise)."""
    raw = to_dict(profile)
    # Drop volatile / identity fields from the hash input
    for key in ("created_at", "config_fingerprint", "profile_id"):
        raw.pop(key, None)
    raw.pop("_type", None)
    return raw


def fingerprint_profile(profile: TwinProfile) -> str:
    """
    SHA-256 hex digest of the stable TwinProfile configuration.

    Same topology/traffic/detector/seed/version → same fingerprint.
    Does not promise bit-for-bit network timing determinism.
    """
    payload = _stable_payload(profile)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
