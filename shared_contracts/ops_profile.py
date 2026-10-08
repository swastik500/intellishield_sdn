"""
Operational profile knobs (lab vs production).

Industry practice: separate *policy profile* from algorithm code.
- production: adaptive RL gate within safe bounds; calibrated fusion confidence
- lab: freeze mitigation confidence gate for reproducible demos

Override with env:
  INTELLISHIELD_OPS_PROFILE=lab|production
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class OpsProfile(str, Enum):
    LAB = "lab"
    PRODUCTION = "production"


# RL confidence gate bounds (0–1). Production caps below "near-certainty"
# so actuation cannot be starved by an over-raised gate.
PROD_DEFAULT_CONF_THRESHOLD = 0.60
PROD_MIN_CONF_THRESHOLD = 0.55
PROD_MAX_CONF_THRESHOLD = 0.75

LAB_DEFAULT_CONF_THRESHOLD = 0.60
LAB_MIN_CONF_THRESHOLD = 0.60
LAB_MAX_CONF_THRESHOLD = 0.60  # freeze


@dataclass(frozen=True)
class OpsPolicy:
    profile: OpsProfile
    freeze_rl_confidence_gate: bool
    default_rl_conf_threshold: float
    min_rl_conf_threshold: float
    max_rl_conf_threshold: float


def resolve_ops_profile(raw: str | None = None) -> OpsProfile:
    """
    Resolve profile from argument or INTELLISHIELD_OPS_PROFILE.

    Default is production (safe adaptive bounds). Set lab explicitly for demos.
    """
    text = (raw if raw is not None else os.environ.get("INTELLISHIELD_OPS_PROFILE", "production"))
    text = str(text).strip().lower()
    if text in ("lab", "demo", "development", "dev"):
        return OpsProfile.LAB
    return OpsProfile.PRODUCTION


def get_ops_policy(profile: OpsProfile | None = None) -> OpsPolicy:
    p = profile if profile is not None else resolve_ops_profile()
    if p is OpsProfile.LAB:
        return OpsPolicy(
            profile=p,
            freeze_rl_confidence_gate=True,
            default_rl_conf_threshold=LAB_DEFAULT_CONF_THRESHOLD,
            min_rl_conf_threshold=LAB_MIN_CONF_THRESHOLD,
            max_rl_conf_threshold=LAB_MAX_CONF_THRESHOLD,
        )
    return OpsPolicy(
        profile=p,
        freeze_rl_confidence_gate=False,
        default_rl_conf_threshold=PROD_DEFAULT_CONF_THRESHOLD,
        min_rl_conf_threshold=PROD_MIN_CONF_THRESHOLD,
        max_rl_conf_threshold=PROD_MAX_CONF_THRESHOLD,
    )
