"""Bounded seed-driven scenario variant generation."""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from shared_contracts.models import TwinProfile
from twin.planner import plan_scenario
from twin.scenario_spec import (
    MAX_VARIANTS_DEFAULT,
    MAX_VARIANTS_HARD,
    ScenarioPlan,
)
from twin.validate import TwinValidationError, validate_seed


def generate_variants(
    scenario_id: str | int,
    *,
    seed: int,
    count: int = MAX_VARIANTS_DEFAULT,
    profile: Optional[TwinProfile] = None,
    base_overrides: Optional[Dict[str, Any]] = None,
) -> List[ScenarioPlan]:
    """
    Generate up to *count* parameterized variants from an explicit seed.

    Stochastic choices derive only from ``random.Random(seed)``.
    Hard-capped at MAX_VARIANTS_HARD. Does not launch Mininet.
    """
    validate_seed(seed)
    if count < 1:
        raise TwinValidationError("variant count must be >= 1")
    if count > MAX_VARIANTS_HARD:
        raise TwinValidationError(
            f"variant count {count} exceeds hard bound {MAX_VARIANTS_HARD}"
        )

    rng = random.Random(seed)
    sid = str(scenario_id).strip().upper()
    if sid.isdigit():
        sid = f"S{sid}"

    plans: List[ScenarioPlan] = []
    for i in range(count):
        ov = dict(base_overrides or {})
        # Variant-specific seed for provenance
        variant_seed = seed + i * 1009
        ov_local = _sample_overrides(sid, rng)
        ov.update(ov_local)
        plans.append(
            plan_scenario(
                sid,
                overrides=ov,
                profile=profile,
                seed=variant_seed,
            )
        )
    return plans


def _sample_overrides(sid: str, rng: random.Random) -> Dict[str, Any]:
    """Safe, bounded temporal/intensity jitter per family."""
    ov: Dict[str, Any] = {}
    if sid == "S1":
        ov["duration_sec"] = rng.choice([45, 60, 75, 90])
        return ov
    if sid == "S2":
        ov["baseline_sec"] = rng.choice([15, 20, 25])
        ov["attack_sec"] = rng.choice([20, 25, 30, 35])
        ov["recovery_sec"] = rng.choice([5, 10, 15])
        ov["intensity"] = rng.choice([1000, 5000, 10000])
        ov["source_host"] = rng.choice(["h1", "h3"])
        ov["target_host"] = rng.choice(["h2", "h4"])
        if ov["source_host"] == ov["target_host"]:
            ov["target_host"] = "h2" if ov["source_host"] != "h2" else "h4"
        return ov
    if sid == "S3":
        ov["baseline_sec"] = rng.choice([15, 20, 25])
        ov["attack_sec"] = rng.choice([20, 30])
        ov["recovery_sec"] = rng.choice([5, 10])
        ov["intensity"] = rng.choice(["1M", "5M", "10M"])
        ov["source_host"] = "h1"
        ov["target_host"] = rng.choice(["h2", "h3"])
        return ov
    if sid == "S4":
        ov["baseline_sec"] = rng.choice([10, 15])
        ov["burst_sec"] = rng.choice([5, 8, 10])
        ov["recovery_sec"] = rng.choice([10, 15])
        ov["burst_count"] = rng.choice([1, 2])
        ov["inter_burst_interval_sec"] = rng.choice([0, 5]) if ov["burst_count"] > 1 else 0
        ov["intensity"] = rng.choice([10000, 20000])
        return ov
    if sid == "S5":
        ov["baseline_sec"] = rng.choice([10, 15])
        ov["attack1_sec"] = rng.choice([15, 20])
        ov["gap_sec"] = rng.choice([5, 10])
        ov["attack2_sec"] = rng.choice([15, 20])
        return ov
    raise TwinValidationError(f"unsupported scenario for variants: {sid}")
