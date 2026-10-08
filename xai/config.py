"""XAI configuration (R5.1)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class XAIConfig:
    """Lightweight explanation knobs — no SHAP, no LLM."""

    enabled: bool = True
    max_path_steps: int = 32
    max_importance_features: int = 5
    max_anomalous_features: int = 10
    include_feature_deviation: bool = True
    include_attack_hint: bool = True
    # Denied evidence keys (never copy from prediction extras into narrative refs)
    evidence_denied_keys: tuple = (
        "password",
        "token",
        "secret",
        "api_key",
        "private_key",
        "credential",
        "authorization",
    )
