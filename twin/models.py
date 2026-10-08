"""
Re-export twin contract models for the digital twin package surface.

Canonical definitions live in shared_contracts (FOUNDATION dependency rule).
This module exists so the twin package exposes models.py as documented.
"""

from shared_contracts.enums import TwinLabelSource, TwinRunPurpose, TwinRunStatus
from shared_contracts.models import (
    TwinDetectorConfig,
    TwinHost,
    TwinLink,
    TwinObservation,
    TwinProfile,
    TwinRun,
    TwinScenario,
    TwinSwitch,
    TwinTopology,
    TwinTrafficConfig,
    TwinValidationPolicy,
)

__all__ = [
    "TwinDetectorConfig",
    "TwinHost",
    "TwinLabelSource",
    "TwinLink",
    "TwinObservation",
    "TwinProfile",
    "TwinRun",
    "TwinRunPurpose",
    "TwinRunStatus",
    "TwinScenario",
    "TwinSwitch",
    "TwinTopology",
    "TwinTrafficConfig",
    "TwinValidationPolicy",
]
