"""
Signal category taxonomy for R4 (repository-evidence based; not false OSI L7).

Why these five are distinct:
- DATA_PLANE: OpenFlow switch counters (flows/ports) — network forwarding plane.
- CONTROL_PLANE: Controller host process health / adaptive controller policy (psutil, RL thresholds).
- DETECTION: Online detectors that emit NORMAL/ALERT/ATTACK style security judgments (entropy, ML).
- DRIFT_CLUSTERING: Observational analytics (ADWIN, HDBSCAN) that do not authorize mitigation today.
- SECURITY_RESPONSE: Post-detection pipeline evidence (R7/R8/mitigation/RCA refs).

Do NOT claim application-layer / HTTP / DNS / host-kernel / endpoint telemetry.
"""

from __future__ import annotations

from enum import Enum


class SignalCategory(str, Enum):
    """High-level source class for correlation diversity scoring (R4.2+)."""

    DATA_PLANE = "DATA_PLANE"
    CONTROL_PLANE = "CONTROL_PLANE"
    DETECTION = "DETECTION"
    DRIFT_CLUSTERING = "DRIFT_CLUSTERING"
    SECURITY_RESPONSE = "SECURITY_RESPONSE"
    UNKNOWN = "UNKNOWN"


CATEGORY_RATIONALE: dict[str, str] = {
    SignalCategory.DATA_PLANE.value: (
        "OpenFlow flow/port statistics from the data plane; rates and counters "
        "describe forwarding behaviour, not detector verdicts."
    ),
    SignalCategory.CONTROL_PLANE.value: (
        "Controller-process and controller-policy signals (CPU/memory via psutil; "
        "RL threshold adaptation). Distinct from switch counters and detectors."
    ),
    SignalCategory.DETECTION.value: (
        "Primary online detectors (entropy, ML) that emit security status / "
        "confidence used on the mitigation path."
    ),
    SignalCategory.DRIFT_CLUSTERING.value: (
        "ADWIN drift and HDBSCAN clustering — observational analytics logged each "
        "cycle but not currently driving OpenFlow mitigation."
    ),
    SignalCategory.SECURITY_RESPONSE.value: (
        "Verification, alerts, mitigation actions, and optional RCA references — "
        "downstream of detection, not raw telemetry."
    ),
}
