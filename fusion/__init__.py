"""
IntelliShield Collaborative Detection (Requirement R6).

R6.1: Detector adapters + bounded evidence registry + DetectionEvent assembly.
R6.2: CollaborativeFusionEngine → FusedDecision (no production wiring).
R6.3: Production R6 → R7 integration (never bypasses verification).

R6 does NOT mitigate. R7 verifies. MitigationEngine responds.
"""

from fusion.adapters import (
    adapt_adwin_alerts,
    adapt_correlation_result,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
    adapt_ssl_unavailable,
    degraded,
    map_detector_health,
    unavailable,
)
from fusion.assembly import build_detection_event
from fusion.config import (
    DEFAULT_BASE_RELIABILITY,
    DEFAULT_HEALTH_FACTORS,
    FusionConfig,
)
from fusion.engine import CollaborativeFusionEngine
from fusion.evidence import EvidenceRecord, entity_key_from
from fusion.legacy_compare import (
    LegacyComparison,
    classify_legacy_difference,
    comparison_to_dict,
    legacy_production_decision,
)
from fusion.history import (
    default_fused_decisions_jsonl_path,
    fused_decision_history_stats,
    fused_decision_record_for_api,
    get_fused_decision,
    read_fused_decision_history,
)
from fusion.normalize import to_unit_confidence
from fusion.r7_adapter import (
    fused_decision_to_r7_payload,
    fused_should_enter_verification,
)
from fusion.registry import (
    DEFAULT_FRESHNESS_SECONDS,
    DEFAULT_MAX_RECORDS,
    DetectorDescriptor,
    EvidenceRegistry,
    build_default_registry,
)
from fusion.roles import ROLE_RATIONALE, EvidenceRole, normalize_role
from fusion.runtime import (
    CollaborativeCycleOutcome,
    link_verification_to_fusion_trace,
    prepare_collaborative_cycle,
    r6_fusion_enabled_from_env,
)
from fusion.trace import append_fusion_trace, default_fusion_trace_path

__all__ = [
    "DEFAULT_BASE_RELIABILITY",
    "DEFAULT_FRESHNESS_SECONDS",
    "DEFAULT_HEALTH_FACTORS",
    "DEFAULT_MAX_RECORDS",
    "ROLE_RATIONALE",
    "CollaborativeCycleOutcome",
    "CollaborativeFusionEngine",
    "DetectorDescriptor",
    "EvidenceRecord",
    "EvidenceRegistry",
    "EvidenceRole",
    "FusionConfig",
    "LegacyComparison",
    "adapt_adwin_alerts",
    "adapt_correlation_result",
    "adapt_entropy_metrics",
    "adapt_hdbscan_summary",
    "adapt_ml_prediction",
    "adapt_ssl_unavailable",
    "append_fusion_trace",
    "build_default_registry",
    "build_detection_event",
    "classify_legacy_difference",
    "comparison_to_dict",
    "default_fusion_trace_path",
    "default_fused_decisions_jsonl_path",
    "degraded",
    "entity_key_from",
    "fused_decision_history_stats",
    "fused_decision_record_for_api",
    "fused_decision_to_r7_payload",
    "fused_should_enter_verification",
    "get_fused_decision",
    "legacy_production_decision",
    "link_verification_to_fusion_trace",
    "map_detector_health",
    "normalize_role",
    "prepare_collaborative_cycle",
    "r6_fusion_enabled_from_env",
    "read_fused_decision_history",
    "to_unit_confidence",
    "unavailable",
]
