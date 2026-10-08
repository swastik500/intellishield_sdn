"""
IntelliShield Root Cause Analysis (Requirement R5.2 / R5.3).

Produces FOUNDATION shared_contracts.RootCauseReport from structured evidence.
Does not authorize mitigation. Does not fabricate baselines or causes.
"""

from rca.completeness import CompletenessResult, measure_evidence_completeness
from rca.config import RCAConfig
from rca.context import MitigationEvidence, RCAContext
from rca.engine import RootCauseEngine
from rca.evidence import EvidenceItem, EvidenceKind
from rca.persistence import (
    JsonlRCAStore,
    MemoryRCAStore,
    NullRCAStore,
    default_rca_jsonl_path,
    get_rca_by_event,
    get_rca_report,
    rca_record_for_api,
    read_rca_history,
    safe_append_rca,
)
from rca.runtime import (
    RuntimeEnrichment,
    safe_enrich_verified_event,
    status_allows_xai_rca,
)

__all__ = [
    "CompletenessResult",
    "EvidenceItem",
    "EvidenceKind",
    "JsonlRCAStore",
    "MemoryRCAStore",
    "MitigationEvidence",
    "NullRCAStore",
    "RCAConfig",
    "RCAContext",
    "RootCauseEngine",
    "RuntimeEnrichment",
    "default_rca_jsonl_path",
    "get_rca_by_event",
    "get_rca_report",
    "measure_evidence_completeness",
    "rca_record_for_api",
    "read_rca_history",
    "safe_append_rca",
    "safe_enrich_verified_event",
    "status_allows_xai_rca",
]
