"""
IntelliShield Cross-Layer Correlation (Requirement R4).

R4.1: Signal inventory + SignalEvent / EntityIdentity / CorrelationWindow.
R4.2: CorrelationEngine → shared_contracts.CorrelationResult.
R4.3: Runtime adapters + fail-isolated advisory hook (no mitigation).

Produces CORRELATION EVIDENCE only — does not authorize mitigation.
"""

from correlation.categories import CATEGORY_RATIONALE, SignalCategory
from correlation.clock import FakeTimeProvider, RealTimeProvider, TimeProvider
from correlation.config import CorrelationConfig
from correlation.engine import CorrelationEngine
from correlation.identity import EntityIdentity, build_entity_key
from correlation.inventory import (
    SIGNAL_INVENTORY,
    SignalDescriptor,
    inventory_summary,
    list_available_signals,
)
from correlation.models import CorrelationWindow, SignalEvent, new_signal_id, new_window_id
from correlation.normalization import NormalizationClass
from correlation.persistence import (
    CorrelationStore,
    JsonlCorrelationStore,
    MemoryCorrelationStore,
    NullCorrelationStore,
    correlation_history_stats,
    correlation_record_for_api,
    default_correlation_jsonl_path,
    get_correlation_result,
    read_correlation_history,
    safe_append_correlation,
)
from correlation.runtime import (
    CorrelationRuntimeConfig,
    RuntimeCorrelationOutcome,
    build_cycle_signals,
    safe_correlate_cycle,
)

__all__ = [
    "CATEGORY_RATIONALE",
    "SIGNAL_INVENTORY",
    "CorrelationConfig",
    "CorrelationEngine",
    "CorrelationRuntimeConfig",
    "CorrelationStore",
    "CorrelationWindow",
    "EntityIdentity",
    "FakeTimeProvider",
    "JsonlCorrelationStore",
    "MemoryCorrelationStore",
    "NormalizationClass",
    "NullCorrelationStore",
    "RealTimeProvider",
    "RuntimeCorrelationOutcome",
    "SignalCategory",
    "SignalDescriptor",
    "SignalEvent",
    "TimeProvider",
    "build_cycle_signals",
    "build_entity_key",
    "correlation_history_stats",
    "correlation_record_for_api",
    "default_correlation_jsonl_path",
    "get_correlation_result",
    "inventory_summary",
    "list_available_signals",
    "new_signal_id",
    "new_window_id",
    "read_correlation_history",
    "safe_append_correlation",
    "safe_correlate_cycle",
]
