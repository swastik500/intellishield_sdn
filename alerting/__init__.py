"""
IntelliShield Automated Alert & Notification System (Requirement R8).

R8.1: AlertManager core.
R8.2: Severity / dedup / rate-limit policy.
R8.3: Runtime fan-out from VerificationResult (controller-wired).
R8.4: JSONL persistence + dashboard security-alerts API.
"""

from alerting.adapters.base import NotificationAdapter
from alerting.adapters.logging_adapter import LoggingNotificationAdapter
from alerting.adapters.memory_adapter import MemoryNotificationAdapter
from alerting.clock import FakeTimeProvider, RealTimeProvider, TimeProvider
from alerting.config import AlertingConfig
from alerting.dedup import BoundedDeduplicator
from alerting.factory import AlertFactory, AlertFactoryContext, build_dedup_key
from alerting.manager import AlertDisposition, AlertManager, AlertProcessResult
from alerting.metrics import AlertMetrics
from alerting.persistence import (
    AlertStore,
    JsonlAlertStore,
    MemoryAlertStore,
    NullAlertStore,
    alert_history_stats,
    alert_record_for_api,
    default_alerts_jsonl_path,
    read_alert_history,
)
from alerting.rate_limit import BoundedRateLimiter
from alerting.runtime import (
    build_runtime_alert_context,
    safe_emit_verification_alert,
)
from alerting.severity import (
    DefaultSeverityPolicy,
    SeverityEvidence,
    SeverityPolicy,
)

__all__ = [
    "AlertDisposition",
    "AlertFactory",
    "AlertFactoryContext",
    "AlertManager",
    "AlertMetrics",
    "AlertProcessResult",
    "AlertStore",
    "AlertingConfig",
    "BoundedDeduplicator",
    "BoundedRateLimiter",
    "DefaultSeverityPolicy",
    "FakeTimeProvider",
    "JsonlAlertStore",
    "LoggingNotificationAdapter",
    "MemoryAlertStore",
    "MemoryNotificationAdapter",
    "NotificationAdapter",
    "NullAlertStore",
    "RealTimeProvider",
    "SeverityEvidence",
    "SeverityPolicy",
    "TimeProvider",
    "alert_history_stats",
    "alert_record_for_api",
    "build_dedup_key",
    "build_runtime_alert_context",
    "default_alerts_jsonl_path",
    "read_alert_history",
    "safe_emit_verification_alert",
]
