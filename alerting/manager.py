"""
AlertManager — unified alert processing (R8.1 core + R8.2 policy).

Policy order (R8.2):
  factory severity assignment (on create)
        → dedup
        → rate limit
        → persist
        → dispatch

Duplicates / rate-limited alerts are NOT persisted (simple auditable policy).
"""

from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence

from shared_contracts.models import AlertEvent, VerificationResult
from alerting.adapters.base import NotificationAdapter
from alerting.clock import RealTimeProvider, TimeProvider
from alerting.config import AlertingConfig
from alerting.dedup import BoundedDeduplicator
from alerting.factory import AlertFactory, AlertFactoryContext, build_dedup_key
from alerting.metrics import AlertMetrics
from alerting.persistence import AlertStore, NullAlertStore
from alerting.rate_limit import BoundedRateLimiter
from shared_contracts.enums import AlertType

logger = logging.getLogger("intellishield.alerting")


class AlertDisposition(str, Enum):
    """Outcome of one AlertManager.process call."""

    NEW = "NEW"
    SKIPPED = "SKIPPED"
    DISABLED = "DISABLED"
    DUPLICATE = "DUPLICATE"
    RATE_LIMITED = "RATE_LIMITED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class AlertProcessResult:
    disposition: AlertDisposition
    alert: Optional[AlertEvent] = None
    adapters_ok: int = 0
    adapters_failed: int = 0
    adapters_skipped: int = 0
    persisted: bool = False
    reason: str = ""


class AlertManager:
    """
    Process verified security events into AlertEvents and notify adapters.

    Fail-safe: adapter / factory / store / policy errors never propagate.
    Does not authorize or suppress mitigation.
    """

    def __init__(
        self,
        config: Optional[AlertingConfig] = None,
        adapters: Optional[Sequence[NotificationAdapter]] = None,
        factory: Optional[AlertFactory] = None,
        metrics: Optional[AlertMetrics] = None,
        store: Optional[AlertStore] = None,
        clock: Optional[TimeProvider] = None,
        deduplicator: Optional[BoundedDeduplicator] = None,
        rate_limiter: Optional[BoundedRateLimiter] = None,
    ) -> None:
        self.config = config or AlertingConfig()
        self.factory = factory or AlertFactory(self.config)
        self.metrics = metrics or AlertMetrics()
        self.store: AlertStore = store or NullAlertStore()
        self.clock: TimeProvider = clock or RealTimeProvider()
        self.deduplicator = deduplicator or BoundedDeduplicator(
            window_sec=self.config.dedup_window_sec,
            max_keys=self.config.dedup_max_keys,
            clock=self.clock,
        )
        self.rate_limiter = rate_limiter or BoundedRateLimiter(
            limit=self.config.rate_limit_per_window,
            window_sec=self.config.rate_limit_window_sec,
            max_keys=self.config.rate_limit_max_keys,
            clock=self.clock,
        )
        self._adapters: List[NotificationAdapter] = list(adapters or [])

    def add_adapter(self, adapter: NotificationAdapter) -> None:
        self._adapters.append(adapter)

    def clear_adapters(self) -> None:
        self._adapters.clear()

    def reset_policy_state(self) -> None:
        """Reset dedup + rate-limit state (tests / reconnect)."""
        self.deduplicator.reset()
        self.rate_limiter.reset()

    def process_verification(
        self,
        result: VerificationResult,
        context: Optional[AlertFactoryContext] = None,
    ) -> AlertProcessResult:
        """Primary R8 entry: VerificationResult → severity → policy → persist → dispatch."""
        self.metrics.incr("alerts_received")
        try:
            if result is None:
                self.metrics.incr("alerts_skipped")
                logger.info("[DIAG] AlertManager: null verification result, skipping")
                return AlertProcessResult(
                    disposition=AlertDisposition.SKIPPED,
                    reason="null_verification_result",
                )
            if not self.config.enabled:
                self.metrics.incr("alerts_skipped")
                logger.info("[DIAG] AlertManager: alerting disabled, skipping")
                return AlertProcessResult(
                    disposition=AlertDisposition.DISABLED,
                    reason="alerting_disabled",
                )

            logger.info("[DIAG] AlertManager: processing verification result_id=%s status=%s eligible=%s", 
                       getattr(result, "verification_id", "?"), 
                       getattr(result, "status", "?"), 
                       getattr(result, "mitigation_eligible", "?"))
            alert = self.factory.from_verification(result, context)
            if alert is None:
                self.metrics.incr("alerts_skipped")
                logger.info("[DIAG] AlertManager: factory returned None, skipping")
                return AlertProcessResult(
                    disposition=AlertDisposition.SKIPPED,
                    reason="factory_skipped",
                )

            return self._apply_policy_and_emit(alert)
        except Exception as exc:  # noqa: BLE001
            self.metrics.incr("manager_failures")
            logger.error(
                "[AlertManager] process_verification failed (isolated):\n%s",
                traceback.format_exc(),
            )
            return AlertProcessResult(
                disposition=AlertDisposition.ERROR,
                reason=f"manager_error:{type(exc).__name__}",
            )

    def process_alert(self, alert: AlertEvent) -> AlertProcessResult:
        """Accept a pre-built AlertEvent (severity already assigned)."""
        self.metrics.incr("alerts_received")
        try:
            if alert is None:
                self.metrics.incr("alerts_skipped")
                return AlertProcessResult(
                    disposition=AlertDisposition.SKIPPED,
                    reason="null_alert",
                )
            if not self.config.enabled:
                self.metrics.incr("alerts_skipped")
                return AlertProcessResult(
                    disposition=AlertDisposition.DISABLED,
                    reason="alerting_disabled",
                )
            return self._apply_policy_and_emit(alert)
        except Exception as exc:  # noqa: BLE001
            self.metrics.incr("manager_failures")
            logger.error(
                "[AlertManager] process_alert failed (isolated):\n%s",
                traceback.format_exc(),
            )
            return AlertProcessResult(
                disposition=AlertDisposition.ERROR,
                reason=f"manager_error:{type(exc).__name__}",
            )

    def _apply_policy_and_emit(self, alert: AlertEvent) -> AlertProcessResult:
        """
        Order: dedup → rate limit → persist → dispatch.

        Severity was assigned at factory (or supplied on AlertEvent).
        """
        key = self._policy_key(alert)

        # 1) Dedup
        if self.config.dedup_enabled:
            decision = self.deduplicator.observe(key)
            if decision.is_duplicate:
                self.metrics.incr("alerts_deduplicated")
                return AlertProcessResult(
                    disposition=AlertDisposition.DUPLICATE,
                    alert=alert,
                    reason=f"dedup:{decision.key}",
                )

        # 2) Rate limit
        if self.config.rate_limit_enabled:
            rl = self.rate_limiter.allow(key)
            if not rl.allowed:
                self.metrics.incr("alerts_rate_limited")
                return AlertProcessResult(
                    disposition=AlertDisposition.RATE_LIMITED,
                    alert=alert,
                    reason=(
                        f"rate_limit:{rl.key} count={rl.count_in_window}/{rl.limit}"
                    ),
                )

        # 3) Persist + dispatch
        self.metrics.incr("alerts_created")
        persisted = self._persist(alert)
        ok, failed, skipped = self._dispatch(alert)
        return AlertProcessResult(
            disposition=AlertDisposition.NEW,
            alert=alert,
            adapters_ok=ok,
            adapters_failed=failed,
            adapters_skipped=skipped,
            persisted=persisted,
            reason="created",
        )

    def _policy_key(self, alert: AlertEvent) -> str:
        if alert.dedup_key:
            return str(alert.dedup_key)
        # Reconstruct stable key if missing (malformed / manually built alerts)
        atype = alert.alert_type if alert.alert_type else AlertType.UNKNOWN
        hint = ""
        if isinstance(alert.evidence, dict):
            hint = str(alert.evidence.get("attack_hint") or "")
        attacker = ""
        victim = ""
        if isinstance(alert.evidence, dict):
            attacker = str(alert.evidence.get("attacker_mac") or "")
            victim = str(alert.evidence.get("victim_mac") or "")
        return build_dedup_key(
            alert_type=atype,
            source=alert.source or "",
            attacker_mac=attacker,
            victim_mac=victim,
            attack_hint=hint,
        )

    def _persist(self, alert: AlertEvent) -> bool:
        try:
            ok = bool(self.store.append(alert))
            if ok:
                self.metrics.incr("alerts_persisted")
            else:
                self.metrics.incr("persistence_failures")
            return ok
        except Exception:  # noqa: BLE001
            self.metrics.incr("persistence_failures")
            logger.error(
                "[AlertManager] store.append failed (isolated):\n%s",
                traceback.format_exc(),
            )
            return False

    def _dispatch(self, alert: AlertEvent) -> tuple:
        if not self.config.dispatch_enabled or not self._adapters:
            logger.info("[DIAG] AlertManager dispatch: disabled or no adapters (dispatch_enabled=%s, adapters=%d)", self.config.dispatch_enabled, len(self._adapters))
            return 0, 0, 0
        ok = 0
        failed = 0
        skipped = 0
        for adapter in self._adapters:
            if getattr(adapter, "enabled", True) is False:
                skipped += 1
                logger.info("[DIAG] AlertManager dispatch: adapter %s skipped (enabled=False)", getattr(adapter, "name", type(adapter).__name__))
                continue
            try:
                logger.info("[DIAG] AlertManager dispatch: sending to adapter %s", getattr(adapter, "name", type(adapter).__name__))
                adapter.send(alert)
                ok += 1
                self.metrics.incr("alerts_dispatched")
            except Exception:  # noqa: BLE001
                failed += 1
                self.metrics.incr("adapter_failures")
                name = getattr(adapter, "name", type(adapter).__name__)
                logger.error(
                    "[AlertManager] adapter %r failed (isolated):\n%s",
                    name,
                    traceback.format_exc(),
                )
        logger.info("[DIAG] AlertManager dispatch complete: ok=%d failed=%d skipped=%d", ok, failed, skipped)
        return ok, failed, skipped
