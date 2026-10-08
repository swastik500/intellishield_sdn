"""
Drift & Performance Trigger Manager for Online AutoML.

Enforces trigger policies:
  - Prevents running AutoML every 5-second polling cycle.
  - Triggers only on meaningful ADWIN drift, performance degradation, scheduled intervals,
    or explicit manual operator requests.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional, Tuple

logger = logging.getLogger("intellishield.online_automl.drift_trigger")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")
DRIFT_CSV_PATH = os.path.join(_LOGS_DIR, "drift_alerts.csv")


class AutoMLTriggerManager:
    """
    Evaluates drift and performance signals to trigger AutoML retraining safely.
    """

    def __init__(self, min_interval_sec: float = 300.0) -> None:
        self.min_interval_sec = min_interval_sec
        self.last_run_time: float = 0.0
        self.last_trigger_reason: str = "NO_TRIGGER"
        self.total_triggers: int = 0

    def check_drift_alert(self) -> bool:
        """
        Check if an ADWIN drift alert was recently written to logs/drift_alerts.csv.
        """
        if not os.path.exists(DRIFT_CSV_PATH):
            return False
        try:
            mtime = os.path.getmtime(DRIFT_CSV_PATH)
            # Drift alert created/updated within last 60 seconds
            if (time.time() - mtime) < 60.0:
                return True
        except Exception:
            pass
        return False

    def should_trigger(
        self,
        force: bool = False,
        adwin_drift: bool = False,
        perf_degraded: bool = False,
    ) -> Tuple[bool, str]:
        """
        Evaluate whether AutoML should run.

        Args:
            force: Manual trigger flag (bypasses min_interval_sec).
            adwin_drift: Explicit drift signal.
            perf_degraded: Explicit performance degradation signal.

        Returns:
            Tuple of (should_trigger_bool, trigger_reason_string)
        """
        now = time.time()

        if force:
            self.last_run_time = now
            self.last_trigger_reason = "MANUAL_TRIGGER"
            self.total_triggers += 1
            logger.info("[AutoMLTriggerManager] Triggered: MANUAL_TRIGGER")
            return True, "MANUAL_TRIGGER"

        elapsed = now - self.last_run_time
        if elapsed < self.min_interval_sec:
            # Enforce minimum interval — do not trigger every 5s poll cycle
            return False, f"COOLDOWN ({int(self.min_interval_sec - elapsed)}s remaining)"

        if adwin_drift or self.check_drift_alert():
            self.last_run_time = now
            self.last_trigger_reason = "DRIFT_DETECTED"
            self.total_triggers += 1
            logger.info("[AutoMLTriggerManager] Triggered: DRIFT_DETECTED")
            return True, "DRIFT_DETECTED"

        if perf_degraded:
            self.last_run_time = now
            self.last_trigger_reason = "PERFORMANCE_DEGRADATION"
            self.total_triggers += 1
            logger.info("[AutoMLTriggerManager] Triggered: PERFORMANCE_DEGRADATION")
            return True, "PERFORMANCE_DEGRADATION"

        # Scheduled run if min_interval_sec elapsed
        if self.last_run_time == 0.0 or elapsed >= self.min_interval_sec * 2.0:
            self.last_run_time = now
            self.last_trigger_reason = "SCHEDULED_INTERVAL"
            self.total_triggers += 1
            logger.info("[AutoMLTriggerManager] Triggered: SCHEDULED_INTERVAL")
            return True, "SCHEDULED_INTERVAL"

        return False, "NO_TRIGGER"
