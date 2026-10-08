"""
Structured logger for Online AutoML lifecycle events and audit records.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

from shared_contracts.models import ValidationResult

logger = logging.getLogger("intellishield.online_automl")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")
AUTOML_EVENTS_LOG = os.path.join(_LOGS_DIR, "automl_events.log")


class AutoMLLogger:
    """Handles logging and audit record persistence for Online AutoML events."""

    def __init__(self, log_filepath: Optional[str] = None) -> None:
        self.log_filepath = log_filepath or AUTOML_EVENTS_LOG
        os.makedirs(os.path.dirname(os.path.abspath(self.log_filepath)), exist_ok=True)

    def log_event(
        self,
        event_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a structured AutoML lifecycle event."""
        payload = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "message": message,
            "details": details or {},
        }
        logger.info("[AutoML Event] %s: %s | %s", event_type, message, details or {})

        try:
            with open(self.log_filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception as exc:  # noqa: BLE001
            logger.debug("[AutoMLLogger] Log write failed: %s", exc)

    def log_validation_summary(self, validation_res: ValidationResult) -> None:
        """Log candidate validation summary."""
        self.log_event(
            event_type="CANDIDATE_VALIDATION",
            message=validation_res.reason,
            details={
                "validation_id": validation_res.validation_id,
                "status": validation_res.status.value,
                "model_id": validation_res.model_id,
                "candidate_id": validation_res.candidate_id,
                "metrics": validation_res.metrics,
            },
        )
