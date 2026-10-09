"""
Email alert configuration — loads from project-root .env via python-dotenv.

Environment variables:
    ALERT_EMAIL_ENABLED           (bool)  — master switch (default: false)
    ALERT_EMAIL_TO                (str)   — recipient address
    ALERT_SMTP_HOST               (str)   — SMTP server  (default: smtp.gmail.com)
    ALERT_SMTP_PORT               (int)   — SMTP port    (default: 587)
    ALERT_SMTP_USER               (str)   — sender / login
    ALERT_SMTP_PASSWORD           (str)   — app password  (never a normal Gmail password)
    ALERT_EMAIL_COOLDOWN_SECONDS  (int)   — per-attack-key cooldown (default: 300)
    ALERT_EMAIL_RECOVERY          (bool)  — send recovery emails   (default: false)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _load_dotenv_once() -> None:
    """Best-effort .env load — never fatal."""
    try:
        from dotenv import load_dotenv

        env_path = Path(__file__).resolve().parent.parent / ".env"
        if env_path.is_file():
            load_dotenv(dotenv_path=str(env_path), override=False)
    except ImportError:
        pass  # python-dotenv optional at import time


_load_dotenv_once()


@dataclass(frozen=True)
class EmailAlertConfig:
    """Immutable snapshot of email alert settings from environment."""

    enabled: bool = False
    recipient: str = ""
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""          # never logged
    cooldown_seconds: int = 300
    recovery_enabled: bool = False

    # Derived convenience
    @property
    def is_configured(self) -> bool:
        """True when all required SMTP fields are populated."""
        return bool(
            self.enabled
            and self.recipient
            and self.smtp_host
            and self.smtp_user
            and self.smtp_password
        )

    def __repr__(self) -> str:
        """Credential-safe repr — password is never shown."""
        return (
            f"EmailAlertConfig(enabled={self.enabled}, recipient='{self.recipient}', "
            f"smtp_host='{self.smtp_host}', smtp_port={self.smtp_port}, "
            f"smtp_user='{self.smtp_user}', smtp_password='***', "
            f"cooldown_seconds={self.cooldown_seconds}, "
            f"recovery_enabled={self.recovery_enabled})"
        )


def load_email_alert_config() -> EmailAlertConfig:
    """Build config from current environment (call after .env is loaded)."""
    _load_dotenv_once()
    raw_pass = os.getenv("ALERT_SMTP_PASSWORD", "")
    clean_pass = raw_pass.strip().replace(" ", "") if raw_pass else ""
    return EmailAlertConfig(
        enabled=os.getenv("ALERT_EMAIL_ENABLED", "").lower() in _TRUE_VALUES,
        recipient=os.getenv("ALERT_EMAIL_TO", "").strip(),
        smtp_host=os.getenv("ALERT_SMTP_HOST", "smtp.gmail.com").strip(),
        smtp_port=int(os.getenv("ALERT_SMTP_PORT", "587")),
        smtp_user=os.getenv("ALERT_SMTP_USER", "").strip(),
        smtp_password=clean_pass,
        cooldown_seconds=int(os.getenv("ALERT_EMAIL_COOLDOWN_SECONDS", "300")),
        recovery_enabled=os.getenv("ALERT_EMAIL_RECOVERY", "").lower() in _TRUE_VALUES,
    )
