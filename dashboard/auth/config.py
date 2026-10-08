"""Authentication configuration from environment (no hardcoded secrets)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from .roles import DEFAULT_ROLE, parse_roles, validate_role_names


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val


@dataclass(frozen=True)
class AuthConfig:
    """Runtime auth settings. Never embeds production secrets in source."""

    enabled: bool
    secret_key: str
    username: str
    password_hash: str
    session_ttl_seconds: int
    cookie_name: str
    cookie_secure: bool
    cookie_samesite: str
    login_max_attempts: int
    login_window_seconds: int
    cors_origins: list[str]
    # Server-assigned roles for the configured credential (Phase 9)
    roles: List[str] = field(default_factory=lambda: [DEFAULT_ROLE.value])
    rbac_enabled: bool = True

    @property
    def configured(self) -> bool:
        """True when a verifiable credential and secret are present."""
        return bool(self.enabled and self.secret_key and self.username and self.password_hash)


def load_auth_config() -> AuthConfig:
    """
    Load auth config from environment.

    Required for login to succeed:
      INTELLISHIELD_AUTH_SECRET_KEY
      INTELLISHIELD_AUTH_USERNAME
      INTELLISHIELD_AUTH_PASSWORD_HASH   (pbkdf2 format from passwords.hash_password)

    Optional:
      INTELLISHIELD_AUTH_ENABLED=1|0
      INTELLISHIELD_AUTH_SESSION_TTL_SECONDS  (default 28800 = 8h)
      INTELLISHIELD_AUTH_COOKIE_SECURE=0|1
      INTELLISHIELD_AUTH_COOKIE_SAMESITE=lax|strict|none
      INTELLISHIELD_AUTH_ROLES=VIEWER|ANALYST|OPERATOR|ADMIN  (comma-separated; default VIEWER)
      INTELLISHIELD_CORS_ORIGINS=comma,separated  (empty → lab default "*")
    """
    secret = _env("INTELLISHIELD_AUTH_SECRET_KEY", "") or ""
    username = _env("INTELLISHIELD_AUTH_USERNAME", "") or ""
    password_hash = _env("INTELLISHIELD_AUTH_PASSWORD_HASH", "") or ""

    enabled_raw = _env("INTELLISHIELD_AUTH_ENABLED")
    if enabled_raw is None:
        enabled = bool(secret and username and password_hash)
    else:
        enabled = enabled_raw.strip().lower() in {"1", "true", "yes", "on"}

    ttl = int(_env("INTELLISHIELD_AUTH_SESSION_TTL_SECONDS", "28800") or "28800")
    ttl = max(60, min(ttl, 86400 * 7))

    secure = (_env("INTELLISHIELD_AUTH_COOKIE_SECURE", "0") or "0").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    samesite = (_env("INTELLISHIELD_AUTH_COOKIE_SAMESITE", "lax") or "lax").lower()
    if samesite not in {"lax", "strict", "none"}:
        samesite = "lax"

    cors_raw = _env("INTELLISHIELD_CORS_ORIGINS", "") or ""
    cors_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]

    roles_raw = _env("INTELLISHIELD_AUTH_ROLES", DEFAULT_ROLE.value) or DEFAULT_ROLE.value
    role_names = [r.strip() for r in roles_raw.split(",") if r.strip()]
    invalid = validate_role_names(role_names)
    if invalid or not role_names:
        # Fail closed to least privilege — never elevate to ADMIN on bad config
        role_names = [DEFAULT_ROLE.value]
    else:
        known, _ = parse_roles(role_names)
        role_names = [r.value for r in known] or [DEFAULT_ROLE.value]

    return AuthConfig(
        enabled=enabled,
        secret_key=secret,
        username=username,
        password_hash=password_hash,
        session_ttl_seconds=ttl,
        cookie_name="is_session",
        cookie_secure=secure,
        cookie_samesite=samesite,
        login_max_attempts=int(_env("INTELLISHIELD_AUTH_LOGIN_MAX_ATTEMPTS", "10") or "10"),
        login_window_seconds=int(_env("INTELLISHIELD_AUTH_LOGIN_WINDOW_SECONDS", "300") or "300"),
        cors_origins=cors_origins,
        roles=role_names,
        rbac_enabled=True,
    )
