"""Password hashing using stdlib PBKDF2-HMAC-SHA256 (no custom crypto)."""

from __future__ import annotations

import hashlib
import hmac
import secrets


_ITERATIONS = 210_000
_ALGO = "sha256"


def hash_password(password: str) -> str:
    """
    Return a storable hash string:

      pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>
    """
    if not isinstance(password, str) or password == "":
        raise ValueError("password required")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(_ALGO, password.encode("utf-8"), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify against hash_password() output."""
    try:
        algo, iters_s, salt_hex, digest_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters_s)
        if iterations < 10_000 or iterations > 5_000_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        got = hashlib.pbkdf2_hmac(_ALGO, password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False
