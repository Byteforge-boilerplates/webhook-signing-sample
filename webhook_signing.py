"""Webhook signing and verification (stdlib only).

Header: ``X-Example-Signature: t=<unix>,v1=<hex>`` where
``v1 = HMAC_SHA256(secret, f"{t}.{raw_body}")``. Receivers reject timestamps more than
300 s away from their clock. During a secret roll, deliveries are signed with the new secret,
and verification accepts any secret still inside its overlap window.

Note: ``verify`` does not remember accepted signatures. Receivers should deduplicate on the
event id header, so a replayed message inside the tolerance window is a no-op.
"""

import hashlib
import hmac
import secrets
import time
from collections.abc import Sequence

SIGNATURE_HEADER = "X-Example-Signature"
EVENT_ID_HEADER = "X-Example-Event-Id"
SIGNATURE_TOLERANCE_SECONDS = 300
USER_AGENT = "Example-Webhooks/1.0"

_SECRET_PREFIX = "whsec_"
_DISPLAY_PREFIX_LENGTH = len(_SECRET_PREFIX) + 4


def generate_secret() -> str:
    """New signing secret: ``whsec_`` followed by 32 random hex characters."""
    return f"{_SECRET_PREFIX}{secrets.token_hex(16)}"


def secret_prefix(secret: str) -> str:
    """Non-secret prefix that is safe to display (for example ``whsec_7f3a``)."""
    return secret[:_DISPLAY_PREFIX_LENGTH]


def _digest(secret: str, raw_body: bytes, timestamp: int) -> str:
    return hmac.new(secret.encode(), f"{timestamp}.".encode() + raw_body, hashlib.sha256).hexdigest()


def sign(secret: str, raw_body: bytes, timestamp: int) -> str:
    """Signature header value ``t=<unix>,v1=<hex>`` for ``raw_body`` sent at ``timestamp``."""
    return f"t={timestamp},v1={_digest(secret, raw_body, timestamp)}"


def verify(
    header: str,
    raw_body: bytes,
    secrets_in_window: Sequence[str],
    tolerance: int = SIGNATURE_TOLERANCE_SECONDS,
    *,
    now: int | None = None,
) -> bool:
    """True when ``header`` is fresh and one of its ``v1`` values matches any secret in the window."""
    timestamp: int | None = None
    signatures: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t" and value.isdigit():
            timestamp = int(value)
        elif key == "v1" and value:
            signatures.append(value)
    if timestamp is None or not signatures:
        return False
    if abs((int(time.time()) if now is None else now) - timestamp) > tolerance:
        return False
    expected = [_digest(secret, raw_body, timestamp) for secret in secrets_in_window]
    return any(hmac.compare_digest(sig, exp) for sig in signatures for exp in expected)


def delivery_headers(
    secret: str, *, event_id: str, raw_body: bytes, timestamp: int, test: bool = False
) -> dict[str, str]:
    """Headers for one outbound delivery attempt, signed at ``timestamp``."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        EVENT_ID_HEADER: event_id,
        SIGNATURE_HEADER: sign(secret, raw_body, timestamp),
    }
    if test:
        headers["X-Example-Test"] = "true"
    return headers
