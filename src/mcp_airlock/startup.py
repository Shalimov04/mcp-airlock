"""Configurations that start fine and are weaker than they look."""
from __future__ import annotations

from urllib.parse import urlsplit

from .identity import IdentityConfig

DEFAULT_PUBLIC_URL = "http://127.0.0.1:9000"


def _usable_webhook_url(webhook: str) -> bool:
    try:
        u = urlsplit(webhook)
        port = u.port  # raises ValueError on a port that is not a number, which httpx refuses too
        return u.scheme in ("http", "https") and bool(u.hostname) and (port is None or port > 0)
    except ValueError:
        return False


def startup_warnings(identity: IdentityConfig, *, secret: str | None, store_dsn: str | None,
                     webhook: str | None, public_url: str | None, otlp_missing: bool = False,
                     telegram_chat: str | None = None) -> list[str]:
    """One sentence per risky setting, in a fixed order. Plain values in, so callers need no environment."""
    out = []
    has_jwt = bool(identity.jwt_secret or identity.jwks_url)
    if not has_jwt and not identity.trust_header:
        out.append("no identity is configured (AIRLOCK_JWT_SECRET, AIRLOCK_JWKS_URL, AIRLOCK_TRUST_PRINCIPAL_HEADER): "
                   "every call is refused with 401.")
    if identity.jwks_url and not identity.audience:
        out.append("AIRLOCK_JWKS_URL is set without AIRLOCK_JWT_AUDIENCE: any token the provider issues is accepted, "
                   "also one meant for another service.")
    if identity.jwt_secret and len(identity.jwt_secret.encode("utf-8", "surrogateescape")) < 32:  # the variable's own bytes
        out.append("AIRLOCK_JWT_SECRET is shorter than 32 bytes: the HS256 signing key is easier to guess.")
    if identity.trust_header and has_jwt:
        out.append("AIRLOCK_TRUST_PRINCIPAL_HEADER=1 is set together with JWT settings: "
                   "a request without an Authorization header is trusted on the principal header alone.")
    if store_dsn and not secret:
        out.append("AIRLOCK_STORE_DSN is set without AIRLOCK_SECRET: every replica signs confirmation tokens "
                   "with its own random key, so a token from one replica is refused by another.")
    if secret and not store_dsn:
        # The memory store remembers a used confirmation only in this process, while a fixed key makes the token
        # valid in every process that has it: a second replica or a restart runs the confirmed call again.
        out.append("AIRLOCK_SECRET is set without AIRLOCK_STORE_DSN: used confirmations are remembered only in this "
                   "process, so a confirmed call can run again on another replica or after a restart.")
    if webhook and (public_url or "").rstrip("/") in ("", DEFAULT_PUBLIC_URL):
        out.append("AIRLOCK_APPROVAL_WEBHOOK is set while AIRLOCK_PUBLIC_URL is the default "
                   f"{DEFAULT_PUBLIC_URL}: nobody but this host can open the approve link in the message.")
    # A webhook that can never deliver is worse than none: with one set the default mode is oob, where only the
    # link in the message approves, so every L2 prompt would wait for a message nobody receives.
    if webhook and not _usable_webhook_url(webhook):
        out.append("AIRLOCK_APPROVAL_WEBHOOK is not an http(s) URL with a host: no approval message can be delivered, "
                   "and in oob mode nothing can be approved.")
    elif webhook and "api.telegram.org" in webhook and not telegram_chat:
        out.append("AIRLOCK_APPROVAL_WEBHOOK is a Telegram URL but AIRLOCK_TELEGRAM_CHAT is not set: Telegram refuses a "
                   "message without a chat id, and in oob mode nothing can be approved.")
    elif telegram_chat and not webhook:
        out.append("AIRLOCK_TELEGRAM_CHAT is set without AIRLOCK_APPROVAL_WEBHOOK: it is ignored, no approval message is sent.")
    if otlp_missing:  # names the variables, never their values: an endpoint can carry credentials
        out.append("an OTLP endpoint is set (OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) but the "
                   "otlp extra is not installed, so spans are not exported: install it with pip install 'mcp-airlock[otlp]'.")
    return out
