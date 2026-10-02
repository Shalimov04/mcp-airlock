"""Configurations that start fine and are weaker than they look."""
from __future__ import annotations

from .identity import IdentityConfig

DEFAULT_PUBLIC_URL = "http://127.0.0.1:9000"


def startup_warnings(identity: IdentityConfig, *, secret: str | None, store_dsn: str | None,
                     webhook: str | None, public_url: str | None) -> list[str]:
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
    if webhook and (public_url or "").rstrip("/") in ("", DEFAULT_PUBLIC_URL):
        out.append("AIRLOCK_APPROVAL_WEBHOOK is set while AIRLOCK_PUBLIC_URL is the default "
                   f"{DEFAULT_PUBLIC_URL}: nobody but this host can open the approve link in the message.")
    return out
