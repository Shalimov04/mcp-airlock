"""Who is calling: verified JWT (HS256 shared secret or OIDC JWKS) or a gateway-owned header. Never the body."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache

import jwt

PRINCIPAL_HEADER = "x-airlock-principal"
GROUPS_HEADER = "x-airlock-groups"


@dataclass(frozen=True)
class Principal:
    sub: str
    groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdentityConfig:
    jwt_secret: str | None = None
    jwks_url: str | None = None
    issuer: str | None = None
    audience: str | None = None
    groups_claim: str = "groups"
    trust_header: bool = False

    @classmethod
    def from_env(cls) -> IdentityConfig:
        env = os.environ.get
        return cls(
            jwt_secret=env("AIRLOCK_JWT_SECRET") or None,
            jwks_url=env("AIRLOCK_JWKS_URL") or None,
            issuer=env("AIRLOCK_JWT_ISSUER") or None,
            audience=env("AIRLOCK_JWT_AUDIENCE") or None,
            groups_claim=env("AIRLOCK_GROUPS_CLAIM") or "groups",
            trust_header=env("AIRLOCK_TRUST_PRINCIPAL_HEADER", "0") == "1",  # opt-in: the header also carries groups
        )


@lru_cache(maxsize=8)  # ponytail: one client per URL for the process lifetime; PyJWKClient caches keys itself
def _jwks_client(url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(url, cache_keys=True)


def _groups(raw: object) -> tuple[str, ...]:
    if isinstance(raw, str):
        raw = raw.replace(",", " ").split()
    return tuple(g.strip() for g in raw if isinstance(g, str) and g.strip()) if isinstance(raw, (list, tuple)) else ()


def _verify(token: str, cfg: IdentityConfig) -> Principal | None:
    try:
        if cfg.jwks_url:
            key, algs = _jwks_client(cfg.jwks_url).get_signing_key_from_jwt(token).key, ["RS256", "ES256"]
        else:
            key, algs = cfg.jwt_secret, ["HS256"]
        claims = jwt.decode(
            token, key, algorithms=algs, issuer=cfg.issuer, audience=cfg.audience,
            options={"require": ["exp", "sub"], "verify_aud": cfg.audience is not None, "verify_iss": cfg.issuer is not None},
        )
    except jwt.PyJWTError:
        return None
    return Principal(str(claims["sub"]), _groups(claims.get(cfg.groups_claim)))


def resolve(headers: Mapping[str, str], cfg: IdentityConfig) -> Principal | None:
    auth = headers.get("authorization") or ""
    if auth[:7].lower() == "bearer " and (cfg.jwt_secret or cfg.jwks_url):
        return _verify(auth[7:].strip(), cfg)  # a presented token that fails never falls through to the header
    if cfg.trust_header and (sub := headers.get(PRINCIPAL_HEADER)):
        return Principal(sub, _groups(headers.get(GROUPS_HEADER)))
    return None
