from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_airlock.identity import IdentityConfig, Principal, resolve

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB_PEM = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
JWKS = {"keys": [{**jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True), "kid": "k1", "alg": "RS256", "use": "sig"}]}
OIDC = IdentityConfig(jwks_url="https://idp.example/jwks", issuer="https://idp.example", audience="airlock")
HS = IdentityConfig(jwt_secret="s3cret")


def claims(**over):
    return {"sub": "alice", "iss": OIDC.issuer, "aud": OIDC.audience, "exp": int(time.time()) + 60, "groups": ["ops", "dev"], **over}


def rs(**over):
    return jwt.encode(claims(**over), KEY, algorithm="RS256", headers={"kid": "k1"})


def bearer(tok, **extra):
    return {"authorization": f"Bearer {tok}", **extra}


@pytest.fixture(autouse=True)
def offline_jwks(monkeypatch):
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda self: JWKS)


def test_rs256_ok():
    assert resolve(bearer(rs()), OIDC) == Principal("alice", ("ops", "dev"))


@pytest.mark.parametrize("bad", [dict(aud="other"), dict(iss="https://evil"), dict(exp=int(time.time()) - 10)])
def test_rs256_bad_claims(bad):
    assert resolve(bearer(rs(**bad)), OIDC) is None


def test_rs256_missing_sub_or_exp():
    c = claims(); del c["exp"]
    assert resolve(bearer(jwt.encode(c, KEY, algorithm="RS256", headers={"kid": "k1"})), OIDC) is None
    c = claims(); del c["sub"]
    assert resolve(bearer(jwt.encode(c, KEY, algorithm="RS256", headers={"kid": "k1"})), OIDC) is None


def test_alg_confusion_public_key_as_hs256_secret():
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")  # PyJWT refuses to forge this itself; an attacker would not
    body = b64(json.dumps({"alg": "HS256", "kid": "k1"}).encode()) + b"." + b64(json.dumps(claims()).encode())
    tok = (body + b"." + b64(hmac.new(PUB_PEM.encode(), body, hashlib.sha256).digest())).decode()
    assert resolve(bearer(tok), OIDC) is None


def test_alg_none_rejected():
    tok = jwt.encode(claims(), None, algorithm="none")  # type: ignore[arg-type]
    assert resolve(bearer(tok), OIDC) is None
    assert resolve(bearer(tok), HS) is None


def test_bearer_failure_never_falls_back_to_header():
    cfg = IdentityConfig(jwks_url=OIDC.jwks_url, trust_header=True)
    assert resolve(bearer(rs(exp=1), **{"x-airlock-principal": "mallory"}), cfg) is None
    cfg = IdentityConfig(jwt_secret="s3cret", trust_header=True)
    assert resolve(bearer("garbage", **{"x-airlock-principal": "mallory"}), cfg) is None


def test_hs256_ok_and_wrong_secret():
    tok = jwt.encode({"sub": "bob", "exp": time.time() + 60, "groups": "a b"}, "s3cret", algorithm="HS256")
    assert resolve(bearer(tok), HS) == Principal("bob", ("a", "b"))
    assert resolve(bearer(tok), IdentityConfig(jwt_secret="other")) is None
    rs_tok = rs()
    assert resolve(bearer(rs_tok), HS) is None  # RS256 token on an HS256-only path


def test_bearer_ignored_when_no_verifier_configured():
    hdrs = bearer("whatever", **{"x-airlock-principal": "carol"})
    assert resolve(hdrs, IdentityConfig(trust_header=True)) == Principal("carol")
    assert resolve(hdrs, IdentityConfig()) is None


def test_header_path():
    hdrs = {"x-airlock-principal": "carol", "x-airlock-groups": "ops, dev,"}
    assert resolve(hdrs, IdentityConfig(trust_header=True)) == Principal("carol", ("ops", "dev"))
    assert resolve(hdrs, IdentityConfig()) is None
    assert resolve({}, IdentityConfig(trust_header=True)) is None


def test_case_insensitive_headers():
    from starlette.datastructures import Headers

    h = Headers({"Authorization": f"Bearer {rs()}"})
    assert resolve(h, OIDC) == Principal("alice", ("ops", "dev"))


def test_groups_claim_name_and_missing():
    cfg = IdentityConfig(jwks_url=OIDC.jwks_url, issuer=OIDC.issuer, audience=OIDC.audience, groups_claim="roles")
    assert resolve(bearer(rs(roles=["admin"])), cfg) == Principal("alice", ("admin",))
    assert resolve(bearer(rs()), cfg) == Principal("alice", ())


def test_from_env(monkeypatch):
    for k in ("AIRLOCK_JWT_SECRET", "AIRLOCK_JWKS_URL", "AIRLOCK_JWT_ISSUER", "AIRLOCK_JWT_AUDIENCE", "AIRLOCK_GROUPS_CLAIM", "AIRLOCK_TRUST_PRINCIPAL_HEADER"):
        monkeypatch.delenv(k, raising=False)
    assert IdentityConfig.from_env() == IdentityConfig(trust_header=False)  # header trust is opt-in
    monkeypatch.setenv("AIRLOCK_JWKS_URL", "https://x/jwks")
    monkeypatch.setenv("AIRLOCK_JWT_ISSUER", "https://x")
    monkeypatch.setenv("AIRLOCK_JWT_AUDIENCE", "a")
    monkeypatch.setenv("AIRLOCK_GROUPS_CLAIM", "roles")
    monkeypatch.setenv("AIRLOCK_TRUST_PRINCIPAL_HEADER", "0")
    assert IdentityConfig.from_env() == IdentityConfig(jwks_url="https://x/jwks", issuer="https://x", audience="a", groups_claim="roles")
