"""Startup warnings: the checks as a pure function, and --strict in main()."""

from __future__ import annotations

import re
import sys
from types import SimpleNamespace

import pytest

from mcp_airlock import __main__ as cli
from mcp_airlock.identity import IdentityConfig
from mcp_airlock.startup import startup_warnings

KEY32 = "k" * 32
GOOD_ID = IdentityConfig(jwt_secret=KEY32)
GOOD = dict(secret="s", store_dsn=None, webhook=None, public_url=None)


def warn(identity=GOOD_ID, **over):
    return startup_warnings(identity, **{**GOOD, **over})


def only(ws, key):
    assert len(ws) == 1 and key in ws[0], ws


# ---------------------------------------------------------------- the checks

def test_a_correct_configuration_has_no_warnings():
    assert warn() == []
    full = IdentityConfig(jwks_url="https://idp/jwks", audience="airlock", issuer="https://idp")
    assert warn(full, store_dsn="postgresql://x", webhook="https://hooks/x", public_url="https://airlock.example.com") == []


def test_no_identity_warns():
    only(warn(IdentityConfig()), "no identity")


@pytest.mark.parametrize("identity", [
    IdentityConfig(jwt_secret=KEY32),
    IdentityConfig(jwks_url="https://idp/jwks", audience="a"),
    IdentityConfig(trust_header=True),
])
def test_any_one_identity_source_is_enough(identity):
    assert warn(identity) == []


def test_jwks_without_audience_warns():
    only(warn(IdentityConfig(jwks_url="https://idp/jwks")), "AIRLOCK_JWT_AUDIENCE")
    assert warn(IdentityConfig(jwks_url="https://idp/jwks", audience="a")) == []


def test_audience_without_jwks_is_not_a_warning():
    assert warn(IdentityConfig(jwt_secret=KEY32, audience="a")) == []


def test_short_jwt_secret_warns_at_31_bytes_not_32():
    only(warn(IdentityConfig(jwt_secret="k" * 31)), "AIRLOCK_JWT_SECRET")
    assert warn(IdentityConfig(jwt_secret="k" * 32)) == []


def test_jwt_secret_length_counts_bytes_not_characters():
    assert warn(IdentityConfig(jwt_secret="é" * 16)) == []  # 16 characters, 32 bytes
    only(warn(IdentityConfig(jwt_secret="é" * 15)), "AIRLOCK_JWT_SECRET")  # 15 characters, 30 bytes


def test_jwt_secret_with_a_byte_that_is_not_utf_8_is_counted_not_refused():
    # os.environ keeps such a byte as a lone surrogate; the check counts it as the one byte it was
    assert warn(IdentityConfig(jwt_secret="k" * 31 + "\udcff")) == []  # 32 bytes
    only(warn(IdentityConfig(jwt_secret="k" * 30 + "\udcff")), "AIRLOCK_JWT_SECRET")  # 31 bytes


def test_header_trust_with_a_jwt_secret_or_jwks_warns():
    only(warn(IdentityConfig(jwt_secret=KEY32, trust_header=True)), "AIRLOCK_TRUST_PRINCIPAL_HEADER")
    only(warn(IdentityConfig(jwks_url="https://idp/jwks", audience="a", trust_header=True)), "AIRLOCK_TRUST_PRINCIPAL_HEADER")


def test_header_trust_alone_is_fine():
    assert warn(IdentityConfig(trust_header=True)) == []


def test_store_dsn_without_secret_warns():
    only(warn(store_dsn="postgresql://x", secret=None), "AIRLOCK_STORE_DSN")
    only(warn(store_dsn="postgresql://x", secret=""), "AIRLOCK_STORE_DSN")
    assert warn(store_dsn="postgresql://x", secret="s") == []


def test_no_store_dsn_is_fine_without_a_secret():
    assert warn(store_dsn=None, secret=None) == []
    assert warn(store_dsn="", secret=None) == []


@pytest.mark.parametrize("public_url", [None, "", "http://127.0.0.1:9000", "http://127.0.0.1:9000/"])
def test_webhook_with_the_default_public_url_warns(public_url):
    only(warn(webhook="https://hooks/x", public_url=public_url), "AIRLOCK_PUBLIC_URL")


@pytest.mark.parametrize("public_url", ["https://airlock.example.com", "http://127.0.0.1:9001", "http://127.0.0.1:9000/x"])
def test_webhook_with_a_real_public_url_is_fine(public_url):
    assert warn(webhook="https://hooks/x", public_url=public_url) == []


@pytest.mark.parametrize("webhook", [None, ""])
def test_default_public_url_without_a_webhook_is_fine(webhook):
    assert warn(webhook=webhook, public_url=None) == []
    assert warn(webhook=webhook, public_url="http://127.0.0.1:9000") == []


PUBLIC = "https://airlock.example.com"
TELEGRAM = "https://api.telegram.org/bot123:SECRET/sendMessage"


@pytest.mark.parametrize("webhook", ["ht!tp://bad url/x", "hooks.slack.com/services/x", "ftp://hooks/x", "https:///x",
                                     "https://hooks.slack.com:abc/x", "https://"])
def test_a_webhook_that_is_not_an_http_url_with_a_host_warns(webhook):
    ws = warn(webhook=webhook, public_url=PUBLIC)
    only(ws, "AIRLOCK_APPROVAL_WEBHOOK is not an http(s) URL")
    assert "bad url" not in ws[0] and "hooks" not in ws[0]  # the value is never echoed


@pytest.mark.parametrize("webhook", ["https://hooks.slack.com/services/T/B/X", "http://127.0.0.1:8081/hook", TELEGRAM])
def test_a_usable_webhook_url_is_fine(webhook):
    assert warn(webhook=webhook, public_url=PUBLIC, telegram_chat="-100") == []


def test_a_telegram_webhook_without_a_chat_warns_without_echoing_the_token():
    ws = warn(webhook=TELEGRAM, public_url=PUBLIC)
    only(ws, "AIRLOCK_TELEGRAM_CHAT")
    assert "SECRET" not in ws[0] and "123" not in ws[0]
    assert warn(webhook=TELEGRAM, public_url=PUBLIC, telegram_chat="-100") == []
    assert warn(webhook="https://hooks.slack.com/x", public_url=PUBLIC) == []  # Slack needs no chat


def test_a_chat_without_a_webhook_warns():
    only(warn(telegram_chat="-100"), "AIRLOCK_TELEGRAM_CHAT is set without AIRLOCK_APPROVAL_WEBHOOK")
    assert warn(telegram_chat="") == []


def test_the_webhook_warnings_are_plain_sentences():
    ws = warn(webhook="nope", public_url=PUBLIC) + warn(webhook=TELEGRAM, public_url=PUBLIC) + warn(telegram_chat="1")
    assert len(ws) == 3
    for w in ws:
        assert "\n" not in w and w.endswith(".") and not re.search(r"error|fail|traceback", w, re.I), w


WEAK_ID = IdentityConfig(jwks_url="https://idp/jwks", jwt_secret="short", trust_header=True)
WEAK = dict(secret=None, store_dsn="postgresql://x", webhook="https://hooks/x", public_url=None)


def test_several_problems_give_several_warnings_in_a_fixed_order():
    ws = startup_warnings(WEAK_ID, **WEAK)
    keys = ["AIRLOCK_JWT_AUDIENCE", "AIRLOCK_JWT_SECRET", "AIRLOCK_TRUST_PRINCIPAL_HEADER", "AIRLOCK_STORE_DSN",
            "AIRLOCK_APPROVAL_WEBHOOK"]
    assert len(ws) == len(keys) and all(k in w for k, w in zip(keys, ws, strict=True)), ws
    assert startup_warnings(IdentityConfig(), **WEAK)[0].startswith("no identity")  # first when present


def test_a_missing_otlp_extra_is_one_warning_that_names_the_variables_and_the_extra():
    ws = warn(otlp_missing=True)
    only(ws, "mcp-airlock[otlp]")
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" in ws[0]
    assert startup_warnings(WEAK_ID, **WEAK, otlp_missing=True)[-1] == ws[0]  # last in the fixed order


def test_warnings_are_plain_sentences_that_avoid_the_words_the_e2e_run_greps_for():
    ws = startup_warnings(WEAK_ID, **WEAK) + startup_warnings(IdentityConfig(), **GOOD)
    ws += startup_warnings(GOOD_ID, **GOOD, otlp_missing=True)
    assert len(ws) == 7
    for w in ws:
        assert "\n" not in w and w.endswith(".") and not re.search(r"error|fail|traceback", w, re.I), w


# ---------------------------------------------------------------- main()

ENV_VARS = ["AIRLOCK_JWT_SECRET", "AIRLOCK_JWKS_URL", "AIRLOCK_JWT_ISSUER", "AIRLOCK_JWT_AUDIENCE", "AIRLOCK_TRUST_PRINCIPAL_HEADER",
            "AIRLOCK_SECRET", "AIRLOCK_STORE_DSN", "AIRLOCK_APPROVAL_WEBHOOK", "AIRLOCK_TELEGRAM_CHAT", "AIRLOCK_PUBLIC_URL",
            "AIRLOCK_PINS",
            "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]
GOOD_ENV = {"AIRLOCK_JWT_SECRET": KEY32, "AIRLOCK_SECRET": "s"}
STUB_PROVIDER = SimpleNamespace(shutdown=lambda: None)


def run_main(monkeypatch, env, *argv, seen=None, kw_out=None):
    """main() with build, otel and uvicorn stubbed; seen records which of them ran, also when main() exits early."""
    seen = {} if seen is None else seen
    seen.update(built=False, ran=False, otel=False)
    for k in ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr("sys.argv", ["mcp-airlock", "--policy", "p.yaml", "--upstream", "http://x/mcp", *argv])
    monkeypatch.setattr(cli, "build", lambda *a, **kw: seen.update(built=True) or (kw_out is not None and kw_out.update(kw)) or type("A", (), {"app": None})())
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **kw: seen.update(ran=True))
    monkeypatch.setattr(cli, "setup_otel", lambda f: seen.update(otel=True) or STUB_PROVIDER)
    cli.main()
    return seen


def warning_lines(capsys):
    return [ln for ln in capsys.readouterr().err.splitlines() if ln]


def test_strict_on_a_weak_configuration_exits_2_before_anything_starts(monkeypatch, capsys):
    env = {"AIRLOCK_JWT_SECRET": "short", "AIRLOCK_STORE_DSN": "postgresql://x", "AIRLOCK_APPROVAL_WEBHOOK": "https://hooks/x"}
    seen = {}
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, env, "--strict", seen=seen)
    assert e.value.code == 2 and seen == {"built": False, "ran": False, "otel": False}
    lines = warning_lines(capsys)
    assert len(lines) == 3 and all(ln.startswith("mcp-airlock: warning: ") for ln in lines), lines
    for key, ln in zip(["AIRLOCK_JWT_SECRET", "AIRLOCK_STORE_DSN", "AIRLOCK_APPROVAL_WEBHOOK"], lines, strict=True):
        assert key in ln


def test_a_bad_pins_file_is_reported_before_the_warnings(monkeypatch, capsys, tmp_path):
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, {}, "--strict", "--pins", str(tmp_path / "nope.json"))
    assert "nope.json" in str(e.value.code)
    assert warning_lines(capsys) == []


def test_strict_on_a_good_configuration_starts_quietly(monkeypatch, capsys):
    seen = run_main(monkeypatch, GOOD_ENV, "--strict")
    assert seen == {"built": True, "ran": True, "otel": True}
    assert capsys.readouterr().err == ""


def test_without_strict_a_weak_configuration_warns_and_starts(monkeypatch, capsys):
    seen = run_main(monkeypatch, {})
    assert seen["built"] and seen["ran"]
    lines = warning_lines(capsys)
    assert len(lines) == 1 and lines[0].startswith("mcp-airlock: warning: no identity"), lines


def test_a_good_configuration_prints_nothing(monkeypatch, capsys):
    run_main(monkeypatch, GOOD_ENV)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("env, key", [
    ({}, "no identity"),
    ({**GOOD_ENV, "AIRLOCK_JWKS_URL": "https://idp/jwks"}, "AIRLOCK_JWT_AUDIENCE"),
    ({**GOOD_ENV, "AIRLOCK_JWT_SECRET": "k" * 31}, "AIRLOCK_JWT_SECRET"),
    ({**GOOD_ENV, "AIRLOCK_TRUST_PRINCIPAL_HEADER": "1"}, "AIRLOCK_TRUST_PRINCIPAL_HEADER"),
    ({"AIRLOCK_JWT_SECRET": KEY32, "AIRLOCK_STORE_DSN": "postgresql://x"}, "AIRLOCK_STORE_DSN"),
    ({**GOOD_ENV, "AIRLOCK_SECRET": "", "AIRLOCK_STORE_DSN": "postgresql://x"}, "AIRLOCK_STORE_DSN"),
    ({**GOOD_ENV, "AIRLOCK_APPROVAL_WEBHOOK": "https://hooks/x"}, "AIRLOCK_APPROVAL_WEBHOOK"),
    ({**GOOD_ENV, "AIRLOCK_APPROVAL_WEBHOOK": "https://hooks/x", "AIRLOCK_PUBLIC_URL": "http://127.0.0.1:9000/"},
     "AIRLOCK_APPROVAL_WEBHOOK"),
])
def test_each_setting_is_read_from_the_environment(monkeypatch, capsys, env, key):
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, env, "--strict")
    assert e.value.code == 2
    lines = warning_lines(capsys)
    assert len(lines) == 1 and key in lines[0], lines


def test_a_webhook_with_a_public_url_and_a_store_with_a_secret_pass_strict(monkeypatch, capsys):
    env = {**GOOD_ENV, "AIRLOCK_APPROVAL_WEBHOOK": "https://hooks/x", "AIRLOCK_PUBLIC_URL": "https://airlock.example.com",
           "AIRLOCK_STORE_DSN": "postgresql://x"}
    assert run_main(monkeypatch, env, "--strict")["ran"]
    assert capsys.readouterr().err == ""


def test_main_hands_the_provider_shutdown_to_the_app(monkeypatch):
    kw = {}
    run_main(monkeypatch, GOOD_ENV, kw_out=kw)
    assert kw["on_shutdown"] is STUB_PROVIDER.shutdown


NO_OTLP_EXTRA = "opentelemetry.exporter.otlp.proto.http.trace_exporter"


def test_otlp_without_the_extra_warns_and_starts(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, NO_OTLP_EXTRA, None)  # makes the import raise ImportError
    seen = run_main(monkeypatch, {**GOOD_ENV, "OTEL_EXPORTER_OTLP_ENDPOINT": "http://user:pw@collector:4318"})
    assert seen["built"] and seen["ran"]
    lines = warning_lines(capsys)
    assert len(lines) == 1 and "mcp-airlock[otlp]" in lines[0], lines
    assert "collector" not in lines[0] and "pw" not in lines[0]  # the value is never echoed


def test_otlp_without_the_extra_stops_under_strict(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, NO_OTLP_EXTRA, None)
    seen = {}
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, {**GOOD_ENV, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://collector:4318/v1/traces"},
                 "--strict", seen=seen)
    assert e.value.code == 2 and not seen["built"]
    assert "mcp-airlock[otlp]" in warning_lines(capsys)[0]


def test_a_telegram_webhook_without_a_chat_stops_under_strict_and_starts_with_one(monkeypatch, capsys):
    env = {**GOOD_ENV, "AIRLOCK_APPROVAL_WEBHOOK": TELEGRAM, "AIRLOCK_PUBLIC_URL": PUBLIC}
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, env, "--strict")
    assert e.value.code == 2
    lines = warning_lines(capsys)
    assert len(lines) == 1 and "AIRLOCK_TELEGRAM_CHAT" in lines[0] and "SECRET" not in lines[0], lines
    assert run_main(monkeypatch, {**env, "AIRLOCK_TELEGRAM_CHAT": "-100"}, "--strict")["ran"]
    assert capsys.readouterr().err == ""


def test_a_malformed_webhook_url_stops_under_strict(monkeypatch, capsys):
    env = {**GOOD_ENV, "AIRLOCK_APPROVAL_WEBHOOK": "ht!tp://bad url/x", "AIRLOCK_PUBLIC_URL": PUBLIC}
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, env, "--strict")
    assert e.value.code == 2
    lines = warning_lines(capsys)
    assert len(lines) == 1 and "not an http(s) URL" in lines[0], lines
