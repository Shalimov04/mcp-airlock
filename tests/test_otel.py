"""OTLP export: the exporter is wired from the standard OTEL_* variables and flushed on shutdown.
Only the public SDK API is used here, never the processors' private lists."""

from __future__ import annotations

import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

from mcp_airlock import __main__ as cli

from .conftest import ENVELOPE, ROOT, V

EXPORTER = "opentelemetry.exporter.otlp.proto.http.trace_exporter"


@pytest.fixture
def collector():
    """A stub OTLP/HTTP collector: records (path, headers, body) of every POST."""
    got: list = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0)))
            got.append((self.path, dict(self.headers), body))
            self.send_response(200)
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", got
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def made(monkeypatch, request):
    """setup_otel() with a clean OTEL_* environment; every provider is shut down at teardown."""
    for k in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS",
              "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"):
        monkeypatch.delenv(k, raising=False)
    providers = []

    def make(span_file=None):
        provider = cli.setup_otel(span_file)
        providers.append(provider)
        return provider

    yield make
    for p in providers:
        p.shutdown()


def emit(provider, name="execute_tool x"):
    provider.get_tracer("t").start_span(name).end()
    provider.force_flush()


def test_no_otlp_without_an_endpoint(monkeypatch, made):
    monkeypatch.setattr(cli, "BatchSpanProcessor", lambda *a, **kw: pytest.fail("no endpoint, no OTLP"))
    made(None)


def test_empty_endpoint_is_off(monkeypatch, made):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    monkeypatch.setattr(cli, "BatchSpanProcessor", lambda *a, **kw: pytest.fail("empty endpoint, no OTLP"))
    made(None)


def test_spans_reach_the_endpoint_with_the_standard_headers(monkeypatch, made, collector):
    pytest.importorskip(EXPORTER)
    url, got = collector
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", url)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer t0k")
    emit(made())
    path, headers, body = got[0]
    assert path == "/v1/traces"
    assert headers.get("authorization") == "Bearer t0k"
    assert b"execute_tool x" in body


def test_traces_endpoint_alone_turns_otlp_on(monkeypatch, made, collector):
    pytest.importorskip(EXPORTER)
    url, got = collector
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", url + "/custom/traces")
    emit(made())
    assert [p for p, _, _ in got] == ["/custom/traces"]  # used as-is, no /v1/traces appended


def test_a_missing_extra_does_not_stop_setup(monkeypatch, made):
    monkeypatch.setitem(sys.modules, EXPORTER, None)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    emit(made())  # no SystemExit, and spans still work


def test_file_and_otlp_together(monkeypatch, made, collector, tmp_path):
    pytest.importorskip(EXPORTER)
    url, got = collector
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", url)
    emit(made(str(tmp_path / "spans.jsonl")))
    assert "execute_tool x" in (tmp_path / "spans.jsonl").read_text()
    assert any(b"execute_tool x" in b for _, _, b in got)


# ---------------------------------------------------------------- shutdown flush
@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX signals")
def test_sigterm_right_after_a_call_still_exports_the_span(collector, tmp_path):
    pytest.importorskip(EXPORTER)
    url, got = collector
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy") and not k.startswith("OTEL_")}
    # a huge batch delay: only the flush on shutdown can deliver the span
    env.update(OTEL_EXPORTER_OTLP_ENDPOINT=url, OTEL_BSP_SCHEDULE_DELAY="600000")
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_airlock", "--policy", str(ROOT / "policy.example.yaml"), "--env", "prod",
         "--upstream", "http://127.0.0.1:9/mcp", "--audit", str(tmp_path / "audit.jsonl"), "--port", str(port)],
        env=env, stderr=subprocess.PIPE)
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 15
        while True:
            try:
                if urllib.request.urlopen(base + "/healthz", timeout=1).status == 200:
                    break
            except OSError:
                if time.time() > deadline or proc.poll() is not None:
                    raise AssertionError("proxy did not start") from None
                time.sleep(0.1)
        params = {"_meta": dict(ENVELOPE), "name": "list_services", "arguments": {}}
        req = urllib.request.Request(base + "/mcp", method="POST", data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}).encode(),
            headers={"mcp-protocol-version": V, "mcp-method": "tools/call", "mcp-name": "list_services",
                     "accept": "application/json, text/event-stream", "content-type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            assert e.code == 401  # no principal: a span without touching the upstream
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)  # uvicorn re-raises SIGTERM, so the exit code is -15, not 0
        assert any(p == "/v1/traces" and b"execute_tool list_services" in b for p, _, b in got), got
    finally:
        proc.kill()
        proc.wait()
        proc.stderr.close()
