"""OTLP exporter is attached when OTEL_EXPORTER_OTLP_ENDPOINT is set."""

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
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

from mcp_airlock.__main__ import setup_otel

from .conftest import ENVELOPE, ROOT, V


def _processors(provider):
    multi = getattr(provider, "_active_span_processor", None)
    children = getattr(multi, "_span_processors", None)
    if children is None:
        return []
    return list(children)


def test_no_otlp_without_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    provider = setup_otel(None)
    assert not any(isinstance(p, BatchSpanProcessor) for p in _processors(provider))


def test_otlp_processor_attached_when_endpoint_set(monkeypatch):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    provider = setup_otel(None)
    assert any(isinstance(p, BatchSpanProcessor) for p in _processors(provider))


def test_file_and_otlp_can_both_be_on(monkeypatch, tmp_path):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    provider = setup_otel(str(tmp_path / "spans.jsonl"))
    kinds = {type(p) for p in _processors(provider)}
    assert SimpleSpanProcessor in kinds
    assert BatchSpanProcessor in kinds


# ---------------------------------------------------------------- shutdown flush
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


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX signals")
def test_sigterm_right_after_a_call_still_exports_the_span(collector, tmp_path):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
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
                    raise AssertionError("proxy did not start")
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
