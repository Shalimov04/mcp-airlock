"""CLI: python -m mcp_airlock --policy policy.yaml --upstream http://127.0.0.1:9001/mcp"""

from __future__ import annotations

import argparse
import os
import sys

import uvicorn
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

from . import approvals, pins
from .app import build
from .identity import IdentityConfig
from .startup import startup_warnings


def setup_otel(span_file: str | None) -> None:
    provider = TracerProvider(resource=Resource.create({"service.name": "mcp-airlock"}))
    if span_file:  # ponytail: file/console exporter only; add opentelemetry-exporter-otlp when you have a collector
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter(out=open(span_file, "a"))))
    trace.set_tracer_provider(provider)


def main() -> None:
    ap = argparse.ArgumentParser(prog="mcp-airlock")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--upstream", required=True, help="upstream MCP endpoint, e.g. http://127.0.0.1:9001/mcp")
    ap.add_argument("--env", default=None, help="environment name; overrides policy.environment / AIRLOCK_ENV")
    ap.add_argument("--audit", default="audit.jsonl")
    ap.add_argument("--otel-file", default=os.environ.get("AIRLOCK_OTEL_FILE"), help="write spans (JSON) to this file")
    ap.add_argument("--pins", default=os.environ.get("AIRLOCK_PINS"), help="tool pins file written by `airlock-policy pin`; a pinned tool whose definition changed is hidden from tools/list")
    ap.add_argument("--strict", action="store_true", help="exit with status 2 if the configuration has any startup warning")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()
    try:
        tool_pins = pins.load(a.pins) if a.pins else None
    except ValueError as e:
        raise SystemExit(f"mcp-airlock: {e}")
    warnings = startup_warnings(
        IdentityConfig.from_env(), secret=os.environ.get("AIRLOCK_SECRET"),
        store_dsn=os.environ.get("AIRLOCK_STORE_DSN"), webhook=approvals.config_from_env()[0],
        public_url=os.environ.get("AIRLOCK_PUBLIC_URL"))
    for w in warnings:
        print(f"mcp-airlock: warning: {w}", file=sys.stderr)
    if a.strict and warnings:
        raise SystemExit(2)
    setup_otel(a.otel_file)
    airlock = build(a.policy, a.upstream, a.audit, a.env, pins=tool_pins, pins_path=a.pins)
    uvicorn.run(airlock.app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
