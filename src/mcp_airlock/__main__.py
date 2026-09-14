"""CLI: python -m mcp_airlock --policy policy.yaml --upstream http://127.0.0.1:9001/mcp"""

from __future__ import annotations

import argparse
import os

import uvicorn
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

from .app import build


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
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()
    setup_otel(a.otel_file)
    airlock = build(a.policy, a.upstream, a.audit, a.env)
    uvicorn.run(airlock.app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
