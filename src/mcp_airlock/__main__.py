"""CLI: python -m mcp_airlock --policy policy.yaml --upstream http://127.0.0.1:9001/mcp"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable

import uvicorn
from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, OTELResourceDetector, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor

from . import approvals, pins
from .app import build
from .identity import IdentityConfig
from .pg import psycopg_module
from .startup import startup_warnings


OTLP_ENDPOINT_VARS = ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")


def otlp_requested() -> bool:
    return any(os.environ.get(v) for v in OTLP_ENDPOINT_VARS)


def _otlp_exporter():  # the class, or None without the otlp extra
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    except ImportError:
        return None
    return OTLPSpanExporter


def setup_otel(span_file: str | None) -> TracerProvider:
    # OTEL_SERVICE_NAME or service.name in OTEL_RESOURCE_ATTRIBUTES wins; "mcp-airlock" is only the default
    named = OTELResourceDetector().detect().attributes.get(SERVICE_NAME)
    provider = TracerProvider(resource=Resource.create({} if named else {SERVICE_NAME: "mcp-airlock"}))
    if span_file:  # file/console exporter, independent of OTLP
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter(out=open(span_file, "a"))))
    if otlp_requested() and (exporter := _otlp_exporter()) is not None:
        # endpoint, headers, timeout, TLS come from the standard OTEL_* variables
        provider.add_span_processor(BatchSpanProcessor(exporter()))
    trace.set_tracer_provider(provider)
    return provider


def _int_min(low: int) -> Callable[[str], int]:
    def parse(text: str) -> int:
        try:
            n = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None
        if n < low:
            raise argparse.ArgumentTypeError(f"must be at least {low}")
        return n
    return parse


def main() -> None:
    ap = argparse.ArgumentParser(prog="mcp-airlock")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--upstream", required=True, help="upstream MCP endpoint, e.g. http://127.0.0.1:9001/mcp")
    ap.add_argument("--env", default=None, help="environment name; overrides policy.environment / AIRLOCK_ENV")
    ap.add_argument("--audit", default="audit.jsonl")
    ap.add_argument("--audit-max-bytes", type=_int_min(0), default=None, help="rotate the audit file before a write would pass this size; 0 or unset: never")
    ap.add_argument("--audit-keep", type=_int_min(1), default=5, help="rotated audit files to keep (audit.jsonl.1 ...); default 5")
    ap.add_argument("--otel-file", default=os.environ.get("AIRLOCK_OTEL_FILE"), help="write spans (JSON) to this file")
    ap.add_argument("--pins", default=os.environ.get("AIRLOCK_PINS"), help="tool pins file written by `airlock-policy pin`; a pinned tool whose definition changed is hidden from tools/list")
    ap.add_argument("--strict", action="store_true", help="exit with status 2 if the configuration has any startup warning")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()
    try:
        tool_pins = pins.load(a.pins) if a.pins else None
    except ValueError as e:
        raise SystemExit(f"mcp-airlock: {e}") from None
    warnings = startup_warnings(
        IdentityConfig.from_env(), secret=os.environ.get("AIRLOCK_SECRET"),
        store_dsn=os.environ.get("AIRLOCK_STORE_DSN"), webhook=approvals.config_from_env()[0],
        public_url=os.environ.get("AIRLOCK_PUBLIC_URL"), otlp_missing=otlp_requested() and _otlp_exporter() is None)
    for w in warnings:
        print(f"mcp-airlock: warning: {w}", file=sys.stderr)
    if a.strict and warnings:
        raise SystemExit(2)
    if os.environ.get("AIRLOCK_STORE_DSN") or os.environ.get("AIRLOCK_AUDIT_DSN"):
        try:
            psycopg_module()
        except RuntimeError as e:
            raise SystemExit(f"mcp-airlock: {e}") from None
    provider = setup_otel(a.otel_file)
    airlock = build(a.policy, a.upstream, a.audit, a.env, pins=tool_pins, pins_path=a.pins,
                    audit_max_bytes=a.audit_max_bytes, audit_keep=a.audit_keep,
                    on_shutdown=provider.shutdown)
    uvicorn.run(airlock.app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
