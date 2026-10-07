"""CLI: python -m mcp_airlock --policy policy.yaml --upstream http://127.0.0.1:9001/mcp"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable

import uvicorn
import yaml
from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, OTELResourceDetector, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor

from . import approvals, pins
from .app import build
from .identity import IdentityConfig
from .pg import psycopg_module, psycopg_pool_module
from .policy_cli import policy_error_message
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
    out = open(span_file, "a") if span_file else None
    try:
        if out:  # JSON Lines: the SDK default indents
            exporter = ConsoleSpanExporter(out=out, formatter=lambda s: s.to_json(indent=None) + "\n")
            provider.add_span_processor(SimpleSpanProcessor(exporter))
        if otlp_requested() and (otlp := _otlp_exporter()) is not None:
            # endpoint, headers, timeout, TLS come from the standard OTEL_* variables
            provider.add_span_processor(BatchSpanProcessor(otlp()))
    except BaseException:
        if out:
            out.close()
        raise
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


def _port(text: str) -> int:
    n = _int_min(0)(text)
    if n > 65535:  # otherwise the bind fails inside uvicorn with an OverflowError traceback
        raise argparse.ArgumentTypeError("must be between 0 and 65535")
    return n


def _fail(e: BaseException, message: str | None = None) -> SystemExit:
    """Bad input is one line on stderr and exit 1; AIRLOCK_DEBUG=1 keeps the traceback to see where it came from."""
    if os.environ.get("AIRLOCK_DEBUG") == "1":  # exactly 1, as documented: "0" or "false" must not mean debug
        raise e
    return SystemExit(f"mcp-airlock: {message or e}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="mcp-airlock")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--upstream", required=True, help="upstream MCP endpoint, e.g. http://127.0.0.1:9001/mcp")
    ap.add_argument("--env", default=None, help="environment name; overrides policy.environment / AIRLOCK_ENV")
    ap.add_argument("--audit", default="audit.jsonl")
    ap.add_argument("--audit-max-bytes", type=_int_min(0), default=None, help="rotate the audit file before a write would pass this size; 0 or unset: never")
    ap.add_argument("--audit-keep", type=_int_min(1), default=5, help="rotated audit files to keep (audit.jsonl.1 ...); default 5")
    ap.add_argument("--otel-file", default=os.environ.get("AIRLOCK_OTEL_FILE"), help="append spans to this file as JSON Lines, one span per line")
    ap.add_argument("--pins", default=os.environ.get("AIRLOCK_PINS"), help="tool pins file written by `airlock-policy pin`; a pinned tool whose definition changed is hidden from tools/list")
    ap.add_argument("--strict", action="store_true", help="exit with status 2 if the configuration has any startup warning")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=_port, default=9000)
    a = ap.parse_args()
    try:
        tool_pins = pins.load(a.pins) if a.pins else None
    except ValueError as e:
        raise _fail(e) from None
    webhook, telegram_chat = approvals.config_from_env()
    warnings = startup_warnings(
        IdentityConfig.from_env(), secret=os.environ.get("AIRLOCK_SECRET"),
        store_dsn=os.environ.get("AIRLOCK_STORE_DSN"), webhook=webhook, telegram_chat=telegram_chat,
        public_url=os.environ.get("AIRLOCK_PUBLIC_URL"), otlp_missing=otlp_requested() and _otlp_exporter() is None)
    for w in warnings:
        print(f"mcp-airlock: warning: {w}", file=sys.stderr)
    if a.strict and warnings:
        raise SystemExit(2)
    if os.environ.get("AIRLOCK_STORE_DSN") or os.environ.get("AIRLOCK_AUDIT_DSN"):
        try:
            psycopg_module()
            if os.environ.get("AIRLOCK_STORE_DSN"):
                psycopg_pool_module()
        except RuntimeError as e:
            raise _fail(e) from None
    try:
        provider = setup_otel(a.otel_file)
    except (ValueError, OSError) as e:  # the span file, or an OTEL_* setting the SDK rejects
        raise _fail(e, f"OTEL: {e}") from None
    try:
        airlock = build(a.policy, a.upstream, a.audit, a.env, pins=tool_pins, pins_path=a.pins,
                        audit_max_bytes=a.audit_max_bytes, audit_keep=a.audit_keep,
                        on_shutdown=provider.shutdown)
    except (ValueError, OSError, yaml.YAMLError) as e:
        # policy_error_message only reshapes YAML and pydantic errors; tests/test_cli_errors.py checks that only
        # policy.py raises them inside build(), so the policy path never labels another error
        raise _fail(e, policy_error_message(a.policy, e)) from None
    uvicorn.run(airlock.app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
