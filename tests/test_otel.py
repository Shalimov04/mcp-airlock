"""OTLP exporter is attached when OTEL_EXPORTER_OTLP_ENDPOINT is set."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

from mcp_airlock.__main__ import setup_otel


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
