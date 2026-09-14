"""Content-level prompt-injection *marking* for tool results. Marks, never blocks: the caller decides what to do."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any, Iterable

_F = re.IGNORECASE | re.DOTALL
_ACT = r"\b(?:call|run|execute|delete)\b"
_URGE = r"\b(?:immediately|right\s+now|urgent(?:ly)?)\b"
# ponytail: naive regex heuristics; swap for a classifier if false positives/negatives bite
RULES: dict[str, re.Pattern[str]] = {name: re.compile(p, _F) for name, p in {
    "override_phrase": r"\b(?:ignore|disregard)\s+(?:all|any|previous|prior|above)\b(?:\s+\w+){0,2}\s+(?:instructions|policies|rules|guidelines)\b"
                       r"|\bsystem\s+override\b|\bnew\s+instructions:|\byou\s+are\s+now\b",
    "urgent_action": rf"{_URGE}.{{0,80}}?{_ACT}|{_ACT}.{{0,80}}?{_URGE}",
    "secrecy": r"\b(?:do\s+not\s+tell|don['’]?t\s+tell|hide\s+this\s+from)\s+the\s+(?:user|operator)\b",
    "hidden_text": r"[​-‏⁠﻿]",
}.items()}
_B64 = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
MAX_FINDINGS = 20


@lru_cache(maxsize=64)
def _tool_rx(names: tuple[str, ...]) -> re.Pattern[str]:
    alt = "|".join(map(re.escape, names))
    return re.compile(rf"\b(?:call|run|invoke|execute)\s+[`'\"]?(?:{alt})\b|\b(?:{alt})\b.{{0,40}}?\(", _F)


def _hits(text: str, tools: tuple[str, ...]) -> Iterable[tuple[str, str]]:
    for rule, rx in RULES.items():
        if m := rx.search(text):
            yield rule, m.group()
    if tools and (m := _tool_rx(tools).search(text)):
        yield "tool_mention", m.group()
    # a base64 blob has varied chars; a 200 kB run of 'x' is just a long log line
    if m := next((m for m in _B64.finditer(text) if len(set(m.group())) > 16), None):
        yield "hidden_text", m.group()


def scan(result: dict[str, Any], tool_names: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Findings [{"rule", "block", "excerpt"}] over text blocks in result["content"] (block = index) and
    result["structuredContent"] serialized (block = -1). [] when clean. Deduped by (rule, excerpt): the same phrase in a
    text block and in structuredContent is one finding, attributed to the first block. Capped at 20."""
    tools = tuple(sorted(set(tool_names)))
    content = result.get("content")
    blocks = [(i, b["text"]) for i, b in enumerate(content if isinstance(content, list) else [])
              if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)]  # tolerate junk upstreams
    if "structuredContent" in result:
        blocks.append((-1, json.dumps(result["structuredContent"], ensure_ascii=False, default=str)))
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for i, text in blocks:
        for rule, excerpt in _hits(text, tools):
            excerpt = " ".join(excerpt.split())[:120]
            found.setdefault((rule, excerpt), {"rule": rule, "block": i, "excerpt": excerpt})
            if len(found) >= MAX_FINDINGS:
                return list(found.values())
    return list(found.values())
