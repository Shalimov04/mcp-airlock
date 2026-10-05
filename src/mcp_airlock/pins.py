"""Tool pins: a sha256 of what the model reads about a tool, kept in a JSON file ({tool: "sha256v2:<hex>"}) next to the policy."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

# what the model reads; icons and _meta are shown to users or clients, and icon URLs rotate, so they stay out
FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
PIN = re.compile(r"sha256v2:[0-9a-f]{64}")
OLD_PIN = re.compile(r"sha256:[0-9a-f]{64}")  # v1 did not cover the title


def tool_hash(tool: dict[str, Any]) -> str:
    canon = json.dumps({k: tool.get(k) for k in FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256v2:" + hashlib.sha256(canon.encode("utf-8", "surrogatepass")).hexdigest()  # a lone surrogate must not break tools/list


def changed(pins: dict[str, str], tool: dict[str, Any]) -> bool:
    """True when the tool has a pin and its current hash differs. A tool without a pin is not changed."""
    pin = pins.get(str(tool.get("name")))
    return pin is not None and pin != tool_hash(tool)


def load(path: str | Path) -> dict[str, str]:
    """Raises ValueError naming the file when it is unreadable, not a JSON object, or holds anything but 'sha256v2:' + 64 hex.
    A file holding any v1 pin ('sha256:') is refused as a whole: they cannot be compared, and accepting them would leave tools unpinned."""
    try:
        pins = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise ValueError(f"pins file {path}: {e}") from e
    if not isinstance(pins, dict):
        raise ValueError(f"pins file {path}: expected a JSON object of tool name to sha256v2 pin")
    if any(isinstance(p, str) and OLD_PIN.fullmatch(p) for p in pins.values()):
        raise ValueError(f"pins file {path}: written in the old pin format (sha256:, which did not cover the tool title); "
                         "rewrite it with `airlock-policy pin`")
    for name, pin in pins.items():
        if not isinstance(pin, str) or not PIN.fullmatch(pin):
            raise ValueError(f"pins file {path}: the pin for {name!r} is not 'sha256v2:' plus 64 lowercase hex characters")
    return pins
