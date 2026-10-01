"""Tool pins: a sha256 of what the model reads about a tool, kept in a JSON file ({tool: "sha256:<hex>"}) next to the policy."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

FIELDS = ("name", "description", "inputSchema", "outputSchema", "annotations")
PIN = re.compile(r"sha256:[0-9a-f]{64}")


def tool_hash(tool: dict[str, Any]) -> str:
    canon = json.dumps({k: tool.get(k) for k in FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8", "surrogatepass")).hexdigest()  # a lone surrogate must not break tools/list


def changed(pins: dict[str, str], tool: dict[str, Any]) -> bool:
    """True when the tool has a pin and its current hash differs. A tool without a pin is not changed."""
    pin = pins.get(str(tool.get("name")))
    return pin is not None and pin != tool_hash(tool)


def load(path: str | Path) -> dict[str, str]:
    """Raises ValueError naming the file when it is unreadable, not a JSON object, or holds anything but 'sha256:' + 64 hex."""
    try:
        pins = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise ValueError(f"pins file {path}: {e}") from e
    if not isinstance(pins, dict):
        raise ValueError(f"pins file {path}: expected a JSON object of tool name to sha256 pin")
    for name, pin in pins.items():
        if not isinstance(pin, str) or not PIN.fullmatch(pin):
            raise ValueError(f"pins file {path}: the pin for {name!r} is not 'sha256:' plus 64 lowercase hex characters")
    return pins
