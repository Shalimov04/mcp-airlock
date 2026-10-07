"""The release workflow's README image-tag check (scripts/check_image_tag.sh)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_image_tag.sh"

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="no sh")


def check(tag: str, *files: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(SCRIPT), tag, *map(str, files)], capture_output=True, text=True)


def readmes() -> list[Path]:
    return [ROOT / "README.md", ROOT / "README.ru.md"]


def test_matching_minor_passes(tmp_path):
    tags = {p.read_text().split("mcp-airlock:")[1].split(" ")[0] for p in readmes()}
    assert len(tags) == 1
    assert check(f"v{tags.pop()}.7", *readmes()).returncode == 0


def test_next_minor_fails():
    run = check("v99.0.0", *readmes())
    assert run.returncode == 1 and "99.0" in run.stderr


def test_one_stale_file_fails(tmp_path):
    good = tmp_path / "a.md"
    good.write_text("ghcr.io/shalimov04/mcp-airlock:0.4 --policy p\n")
    stale = tmp_path / "b.md"
    stale.write_text("ghcr.io/shalimov04/mcp-airlock:0.3 --policy p\n")
    assert check("v0.4.0", good).returncode == 0
    assert check("v0.4.0", good, stale).returncode == 1


def test_missing_tag_fails(tmp_path):
    f = tmp_path / "c.md"
    f.write_text("no image here\n")
    assert check("v0.4.0", f).returncode == 1
