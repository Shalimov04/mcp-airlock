"""The client docs say what the commands in them do."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_claude_code_add_command_registers_at_user_scope():
    # The text calls it user scope; without --scope user the default is the current project only.
    text = (ROOT / "docs" / "clients.md").read_text().replace("\\\n", " ")
    commands = re.findall(r"^claude mcp add .*$", text, re.M)
    assert commands, "no claude mcp add command in docs/clients.md"
    assert all("--scope user" in c for c in commands), commands
