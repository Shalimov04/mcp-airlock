"""Record docs/demo.gif: real requests through the proxy, rendered as a terminal.

    uv run --with pillow python docs/make_demo_gif.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import httpx
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo import ENVELOPE, PROXY, V, wait  # noqa: E402

HTTP = httpx.Client(timeout=10, trust_env=False)
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
COLS, ROWS, PX = 96, 26, 15
BG, FG, DIM, GREEN, RED, YELLOW, BLUE = "#14171c", "#d9dde3", "#6c7480", "#7bd88f", "#ff6b6b", "#ffd166", "#79b8ff"


def call(name: str, args: dict, principal: str | None = "alice", **extra) -> tuple[int, dict]:
    params = {"_meta": dict(ENVELOPE), "name": name, "arguments": args, **extra}
    h = {"mcp-protocol-version": V, "mcp-method": "tools/call", "mcp-name": name,
         "accept": "application/json, text/event-stream"}
    if principal:
        h["x-airlock-principal"] = principal
    r = HTTP.post(PROXY, headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
    body = r.json()
    return r.status_code, body.get("result") or body.get("error")


def meta(res: dict, key: str):
    return (res.get("_meta") or {}).get("io.mcp-airlock/" + key)


def text_of(res: dict) -> str:
    return " ".join(b.get("text", "") for b in res.get("content", []) if b.get("type") == "text")


def record() -> list[tuple[str, list[tuple[str, str]]]]:
    """Each scene: (typed command line, output lines with colors)."""
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")} | {
        "PYTHONPATH": str(ROOT), "AIRLOCK_TRUST_PRINCIPAL_HEADER": "1"}
    up = subprocess.Popen([sys.executable, "-m", "tests.fake_upstream"], env=env, cwd=ROOT,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    px = subprocess.Popen([sys.executable, "-m", "mcp_airlock", "--policy", "policy.example.yaml", "--env", "prod",
                           "--upstream", "http://127.0.0.1:9001/mcp", "--audit", "/dev/null"], env=env, cwd=ROOT,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    scenes = []
    try:
        wait("http://127.0.0.1:9001/mcp"); wait(PROXY)

        st, res = call("rm_rf", {"path": "/"})
        scenes.append(('tools/call rm_rf {"path": "/"}', [
            (f"HTTP {st}  denied  rule={meta(res, 'rule_id')}", RED),
            (text_of(res), DIM)]))

        st, res = call("delete_service", {"name": "prod-db", "dry_run": False})
        prompt = res["inputRequests"]["airlock-confirm"]["params"]["message"].splitlines()
        token = res["requestState"]
        scenes.append(('tools/call delete_service {"name": "prod-db", "dry_run": false}', [
            (f"HTTP {st}  resultType={res['resultType']}  verdict={meta(res, 'verdict')}", YELLOW),
            ("upstream saw dry_run=true, nothing was deleted", DIM),
            *[(l, FG) for l in prompt]]))

        confirm = {"requestState": token,
                   "inputResponses": {"airlock-confirm": {"action": "accept", "content": {"confirm": True}}}}
        st, res = call("delete_service", {"name": "prod-db"}, **confirm)
        scenes.append(('tools/call delete_service {"name": "prod-db"}  + human confirmation', [
            (f"HTTP {st}  executed  rule={meta(res, 'rule_id')}", GREEN),
            (text_of(res), DIM)]))

        st, res = call("delete_service", {"name": "prod-db"}, **confirm)
        scenes.append(('tools/call delete_service {"name": "prod-db"}  + same confirmation again', [
            (f"HTTP {st}  denied  rule={meta(res, 'rule_id')}", RED),
            (text_of(res), DIM)]))

        st, res = call("get_service", {"name": "evil"})
        sus = [(f["rule"], f["excerpt"]) for f in meta(res, "suspicious") or []]
        scenes.append(('tools/call get_service {"name": "evil"}', [
            (f"HTTP {st}  allowed (L0 read), result marked suspicious", YELLOW),
            (text_of(res), DIM),
            *[(f"_meta suspicious: {rule:<16} {excerpt}", RED) for rule, excerpt in sus]]))
    finally:
        px.terminate(); up.terminate(); px.wait(); up.wait()
    return scenes


def wrap(s: str, width: int) -> list[str]:
    return textwrap.wrap(s, width) or [""]


def render(scenes, out: Path) -> None:
    font = ImageFont.truetype(FONT, PX)
    cw, ch = font.getlength("M"), PX + 5
    W, H = int(cw * COLS + 32), int(ch * ROWS + 32)
    frames, durations = [], []
    screen: list[tuple[str, str]] = [("mcp-airlock demo: agent calls go through the proxy, policy env=prod", DIM), ("", FG)]

    def snap(ms: int, cursor: str = "") -> None:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        visible = screen[-ROWS:]
        for i, (line, color) in enumerate(visible):
            d.text((16, 16 + i * ch), line, font=font, fill=color)
        if cursor:
            i = len(visible) - 1
            d.text((16 + cw * len(visible[-1][0]), 16 + i * ch), cursor, font=font, fill=FG)
        frames.append(img.quantize(colors=32, method=Image.Quantize.MEDIANCUT)); durations.append(ms)

    for cmd, lines in scenes:
        screen.append(("$ ", BLUE))
        for c in cmd:  # typing
            screen[-1] = (screen[-1][0] + c, BLUE)
            snap(28 if c != " " else 60, "_")
        snap(350)
        for line, color in lines:
            for piece in wrap(line, COLS - 2):
                screen.append(("  " + piece, color))
            snap(120)
        screen.append(("", FG))
        snap(2200)
    snap(3500)
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    print(f"{out}: {len(frames)} frames, {out.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    render(record(), ROOT / "docs" / "demo.gif")
