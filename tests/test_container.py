"""The container HEALTHCHECK: what the Dockerfiles say, and what the probe does when run for real."""

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ["Dockerfile", "Dockerfile.demo"]
PROXY_VARS = ("http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY")


def healthcheck(name: str) -> tuple[list[str], list[str]]:
    text = (ROOT / name).read_text().replace("\\\n", " ")
    m = re.search(r"^HEALTHCHECK\s+(.*?)\s+CMD\s+(\[.*\])\s*$", text, re.M)
    assert m, f"no HEALTHCHECK in {name}"
    return m.group(1).split(), json.loads(m.group(2))


@contextlib.contextmanager
def serve(status: int):
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send_response(status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        server.server_close()


def clean_env() -> dict[str, str]:
    # The developer's own proxy settings must not change the result.
    return {k: v for k, v in os.environ.items() if k not in PROXY_VARS}


def probe(port: int, env=None, cwd=None) -> int:
    _, cmd = healthcheck("Dockerfile")
    cmd = [sys.executable, *cmd[1:]]
    cmd[-1] = cmd[-1].replace(":9000/", f":{port}/")
    assert f":{port}/" in cmd[-1]
    run = subprocess.run(cmd, timeout=30, capture_output=True, env=env or clean_env(), cwd=cwd)
    return run.returncode


@pytest.mark.parametrize("name", FILES)
def test_build_stage_compiles_bytecode(name):
    # The venv is root-owned and the process runs as 65532 on a read-only root, so the .pyc files
    # can only come from the build; without them every start pays the import cost.
    text = (ROOT / name).read_text()
    assert "ENV UV_COMPILE_BYTECODE=1" in text
    assert text.index("ENV UV_COMPILE_BYTECODE=1") < text.index("RUN uv sync")
    # The slim base image ships the stdlib without .pyc as well, and uv only compiles the venv.
    # As root, so it may write under /usr/local; after the last FROM, so it lands in the image.
    stdlib = "RUN python -m compileall -q /usr/local/lib/python3.12"
    assert stdlib in text
    assert text.rindex("FROM ") < text.index(stdlib) < text.index("USER 65532")


def test_readme_docker_run_example_reaches_a_host_upstream_on_linux():
    # Docker Engine on Linux has no host.docker.internal without --add-host; Desktop adds it itself.
    lines = {}
    for name in ("README.md", "README.ru.md"):
        text = (ROOT / name).read_text().replace("\\\n", " ")
        m = re.search(r"^docker run --rm .*ghcr\.io/shalimov04/mcp-airlock:\S+ .*$", text, re.M)
        assert m, f"no docker run example in {name}"
        lines[name] = re.sub(r"\s+", " ", m.group(0))
        assert "--add-host=host.docker.internal:host-gateway" in lines[name], name
    assert lines["README.md"] == lines["README.ru.md"]


@pytest.mark.parametrize("name", FILES)
def test_both_images_probe_healthz_on_the_exposed_port(name):
    text = (ROOT / name).read_text()
    expose = re.search(r"^EXPOSE (\d+)", text, re.M).group(1)
    assert expose == "9000"
    _, cmd = healthcheck(name)
    assert cmd[:3] == ["python", "-I", "-c"]
    assert f"http://127.0.0.1:{expose}/healthz" in cmd[3]
    assert healthcheck(name) == healthcheck("Dockerfile")


@pytest.mark.parametrize("name", FILES)
def test_pinned_uv_is_inside_the_uv_build_range(name):
    # outside the range uv fetches an unlocked uv_build from PyPI on every image build
    def ver(v):
        return tuple(int(p) for p in v.split("."))

    m = re.search(r"^COPY --from=ghcr\.io/astral-sh/uv:([\d.]+)@sha256:\w+ /uv /bin/$",
                  (ROOT / name).read_text(), re.M)
    assert m, f"no pinned uv COPY in {name}"
    requires = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]["requires"]
    spec = next(r for r in requires if r.startswith("uv_build"))
    lo = re.search(r">=([\d.]+)", spec).group(1)
    hi = re.search(r"<([\d.]+)", spec).group(1)
    assert ver(lo) <= ver(m.group(1)) < ver(hi), f"{name}: uv {m.group(1)} vs {spec}"


def test_probe_passes_on_200_and_only_asks_for_healthz():
    with serve(200) as (port, seen):
        assert probe(port) == 0
    assert seen == ["/healthz"]


def test_probe_fails_on_503():
    with serve(503) as (port, _):
        assert probe(port) == 1


def test_probe_fails_when_nothing_listens():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert probe(port) != 0


def test_probe_ignores_http_proxy():
    # A deployment that sets HTTP_PROXY for the upstream must not send the probe there.
    with serve(200) as (port, seen), serve(200) as (proxy_port, proxy_seen):
        env = clean_env()
        env["http_proxy"] = env["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
        assert probe(port, env=env) == 0
    assert proxy_seen == []
    assert seen == ["/healthz"]


def test_probe_does_not_import_from_the_working_directory(tmp_path):
    # /data is a writable mounted volume: a planted urllib/ must not run on every probe.
    (tmp_path / "urllib").mkdir()
    (tmp_path / "urllib" / "__init__.py").write_text("raise SystemExit(3)\n")
    env = clean_env()
    env["PYTHONPATH"] = str(tmp_path)
    with serve(200) as (port, _):
        assert probe(port, env=env, cwd=tmp_path) == 0
