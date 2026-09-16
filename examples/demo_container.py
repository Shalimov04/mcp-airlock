"""Runs a sample upstream and the proxy in front of it, in one container, on one port.

This exists for directory crawlers that start an image with no configuration and expect it to
answer `tools/list`. mcp-airlock has no catalog of its own: it governs the catalog of whatever
server you point it at, so without an upstream there is nothing to introspect. Here the upstream
is `tests/fake_upstream.py` and the policy is `policy.example.yaml`, so what comes back is the
example policy applied to the example server: `rm_rf` hidden by the allowlist, the rest tiered.

Not a deployment target. See the README for running the real thing.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx
import uvicorn

DEMO = "/app/demo"
UPSTREAM = "http://127.0.0.1:9001/mcp"


def as_demo_principal(inner):
    """Every request arrives as the same principal, because the demo has no identity provider.

    The real proxy takes the principal from a JWT or from a gateway that already authenticated the
    caller, and refuses the call outright when there is none. That refusal is the correct answer to
    an anonymous crawler, and also an unhelpful one, so the demo answers it for them.
    """

    async def app(scope, receive, send):
        if scope["type"] == "http":
            scope = {**scope, "headers": [*scope["headers"], (b"x-airlock-principal", b"demo")]}
        await inner(scope, receive, send)

    return app


def main() -> None:
    os.environ["AIRLOCK_TRUST_PRINCIPAL_HEADER"] = "1"  # the header above is the demo's only identity
    up = subprocess.Popen([sys.executable, f"{DEMO}/fake_upstream.py"])
    with httpx.Client(timeout=2, trust_env=False) as http:
        for _ in range(100):
            if up.poll() is not None:
                sys.exit("demo upstream died on startup")
            try:
                http.post(UPSTREAM)
                break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            sys.exit("demo upstream never came up")

    from mcp_airlock.app import build  # after the env var above, which build() reads

    airlock = build(f"{DEMO}/policy.example.yaml", UPSTREAM, "/data/audit.jsonl", "prod")
    uvicorn.run(as_demo_principal(airlock.app), host="0.0.0.0", port=9000, log_level="warning")


if __name__ == "__main__":
    main()
