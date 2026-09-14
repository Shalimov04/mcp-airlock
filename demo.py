"""End-to-end demo over real sockets: fake upstream :9001 ← mcp-airlock :9000 ← this script.

    uv run python demo.py            # writes examples/audit.jsonl and examples/spans.jsonl
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).parent
EX = ROOT / "examples"
V = "2026-07-28"
ENVELOPE = {"io.modelcontextprotocol/protocolVersion": V, "io.modelcontextprotocol/clientCapabilities": {}}
PROXY = "http://127.0.0.1:9000/mcp"
HTTP = httpx.Client(timeout=10, trust_env=False)  # ignore *_PROXY env vars for localhost


def rpc(method: str, params: dict | None = None, principal: str | None = "alice", rid: int = 1) -> httpx.Response:
    params = {"_meta": dict(ENVELOPE), **(params or {})}
    h = {"mcp-protocol-version": V, "mcp-method": method, "accept": "application/json, text/event-stream"}
    if method == "tools/call":
        h["mcp-name"] = params["name"]
    if principal:
        h["x-airlock-principal"] = principal
    return HTTP.post(PROXY, headers=h, json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params})


def show(title: str, r: httpx.Response) -> dict:
    body = r.json()
    res = body.get("result") or body.get("error")
    brief = {k: v for k, v in res.items() if k in ("resultType", "isError", "code", "message", "requestState")}
    text = " | ".join(b["text"][:110] for b in res.get("content", []) if b.get("type") == "text")
    meta = {k.split("/")[-1]: v for k, v in (res.get("_meta") or {}).items() if k.startswith("io.mcp-airlock/") and k != "io.mcp-airlock/dry_run_preview"}
    print(f"\n▶ {title}\n  HTTP {r.status_code} {brief}\n  meta {meta}")
    if text:
        print(f"  text {text}")
    return res


def wait(url: str) -> None:
    for _ in range(50):
        try:
            HTTP.post(url)
            return
        except httpx.HTTPError:
            time.sleep(0.1)
    sys.exit(f"{url} did not come up")


def main() -> None:
    EX.mkdir(exist_ok=True)
    for f in ("audit.jsonl", "spans.jsonl"):
        (EX / f).unlink(missing_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")} | {
        "PYTHONPATH": str(ROOT), "AIRLOCK_TRUST_PRINCIPAL_HEADER": "1"}  # demo authenticates with a plain header
    up = subprocess.Popen([sys.executable, "-m", "tests.fake_upstream"], env=env)
    px = subprocess.Popen([sys.executable, "-m", "mcp_airlock", "--policy", "policy.example.yaml", "--env", "prod",
                           "--upstream", "http://127.0.0.1:9001/mcp", "--audit", str(EX / "audit.jsonl"),
                           "--otel-file", str(EX / "spans.jsonl")], env=env, cwd=ROOT)
    try:
        wait("http://127.0.0.1:9001/mcp"); wait(PROXY)
        show("server/discover", rpc("server/discover"))
        res = show("tools/list (rm_rf hidden by allowlist)", rpc("tools/list"))
        print("  tools", [t["name"] for t in res["tools"]])
        show("read tool, L0", rpc("tools/call", {"name": "get_service", "arguments": {"name": "api"}}))
        show("no principal → 401", rpc("tools/call", {"name": "list_services", "arguments": {}}, principal=None))
        show("not allowlisted → denied", rpc("tools/call", {"name": "rm_rf", "arguments": {"path": "/"}}))
        show("injection payload comes back from a read tool", rpc("tools/call", {"name": "get_service", "arguments": {"name": "evil"}}))
        res = show("L2 write with dry_run=false → forced dry-run + input_required",
                   rpc("tools/call", {"name": "delete_service", "arguments": {"name": "prod-db", "dry_run": False}}))
        token = res["requestState"]
        print("  prompt:", res["inputRequests"]["airlock-confirm"]["params"]["message"].replace("\n", "\n          "))
        confirm = {"requestState": token, "inputResponses": {"airlock-confirm": {"action": "accept", "content": {"confirm": True}}}}
        show("human confirms → executed once", rpc("tools/call", {"name": "delete_service", "arguments": {"name": "prod-db"}, **confirm}))
        show("replay same confirmation → denied", rpc("tools/call", {"name": "delete_service", "arguments": {"name": "prod-db"}, **confirm}))
        show("blast radius: 4 objects > max_per_call=3",
             rpc("tools/call", {"name": "set_replicas", "arguments": {"names": ["a", "b", "c", "d"], "replicas": 0}}))
        show("output cap: 100k chars → 5000", rpc("tools/call", {"name": "get_service", "arguments": {"name": "big"}}))
        show("L2 tool without dry_run → prompt without preview, nothing forwarded",
             rpc("tools/call", {"name": "restart_service", "arguments": {"name": "api"}}))
        os.environ.pop("ALL_PROXY", None); os.environ.pop("HTTPS_PROXY", None); os.environ.pop("HTTP_PROXY", None)
        diff_against_live_upstream()
    finally:
        px.terminate(); up.terminate(); px.wait(); up.wait()
    rows = [json.loads(l) for l in (EX / "audit.jsonl").read_text().splitlines()]
    print(f"\n▶ audit: {len(rows)} records in {EX / 'audit.jsonl'} (2 per call). Last two:")
    for r in rows[-2:]:
        print("  ", json.dumps(r, ensure_ascii=False))
    spans = (EX / "spans.jsonl").read_text()
    print(f"▶ spans: {spans.count('\"name\"')} spans in {EX / 'spans.jsonl'}")
    from mcp_airlock import audit_cli, policy_cli
    print("\n▶ airlock-audit query --stats")
    audit_cli.main(["query", "--jsonl", str(EX / "audit.jsonl"), "--stats"])
    print("\n▶ airlock-policy lint policy.example.yaml")
    policy_cli.main(["lint", str(ROOT / "policy.example.yaml")])


def diff_against_live_upstream() -> None:
    """Runs while the fake upstream is up: what the catalog has that the policy doesn't."""
    from mcp_airlock import policy_cli
    print("\n▶ airlock-policy diff policy.example.yaml --upstream http://127.0.0.1:9001/mcp --env prod")
    policy_cli.main(["diff", str(ROOT / "policy.example.yaml"), "--upstream", "http://127.0.0.1:9001/mcp", "--env", "prod"])


if __name__ == "__main__":
    main()
