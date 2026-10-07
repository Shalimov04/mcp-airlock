"""Size limits on the request body and the upstream answer, the shutdown hook, and /approve off the event loop."""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from contextlib import asynccontextmanager

import httpx
import pytest

from mcp_airlock import Airlock, Policy
from mcp_airlock.app import CONFIRM_KEY, META, build
from mcp_airlock.audit import AuditLog, MultiAudit, PostgresAuditLog
from mcp_airlock.identity import IdentityConfig, Principal

from .conftest import ENVELOPE, ROOT, audit_rows, call, make_airlock, rpc

LIMIT = 2000
PG = os.environ.get("AIRLOCK_TEST_PG_DSN")


@asynccontextmanager
async def serving(airlock: Airlock):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=airlock.app), base_url="http://localhost:9000") as c:
        yield c


def fake_airlock(audit_path, upstream, env="prod", **kw) -> Airlock:
    """An airlock in front of `upstream`: a `handler(request) -> httpx.Response` or an httpx transport, which sees every
    request the proxy sends upstream."""
    transport = upstream if isinstance(upstream, httpx.AsyncBaseTransport) else httpx.MockTransport(upstream)
    return Airlock(Policy.load(ROOT / "policy.example.yaml", env), "http://upstream/mcp", AuditLog(audit_path),
                   http=httpx.AsyncClient(transport=transport), trust_principal_header=True, **kw)


def sized(size: int, rid, *, sse: bool = False) -> bytes:
    """A JSON-RPC tools/call answer of exactly `size` bytes."""
    def make(pad: str) -> bytes:
        msg = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"resultType": "complete", "content": [{"type": "text", "text": pad}]}})
        return f"event: message\ndata: {msg}\n\n".encode() if sse else msg.encode()
    out = make("x" * (size - len(make(""))))
    assert len(out) == size
    return out


def answer(size: int, *, status: int = 200, sse: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        rid = json.loads(request.content)["id"]
        ctype = "text/event-stream" if sse else "application/json"
        return httpx.Response(status, content=sized(size, rid, sse=sse), headers={"content-type": ctype})
    return handler


def accept(token: str) -> dict:
    return {"requestState": token, "inputResponses": {CONFIRM_KEY: {"action": "accept", "content": {"confirm": True}}}}


def list_request(pad: int = 0) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": dict(ENVELOPE), "pad": "x" * pad}}


MCP_HEADERS = {"mcp-protocol-version": "2026-07-28", "mcp-method": "tools/list", "content-type": "application/json",
               "x-airlock-principal": "alice"}


# ---------------------------------------------------------------- request limit
async def test_request_over_the_limit_by_content_length_is_413(upstream, audit_path, monkeypatch):
    al = make_airlock(upstream, audit_path, max_request_bytes=LIMIT)
    resolved: list[dict] = []
    monkeypatch.setattr("mcp_airlock.app.resolve", lambda headers, cfg: resolved.append(headers))
    body = b'{"secret-looking": "' + b"b" * LIMIT + b'"}'
    async with serving(al) as c:
        r = await c.post("/mcp", content=body, headers={"content-type": "application/json"})  # no principal: 413, not 401
    assert r.status_code == 413
    err = r.json()
    assert err["id"] is None and err["error"]["code"] == -32600 and "too large" in err["error"]["message"], err
    assert resolved == [] and upstream.CALLS == []  # rejected before identity and before the upstream
    rows = audit_rows(audit_path)
    assert [(x["phase"], x["verdict"], x["rule_id"], x["principal"]) for x in rows] == [("intent", "deny", "request.too_large", None),
                                                                                       ("outcome", "deny", "request.too_large", None)]
    assert str(LIMIT) in rows[0]["detail"] and "secret-looking" not in audit_path.read_text() and "bbbb" not in audit_path.read_text()


async def test_request_streamed_without_content_length_stops_at_the_limit(upstream, audit_path):
    al = make_airlock(upstream, audit_path, max_request_bytes=LIMIT)
    pulled = 0

    async def chunks():
        nonlocal pulled
        for _ in range(1000):
            pulled += 100
            yield b"x" * 100

    async with serving(al) as c:
        r = await c.post("/mcp", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413 and "content-length" not in r.request.headers
    assert pulled <= LIMIT + 100  # never reads more than the limit plus one chunk
    rows = audit_rows(audit_path)
    assert [(x["rule_id"], x["detail"]) for x in rows] == [("request.too_large", f"limit {LIMIT} bytes")] * 2
    assert "xxxx" not in audit_path.read_text()  # the chunks read before the overflow are not logged


async def test_request_with_a_declared_length_over_the_limit_is_not_read(upstream, audit_path):
    al = make_airlock(upstream, audit_path, max_request_bytes=LIMIT)
    pulled = 0

    async def chunks():
        nonlocal pulled
        pulled += 1
        yield b"x" * (LIMIT + 1)

    async with serving(al) as c:
        r = await c.post("/mcp", content=chunks(), headers={"content-type": "application/json", "content-length": str(LIMIT + 1)})
    assert r.status_code == 413 and pulled == 0


async def test_request_with_a_wrong_content_length_is_still_limited(upstream, audit_path):
    al = make_airlock(upstream, audit_path, max_request_bytes=LIMIT)
    async with serving(al) as c:
        r = await c.post("/mcp", content=b"x" * (LIMIT * 5), headers={"content-type": "application/json", "content-length": "5"})
        junk = await c.post("/mcp", content=b"x" * (LIMIT * 5), headers={"content-type": "application/json", "content-length": "abc"})
    assert r.status_code == 413 and junk.status_code == 413


async def chunked(*parts: bytes):
    for part in parts:
        yield part


async def test_request_exactly_at_the_limit_passes_and_one_byte_over_fails(upstream, audit_path):
    base = len(json.dumps(list_request(), separators=(",", ":")))
    exact = json.dumps(list_request(LIMIT - base), separators=(",", ":")).encode()
    assert len(exact) == LIMIT
    al = make_airlock(upstream, audit_path, max_request_bytes=LIMIT)
    async with serving(al) as c:
        ok = await c.post("/mcp", content=exact, headers=MCP_HEADERS)
        over = await c.post("/mcp", content=exact + b" ", headers=MCP_HEADERS)
        over_streamed = await c.post("/mcp", content=chunked(exact, b" "), headers=MCP_HEADERS)  # no Content-Length
    assert ok.status_code == 200 and "tools" in ok.json()["result"]
    assert over.status_code == 413 and over_streamed.status_code == 413


# ---------------------------------------------------------------- upstream limit
@pytest.mark.parametrize("status", [200, 500])
async def test_oversize_tool_answer_becomes_a_tool_error_that_says_the_call_ran(audit_path, status):
    al = fake_airlock(audit_path, answer(LIMIT + 1, status=status), max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        res = await call(c, "get_service", {"name": "api"})
    assert res["isError"] is True and res["_meta"][META + "rule_id"] == "upstream.too_large"
    text = res["content"][0]["text"]
    assert str(LIMIT) in text and "the call itself ran" in text and "xxx" not in text, text
    intent, outcome = audit_rows(audit_path)
    assert (outcome["verdict"], outcome["rule_id"], outcome["upstream_status"]) == ("error", "upstream.too_large", status)
    assert intent["rule_id"] == "tier.L0.read" and str(LIMIT) in outcome["detail"] and "xxx" not in audit_path.read_text()


@pytest.mark.parametrize("sse", [False, True])
async def test_answer_exactly_at_the_limit_passes_and_one_byte_over_fails(audit_path, sse):
    al = fake_airlock(audit_path, answer(LIMIT, sse=sse), max_upstream_bytes=LIMIT)
    over = fake_airlock(audit_path, answer(LIMIT + 1, sse=sse), max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        ok = await call(c, "get_service", {"name": "api"})
    async with serving(over) as c:
        res = await call(c, "get_service", {"name": "api"})
    assert not ok.get("isError") and ok["content"][0]["text"].startswith("xxx")
    assert res["isError"] and res["_meta"][META + "rule_id"] == "upstream.too_large"


async def test_oversize_tools_list_is_a_502(audit_path):
    al = fake_airlock(audit_path, answer(LIMIT + 1), max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        r = await rpc(c, "tools/list", rid=7)
    err = r.json()
    assert r.status_code == 502 and err["id"] == 7 and err["error"]["code"] == -32603, err
    assert str(LIMIT) in err["error"]["message"] and "exceeded" in err["error"]["message"] and "xxx" not in r.text
    outcome = audit_rows(audit_path)[-1]
    assert (outcome["phase"], outcome["rule_id"], outcome["upstream_status"]) == ("outcome", "upstream.too_large", 200)


async def test_oversize_catalog_fetch_fails_closed_as_catalog_unavailable(audit_path):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["method"])
        return answer(LIMIT + 1)(request)

    al = fake_airlock(audit_path, handler, max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
    assert res["isError"] and res["_meta"][META + "rule_id"] == "catalog.unavailable" and "exceeded" in res["content"][0]["text"]
    assert seen == ["tools/list"]  # no tools/call went upstream


def l2_upstream(forwarded: list[dict], sizes: dict[str, int], tool: str = "delete_service"):
    """tools/list declares dry_run on `tool`; a dry run answers sizes["preview"] bytes, a real call sizes["real"] and lands in `forwarded`."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "tools/list":
            tools = [{"name": tool, "inputSchema": {"type": "object", "properties": {"dry_run": {"type": "boolean"}}}}]
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"tools": tools, "ttlMs": 0}})
        if body["params"]["arguments"].get("dry_run") is True:
            return answer(sizes["preview"])(request)
        forwarded.append(body)
        return answer(sizes["real"])(request)
    return handler


async def test_oversize_answer_to_a_confirmed_call_keeps_the_key_burned_and_the_charge(audit_path):
    forwarded: list[dict] = []
    al = fake_airlock(audit_path, l2_upstream(forwarded, {"preview": 200, "real": LIMIT + 1}), max_upstream_bytes=LIMIT)

    async def confirmed(name: str) -> tuple[dict, dict]:
        async with serving(al) as c:
            issued = await call(c, "delete_service", {"name": name})
            extra = accept(issued["requestState"])
            return await call(c, "delete_service", {"name": name}, extra=extra), extra

    first, extra = await confirmed("a")
    assert first["isError"] and first["_meta"][META + "rule_id"] == "upstream.too_large" and "the call itself ran" in first["content"][0]["text"]
    async with serving(al) as c:
        replay = await call(c, "delete_service", {"name": "a"}, extra=extra)
    assert replay["_meta"][META + "rule_id"] == "mrtr.replay" and len(forwarded) == 1  # the key is spent, nothing re-ran
    assert (await confirmed("b"))[0]["_meta"][META + "rule_id"] == "upstream.too_large"
    async with serving(al) as c:  # delete_service allows 2 objects per principal per window: both overflows were charged
        third = await call(c, "delete_service", {"name": "c"})
    assert third["_meta"][META + "rule_id"] == "blast_radius.per_principal" and len(forwarded) == 2
    outcomes = [x for x in audit_rows(audit_path) if x["phase"] == "outcome" and x["rule_id"] == "upstream.too_large"]
    assert len(outcomes) == 2 and outcomes[0]["tier"] == "L2" and outcomes[0]["dry_run"] is False


async def test_oversize_dry_run_preview_prompts_nobody_and_charges_nothing(audit_path):
    forwarded: list[dict] = []
    sizes = {"preview": LIMIT + 1, "real": 200}
    al = fake_airlock(audit_path, l2_upstream(forwarded, sizes), max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        for name in ("a", "b"):
            res = await call(c, "delete_service", {"name": name})
            text = res["content"][0]["text"]
            assert res["isError"] and res["_meta"][META + "rule_id"] == "upstream.too_large" and "requestState" not in res, res
            assert "no confirmation was issued" in text and "nothing was executed" in text and "the call itself ran" not in text, text
        assert forwarded == []  # only the dry runs went upstream
        sizes["preview"] = 200  # delete_service allows 2 objects per principal per window: a charged preview would deny this one
        issued = await call(c, "delete_service", {"name": "c"})
        done = await call(c, "delete_service", {"name": "c"}, extra=accept(issued["requestState"]))
    assert issued["resultType"] == "input_required" and done["_meta"][META + "rule_id"] == "tier.L2.confirmed" and not done.get("isError")
    assert [b["params"]["arguments"] for b in forwarded] == [{"name": "c", "dry_run": False}]
    outcomes = [(x["verdict"], x["rule_id"], x["tier"], x["dry_run"]) for x in audit_rows(audit_path) if x["phase"] == "outcome"]
    assert outcomes[:2] == [("error", "upstream.too_large", "L2", True)] * 2


@pytest.mark.parametrize("env, tool, args, rule", [("staging", "set_replicas", {"names": ["api"]}, "tier.L1.dry_run"),
                                                   ("prod", "delete_service", {"name": "api", "dry_run": True}, "tier.L2.dry_run")])
async def test_oversize_dry_run_answer_says_the_dry_run_ran(audit_path, env, tool, args, rule):
    forwarded: list[dict] = []
    al = fake_airlock(audit_path, l2_upstream(forwarded, {"preview": LIMIT + 1, "real": 200}, tool), env, max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        res = await call(c, tool, args)
    text = res["content"][0]["text"]
    assert res["isError"] and res["_meta"][META + "rule_id"] == "upstream.too_large" and forwarded == []
    assert "the dry run itself ran, nothing was executed" in text and "the call itself ran" not in text and "confirmation" not in text, text
    intent, outcome = audit_rows(audit_path)
    assert (intent["rule_id"], intent["dry_run"]) == (rule, True)
    assert (outcome["verdict"], outcome["rule_id"], outcome["dry_run"]) == ("error", "upstream.too_large", True)


class Flood(httpx.AsyncBaseTransport):
    """Answers with far more than any limit, one chunk at a time, and counts what it actually produced."""

    def __init__(self, chunk: int = 100, chunks: int = 10_000, headers: dict[str, str] | None = None):
        self.chunk, self.chunks, self.produced, self.closed = chunk, chunks, 0, False
        self.headers = {"content-type": "application/json", **(headers or {})}
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        flood = self
        self.requests.append(request)

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                for _ in range(flood.chunks):
                    flood.produced += flood.chunk
                    yield b"x" * flood.chunk

            async def aclose(self):
                flood.closed = True

        return httpx.Response(200, headers=self.headers, stream=Body())


@pytest.mark.parametrize("headers", [None, {"content-encoding": "Identity"}])  # a stated identity is read, in any case
async def test_upstream_flood_is_read_only_up_to_the_limit_plus_one_chunk(audit_path, headers):
    flood = Flood(headers=headers)
    al = fake_airlock(audit_path, flood, max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        res = await call(c, "get_service", {"name": "api"})
    assert res["_meta"][META + "rule_id"] == "upstream.too_large"
    assert flood.produced <= LIMIT + flood.chunk < flood.chunk * flood.chunks  # 1 MB on offer, about 2 KB pulled
    assert flood.closed


@pytest.mark.parametrize("encoding", ["gzip", "DEFLATE", "br, identity"])
async def test_upstream_is_asked_for_plain_bytes_and_an_encoded_answer_is_refused_unread(audit_path, encoding):
    # An upstream that compresses anyway could make one wire chunk decode to far above the limit: nothing of it is read.
    flood = Flood(headers={"content-encoding": encoding})
    al = fake_airlock(audit_path, flood, max_upstream_bytes=LIMIT)
    async with serving(al) as c:
        res = await call(c, "get_service", {"name": "api"})
    assert flood.requests[-1].headers["accept-encoding"] == "identity"
    assert res["isError"] and res["_meta"][META + "rule_id"] == "upstream.encoded", res
    assert "accept-encoding identity" in res["content"][0]["text"] and "may have run" in res["content"][0]["text"]
    assert flood.produced == 0 and flood.closed
    outcome = audit_rows(audit_path)[-1]
    assert outcome["verdict"] == "error" and outcome["rule_id"] == "upstream.encoded" and outcome["upstream_status"] == 200


# ---------------------------------------------------------------- configuration
def test_build_reads_the_limits_and_rejects_bad_values(monkeypatch, tmp_path):
    for var in ("AIRLOCK_APPROVAL_WEBHOOK", "AIRLOCK_APPROVAL_MODE", "AIRLOCK_STORE_DSN", "AIRLOCK_AUDIT_DSN",
                "AIRLOCK_MAX_REQUEST_BYTES", "AIRLOCK_MAX_UPSTREAM_BYTES"):
        monkeypatch.delenv(var, raising=False)
    audit = tmp_path / "audit.jsonl"

    def make() -> Airlock:
        return build(str(ROOT / "policy.example.yaml"), "http://localhost:9001/mcp", str(audit), "prod")

    al = make()
    assert (al.max_request_bytes, al.max_upstream_bytes) == (1048576, 8388608)
    audit.unlink()
    monkeypatch.setenv("AIRLOCK_MAX_REQUEST_BYTES", "")  # empty means unset
    monkeypatch.setenv("AIRLOCK_MAX_UPSTREAM_BYTES", "4096")
    al = make()
    assert (al.max_request_bytes, al.max_upstream_bytes) == (1048576, 4096)
    audit.unlink()
    for var in ("AIRLOCK_MAX_REQUEST_BYTES", "AIRLOCK_MAX_UPSTREAM_BYTES"):
        for bad in ("0", "-1", "abc", "1.5", "1 MiB"):
            monkeypatch.setenv(var, bad)
            with pytest.raises(ValueError, match=var):
                make()
        monkeypatch.delenv(var)
    assert not audit.exists()  # refused before the audit file was opened


# ---------------------------------------------------------------- shutdown
class Sink:
    def __init__(self):
        self.closed = 0

    def write(self, **rec) -> None:
        pass

    def close(self) -> None:
        self.closed += 1


async def run_lifespan(al: Airlock) -> None:
    async with al.app.router.lifespan_context(al.app):
        pass


async def test_shutdown_closes_what_airlock_created_and_the_audit_sinks(tmp_path):
    a, b = Sink(), Sink()
    pg = PostgresAuditLog("postgresql://unused")
    pg._conn = conn = Sink()
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp", MultiAudit(a, b, pg))
    assert not al.http.is_closed
    await run_lifespan(al)
    assert al.http.is_closed and (a.closed, b.closed, conn.closed) == (1, 1, 1)
    file_audit = AuditLog(tmp_path / "audit.jsonl")
    await run_lifespan(Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp", file_audit))
    assert file_audit._f.closed


@pytest.mark.skipif(not PG, reason="AIRLOCK_TEST_PG_DSN not set")
async def test_shutdown_closes_the_postgres_audit_connection(tmp_path):
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp",
                 MultiAudit(AuditLog(tmp_path / "audit.jsonl"), PostgresAuditLog(PG)))
    al.audit.write(phase="intent", call_id="shutdown", verdict="deny", rule_id="allowlist.deny")  # opens the connection
    pg = al.audit.sinks[1]
    assert pg.flush(10)  # the worker thread opens and owns the connection
    conn = pg._conn
    assert not conn.closed
    await run_lifespan(al)
    assert conn.closed and pg._conn is None and al.audit.sinks[0]._f.closed
    import psycopg
    with psycopg.connect(PG, autocommit=True) as c:
        c.execute("DELETE FROM airlock_audit WHERE call_id = 'shutdown'")  # the database is shared


async def test_shutdown_leaves_injected_clients_open(upstream, audit_path):
    notify = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    al = make_airlock(upstream, audit_path, notify_http=notify)
    await run_lifespan(al)
    assert not al.http.is_closed and not notify.is_closed
    assert al.audit._f.closed  # the audit sinks are always closed
    await al.http.aclose()
    await notify.aclose()


async def test_shutdown_twice_does_not_raise(tmp_path):
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp", AuditLog(tmp_path / "audit.jsonl"))
    await run_lifespan(al)
    await run_lifespan(al)
    assert al.http.is_closed


async def test_audit_is_closed_even_when_closing_the_client_fails(tmp_path):
    sink = Sink()
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp", sink)

    async def boom():
        raise RuntimeError("close failed")

    al.http.aclose = boom
    with pytest.raises(RuntimeError):
        await run_lifespan(al)
    assert sink.closed == 1


async def test_shutdown_runs_the_hook_once_after_the_audit_closes():
    sink, seen = Sink(), []
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp", sink,
                 on_shutdown=lambda: seen.append(sink.closed))
    await run_lifespan(al)
    assert seen == [1]


async def test_shutdown_hook_runs_even_when_closing_the_client_fails():
    calls = []
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp", Sink(),
                 on_shutdown=lambda: calls.append(1))

    async def boom():
        raise RuntimeError("close failed")

    al.http.aclose = boom
    with pytest.raises(RuntimeError):
        await run_lifespan(al)
    assert calls == [1]


# ---------------------------------------------------------------- /approve
async def approving(upstream, audit_path, resolve_threads: list[int], monkeypatch, **kw):
    posted: list[str] = []
    notify = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: (posted.append(json.loads(r.content)["text"]), httpx.Response(200))[1]))

    def resolve(headers, cfg):  # stands in for a JWKS verification that blocks on the network
        resolve_threads.append(threading.get_ident())
        if "x-slow" in headers:
            time.sleep(0.3)
        return Principal("alice")

    monkeypatch.setattr("mcp_airlock.app.resolve", resolve)
    al = make_airlock(upstream, audit_path, webhook="https://hooks.example/x", public_url="https://a.example",
                      notify_http=notify, **kw)
    async with serving(al) as c:
        await call(c, "delete_service", {"name": "api"})
        link = next(w for w in posted[-1].split() if w.startswith("https://a.example/approve/")).removeprefix("https://a.example")
    return al, link


async def test_approve_with_a_slow_jwks_does_not_block_the_event_loop(upstream, audit_path, monkeypatch):
    threads: list[int] = []
    al, link = await approving(upstream, audit_path, threads, monkeypatch,
                               identity=IdentityConfig(jwks_url="https://idp.example/jwks", trust_header=True))
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    task = asyncio.create_task(ticker())
    async with serving(al) as c:
        r = await c.post(link, headers={"x-slow": "1", "authorization": "Bearer t"})
    task.cancel()
    assert r.status_code == 200 and "Approved delete_service" in r.text
    assert ticks >= 10, ticks  # a resolve on the loop thread would leave the ticker at 0 or 1
    assert threads[-1] != threading.get_ident()


async def test_approve_resolves_on_the_loop_without_a_jwks_url(upstream, audit_path, monkeypatch):
    threads: list[int] = []
    al, link = await approving(upstream, audit_path, threads, monkeypatch)
    async with serving(al) as c:
        r = await c.post(link)
    assert r.status_code == 200 and threads[-1] == threading.get_ident()


async def test_shutdown_closes_the_audit_off_the_event_loop():
    class Slow(Sink):
        def close(self):
            time.sleep(0.5)
            super().close()

    sink, ticks = Slow(), []
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://upstream/mcp", sink)

    async def tick():
        while True:
            ticks.append(1)
            await asyncio.sleep(0.05)

    t = asyncio.create_task(tick())
    await run_lifespan(al)
    t.cancel()
    assert sink.closed == 1 and len(ticks) >= 5  # the loop kept running while close() slept
