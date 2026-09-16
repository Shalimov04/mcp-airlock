"""mcp-airlock: stateless governance proxy in front of any MCP (2026-07-28) server."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import time
import uuid
from typing import Any

import httpx
from mcp.shared.inbound import (
    ERROR_CODE_HTTP_STATUS,
    classify_inbound_request,
    find_duplicated_routing_header,
    InboundLadderRejection,
)
from mcp_types.jsonrpc import INVALID_PARAMS, INVALID_REQUEST, INTERNAL_ERROR, METHOD_NOT_FOUND, PARSE_ERROR
from opentelemetry import trace
from opentelemetry.propagate import extract, inject
from opentelemetry.trace import SpanKind, format_trace_id
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from . import approvals, guard
from .audit import audit_from_env, redact, scrub
from .identity import IdentityConfig, Principal, resolve
from .policy import Engine, Policy
from .store import store_from_env

log = logging.getLogger("mcp_airlock")
META = "io.mcp-airlock/"
FORWARD_HEADERS = ("mcp-protocol-version", "mcp-method", "mcp-name", "content-type")  # accept is always the dual value
MCP_PARAM_PREFIX = "mcp-param-"
PROXIED_METHODS = frozenset({"server/discover", "tools/list", "tools/call"})
PRINCIPAL_REQUIRED = -32011  # airlock-specific JSON-RPC code (implementation range, not used by the SDK), HTTP 401
TOKEN_PREFIX = "al1."  # requestState: held by the agent
APPROVE_PREFIX = "al2."  # approve link: held by the human, signed with a derived key the agent never sees
CONFIRM_KEY = "airlock-confirm"
_tracer = trace.get_tracer("mcp-airlock")


class CatalogUnavailable(Exception):
    """The upstream did not give us a usable tools/list; we cannot tell whether a tool has dry_run."""


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def args_hash(args: dict[str, Any]) -> str:
    clean = {k: v for k, v in args.items() if k != "dry_run"}
    return hashlib.sha256(json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class Airlock:
    def __init__(
        self,
        policy: Policy,
        upstream: str,
        audit: Any,
        *,
        secret: bytes | None = None,
        identity: IdentityConfig | None = None,
        trust_principal_header: bool = False,  # legacy shortcuts, used when `identity` is None
        jwt_secret: str | None = None,
        store: Any = None,
        upstream_headers: dict[str, str] | None = None,
        confirm_ttl_s: int = 600,
        http: httpx.AsyncClient | None = None,
        webhook: str | None = None,
        telegram_chat: str | None = None,
        notify_http: httpx.AsyncClient | None = None,
        public_url: str | None = None,
    ):
        self.engine = Engine(policy, store)
        self.audit = audit
        self.secret = secret or secrets.token_bytes(32)  # random per process: restart voids pending confirmations
        self.approve_secret = hmac.new(self.secret, b"approve", hashlib.sha256).digest()
        self.identity = identity or IdentityConfig(jwt_secret=jwt_secret, trust_header=trust_principal_header)
        self.upstream_headers = upstream_headers or {}
        self.confirm_ttl_s = confirm_ttl_s
        self.http = http or httpx.AsyncClient(timeout=60.0)
        self.upstream = upstream
        self.webhook, self.telegram_chat = webhook, telegram_chat
        self.notify_http = notify_http or self.http
        self.public_url = (public_url or "").rstrip("/")
        self._catalog: dict[tuple, tuple[float, dict[str, dict[str, Any]]]] = {}  # (version, sub, groups) to (expires_at, tools)
        self.app = Starlette(routes=[
            Route("/mcp", self.handle, methods=["POST"]),
            Route("/approve/{token}", self.approve_page, methods=["GET"]),
            Route("/approve/{token}", self.approve_submit, methods=["POST"]),
        ])

    # ---------- MRTR confirmation tokens (stateless, HMAC-signed) ----------
    def _binding(self, principal: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        # Everything the human saw, plus where it applies: a dev confirmation must not run in prod.
        return {"p": principal, "t": tool, "h": args_hash(args), "e": self.engine.policy.environment, "u": self.upstream}

    def _sign(self, body: str, prefix: str) -> str:
        key = self.approve_secret if prefix == APPROVE_PREFIX else self.secret
        return f"{prefix}{body}.{_b64(hmac.new(key, body.encode(), hashlib.sha256).digest())}"

    def issue_token(self, principal: str, tool: str, args: dict[str, Any]) -> tuple[str, str, float]:
        key, exp = uuid.uuid4().hex, time.time() + self.confirm_ttl_s
        claims = {**self._binding(principal, tool, args), "k": key, "exp": exp}
        body = _b64(json.dumps(claims, separators=(",", ":")).encode())
        return self._sign(body, TOKEN_PREFIX), key, exp

    def approve_link(self, request_state: str) -> str:
        """Same claims as the agent's requestState, different signature: only this form is accepted by /approve."""
        body = request_state[len(TOKEN_PREFIX):].split(".", 1)[0]
        return f"{self.public_url}/approve/{self._sign(body, APPROVE_PREFIX)}"

    def verify_token(self, token: str, prefix: str = TOKEN_PREFIX) -> dict[str, Any] | None:
        """Signature + shape (not expiry). None when anything is off, including the wrong token kind."""
        try:
            if not token.startswith(prefix):
                return None
            body, sig = token[len(prefix):].split(".", 1)
            good = self._sign(body, prefix)[len(prefix) + len(body) + 1:]
            if not hmac.compare_digest(good, sig):
                return None
            claims = json.loads(_unb64(body))
            if not isinstance(claims, dict) or not isinstance(claims.get("k"), str) or not isinstance(claims.get("exp"), (int, float)):
                return None
            return claims
        except Exception:
            return None

    async def verify_confirmation(self, params: dict[str, Any], principal: str, tool: str, args: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        """Returns (mode, claims): mode is 'none' (no airlock token), 'accepted', 'pending' (token but no answer yet),
        or 'deny:<rule>'. Never consumes the key on accept; `_call` does that right before forwarding."""
        state = params.get("requestState")
        if not isinstance(state, str) or not state.startswith(TOKEN_PREFIX):
            return "none", None  # plain call, or an upstream-owned requestState (forwarded untouched)
        claims = self.verify_token(state)
        if claims is None:
            return "deny:mrtr.bad_signature", None
        if claims["exp"] < time.time():
            return "deny:mrtr.expired", None
        if any(claims.get(k) != v for k, v in self._binding(principal, tool, args).items()):
            return "deny:mrtr.mismatch", None
        responses = params.get("inputResponses")
        answer = responses.get(CONFIRM_KEY) if isinstance(responses, dict) else responses
        if answer is None:  # no answer for our question: approved out-of-band, or still waiting (nothing burned)
            return ("accepted" if await self.engine.store.is_approved(claims["k"]) else "pending"), claims
        content = answer.get("content") if isinstance(answer, dict) else None
        if isinstance(answer, dict) and answer.get("action") == "accept" and isinstance(content, dict) and content.get("confirm") is True:
            return "accepted", claims
        burned = await self.engine.store.consume_once(claims["k"], claims["exp"])  # decline/cancel/malformed: one answer per prompt
        return ("deny:mrtr.declined" if burned else "deny:mrtr.replay"), None

    # ---------- request handling ----------
    async def handle(self, request: Request) -> Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        # JWKS verification may fetch keys over the network (blocking urllib): keep it off the event loop.
        who = await asyncio.to_thread(resolve, headers, self.identity) if self.identity.jwks_url else resolve(headers, self.identity)
        sub = who.sub if who else None
        try:
            body = json.loads(await request.body())
        except ValueError:
            return self._reject(None, PARSE_ERROR, "Parse error", sub, None, None)
        if not isinstance(body, dict) or "id" not in body or not isinstance(body.get("method"), str):
            return self._reject(None, INVALID_REQUEST, "Body must be a single JSON-RPC request", sub, None, None)
        rid, method = body["id"], body["method"]
        params = body.get("params")
        tool = params.get("name") if method == "tools/call" and isinstance(params, dict) else None
        if (dup := find_duplicated_routing_header(request.headers.items())) is not None:
            return self._reject(rid, -32020, f"{dup} header appears more than once", sub, method, tool)
        route = classify_inbound_request(body, headers=headers)  # SDK ladder: _meta envelope + header match
        if isinstance(route, InboundLadderRejection):
            return self._reject(rid, route.code, route.message, sub, method, tool, route.data)
        if method not in PROXIED_METHODS:
            return self._reject(rid, METHOD_NOT_FOUND, f"airlock does not proxy {method!r}", sub, method, tool)
        args = params.get("arguments") or {} if method == "tools/call" else {}
        if method == "tools/call" and (not isinstance(tool, str) or not isinstance(args, dict)):
            return self._reject(rid, INVALID_PARAMS, "tools/call needs string 'name' and object 'arguments'", sub, method, None)

        parent = extract(headers) if "traceparent" in headers else extract(params.get("_meta") or {})
        span_name = f"execute_tool {tool}" if tool else method
        with _tracer.start_as_current_span(span_name, context=parent, kind=SpanKind.SERVER) as span:
            span.set_attribute("gen_ai.operation.name", "execute_tool" if tool else method)
            span.set_attribute("rpc.method", method)
            if tool:
                span.set_attribute("gen_ai.tool.name", tool)
                span.set_attribute("gen_ai.tool.call.id", str(rid))
            trace_id = format_trace_id(span.get_span_context().trace_id)
            base = dict(call_id=uuid.uuid4().hex, principal=sub, method=method, tool=tool, args=args, trace_id=trace_id)
            if who is None:
                self._audit_deny(base, "principal.missing", None, "no principal in Authorization/X-Airlock-Principal")
                span.set_attribute("airlock.verdict", "deny")
                return _rpc_error(rid, PRINCIPAL_REQUIRED, "airlock: principal required", status=401)
            span.set_attribute("enduser.id", who.sub)
            try:
                if method == "tools/call":
                    return await self._call(rid, body, params, headers, who, tool, args, base, span)
                return await self._passthrough(body, headers, who, method, base)
            except Exception as e:  # never leak a traceback; try hard to leave an outcome record
                log.exception("airlock internal error")
                self._outcome(verdict="error", rule_id="internal.error", detail=repr(e), **base)
                return _rpc_error(rid, INTERNAL_ERROR, "airlock: internal error")

    async def _passthrough(self, body, headers, who: Principal, method, base) -> Response:
        self.audit.write(phase="intent", verdict="allow", rule_id="passthrough", **base)  # a raise here fails closed
        t0 = time.perf_counter()
        status, reply = await self.forward(body, headers, who)
        if method == "tools/list" and isinstance(reply.get("result"), dict):
            self._filter_tools(reply["result"], who)
        self._outcome(verdict="allow", rule_id="passthrough", upstream_status=status, latency_ms=_ms(t0), **base)
        return JSONResponse(reply, status_code=status)

    async def _call(self, rid, body, params, headers, who: Principal, tool, args, base, span) -> Response:
        policy = self.engine.policy
        mode, claims = await self.verify_confirmation(params, who.sub, tool, args)
        if mode.startswith("deny:"):
            rule = mode[5:]
            self._audit_deny(base, rule, policy.tier(tool, who.sub, who.groups), "confirmation rejected")
            span.set_attribute("airlock.verdict", "deny")
            return _tool_error(rid, f"airlock: denied ({rule})", rule)
        tier = policy.tier(tool, who.sub, who.groups)
        dry_run_prop: dict[str, Any] | None = None
        if tier in ("L1", "L2") or (tier == "L3" and "dry_run" in args):
            try:
                dry_run_prop = await self._dry_run_property(headers, who, tool)
            except CatalogUnavailable as e:
                self._audit_deny(base, "catalog.unavailable", tier, str(e))
                return _tool_error(rid, f"airlock: denied (catalog.unavailable): {e}", "catalog.unavailable")
        d = await self.engine.evaluate(tool, args, who.sub, confirmed=mode == "accepted", groups=who.groups,
                                       dry_run_supported=dry_run_prop is not None)
        span.set_attributes({"airlock.verdict": d.verdict, "airlock.rule_id": d.rule_id, "airlock.tier": d.tier or ""})
        if d.verdict == "deny":
            self._audit_deny(base, d.rule_id, d.tier, d.message)
            return _tool_error(rid, f"airlock: denied ({d.rule_id}): {d.message}", d.rule_id)
        if d.verdict == "confirm" and mode == "pending":
            # Waiting for the out-of-band approval: same key, no new prompt (a client would re-ask the human), nothing burned.
            for phase in ("intent", "outcome"):
                self.audit.write(phase=phase, verdict="confirm", rule_id="mrtr.pending", tier=d.tier, dry_run=None, **base)
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {
                "resultType": "input_required", "requestState": params["requestState"],
                "_meta": {META + "status": "pending", META + "idempotency_key": claims["k"],
                          META + "message": "Awaiting approval. Retry with this requestState once the approver has confirmed."}}})
        if d.rule_id == "tier.L2.confirmed":  # the one path that executes for real: burn the key first, atomically
            if not await self.engine.store.consume_once(claims["k"], claims["exp"]):
                self._audit_deny(base, "mrtr.replay", d.tier, "idempotency key already used")
                return _tool_error(rid, "airlock: denied (mrtr.replay)", "mrtr.replay")
        d = await self.engine.reserve(who.sub, tool, d)  # atomic window charge; a replay never gets this far
        if d.verdict == "deny":
            self._audit_deny(base, d.rule_id, d.tier, d.message)
            return _tool_error(rid, f"airlock: denied ({d.rule_id}): {d.message}", d.rule_id)

        if d.verdict == "confirm" and not d.preview:
            # Tool has no dry_run: nothing safe to forward. Prompt the human without a preview.
            self.audit.write(phase="intent", verdict="confirm", rule_id=d.rule_id, tier=d.tier, dry_run=None, **base)
            result = self._input_required(who.sub, tool, args, None)
            await self._notify(result, who.sub)
            self._outcome(verdict="confirm", rule_id=d.rule_id, tier=d.tier, dry_run=None, upstream_status=None, latency_ms=0, **base)
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result})

        fwd_args, fwd_headers = dict(args), dict(headers)
        if d.dry_run is not None:
            fwd_args["dry_run"] = d.dry_run
            if mirror := (dry_run_prop or {}).get("x-mcp-header"):  # keep the mirrored header in step with the body
                fwd_headers[f"{MCP_PARAM_PREFIX}{str(mirror).lower()}"] = "true" if d.dry_run else "false"
        fwd = dict(body, params={k: v for k, v in params.items() if k not in ("inputResponses", "requestState")}
                   if mode != "none" or d.verdict == "confirm" else dict(params))
        fwd["params"]["arguments"] = fwd_args
        self.audit.write(phase="intent", verdict=d.verdict, rule_id=d.rule_id, tier=d.tier, dry_run=d.dry_run, **base)
        t0 = time.perf_counter()
        status, reply = await self.forward(fwd, fwd_headers, who)
        result = reply.get("result")
        gated = d.verdict == "confirm" or d.rule_id == "tier.L2.confirmed"
        if gated and isinstance(result, dict) and result.get("resultType") == "input_required":
            # The upstream's question and ours share requestState/inputResponses; passing it on loops forever
            # (every retry is a new prompt and a real forward). Refuse instead.
            rule, msg = "mrtr.upstream_input_required", "the upstream asked for its own input behind an L2 gate; put this tool at L0, L1 or L3"
            self._outcome(verdict="deny", rule_id=rule, tier=d.tier, dry_run=d.dry_run, upstream_status=status,
                          latency_ms=_ms(t0), detail=msg, **base)
            return _tool_error(rid, f"airlock: denied ({rule}): {msg}", rule)
        detail: dict[str, Any] = {}
        if isinstance(result, dict):
            result.setdefault("_meta", {}).update({META + "verdict": d.verdict, META + "rule_id": d.rule_id, META + "dry_run": d.dry_run})
            try:  # the upstream already acted: a malformed result must reach the caller, not become a 500
                if truncated := self._cap_output(tool, result):  # after the _meta additions so the cap covers the final size
                    detail.update(truncated)
                if findings := guard.scan(result, policy.tools):
                    result["_meta"][META + "suspicious"] = findings  # marked, never blocked: the client decides how to render
                    detail["suspicious"] = sorted({f["rule"] for f in findings})
                    span.set_attribute("airlock.suspicious", len(findings))
            except Exception as e:
                log.exception("post-processing failed; returning the upstream result as-is")
                detail["postprocess_error"] = repr(e)
            if d.verdict == "confirm" and status == 200 and not result.get("isError"):
                reply["result"] = self._input_required(who.sub, tool, args, result)  # preview failed: no gate, just the error
                await self._notify(reply["result"], who.sub)
        self._outcome(verdict=d.verdict, rule_id=d.rule_id, tier=d.tier, dry_run=d.dry_run,
                      upstream_status=status, latency_ms=_ms(t0), detail=detail or None, **base)
        return JSONResponse(reply, status_code=status)

    # ---------- audit helpers ----------
    def _outcome(self, **rec: Any) -> None:
        """Outcome records are written after the upstream acted: a failing log must not hide the result from the caller."""
        try:
            self.audit.write(phase="outcome", **rec)
        except Exception:
            log.exception("audit outcome write failed for call %s", rec.get("call_id"))

    def _reject(self, rid, code, message, principal, method, tool, data=None) -> JSONResponse:
        base = dict(call_id=uuid.uuid4().hex, principal=principal, method=method, tool=tool, args=None, trace_id=None)
        self._audit_deny(base, f"protocol.{code}", None, message)
        return _rpc_error(rid, code, message, data)

    def _audit_deny(self, base: dict[str, Any], rule_id: str, tier: str | None, detail: str) -> None:
        self.audit.write(phase="intent", verdict="deny", rule_id=rule_id, tier=tier, detail=detail, **base)
        self._outcome(verdict="deny", rule_id=rule_id, tier=tier, detail=detail, upstream_status=None, latency_ms=0, **base)

    # ---------- upstream catalog ----------
    async def _catalog_tools(self, headers: dict[str, str], who: Principal) -> dict[str, dict[str, Any]]:
        """Upstream tools by name. Cached for `ttlMs` when the upstream sets one (0 means refetched every time),
        per caller because an upstream may filter its catalog by principal. Raises CatalogUnavailable on any failure."""
        ckey = (headers.get("mcp-protocol-version", ""), who.sub, who.groups)
        cached = self._catalog.get(ckey)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        envelope = {"io.modelcontextprotocol/protocolVersion": headers.get("mcp-protocol-version", ""),
                    "io.modelcontextprotocol/clientCapabilities": {}}
        list_headers = {k: v for k, v in headers.items() if not k.startswith(MCP_PARAM_PREFIX)}
        list_headers["mcp-method"] = "tools/list"
        list_headers.pop("mcp-name", None)
        tools: dict[str, dict[str, Any]] = {}
        ttl_ms, cursor = 0, None
        for _ in range(10):  # ponytail: 10 pages max; a bigger catalog deserves a real cache
            params: dict[str, Any] = {"_meta": envelope, **({"cursor": cursor} if cursor else {})}
            status, reply = await self.forward({"jsonrpc": "2.0", "id": f"airlock-catalog-{uuid.uuid4().hex[:8]}",
                                                "method": "tools/list", "params": params}, list_headers, who)
            result = reply.get("result") if status == 200 else None
            if not isinstance(result, dict):
                raise CatalogUnavailable(f"upstream tools/list failed (HTTP {status}): {reply.get('error') or 'no result'}")
            tools.update({t["name"]: t for t in result.get("tools") or [] if isinstance(t, dict) and "name" in t})
            ttl_ms = result.get("ttlMs") if isinstance(result.get("ttlMs"), int) else 0
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str):
                break
        else:
            raise CatalogUnavailable("upstream tools/list did not finish within 10 pages")
        if ttl_ms > 0:
            now = time.monotonic()
            self._catalog = {k: v for k, v in self._catalog.items() if v[0] > now}  # bounded by live principals
            self._catalog[ckey] = (now + ttl_ms / 1000, tools)
        return tools

    async def _dry_run_property(self, headers: dict[str, str], who: Principal, tool: str) -> dict[str, Any] | None:
        """The tool's `dry_run` schema property, or None when the tool does not declare one."""
        t = (await self._catalog_tools(headers, who)).get(tool)
        props = ((t or {}).get("inputSchema") or {}).get("properties") or {}
        if "dry_run" not in props:
            return None
        return props["dry_run"] if isinstance(props["dry_run"], dict) else {}

    async def forward(self, body: dict[str, Any], headers: dict[str, str], who: Principal) -> tuple[int, dict[str, Any]]:
        params = dict(body["params"])
        meta = {k: v for k, v in (params.get("_meta") or {}).items()
                if not k.startswith(META) and k not in ("traceparent", "tracestate")}
        meta[META + "principal"] = who.sub  # identity travels in _meta; upstream auth is the proxy's own
        if who.groups:
            meta[META + "groups"] = list(who.groups)
        inject(meta)  # traceparent/tracestate from the current span
        params["_meta"] = meta
        out_headers = {k: v for k, v in headers.items() if k in FORWARD_HEADERS or k.startswith(MCP_PARAM_PREFIX)}
        out_headers["accept"] = "application/json, text/event-stream"  # we parse both; never let a picky client cause a 406
        out_headers["traceparent"] = meta.get("traceparent", "")
        out_headers.update(self.upstream_headers)
        try:
            r = await self.http.post(self.upstream, content=json.dumps(dict(body, params=params)), headers=out_headers)
        except httpx.HTTPError as e:
            return 502, {"jsonrpc": "2.0", "id": body["id"], "error": {"code": INTERNAL_ERROR, "message": f"upstream unreachable: {e}"}}
        ctype = r.headers.get("content-type", "")
        if ctype.startswith("text/event-stream"):
            return r.status_code, _last_sse_message(r.text)
        try:
            reply = r.json()
        except ValueError:
            return 502, {"jsonrpc": "2.0", "id": body["id"], "error": {"code": INTERNAL_ERROR, "message": f"upstream returned non-JSON ({r.status_code})"}}
        if not isinstance(reply, dict):
            return 502, {"jsonrpc": "2.0", "id": body["id"], "error": {"code": INTERNAL_ERROR, "message": "upstream returned a non-object"}}
        return r.status_code, reply

    def _filter_tools(self, result: dict[str, Any], who: Principal) -> None:
        tools = result.get("tools")
        if not isinstance(tools, list):
            return
        policy = self.engine.policy
        visible = [t for t in tools if isinstance(t, dict) and policy.tier(str(t.get("name")), who.sub, who.groups) is not None]
        result.setdefault("_meta", {})[META + "hidden_tools"] = len(tools) - len(visible)
        result["tools"] = visible  # ttlMs / cacheScope pass through untouched

    def _cap_output(self, tool: str, result: dict[str, Any]) -> dict[str, Any] | None:
        cap = self.engine.policy.output_cap(tool)
        size = len(json.dumps(result, ensure_ascii=False, default=str))
        if size <= cap.max_chars:
            return None
        info = {"truncated": True, "chars": size, "max_chars": cap.max_chars, "est_tokens": round(size / cap.chars_per_token)}
        if result.pop("structuredContent", None) is not None:
            # No longer matches the tool's outputSchema; SDK clients raise on that unless the result is an error.
            result["isError"] = True
        result.setdefault("_meta", {})[META + "output"] = info
        note = f"\n\n[airlock: output truncated to {cap.max_chars} chars from {size}; the call itself ran]"
        content = result.get("content")
        texts = [b for b in (content if isinstance(content, list) else [])
                 if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)]
        # ponytail: non-text blocks dropped when over cap; count their bytes if you need images
        shell = {**result, "content": [{**b, "text": ""} for b in texts[:1]] or [{"type": "text", "text": ""}]}
        budget = max(cap.max_chars - len(json.dumps(shell, ensure_ascii=False, default=str)) - len(json.dumps(note)), 0)
        kept: list[dict[str, Any]] = []
        for block in texts:
            text = block["text"][:budget]
            budget -= len(text) + len(json.dumps({**block, "text": ""}))  # per-block envelope cost
            kept.append({**block, "text": text})
            if budget <= 0:
                break
        if not kept:
            kept.append({"type": "text", "text": ""})
        kept[-1]["text"] += note
        result["content"] = kept
        # JSON escaping (quotes, newlines) inflates text beyond raw length: trim until the serialized size fits.
        while (over := len(json.dumps(result, ensure_ascii=False, default=str)) - cap.max_chars) > 0:
            body = kept[-1]["text"][: -len(note)]
            if not body:
                if len(kept) == 1:
                    break
                kept.pop()
                kept[-1]["text"] += note
                continue
            kept[-1]["text"] = body[:-over] + note
        return info

    def _input_required(self, principal: str, tool: str, args: dict[str, Any], preview: dict[str, Any] | None) -> dict[str, Any]:
        token, key, _ = self.issue_token(principal, tool, args)
        rule = self.engine.policy.tools[tool]
        env = self.engine.policy.environment
        shown = redact({k: v for k, v in args.items() if k != "dry_run"})  # this text reaches humans, Slack, logs
        if preview is None:
            preview_line = "No dry-run preview: this tool has no dry_run argument, nothing was executed."
            preview_blocks = None
        else:
            raw = preview.get("content")
            preview_blocks = [{**b, "text": scrub(b["text"])} if isinstance(b, dict) and isinstance(b.get("text"), str) else b
                              for b in (raw if isinstance(raw, list) else [])]
            text = " ".join(b["text"] for b in preview_blocks if isinstance(b, dict) and isinstance(b.get("text"), str))[:2000]
            preview_line = f"Dry-run preview: {text or '(empty)'}"
        message = (f"[{env}] {tool}: {rule.description or 'write operation'} (tier L2).\n"
                   f"Arguments: {json.dumps(shown, ensure_ascii=False, default=str)}\n{preview_line}\n"
                   f"Confirm to execute for real. Idempotency key: {key}")
        meta = {**((preview or {}).get("_meta") or {}), META + "idempotency_key": key, META + "verdict": "confirm",
                META + "rule_id": "tier.L2.confirm"}
        if preview_blocks is not None:
            meta[META + "dry_run_preview"] = preview_blocks
        return {
            "resultType": "input_required",
            "inputRequests": {CONFIRM_KEY: {"method": "elicitation/create", "params": {
                "mode": "form", "message": message,
                "requestedSchema": {"type": "object", "properties": {"confirm": {"type": "boolean",
                                    "title": f"Execute {tool} in {env}?"}}, "required": ["confirm"]}}}},
            "requestState": token,
            "_meta": meta,
        }

    async def _notify(self, result: dict[str, Any], principal: str) -> None:
        if not self.webhook:
            return
        text = f"mcp-airlock approval request from {principal}\n" + result["inputRequests"][CONFIRM_KEY]["params"]["message"]
        await approvals.notify(text, self.approve_link(result["requestState"]), webhook=self.webhook,
                               http=self.notify_http, telegram_chat=self.telegram_chat)

    # ---------- out-of-band approval page ----------
    def _approval_claims(self, request: Request) -> dict[str, Any] | None:
        claims = self.verify_token(request.path_params["token"], APPROVE_PREFIX)  # an agent's requestState is refused here
        return claims if claims and claims["exp"] >= time.time() else None

    async def approve_page(self, request: Request) -> Response:
        if (claims := self._approval_claims(request)) is None:
            return HTMLResponse("Invalid or expired approval link.", status_code=400)
        # GET only renders (link unfurlers and prefetchers do GETs); the POST below approves.
        return HTMLResponse(f"""<!doctype html><title>mcp-airlock approval</title>
<h2>Approve tool call?</h2>
<p><b>{html.escape(claims['t'])}</b> requested by <b>{html.escape(claims['p'])}</b> in <b>{html.escape(claims['e'])}</b><br>
idempotency key <code>{html.escape(claims['k'])}</code></p>
<form method="post"><button type="submit">Approve</button></form>""")

    async def approve_submit(self, request: Request) -> Response:
        if (claims := self._approval_claims(request)) is None:
            return HTMLResponse("Invalid or expired approval link.", status_code=400)
        await self.engine.store.approve(claims["k"], claims["exp"])
        headers = {k.lower(): v for k, v in request.headers.items()}
        who = resolve(headers, self.identity)
        # Who clicked: a verified token when there is one, else whatever the fronting SSO proxy put in a header.
        if who and headers.get("authorization"):
            approver, source = who.sub, "verified"
        else:
            approver, source = (who.sub if who else headers.get("x-airlock-principal") or headers.get("x-forwarded-user")), "header"
        base = dict(call_id=uuid.uuid4().hex, principal=claims["p"], method="approve", tool=claims["t"], args=None, trace_id=None)
        detail = {"key": claims["k"], "approved_by": approver, "approved_by_source": source if approver else None}
        self.audit.write(phase="intent", verdict="allow", rule_id="mrtr.approved_oob", detail=detail, **base)
        self._outcome(verdict="allow", rule_id="mrtr.approved_oob", detail=detail, **base)
        return HTMLResponse(f"Approved {html.escape(claims['t'])} for {html.escape(claims['p'])}. The agent can retry now.")


def _ms(t0: float) -> int:
    return round((time.perf_counter() - t0) * 1000)


def _rpc_error(rid: Any, code: int, message: str, data: Any = None, status: int | None = None) -> JSONResponse:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": err}, status_code=status or ERROR_CODE_HTTP_STATUS.get(code, 500))


def _tool_error(rid: Any, text: str, rule_id: str) -> JSONResponse:
    # Policy denials are tool results with isError so the model sees them and can adapt (MCP guidance).
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {
        "resultType": "complete", "isError": True, "content": [{"type": "text", "text": text}],
        "_meta": {META + "verdict": "deny", META + "rule_id": rule_id}}})


def _last_sse_message(text: str) -> dict[str, Any]:
    last: dict[str, Any] = {}
    for frame in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].strip() for line in frame.split("\n") if line.startswith("data:"))
        if data:
            try:
                msg = json.loads(data)
                if isinstance(msg, dict) and "id" in msg:
                    last = msg
            except ValueError:
                pass
    return last or {"jsonrpc": "2.0", "id": None, "error": {"code": INTERNAL_ERROR, "message": "empty SSE response"}}


def build(policy_path: str, upstream: str, audit_path: str, environment: str | None = None, **kw: Any) -> Airlock:
    policy = Policy.load(policy_path, environment or os.environ.get("AIRLOCK_ENV"))
    secret = os.environ.get("AIRLOCK_SECRET")
    upstream_headers = {}
    if auth := os.environ.get("AIRLOCK_UPSTREAM_AUTH"):
        upstream_headers["authorization"] = auth
    webhook, telegram_chat = approvals.config_from_env()
    return Airlock(policy, upstream, audit_from_env(audit_path),
                   secret=secret.encode() if secret else None,
                   identity=IdentityConfig.from_env(), store=store_from_env(),
                   upstream_headers=upstream_headers, webhook=webhook, telegram_chat=telegram_chat,
                   public_url=os.environ.get("AIRLOCK_PUBLIC_URL", "http://127.0.0.1:9000"), **kw)
