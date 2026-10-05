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
import signal
import sys
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator

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
from . import pins as tool_pins
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
ERROR_TEXT_MAX = 300  # chars of upstream or exception text kept in a caller message or audit detail
PROMPT_TEXT_MAX = 8000  # chars of the prompt kept for the approve page
PROMPT_CUT_NOTE = f"\n[cut at {PROMPT_TEXT_MAX} characters; the full text is in the original message]"
READY_TIMEOUT_S = 2.0  # a hung store must not hang the readiness probe
DEFAULT_MAX_REQUEST_BYTES = 1 << 20  # AIRLOCK_MAX_REQUEST_BYTES
DEFAULT_MAX_UPSTREAM_BYTES = 8 << 20  # AIRLOCK_MAX_UPSTREAM_BYTES
_tracer = trace.get_tracer("mcp-airlock")


def _tool_texts(tool: dict[str, Any]) -> list[Any]:
    """The text fields of a tool the model reads: description, title, annotations.title."""
    ann = tool.get("annotations")
    return [tool.get("description"), tool.get("title"), ann.get("title") if isinstance(ann, dict) else None]


@dataclass(frozen=True)
class ReloadSource:
    """Where a reload reads from: the policy file, and the pins file when one is configured."""
    policy_path: str
    pins_path: str | None = None


@dataclass(frozen=True)
class ReloadResult:
    ok: bool
    tools_before: int
    tools_after: int
    error: str | None = None


class CatalogUnavailable(Exception):
    """The upstream did not give us a usable tools/list; we cannot tell whether a tool has dry_run."""


class UpstreamTooLarge(Exception):
    """The upstream answer passed max_upstream_bytes and was dropped; `status` is what the upstream sent."""

    def __init__(self, status: int, limit: int):
        super().__init__(f"upstream response exceeded {limit} bytes")
        self.status, self.limit = status, limit


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
        approval_mode: str | None = None,
        pins: dict[str, str] | None = None,  # {tool: "sha256v2:<hex>"}, None means off
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_upstream_bytes: int = DEFAULT_MAX_UPSTREAM_BYTES,
        reload_source: ReloadSource | None = None,  # None: reload() has nothing to read
    ):
        self.engine = Engine(policy, store)
        self.reload_source = reload_source
        self.audit = audit
        self.secret = secret or secrets.token_bytes(32)  # random per process: restart voids pending confirmations
        self.approve_secret = hmac.new(self.secret, b"approve", hashlib.sha256).digest()
        self.identity = identity or IdentityConfig(jwt_secret=jwt_secret, trust_header=trust_principal_header)
        self.upstream_headers = upstream_headers or {}
        self.confirm_ttl_s = confirm_ttl_s
        self.http = http or httpx.AsyncClient(timeout=60.0)
        self._owns_http = http is None  # only a client we created is ours to close
        self.max_request_bytes, self.max_upstream_bytes = max_request_bytes, max_upstream_bytes
        self.upstream = upstream
        self.pins = pins
        self.webhook, self.telegram_chat = webhook, telegram_chat
        # oob: only the approve link approves. Without a webhook nobody receives a link, so every L2 call would stay pending.
        self.approval_mode = approval_mode if approval_mode is not None else ("oob" if webhook else "inband")
        if self.approval_mode not in ("oob", "inband"):
            raise ValueError(f"unknown approval mode {self.approval_mode!r}: use 'oob' or 'inband'")
        if self.approval_mode == "oob" and not webhook:
            raise ValueError("approval mode 'oob' needs AIRLOCK_APPROVAL_WEBHOOK: without it nobody gets an approve link")
        self.notify_http = notify_http or self.http
        self.public_url = (public_url or "").rstrip("/")
        self._catalog: dict[tuple, tuple[float, dict[str, dict[str, Any]]]] = {}  # (version, sub, groups) to (expires_at, tools)
        self._ping: asyncio.Task | None = None  # the in-flight readiness check, shared by the probes that arrive within one bound
        self.app = Starlette(lifespan=self._lifespan, routes=[
            Route("/healthz", self.healthz, methods=["GET"]),
            Route("/readyz", self.readyz, methods=["GET"]),
            Route("/mcp", self.handle, methods=["POST"]),
            Route("/approve/{token}", self.approve_page, methods=["GET"]),
            Route("/approve/{token}", self.approve_submit, methods=["POST"]),
        ])

    @asynccontextmanager
    async def _lifespan(self, app: Starlette) -> AsyncIterator[None]:
        loop, hup = asyncio.get_running_loop(), getattr(signal, "SIGHUP", None)  # no SIGHUP on Windows
        if hup is not None:
            try:
                loop.add_signal_handler(hup, self.reload)
            except RuntimeError:  # a loop without signal support (NotImplementedError is one), or not in the main thread
                hup = None
        try:
            yield
        finally:
            if hup is not None:
                loop.remove_signal_handler(hup)
            try:
                if self._owns_http:  # notify_http is never ours: it is injected or the same client as http
                    await self.http.aclose()
            finally:
                self.audit.close()

    def reload(self) -> ReloadResult:
        """Load the policy file and the pins file, then swap both in together. Nothing changes unless both load.
        A request holds the engine and pins it started with, so a swap only reaches the next one. The store carries
        over: usage windows and confirmation keys outlive a reload. Approval mode, secrets and upstream are not reloaded."""
        before = len(self.engine.policy.tools)
        src = self.reload_source
        if src is None:
            return ReloadResult(False, before, before, "nothing to reload: no policy file is known")
        try:
            # The running environment name, so a changed `environment:` in the file cannot void pending confirmations.
            policy = Policy.load(src.policy_path, self.engine.policy.environment)
            pins = tool_pins.load(src.pins_path) if src.pins_path else self.pins
        except Exception as e:  # a bad file must never take the process down
            error = " ".join(str(e).split())
            print(f"mcp-airlock: policy reload failed, keeping the current policy: {error}", file=sys.stderr)
            log.error("policy reload failed, keeping the current policy: %s", error)
            return ReloadResult(False, before, before, error)
        self.engine, self.pins = Engine(policy, self.engine.store), pins  # no await in between: one swap
        after = len(policy.tools)
        print(f"mcp-airlock: policy reloaded: {after} tools (was {before})", file=sys.stderr)
        log.info("policy reloaded: %d tools (was %d)", after, before)
        return ReloadResult(True, before, after)

    # ---------- MRTR confirmation tokens (stateless, HMAC-signed) ----------
    def _binding(self, principal: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        # Everything the human saw, plus where it applies: a dev confirmation must not run in prod.
        return {"p": principal, "t": tool, "h": args_hash(args), "e": self.engine.policy.environment, "u": self.upstream}

    def _sign(self, body: str, prefix: str) -> str:
        key = self.approve_secret if prefix == APPROVE_PREFIX else self.secret
        return f"{prefix}{body}.{_b64(hmac.new(key, body.encode(), hashlib.sha256).digest())}"

    def issue_token(self, principal: str, tool: str, args: dict[str, Any]) -> tuple[str, str, float]:
        key, exp = uuid.uuid4().hex, time.time() + self.confirm_ttl_s
        # The mode is not part of the binding: a replica in another mode accepts the token and applies the stricter one.
        claims = {**self._binding(principal, tool, args), "k": key, "exp": exp, "m": self.approval_mode}
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
        'pending:ignored' (pending, and an in-band accept was ignored in oob mode of the token or the replica) or 'deny:<rule>'.
        Never consumes the key on accept; `_call` does that right before forwarding."""
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
        content = answer.get("content") if isinstance(answer, dict) else None
        in_band = isinstance(answer, dict) and answer.get("action") == "accept" and isinstance(content, dict) and content.get("confirm") is True
        # The stricter mode wins; a token without m (issued before the upgrade) falls back to this replica's mode.
        strict = self.approval_mode == "oob" or ("m" in claims and claims["m"] != "inband")
        if answer is None or (in_band and strict):
            # No answer for our question (or, in oob mode, one that does not count): approved out-of-band, or still waiting (nothing burned)
            if await self.engine.store.is_approved(claims["k"]):
                return "accepted", claims
            return ("pending" if answer is None else "pending:ignored"), claims
        if in_band:
            return "accepted", claims
        burned = await self.engine.store.consume_once(claims["k"], claims["exp"])  # decline/cancel/malformed: one answer per prompt
        return ("deny:mrtr.declined" if burned else "deny:mrtr.replay"), None

    # ---------- request handling ----------
    async def handle(self, request: Request) -> Response:
        engine, pins = self.engine, self.pins  # one policy and one pins mapping for the whole request, whatever a reload does
        headers = {k.lower(): v for k, v in request.headers.items()}
        raw = await self._read_body(request)  # before identity: resolving may fetch keys over the network
        if raw is None:
            return self._request_too_large()
        who = await self._resolve(headers)
        sub = who.sub if who else None
        try:
            body = json.loads(raw)
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
                    return await self._call(rid, body, params, headers, who, tool, args, base, span, engine)
                return await self._passthrough(body, headers, who, method, base, engine.policy, pins)
            except Exception as e:  # never leak a traceback; try hard to leave an outcome record
                log.exception("airlock internal error")
                self._outcome(verdict="error", rule_id="internal.error", detail=_exc_text(e), **base)
                return _rpc_error(rid, INTERNAL_ERROR, "airlock: internal error")

    async def _resolve(self, headers: dict[str, str]) -> Principal | None:
        # JWKS verification may fetch keys over the network (blocking urllib): keep it off the event loop.
        return await asyncio.to_thread(resolve, headers, self.identity) if self.identity.jwks_url else resolve(headers, self.identity)

    async def _read_body(self, request: Request) -> bytes | None:
        """The request body, or None once it passes max_request_bytes. Holds at most the limit plus one chunk."""
        try:
            declared = int(request.headers.get("content-length", ""))
        except ValueError:
            declared = 0  # absent or malformed: the running total below is the check
        if declared > self.max_request_bytes:
            return None
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > self.max_request_bytes:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    def _request_too_large(self) -> JSONResponse:
        base = dict(call_id=uuid.uuid4().hex, principal=None, method=None, tool=None, args=None, trace_id=None)
        self._audit_deny(base, "request.too_large", None, f"limit {self.max_request_bytes} bytes")
        return _rpc_error(None, INVALID_REQUEST, "Request body too large", status=413)

    async def _passthrough(self, body, headers, who: Principal, method, base, policy: Policy, pins: dict[str, str] | None) -> Response:
        self.audit.write(phase="intent", verdict="allow", rule_id="passthrough", **base)  # a raise here fails closed
        t0 = time.perf_counter()
        try:
            status, reply = await self.forward(body, headers, who)
        except UpstreamTooLarge as e:
            self._outcome(verdict="error", rule_id="upstream.too_large", upstream_status=e.status, latency_ms=_ms(t0),
                          detail=f"limit {e.limit} bytes", **base)
            return _rpc_error(body["id"], INTERNAL_ERROR, f"airlock: the upstream response exceeded {e.limit} bytes", status=502)
        if method == "tools/list" and isinstance(reply.get("result"), dict):
            self._filter_tools(reply["result"], who, policy)
            self._vet_tools(reply["result"], base, pins)
        self._outcome(verdict="allow", rule_id="passthrough", upstream_status=status, latency_ms=_ms(t0), **base)
        return JSONResponse(reply, status_code=status)

    async def _call(self, rid, body, params, headers, who: Principal, tool, args, base, span, engine: Engine) -> Response:
        policy = engine.policy
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
        d = await engine.evaluate(tool, args, who.sub, confirmed=mode == "accepted", groups=who.groups,
                                       dry_run_supported=dry_run_prop is not None)
        span.set_attributes({"airlock.verdict": d.verdict, "airlock.rule_id": d.rule_id, "airlock.tier": d.tier or ""})
        if d.verdict == "deny":
            self._audit_deny(base, d.rule_id, d.tier, d.message)
            return _tool_error(rid, f"airlock: denied ({d.rule_id}): {d.message}", d.rule_id)
        if d.verdict == "confirm" and mode.startswith("pending"):
            # Waiting for the out-of-band approval: same key, no new prompt (a client would re-ask the human), nothing burned.
            detail = "in-band accept ignored (approval mode oob)" if mode == "pending:ignored" else None
            for phase in ("intent", "outcome"):
                self.audit.write(phase=phase, verdict="confirm", rule_id="mrtr.pending", tier=d.tier, dry_run=None, detail=detail, **base)
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {
                "resultType": "input_required", "requestState": params["requestState"],
                "_meta": {META + "status": "pending", META + "idempotency_key": claims["k"],
                          META + "message": "Awaiting approval. Retry with this requestState once the approver has confirmed."}}})
        if d.rule_id == "tier.L2.confirmed":  # the one path that executes for real: burn the key first, atomically
            if not await self.engine.store.consume_once(claims["k"], claims["exp"]):
                self._audit_deny(base, "mrtr.replay", d.tier, "idempotency key already used")
                return _tool_error(rid, "airlock: denied (mrtr.replay)", "mrtr.replay")
        d = await engine.reserve(who.sub, tool, d)  # atomic window charge; a replay never gets this far
        if d.verdict == "deny":
            self._audit_deny(base, d.rule_id, d.tier, d.message)
            return _tool_error(rid, f"airlock: denied ({d.rule_id}): {d.message}", d.rule_id)

        if d.verdict == "confirm" and not d.preview:
            # Tool has no dry_run: nothing safe to forward. Prompt the human without a preview.
            self.audit.write(phase="intent", verdict="confirm", rule_id=d.rule_id, tier=d.tier, dry_run=None, **base)
            result = self._input_required(who.sub, tool, args, None, policy)
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
        try:
            status, reply = await self.forward(fwd, fwd_headers, who)
        except UpstreamTooLarge as e:  # the upstream acted: on a real call the key stays burned and the charge stays
            self._outcome(verdict="error", rule_id="upstream.too_large", tier=d.tier, dry_run=d.dry_run,
                          upstream_status=e.status, latency_ms=_ms(t0), detail=f"limit {e.limit} bytes", **base)
            ran = "the dry run itself ran, nothing was executed" if d.dry_run else "the call itself ran"
            if d.verdict == "confirm":  # the preview is gone: no prompt without it, and a retry costs nothing
                ran += " and no confirmation was issued"
            return _tool_error(rid, f"airlock: the upstream response exceeded {e.limit} bytes and was dropped; {ran}", "upstream.too_large")
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
                if truncated := self._cap_output(tool, result, policy):  # after the _meta additions so the cap covers the final size
                    detail.update(truncated)
                if findings := guard.scan(result, policy.tools):
                    result["_meta"][META + "suspicious"] = findings  # marked, never blocked: the client decides how to render
                    detail["suspicious"] = sorted({f["rule"] for f in findings})
                    span.set_attribute("airlock.suspicious", len(findings))
            except Exception as e:
                log.exception("post-processing failed; returning the upstream result as-is")
                detail["postprocess_error"] = _exc_text(e)
            if d.verdict == "confirm" and status == 200 and not result.get("isError"):
                reply["result"] = self._input_required(who.sub, tool, args, result, policy)  # preview failed: no gate, just the error
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
            try:
                status, reply = await self.forward({"jsonrpc": "2.0", "id": f"airlock-catalog-{uuid.uuid4().hex[:8]}",
                                                    "method": "tools/list", "params": params}, list_headers, who)
            except UpstreamTooLarge as e:
                raise CatalogUnavailable(f"upstream tools/list response exceeded {e.limit} bytes") from e
            result = reply.get("result") if status == 200 else None
            if not isinstance(result, dict):
                raise CatalogUnavailable(f"upstream tools/list failed (HTTP {status}): {_clip(str(reply.get('error') or 'no result'))}")
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
        out_headers["accept-encoding"] = "identity"  # the limit below holds per wire chunk only while nothing is decoded
        out_headers["traceparent"] = meta.get("traceparent", "")
        out_headers.update(self.upstream_headers)
        chunks: list[bytes] = []
        total = 0
        try:
            async with self.http.stream("POST", self.upstream, content=json.dumps(dict(body, params=params)), headers=out_headers) as r:
                if r.headers.get("content-encoding", "identity").strip().lower() not in ("identity", ""):
                    # Refused unread: one gzip chunk can decode to a thousand times its size before the count below sees it.
                    return 502, {"jsonrpc": "2.0", "id": body["id"], "error": {"code": INTERNAL_ERROR, "message": f"upstream returned encoded content despite accept-encoding identity ({r.status_code})"}}
                async for chunk in r.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_upstream_bytes:
                        raise UpstreamTooLarge(r.status_code, self.max_upstream_bytes)  # leaving the block closes the response
                    chunks.append(chunk)
        except httpx.HTTPError as e:
            return 502, {"jsonrpc": "2.0", "id": body["id"], "error": {"code": INTERNAL_ERROR, "message": f"upstream unreachable: {type(e).__name__}"}}
        raw = b"".join(chunks)
        ctype = r.headers.get("content-type", "")
        if ctype.startswith("text/event-stream"):
            return r.status_code, _last_sse_message(raw.decode("utf-8", errors="replace"))
        try:
            reply = json.loads(raw)
        except ValueError:
            return 502, {"jsonrpc": "2.0", "id": body["id"], "error": {"code": INTERNAL_ERROR, "message": f"upstream returned non-JSON ({r.status_code})"}}
        if not isinstance(reply, dict):
            return 502, {"jsonrpc": "2.0", "id": body["id"], "error": {"code": INTERNAL_ERROR, "message": "upstream returned a non-object"}}
        return r.status_code, reply

    def _filter_tools(self, result: dict[str, Any], who: Principal, policy: Policy) -> None:
        tools = result.get("tools")
        if not isinstance(tools, list):
            return
        visible = [t for t in tools if isinstance(t, dict) and policy.tier(str(t.get("name")), who.sub, who.groups) is not None]
        result.setdefault("_meta", {})[META + "hidden_tools"] = len(tools) - len(visible)
        result["tools"] = visible  # ttlMs / cacheScope pass through untouched

    def _vet_tools(self, result: dict[str, Any], base: dict[str, Any], pins: dict[str, str] | None) -> None:
        """After the allowlist filter: drop pinned tools whose definition changed, mark suspicious descriptions and titles."""
        tools = result.get("tools")
        if not isinstance(tools, list):
            return
        meta = result.setdefault("_meta", {})
        if pins:
            kept: list[dict[str, Any]] = []
            dropped: list[dict[str, Any]] = []
            for t in tools:
                (dropped if tool_pins.changed(pins, t) else kept).append(t)
            if dropped:
                for t in dropped:  # own call_id: the tools/list call keeps its single intent/outcome pair
                    self._audit_deny(dict(base, call_id=uuid.uuid4().hex), "catalog.pin_mismatch", None,
                                     f"{t.get('name')}: definition changed since it was pinned")
                meta[META + "pin_mismatch"] = len(dropped)
                result["tools"] = tools = kept
        # one scan per tool: guard.scan dedupes by phrase, and the same phrase in two tools must name both
        findings = [{"rule": f["rule"], "tool": t.get("name"), "excerpt": f["excerpt"]} for t in tools
                    for f in guard.scan({"content": [{"type": "text", "text": x} for x in _tool_texts(t)]})]
        if findings:
            meta[META + "suspicious"] = findings[:guard.MAX_FINDINGS]  # marked, never removed; one cap for the whole list

    def _cap_output(self, tool: str, result: dict[str, Any], policy: Policy) -> dict[str, Any] | None:
        cap = policy.output_cap(tool)
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

    def _input_required(self, principal: str, tool: str, args: dict[str, Any], preview: dict[str, Any] | None,
                        policy: Policy) -> dict[str, Any]:
        token, key, _ = self.issue_token(principal, tool, args)
        rule = policy.tools[tool]
        env = policy.environment
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
        ask = ("Approval happens through the link sent to the approval channel; confirming in the client does not approve, "
               "and declining cancels the request." if self.approval_mode == "oob" else "Confirm to execute for real.")
        message = (f"[{env}] {tool}: {rule.description or 'write operation'} (tier L2).\n"
                   f"Arguments: {json.dumps(shown, ensure_ascii=False, default=str)}\n{preview_line}\n"
                   f"{ask} Idempotency key: {key}")
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
        message = result["inputRequests"][CONFIRM_KEY]["params"]["message"]
        stored = message.replace("\x00", "")  # Postgres text cannot hold NUL
        if len(stored) > PROMPT_TEXT_MAX:  # say so on the page: the cut can hide the target argument and the preview
            stored = stored[:PROMPT_TEXT_MAX - len(PROMPT_CUT_NOTE)] + PROMPT_CUT_NOTE
        try:  # the approve page shows this text; a failed save only leaves the page without it
            claims = self.verify_token(result["requestState"])
            await self.engine.store.save_prompt(claims["k"], stored, claims["exp"])
        except Exception as e:
            log.warning("saving the approval prompt text failed: %s", type(e).__name__)
        text = f"mcp-airlock approval request from {principal}\n" + message
        await approvals.notify(text, self.approve_link(result["requestState"]), webhook=self.webhook,
                               http=self.notify_http, telegram_chat=self.telegram_chat)

    # ---------- probes: no identity, no audit, no span, no upstream ----------
    async def healthz(self, request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(self, request: Request) -> Response:
        ping = self._ping
        if ping is None or ping.done():
            # Never cancelled: psycopg answers a cancel on a silent query by waiting for it without a bound.
            ping = self._ping = asyncio.create_task(self.engine.store.ping())
            # Retrieved here: a failure after the probe gave up is otherwise logged by asyncio with the exception text.
            ping.add_done_callback(lambda t: t.cancelled() or t.exception())
        try:
            await asyncio.wait_for(asyncio.shield(ping), READY_TIMEOUT_S)
        except Exception as e:  # the body never carries exception text
            if self._ping is ping:
                self._ping = None  # left behind: a ping stuck on a black-holed socket would otherwise pin /readyz at 503
            log.warning("readiness check failed: %s", type(e).__name__)
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok"})

    # ---------- out-of-band approval page ----------
    def _approval_claims(self, request: Request) -> dict[str, Any] | None:
        claims = self.verify_token(request.path_params["token"], APPROVE_PREFIX)  # an agent's requestState is refused here
        return claims if claims and claims["exp"] >= time.time() else None

    async def approve_page(self, request: Request) -> Response:
        if (claims := self._approval_claims(request)) is None:
            return HTMLResponse("Invalid or expired approval link.", status_code=400)
        # GET only renders (link unfurlers and prefetchers do GETs); the POST below approves.
        try:  # a store outage leaves the page without the text, like a failed save
            text = await self.engine.store.get_prompt(claims["k"])
        except Exception as e:
            log.warning("reading the approval prompt text failed: %s", type(e).__name__)
            text = None
        details = (f"<pre>{html.escape(text)}</pre>" if text is not None else
                   "<p>The details of this request are not available; check the original message before approving.</p>")
        return HTMLResponse(f"""<!doctype html><title>mcp-airlock approval</title>
<h2>Approve tool call?</h2>
<p><b>{html.escape(claims['t'])}</b> requested by <b>{html.escape(claims['p'])}</b> in <b>{html.escape(claims['e'])}</b><br>
idempotency key <code>{html.escape(claims['k'])}</code></p>
{details}
<form method="post"><button type="submit">Approve</button></form>""")

    async def approve_submit(self, request: Request) -> Response:
        if (claims := self._approval_claims(request)) is None:
            return HTMLResponse("Invalid or expired approval link.", status_code=400)
        await self.engine.store.approve(claims["k"], claims["exp"])
        headers = {k.lower(): v for k, v in request.headers.items()}
        who = await self._resolve(headers)
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


def _clip(text: str) -> str:
    """Upstream or exception text bound for the caller or the audit: scrubbed first, so a cut never splits a credential."""
    return scrub(text)[:ERROR_TEXT_MAX]


def _exc_text(e: Exception) -> str:
    return f"{type(e).__name__}: {_clip(str(e))}"


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


def _env_limit(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        n = 0
    if n <= 0:
        raise ValueError(f"{name} must be a positive integer, got {raw!r}")
    return n


def build(policy_path: str, upstream: str, audit_path: str, environment: str | None = None, pins_path: str | None = None,
          audit_max_bytes: int | None = None, audit_keep: int = 5, **kw: Any) -> Airlock:
    policy = Policy.load(policy_path, environment or os.environ.get("AIRLOCK_ENV"))
    max_request = _env_limit("AIRLOCK_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES)  # before the audit file and store open
    max_upstream = _env_limit("AIRLOCK_MAX_UPSTREAM_BYTES", DEFAULT_MAX_UPSTREAM_BYTES)
    secret = os.environ.get("AIRLOCK_SECRET")
    upstream_headers = {}
    if auth := os.environ.get("AIRLOCK_UPSTREAM_AUTH"):
        upstream_headers["authorization"] = auth
    webhook, telegram_chat = approvals.config_from_env()
    return Airlock(policy, upstream, audit_from_env(audit_path, audit_max_bytes, audit_keep),
                   secret=secret.encode() if secret else None,
                   identity=IdentityConfig.from_env(), store=store_from_env(),
                   upstream_headers=upstream_headers, webhook=webhook, telegram_chat=telegram_chat,
                   public_url=os.environ.get("AIRLOCK_PUBLIC_URL", "http://127.0.0.1:9000"),
                   approval_mode=os.environ.get("AIRLOCK_APPROVAL_MODE") or None,
                   max_request_bytes=max_request, max_upstream_bytes=max_upstream,
                   reload_source=ReloadSource(policy_path, pins_path), **kw)
