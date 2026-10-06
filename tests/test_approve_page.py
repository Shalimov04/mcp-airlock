"""The approve page at the HTTP level, the way the end-to-end pass found it: the headers every response carries."""

from __future__ import annotations

from .conftest import call
from .test_features import approve_path, proxy_client, webhook_airlock


async def test_approve_page_sends_anti_framing_referrer_and_cache_headers(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
        path = approve_path(posted)
        responses = [await c.get(path), await c.post(path), await c.post(path),  # page, approval, already approved
                     await c.get("/approve/al2.bogus.sig"), await c.post("/approve/al2.bogus.sig")]
    assert [r.status_code for r in responses] == [200, 200, 200, 400, 400]
    for r in responses:
        h = r.headers
        assert h["x-frame-options"] == "DENY" and h["referrer-policy"] == "no-referrer", dict(h)
        assert h["cache-control"] == "no-store" and h["x-content-type-options"] == "nosniff"
        csp = h["content-security-policy"]
        assert "frame-ancestors 'none'" in csp and "form-action 'self'" in csp and "default-src 'none'" in csp
