"""The approve page at the HTTP level, the way the end-to-end pass found it: what it shows and answers once the
confirmation is burned or already approved, and the headers every response carries."""

from __future__ import annotations

from mcp_airlock.app import CONFIRM_KEY, META

from .conftest import audit_rows, call
from .test_features import approve_path, proxy_client, real_deletes, webhook_airlock

DECLINE = {CONFIRM_KEY: {"action": "decline"}}


async def test_approve_after_a_decline_or_an_execution_is_refused_and_not_audited(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token, "inputResponses": DECLINE})
        assert res["_meta"][META + "rule_id"] == "mrtr.declined"
        path = approve_path(posted)
        page = await c.get(path)
        assert page.status_code == 200 and "<form" not in page.text and "already executed or declined" in page.text
        for i in range(3):
            r = await c.post(path, headers={"x-forwarded-user": f"bob{i}"})
            assert r.status_code == 409 and "already executed or declined" in r.text and "retry now" not in r.text
        token = (await call(c, "delete_service", {"name": "db"}))["requestState"]  # a second prompt, approved and run
        assert (await c.post(approve_path(posted))).status_code == 200
        res = await call(c, "delete_service", {"name": "db"}, extra={"requestState": token})
        assert res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
        assert (await c.post(approve_path(posted))).status_code == 409
        assert "<form" not in (await c.get(approve_path(posted))).text
    approved = [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.approved_oob"]
    assert len(approved) == 2 and {r["detail"]["key"] for r in approved} == {al.verify_token(token)["k"]}  # one pair, one key
    assert len(real_deletes(upstream)) == 1


async def test_a_second_approve_click_changes_nothing_and_is_not_recorded_twice(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
        path = approve_path(posted)
        assert "<form" in (await c.get(path)).text
        assert (await c.post(path)).status_code == 200
        page = await c.get(path)
        assert "<form" not in page.text and "Already approved" in page.text
        r = await c.post(path)
        assert r.status_code == 200 and "already approved" in r.text.lower()
    assert len([r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.approved_oob"]) == 2


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
