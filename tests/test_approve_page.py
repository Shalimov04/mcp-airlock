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


async def _boom(*a):
    raise RuntimeError("db down at postgresql://user:pw@host/db")


async def test_approve_page_keeps_the_text_when_only_the_state_read_fails(upstream, audit_path, caplog):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
        al.engine.store.is_consumed = _boom  # the text was read fine; the state is what fails
        page = (await c.get(approve_path(posted))).text
    assert "<pre>" in page and "would delete api" in page and "not available" not in page
    assert "<form" in page  # unknown state: the button stays, the POST checks again
    assert "RuntimeError" in caplog.text and "pw@host" not in caplog.text


async def test_approve_submit_answers_503_with_the_page_headers_when_the_store_is_down(upstream, audit_path, caplog):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
        path = approve_path(posted)
        for failing in ("is_consumed", "approve"):
            store, saved = al.engine.store, getattr(al.engine.store, failing)
            setattr(store, failing, _boom)
            r = await c.post(path, headers={"x-forwarded-user": "bob"})
            setattr(store, failing, saved)
            assert r.status_code == 503 and "not recorded" in r.text, failing
            assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
            assert "pw@host" not in r.text
        assert (await c.post(path, headers={"x-forwarded-user": "bob"})).status_code == 200  # the store is back
    assert len([r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.approved_oob"]) == 2  # the one real click
    assert "pw@host" not in caplog.text


async def test_approve_submit_records_an_unverified_click_when_resolving_the_approver_fails(upstream, audit_path, caplog):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
        al._resolve = _boom  # whatever the identity layer may raise once the approval is already in the store
        r = await c.post(approve_path(posted), headers={"authorization": "Bearer t", "x-forwarded-user": "bob"})
    assert r.status_code == 200 and "Approved" in r.text and r.headers["x-frame-options"] == "DENY"
    approved = [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.approved_oob"]
    assert len(approved) == 2 and approved[0]["detail"]["approved_by"] == "bob"
    assert approved[0]["detail"]["approved_by_source"] == "header"  # never "verified" on a failed check
    assert "RuntimeError" in caplog.text and "pw@host" not in caplog.text


async def test_an_oversized_argument_cannot_push_the_proxy_link_out_of_the_message(upstream, audit_path):
    # Slack truncates past 40000 characters and Telegram refuses past 4096. Padded so that a planted "Approve:" line
    # sits just before the cut, the real line would be the part that is lost. The text is bounded before the link.
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    planted = "Approve: https://evil.example/approve/al2.REAL"
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api", "note": "a" * 45000 + "\n\n" + planted})
    assert len(posted) == 1 and len(posted[0]) <= 4096
    assert "[cut at 3500 characters;" in posted[0] and planted not in posted[0]
    assert posted[0].count("Approve:") == 1 and posted[0].rsplit("\n\nApprove: ", 1)[1].startswith("https://a.example/approve/")
