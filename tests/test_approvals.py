import httpx
import pytest

from mcp_airlock import approvals


def _http(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _capture(status=200):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(status, json={"ok": True})

    return seen, handler


async def test_slack_payload():
    seen, h = _capture()
    ok = await approvals.notify("delete_service prod-db", "https://airlock/approve/abc", webhook="https://hooks.slack.com/x", http=_http(h))
    assert ok and len(seen) == 1
    req = seen[0]
    assert req.method == "POST" and str(req.url) == "https://hooks.slack.com/x"
    assert httpx.Response(200, content=req.content).json() == {"text": "delete_service prod-db\n\nApprove: https://airlock/approve/abc"}


async def test_telegram_payload():
    seen, h = _capture()
    ok = await approvals.notify("hi", "https://a/1", webhook="https://api.telegram.org/botT/sendMessage", http=_http(h), telegram_chat="-100")
    assert ok
    assert httpx.Response(200, content=seen[0].content).json() == {
        "chat_id": "-100", "text": "hi\n\nApprove: https://a/1", "disable_web_page_preview": True}


async def test_non_2xx_is_false():
    _, h = _capture(500)
    assert await approvals.notify("hi", "u", webhook="https://hooks/x", http=_http(h)) is False


async def test_connection_error_is_false():
    def boom(request):
        raise httpx.ConnectError("nope")

    assert await approvals.notify("hi", "u", webhook="https://hooks/x", http=_http(boom)) is False


async def test_no_webhook_no_io():
    seen, h = _capture()
    assert await approvals.notify("hi", "u", webhook=None, http=_http(h)) is False
    assert seen == []


def test_config_from_env(monkeypatch):
    monkeypatch.delenv("AIRLOCK_APPROVAL_WEBHOOK", raising=False)
    monkeypatch.delenv("AIRLOCK_TELEGRAM_CHAT", raising=False)
    assert approvals.config_from_env() == (None, None)
    monkeypatch.setenv("AIRLOCK_APPROVAL_WEBHOOK", "https://hooks/x")
    monkeypatch.setenv("AIRLOCK_TELEGRAM_CHAT", "42")
    assert approvals.config_from_env() == ("https://hooks/x", "42")
