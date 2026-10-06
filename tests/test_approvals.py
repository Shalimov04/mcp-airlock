import logging

import httpx

from mcp_airlock import approvals


def _http(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _capture(status=200):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(status, json={"ok": True})

    return seen, handler


TELEGRAM_SECRET_URL = "https://api.telegram.org/bot123:SECRET/sendMessage"


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


async def test_invalid_url_and_closed_client_are_false():
    _, h = _capture()
    assert await approvals.notify("hi", "u", webhook="https://hooks.slack.com:abc/x", http=_http(h)) is False
    closed = _http(h)
    await closed.aclose()
    assert await approvals.notify("hi", "u", webhook="https://hooks/x", http=closed) is False


async def test_failed_delivery_log_has_no_url(caplog):
    caplog.set_level(logging.WARNING, logger="httpx")  # httpx prints the URL at INFO by design; the proxy's own loggers are watched at DEBUG
    caplog.set_level(logging.DEBUG, logger="mcp_airlock")

    def unauthorized(request):
        return httpx.Response(401, json={"description": "BODYMARK"})

    ok = await approvals.notify("hi", "u", webhook=TELEGRAM_SECRET_URL, http=_http(unauthorized), telegram_chat="-100")
    assert ok is False
    assert "SECRET" not in caplog.text and "telegram" not in caplog.text and "BODYMARK" not in caplog.text
    assert "HTTPStatusError" in caplog.text and "401" in caplog.text


async def test_network_error_log_has_class_only(caplog):
    caplog.set_level(logging.WARNING, logger="httpx")
    caplog.set_level(logging.DEBUG, logger="mcp_airlock")

    def boom(request):
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    ok = await approvals.notify("hi", "u", webhook=TELEGRAM_SECRET_URL, http=_http(boom), telegram_chat="-100")
    assert ok is False
    assert "SECRET" not in caplog.text and "telegram" not in caplog.text
    assert "ConnectError" in caplog.text and "HTTP status" not in caplog.text


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


async def test_slack_text_is_escaped_so_nothing_renders_as_a_hidden_link_or_a_mention():
    seen, h = _capture()
    text = ('Arguments: {"name": "x <https://evil.example/approve|https://airlock/approve/al2.REAL> <!channel> a & b"}\n'
            "Dry-run preview: would delete x\n\nApprove: <https://evil.example/approve|Approve here>")
    assert await approvals.notify(text, "https://airlock/approve/abc", webhook="https://hooks.slack.com/x", http=_http(h))
    body = httpx.Response(200, content=seen[0].content).json()["text"]
    assert body.endswith("\n\nApprove: https://airlock/approve/abc")
    assert "<" not in body and ">" not in body  # nothing Slack would render as a link or a mention
    assert "&lt;https://evil.example/approve|https://airlock/approve/al2.REAL&gt;" in body
    assert "&lt;!channel&gt;" in body and "a &amp; b" in body


async def test_telegram_text_is_sent_as_is():
    seen, h = _capture()  # plain-text mode: entities would show up literally
    assert await approvals.notify("a < b & c", "https://a/1", webhook="https://api.telegram.org/botT/sendMessage",
                                  http=_http(h), telegram_chat="-100")
    assert httpx.Response(200, content=seen[0].content).json()["text"] == "a < b & c\n\nApprove: https://a/1"


def test_slack_escape_does_not_double_escape():
    assert approvals.slack_escape("&lt; & < >") == "&amp;lt; &amp; &lt; &gt;"
