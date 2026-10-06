"""Out-of-band approval notification: one POST to a Slack-compatible webhook or a Telegram bot URL."""

from __future__ import annotations

import logging
import os

import httpx

log = logging.getLogger(__name__)


def config_from_env() -> tuple[str | None, str | None]:
    return os.environ.get("AIRLOCK_APPROVAL_WEBHOOK") or None, os.environ.get("AIRLOCK_TELEGRAM_CHAT") or None


def slack_escape(text: str) -> str:
    """The three characters Slack's message parser treats as markup, in the order the docs give."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def notify(text: str, approve_url: str, *, webhook: str | None, http: httpx.AsyncClient,
                 telegram_chat: str | None = None) -> bool:
    """True when the webhook accepted the message. False (never raises) when unconfigured or delivery failed."""
    if not webhook:
        return False
    if "api.telegram.org" in webhook:
        payload = {"chat_id": telegram_chat, "text": f"{text}\n\nApprove: {approve_url}", "disable_web_page_preview": True}
    else:
        # Slack parses <url|label> and <!channel> wherever they appear, and the text carries agent-controlled
        # arguments and the upstream's preview. Escaped, nothing in it renders as a hidden-target link or a mention;
        # a bare URL still shows as one, so the README tells approvers to read the Approve line at the end.
        payload = {"text": f"{slack_escape(text)}\n\nApprove: {approve_url}"}
    try:
        (await http.post(webhook, json=payload, timeout=5.0)).raise_for_status()
        return True
    except Exception as e:  # ponytail: no retry; the approve link still works, the human just isn't pinged
        # Exception, not HTTPError: a bad URL or a closed client must not become an internal error. str(e) carries the URL, the URL carries the token: class and status only
        status = f", HTTP status {e.response.status_code}" if isinstance(e, httpx.HTTPStatusError) else ""
        log.warning("approval notify failed: %s%s", type(e).__name__, status)
        return False
