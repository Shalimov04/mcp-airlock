"""Out-of-band approval notification: one POST to a Slack-compatible webhook or a Telegram bot URL."""

from __future__ import annotations

import logging
import os

import httpx

log = logging.getLogger(__name__)


def config_from_env() -> tuple[str | None, str | None]:
    return os.environ.get("AIRLOCK_APPROVAL_WEBHOOK") or None, os.environ.get("AIRLOCK_TELEGRAM_CHAT") or None


async def notify(text: str, approve_url: str, *, webhook: str | None, http: httpx.AsyncClient,
                 telegram_chat: str | None = None) -> bool:
    """True when the webhook accepted the message. False (never raises) when unconfigured or delivery failed."""
    if not webhook:
        return False
    body = f"{text}\n\nApprove: {approve_url}"
    payload = ({"chat_id": telegram_chat, "text": body, "disable_web_page_preview": True}
               if "api.telegram.org" in webhook else {"text": body})
    try:
        (await http.post(webhook, json=payload, timeout=5.0)).raise_for_status()
        return True
    except httpx.HTTPError as e:  # ponytail: no retry; the approve link still works, the human just isn't pinged
        log.warning("approval notify failed: %s", e)
        return False
