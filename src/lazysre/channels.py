from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ChannelMessage:
    provider: str
    text: str
    user_id: str = ""
    chat_id: str = ""
    event_id: str = ""
    raw: dict[str, Any] | None = None


class ChannelParseError(ValueError):
    pass


def parse_channel_message(provider: str, payload: dict[str, Any]) -> ChannelMessage:
    name = provider.strip().lower()
    if name == "generic":
        return _parse_generic(payload, name)
    if name == "telegram":
        return _parse_telegram(payload, name)
    if name in {"dingtalk", "dingding"}:
        return _parse_dingtalk(payload, "dingtalk")
    if name == "feishu":
        return _parse_feishu(payload, name)
    if name in {"qq", "onebot"}:
        return _parse_onebot(payload, "onebot")
    raise ChannelParseError(f"unsupported channel provider: {provider}")


def format_channel_reply(provider: str, reply: str, message: ChannelMessage) -> dict[str, Any]:
    name = provider.strip().lower()
    text = _limit_reply(reply)
    if name == "telegram":
        return {"method": "sendMessage", "chat_id": message.chat_id, "text": text}
    if name in {"dingtalk", "dingding"}:
        return {"msgtype": "text", "text": {"content": text}}
    if name == "feishu":
        return {"reply": text, "note": "Use Feishu send API with this reply text."}
    if name in {"qq", "onebot"}:
        return {"reply": text, "message_type": "text", "user_id": message.user_id, "group_id": message.chat_id}
    return {"reply": text}


def _parse_generic(payload: dict[str, Any], provider: str) -> ChannelMessage:
    text = str(payload.get("text") or payload.get("message") or "").strip()
    if not text:
        raise ChannelParseError("generic payload requires text/message")
    return ChannelMessage(
        provider=provider,
        text=text,
        user_id=str(payload.get("user_id") or payload.get("user") or ""),
        chat_id=str(payload.get("chat_id") or payload.get("chat") or ""),
        event_id=str(
            payload.get("event_id")
            or payload.get("message_id")
            or payload.get("request_id")
            or payload.get("id")
            or ""
        ),
        raw=payload,
    )


def _parse_telegram(payload: dict[str, Any], provider: str) -> ChannelMessage:
    msg = payload.get("message") or payload.get("edited_message") or {}
    if not isinstance(msg, dict):
        raise ChannelParseError("telegram payload missing message")
    text = str(msg.get("text") or "").strip()
    if not text:
        raise ChannelParseError("telegram message text is empty")
    chat = msg.get("chat") or {}
    sender = msg.get("from") or {}
    return ChannelMessage(
        provider=provider,
        text=text,
        user_id=str(sender.get("id") or ""),
        chat_id=str(chat.get("id") or ""),
        event_id=str(payload.get("update_id") or msg.get("message_id") or ""),
        raw=payload,
    )


def _parse_dingtalk(payload: dict[str, Any], provider: str) -> ChannelMessage:
    text_obj = payload.get("text") or {}
    text = ""
    if isinstance(text_obj, dict):
        text = str(text_obj.get("content") or "").strip()
    if not text:
        text = str(payload.get("content") or payload.get("text") or "").strip()
    if not text:
        raise ChannelParseError("dingtalk payload text.content is empty")
    return ChannelMessage(
        provider=provider,
        text=text,
        user_id=str(payload.get("senderStaffId") or payload.get("senderId") or ""),
        chat_id=str(payload.get("conversationId") or ""),
        event_id=str(payload.get("msgId") or payload.get("messageId") or payload.get("sessionWebhookExpiredTime") or ""),
        raw=payload,
    )


def _parse_feishu(payload: dict[str, Any], provider: str) -> ChannelMessage:
    if payload.get("challenge"):
        return ChannelMessage(provider=provider, text="", raw=payload)
    event = payload.get("event") or {}
    if not isinstance(event, dict):
        raise ChannelParseError("feishu payload missing event")
    msg = event.get("message") or {}
    sender = event.get("sender") or {}
    content = msg.get("content") or ""
    text = ""
    if isinstance(content, str):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                text = str(parsed.get("text") or "").strip()
        except Exception:
            text = content.strip()
    elif isinstance(content, dict):
        text = str(content.get("text") or "").strip()
    if not text:
        raise ChannelParseError("feishu message text is empty")
    sender_id = sender.get("sender_id") if isinstance(sender, dict) else {}
    header = payload.get("header") or {}
    if not isinstance(header, dict):
        header = {}
    return ChannelMessage(
        provider=provider,
        text=text,
        user_id=str((sender_id or {}).get("open_id") or ""),
        chat_id=str(msg.get("chat_id") or ""),
        event_id=str(header.get("event_id") or msg.get("message_id") or ""),
        raw=payload,
    )


def _parse_onebot(payload: dict[str, Any], provider: str) -> ChannelMessage:
    text = str(payload.get("raw_message") or payload.get("message") or "").strip()
    if not text:
        raise ChannelParseError("onebot payload raw_message/message is empty")
    return ChannelMessage(
        provider=provider,
        text=text,
        user_id=str(payload.get("user_id") or ""),
        chat_id=str(payload.get("group_id") or payload.get("guild_id") or ""),
        event_id=str(payload.get("message_id") or payload.get("id") or ""),
        raw=payload,
    )


def _limit_reply(text: str, limit: int = 3600) -> str:
    value = str(text or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 40].rstrip() + "\n... [truncated by LazySRE channel gateway]"
