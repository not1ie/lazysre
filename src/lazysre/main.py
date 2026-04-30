import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse

from lazysre import __version__
from lazysre.cli.approval import ApprovalStore
from lazysre.cli.memory import IncidentMemoryStore
from lazysre.cli.policy import assess_command
from lazysre.cli.target import TargetEnvStore
from lazysre.cli.target_profiles import ClusterProfileStore
from lazysre.channels import ChannelParseError, format_channel_reply, parse_channel_message
from lazysre.integrations.aiops_bridge import (
    AIOpsBridgeClient,
    AIOpsBridgeConfig,
    AIOpsBridgeStore,
)
from lazysre.models import MemorySearchResponse, TaskCreateRequest, TaskRecord
from lazysre.platform.models import (
    AgentCreateRequest,
    AgentDefinition,
    ApprovalAdvice,
    ArtifactItem,
    AutoDesignRequest,
    EnvironmentBootstrapRequest,
    EnvironmentBootstrapResult,
    IncidentBriefing,
    OpsToolDefinition,
    PlatformOverview,
    PlatformTemplate,
    QuickstartRequest,
    RunComparison,
    RunApprovalRequest,
    RunCreateRequest,
    SkillCreateRequest,
    SkillDefinition,
    SkillRunRequest,
    SkillRunResult,
    ToolCreateRequest,
    ToolHealthItem,
    ToolProbeRequest,
    ToolProbeResult,
    WorkflowCreateRequest,
    WorkflowDefinition,
    WorkflowRun,
)
from lazysre.platform.service import PlatformService
from lazysre.services.task_service import TaskService

app = FastAPI(title="LazySRE", version=__version__)
task_service = TaskService()
platform_service = PlatformService()


def _aiops_bridge_config_path() -> Path:
    primary = Path.home() / ".lazysre" / "aiops_bridge.json"
    try:
        primary.parent.mkdir(parents=True, exist_ok=True)
        return primary
    except Exception:
        fallback = Path(".data/lsre-aiops-bridge.json")
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


def _open_aiops_bridge_store() -> AIOpsBridgeStore:
    return AIOpsBridgeStore(_aiops_bridge_config_path())


def _build_aiops_bridge_client(config: AIOpsBridgeConfig, *, explicit_api_key: str = "") -> AIOpsBridgeClient:
    return AIOpsBridgeClient(config, explicit_api_key=explicit_api_key)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"service": "lazysre", "status": "ok"}


@app.get("/v1/aiops/bridge")
async def aiops_bridge_show() -> dict[str, Any]:
    store = _open_aiops_bridge_store()
    cfg = store.load()
    return {
        "base_url": cfg.base_url,
        "api_key_env": cfg.api_key_env,
        "has_api_key": bool(os.getenv(cfg.api_key_env, "").strip()),
        "timeout_sec": cfg.timeout_sec,
        "verify_tls": cfg.verify_tls,
        "updated_at": cfg.updated_at,
        "config_path": str(_aiops_bridge_config_path()),
    }


@app.post("/v1/aiops/bridge/bind")
async def aiops_bridge_bind(payload: dict[str, Any]) -> dict[str, Any]:
    base_url = str(payload.get("base_url", "")).strip()
    if not base_url:
        raise HTTPException(status_code=400, detail="base_url is required")
    api_key_env = str(payload.get("api_key_env", "LAZY_AIOPS_API_KEY")).strip() or "LAZY_AIOPS_API_KEY"
    timeout_sec = max(3, min(int(payload.get("timeout_sec", 12) or 12), 120))
    verify_tls = bool(payload.get("verify_tls", True))
    store = _open_aiops_bridge_store()
    saved = store.save(
        AIOpsBridgeConfig(
            base_url=base_url,
            api_key_env=api_key_env,
            timeout_sec=timeout_sec,
            verify_tls=verify_tls,
        )
    )
    saved["config_path"] = str(_aiops_bridge_config_path())
    saved["has_api_key"] = bool(os.getenv(api_key_env, "").strip())
    return saved


@app.get("/v1/aiops/bridge/ping")
async def aiops_bridge_ping(x_aiops_api_key: str = Header(default="")) -> dict[str, Any]:
    store = _open_aiops_bridge_store()
    cfg = store.load()
    client = _build_aiops_bridge_client(cfg, explicit_api_key=x_aiops_api_key.strip())
    payload = client.health()
    payload["base_url"] = cfg.base_url
    payload["api_key_env"] = cfg.api_key_env
    payload["has_api_key"] = bool(os.getenv(cfg.api_key_env, "").strip() or x_aiops_api_key.strip())
    return payload


@app.get("/v1/aiops/bridge/skills")
async def aiops_bridge_skills(
    limit: int = 30,
    min_score: float = 0.0,
    source_contains: str = "",
    x_aiops_api_key: str = Header(default=""),
) -> dict[str, Any]:
    cap = max(1, min(int(limit), 200))
    store = _open_aiops_bridge_store()
    cfg = store.load()
    client = _build_aiops_bridge_client(cfg, explicit_api_key=x_aiops_api_key.strip())
    payload = client.list_skills(limit=cap)
    # Reserved fields for web-side unified filters, kept for forward compatibility.
    payload["query_options"] = {
        "limit": cap,
        "min_score": max(0.0, min(float(min_score), 1.0)),
        "source_contains": str(source_contains or "").strip(),
    }
    payload["base_url"] = cfg.base_url
    payload["api_key_env"] = cfg.api_key_env
    payload["has_api_key"] = bool(os.getenv(cfg.api_key_env, "").strip() or x_aiops_api_key.strip())
    return payload


@app.post("/v1/channels/{provider}/webhook")
async def channel_webhook(
    provider: str,
    request: Request,
    x_lazysre_channel_token: str = Header(default=""),
    x_telegram_bot_api_secret_token: str = Header(default=""),
    x_lark_request_timestamp: str = Header(default=""),
    x_lark_request_nonce: str = Header(default=""),
    x_lark_signature: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> dict[str, Any]:
    body_bytes = await request.body()
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid json payload: {exc}") from exc
    if provider.strip().lower() == "feishu" and isinstance(payload, dict) and payload.get("challenge"):
        return {"challenge": payload.get("challenge")}

    expected = os.environ.get("LAZYSRE_CHANNEL_TOKEN", "").strip()
    if expected and not secrets.compare_digest(x_lazysre_channel_token.strip(), expected):
        raise HTTPException(status_code=401, detail="channel token required")
    _verify_channel_signature(
        provider=provider,
        payload=payload,
        body_bytes=body_bytes,
        telegram_secret_header=x_telegram_bot_api_secret_token,
        lark_timestamp=x_lark_request_timestamp,
        lark_nonce=x_lark_request_nonce,
        lark_signature=x_lark_signature,
        onebot_signature=x_signature,
        request=request,
    )

    try:
        message = parse_channel_message(provider, payload)
    except ChannelParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    trace_id = _channel_trace_id(provider=provider, event_id=str(getattr(message, "event_id", "") or ""))
    control = _maybe_handle_channel_control(provider=provider, message=message, trace_id=trace_id)
    if control is not None:
        return control
    duplicate = _register_channel_event(provider=provider, message=message)
    if duplicate:
        duplicate_text = "duplicate event ignored"
        final_reply = format_channel_reply(provider, duplicate_text, message)
        receipt = _build_channel_receipt(
            provider=provider,
            event_id=message.event_id,
            phase="dedup",
            status="ignored",
            trace_id=trace_id,
            detail="duplicate event",
        )
        return {
            "ok": True,
            "provider": provider,
            "dry_run": True,
            "duplicate": True,
            "event_id": message.event_id,
            "trace_id": trace_id,
            "reply": final_reply,
            "event_count": 0,
            "ack": {
                "received_at": datetime.now(timezone.utc).isoformat(),
                "provider": provider,
                "event_id": message.event_id,
                "trace_id": trace_id,
                "duplicate": True,
            },
            "progress": [{"step": "dedup", "status": "ignored"}],
            "lifecycle": _channel_lifecycle(["queued", "ignored"], trace_id=trace_id),
            "final": {
                "text": duplicate_text,
                "reply": final_reply,
                "handoff": None,
                "trace_id": trace_id,
            },
            "receipt": receipt,
        }

    session_key = _channel_session_key(provider=provider, message=message)
    history_context = _channel_history_context(session_key=session_key, lookback=4)
    progress: list[dict[str, Any]] = [
        {"step": "received", "status": "ok"},
        {"step": "session_context", "status": "loaded", "history_chars": len(history_context)},
    ]

    from lazysre.cli.main import _dispatch

    result = await _dispatch(
        instruction=message.text,
        execute=False,
        approve=False,
        interactive_approval=False,
        approval_mode=os.environ.get("LAZYSRE_CHANNEL_APPROVAL_MODE", "strict"),
        audit_log=os.environ.get("LAZYSRE_CHANNEL_AUDIT_LOG", ".data/lsre-channel-audit.jsonl"),
        lock_file=os.environ.get("LAZYSRE_CHANNEL_LOCK_FILE", ".data/lsre-tool-lock.json"),
        deny_tool=[],
        deny_prefix=[],
        tool_pack=["builtin"],
        remote_gateway=[],
        model=os.environ.get("LAZYSRE_CHANNEL_MODEL", os.environ.get("LAZYSRE_MODEL_NAME", "gpt-5.4-mini")),
        provider=os.environ.get("LAZYSRE_CHANNEL_PROVIDER", "mock"),
        max_steps=int(os.environ.get("LAZYSRE_CHANNEL_MAX_STEPS", "4")),
        conversation_context=history_context,
    )
    progress.append({"step": "dispatch", "status": "completed", "event_count": len(result.events)})
    rendered = result.final_text
    timeline = _compact_channel_timeline(result.events)
    actionables = _build_channel_actionables(
        rendered,
        approval_mode=os.environ.get("LAZYSRE_CHANNEL_APPROVAL_MODE", "strict"),
    )
    execution_templates = _build_execution_templates_from_actionables(
        actionables,
        source="webhook",
        approval_ticket=os.environ.get("LAZYSRE_APPROVAL_TICKET", "").strip(),
        target_context=_channel_target_context(),
    )
    run_artifact = _create_channel_run_artifact(
        provider=provider,
        trace_id=trace_id,
        user_id=message.user_id,
        chat_id=message.chat_id,
        instruction=message.text,
        final_text=rendered,
        event_count=len(result.events),
        timeline=timeline,
        actionables=actionables,
        execution_templates=execution_templates,
    )
    _channel_session_append(
        session_key=session_key,
        user_text=message.text,
        assistant_text=rendered,
    )
    _channel_session_set_last_actionables(session_key=session_key, actionables=actionables)
    handoff = _create_channel_handoff(
        provider=provider,
        instruction=message.text,
        reply=rendered,
        events=result.events,
        user_id=message.user_id,
        chat_id=message.chat_id,
        trace_id=trace_id,
        run_artifact=run_artifact,
    )
    progress.append({"step": "handoff", "status": "created", "handoff_id": handoff.get("id", "")})
    progress.append({"step": "timeline", "status": "ready", "items": len(timeline)})
    progress.append({"step": "actionables", "status": "ready", "commands": len(actionables.get("commands", []))})
    progress.append(
        {"step": "execution_templates", "status": "ready", "items": len(execution_templates.get("items", []))}
    )
    progress.append({"step": "artifact", "status": "saved", "path": run_artifact.get("path", "")})
    final_reply = format_channel_reply(provider, rendered, message)
    receipt = _build_channel_receipt(
        provider=provider,
        event_id=message.event_id,
        phase="completed",
        status="succeeded",
        trace_id=trace_id,
        detail=f"events={len(result.events)} actionables={len(actionables.get('commands', []))}",
    )
    return {
        "ok": True,
        "provider": provider,
        "dry_run": True,
        "event_id": message.event_id,
        "trace_id": trace_id,
        "reply": final_reply,
        "event_count": len(result.events),
        "handoff": handoff,
        "timeline": timeline,
        "actionables": actionables,
        "execution_templates": execution_templates,
        "artifacts": {
            "run": run_artifact,
        },
        "ack": {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "event_id": message.event_id,
            "trace_id": trace_id,
            "duplicate": False,
        },
        "progress": progress,
        "lifecycle": _channel_lifecycle(["queued", "running", "succeeded"], trace_id=trace_id),
        "final": {
            "text": rendered,
            "reply": final_reply,
            "handoff": handoff,
            "timeline": timeline,
            "actionables": actionables,
            "execution_templates": execution_templates,
            "trace_id": trace_id,
            "artifacts": {
                "run": run_artifact,
            },
        },
        "session": {
            "key": session_key,
            "turns": _channel_session_turn_count(session_key=session_key),
        },
        "receipt": receipt,
    }


def _verify_channel_signature(
    *,
    provider: str,
    payload: dict[str, Any],
    body_bytes: bytes,
    telegram_secret_header: str,
    lark_timestamp: str,
    lark_nonce: str,
    lark_signature: str,
    onebot_signature: str,
    request: Request,
) -> None:
    name = provider.strip().lower()
    if name == "telegram":
        expected = os.environ.get("LAZYSRE_TELEGRAM_SECRET_TOKEN", "").strip()
        if expected and not secrets.compare_digest(telegram_secret_header.strip(), expected):
            raise HTTPException(status_code=401, detail="telegram secret token mismatch")
        return
    if name == "feishu":
        verify_token = os.environ.get("LAZYSRE_FEISHU_VERIFICATION_TOKEN", "").strip()
        if verify_token:
            incoming = str(payload.get("token") or "").strip()
            if not incoming or not secrets.compare_digest(incoming, verify_token):
                raise HTTPException(status_code=401, detail="feishu verification token mismatch")
        sign_secret = os.environ.get("LAZYSRE_FEISHU_SIGN_SECRET", "").strip()
        if sign_secret:
            ts = lark_timestamp.strip()
            nonce = lark_nonce.strip()
            incoming_sig = lark_signature.strip()
            if not ts or not nonce or not incoming_sig:
                raise HTTPException(status_code=401, detail="feishu signature headers missing")
            digest = hmac.new(
                sign_secret.encode("utf-8"),
                (ts + nonce).encode("utf-8") + body_bytes,
                hashlib.sha256,
            ).hexdigest()
            if not secrets.compare_digest(incoming_sig.lower(), digest.lower()):
                raise HTTPException(status_code=401, detail="feishu signature mismatch")
        return
    if name in {"qq", "onebot"}:
        secret = os.environ.get("LAZYSRE_ONEBOT_SECRET", "").strip()
        if secret:
            incoming_sig = onebot_signature.strip().lower()
            expected = "sha1=" + hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha1).hexdigest()
            if not incoming_sig or not secrets.compare_digest(incoming_sig, expected.lower()):
                raise HTTPException(status_code=401, detail="onebot signature mismatch")
        return
    if name in {"dingtalk", "dingding"}:
        secret = os.environ.get("LAZYSRE_DINGTALK_WEBHOOK_SECRET", "").strip()
        if secret:
            ts = request.query_params.get("timestamp", "").strip()
            sign = request.query_params.get("sign", "").strip()
            if not ts or not sign:
                raise HTTPException(status_code=401, detail="dingtalk sign params missing")
            raw = f"{ts}\n{secret}".encode("utf-8")
            expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
            expected_b64 = base64.b64encode(expected).decode("utf-8")
            if not secrets.compare_digest(sign, expected_b64):
                raise HTTPException(status_code=401, detail="dingtalk signature mismatch")


def _register_channel_event(*, provider: str, message: Any) -> bool:
    event_id = str(getattr(message, "event_id", "") or "").strip()
    if not event_id:
        return False
    key = f"{provider.strip().lower()}:{event_id}"
    dedup_file = Path(os.environ.get("LAZYSRE_CHANNEL_DEDUP_FILE", ".data/lsre-channel-dedup.json")).expanduser()
    dedup_file.parent.mkdir(parents=True, exist_ok=True)
    ttl_raw = os.environ.get("LAZYSRE_CHANNEL_DEDUP_TTL_SEC", "900").strip()
    try:
        ttl_sec = max(60, min(int(ttl_raw), 86400))
    except Exception:
        ttl_sec = 900
    now_ts = datetime.now(timezone.utc).timestamp()
    payload: dict[str, float] = {}
    if dedup_file.exists():
        try:
            raw = json.loads(dedup_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for k, v in raw.items():
                    try:
                        payload[str(k)] = float(v)
                    except Exception:
                        continue
        except Exception:
            payload = {}
    live = {k: v for k, v in payload.items() if (now_ts - v) <= ttl_sec}
    duplicate = key in live
    live[key] = now_ts
    dedup_file.write_text(json.dumps(live, ensure_ascii=False, indent=2), encoding="utf-8")
    return duplicate


def _channel_session_key(*, provider: str, message: Any) -> str:
    name = provider.strip().lower() or "generic"
    chat_id = str(getattr(message, "chat_id", "") or "-").strip() or "-"
    user_id = str(getattr(message, "user_id", "") or "-").strip() or "-"
    return f"{name}:{chat_id}:{user_id}"


def _channel_session_file() -> Path:
    return Path(os.environ.get("LAZYSRE_CHANNEL_SESSION_FILE", ".data/lsre-channel-session.json")).expanduser()


def _load_channel_sessions() -> dict[str, Any]:
    path = _channel_session_file()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def _save_channel_sessions(payload: dict[str, Any]) -> None:
    path = _channel_session_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _channel_history_context(*, session_key: str, lookback: int = 4) -> str:
    rows = _load_channel_sessions()
    entry = rows.get(session_key)
    if not isinstance(entry, dict):
        return ""
    turns = entry.get("turns", [])
    if not isinstance(turns, list) or not turns:
        return ""
    selected = [x for x in turns if isinstance(x, dict)][-max(1, min(lookback, 12)) :]
    lines: list[str] = []
    for item in selected:
        user_text = str(item.get("user", "")).strip()
        assistant_text = str(item.get("assistant", "")).strip()
        if user_text:
            lines.append(f"User: {user_text}")
        if assistant_text:
            lines.append(f"Assistant: {assistant_text}")
    if not lines:
        return ""
    return "Channel recent turns:\n" + "\n".join(lines)


def _channel_session_append(*, session_key: str, user_text: str, assistant_text: str) -> None:
    rows = _load_channel_sessions()
    entry = rows.get(session_key)
    if not isinstance(entry, dict):
        entry = {}
    turns = entry.get("turns", [])
    if not isinstance(turns, list):
        turns = []
    turns.append(
        {
            "at": datetime.now(timezone.utc).isoformat(),
            "user": str(user_text or "").strip(),
            "assistant": str(assistant_text or "").strip(),
        }
    )
    max_turns_raw = os.environ.get("LAZYSRE_CHANNEL_SESSION_MAX_TURNS", "12").strip()
    try:
        max_turns = max(2, min(int(max_turns_raw), 100))
    except Exception:
        max_turns = 12
    entry["turns"] = turns[-max_turns:]
    entry["updated_at"] = datetime.now(timezone.utc).isoformat()
    rows[session_key] = entry
    _save_channel_sessions(rows)


def _channel_session_turn_count(*, session_key: str) -> int:
    rows = _load_channel_sessions()
    entry = rows.get(session_key)
    if not isinstance(entry, dict):
        return 0
    turns = entry.get("turns", [])
    if not isinstance(turns, list):
        return 0
    return len(turns)


def _channel_session_set_last_actionables(*, session_key: str, actionables: dict[str, Any]) -> None:
    rows = _load_channel_sessions()
    entry = rows.get(session_key)
    if not isinstance(entry, dict):
        entry = {}
    commands = actionables.get("commands", []) if isinstance(actionables, dict) else []
    clean: list[dict[str, Any]] = []
    if isinstance(commands, list):
        for item in commands[:8]:
            if not isinstance(item, dict):
                continue
            command = str(item.get("command", "")).strip()
            if not command:
                continue
            clean.append(
                {
                    "command": command,
                    "risk_level": str(item.get("risk_level", "low")).strip().lower() or "low",
                    "requires_approval": bool(item.get("requires_approval", False)),
                }
            )
    entry["last_actionables"] = clean
    entry["updated_at"] = datetime.now(timezone.utc).isoformat()
    rows[session_key] = entry
    _save_channel_sessions(rows)


def _channel_session_get_last_actionables(*, session_key: str) -> list[dict[str, Any]]:
    rows = _load_channel_sessions()
    entry = rows.get(session_key)
    if not isinstance(entry, dict):
        return []
    values = entry.get("last_actionables", [])
    if not isinstance(values, list):
        return []
    out: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", "")).strip()
        if not command:
            continue
        out.append(
            {
                "command": command,
                "risk_level": str(item.get("risk_level", "low")).strip().lower() or "low",
                "requires_approval": bool(item.get("requires_approval", False)),
            }
        )
    return out


def _channel_session_snapshot(*, session_key: str, recent: int = 3) -> dict[str, Any]:
    rows = _load_channel_sessions()
    entry = rows.get(session_key)
    if not isinstance(entry, dict):
        return {"turns": 0, "recent_user": []}
    turns = entry.get("turns", [])
    if not isinstance(turns, list):
        return {"turns": 0, "recent_user": []}
    selected = [x for x in turns if isinstance(x, dict)][-max(1, min(recent, 10)) :]
    recent_user = [str(item.get("user", "")).strip() for item in selected if str(item.get("user", "")).strip()]
    actionables = _channel_session_get_last_actionables(session_key=session_key)
    return {"turns": len(turns), "recent_user": recent_user, "actionables": actionables[:3]}


def _channel_session_reset(*, session_key: str) -> int:
    rows = _load_channel_sessions()
    entry = rows.get(session_key)
    if not isinstance(entry, dict):
        return 0
    turns = entry.get("turns", [])
    count = len(turns) if isinstance(turns, list) else 0
    if session_key in rows:
        rows.pop(session_key, None)
        _save_channel_sessions(rows)
    return count


def _maybe_handle_channel_control(*, provider: str, message: Any, trace_id: str) -> dict[str, Any] | None:
    text = str(getattr(message, "text", "") or "").strip()
    if not text:
        return None
    lower = text.lower()
    session_key = _channel_session_key(provider=provider, message=message)
    if lower in {"/reset", "reset", "重置", "重置会话"}:
        cleared = _channel_session_reset(session_key=session_key)
        reply_text = f"session reset done, cleared_turns={cleared}"
        reply = format_channel_reply(provider, reply_text, message)
        return {
            "ok": True,
            "provider": provider,
            "dry_run": True,
            "event_id": str(getattr(message, "event_id", "") or ""),
            "trace_id": trace_id,
            "control": "reset",
            "reply": reply,
            "event_count": 0,
            "ack": {"received_at": datetime.now(timezone.utc).isoformat(), "provider": provider, "trace_id": trace_id},
            "progress": [{"step": "control", "status": "reset"}],
            "lifecycle": _channel_lifecycle(["queued", "succeeded"], trace_id=trace_id),
            "final": {"text": reply_text, "reply": reply, "handoff": None},
            "session": {"key": session_key, "turns": 0},
            "receipt": _build_channel_receipt(
                provider=provider,
                event_id=str(getattr(message, "event_id", "") or ""),
                phase="control",
                status="succeeded",
                trace_id=trace_id,
                detail="session reset",
            ),
        }

    if lower in {"/session", "session", "会话", "查看会话"}:
        snap = _channel_session_snapshot(session_key=session_key, recent=3)
        reply_text = (
            f"session turns={snap.get('turns', 0)} "
            f"recent={'; '.join([str(x) for x in snap.get('recent_user', [])])}"
        )
        if isinstance(snap.get("actionables"), list) and snap["actionables"]:
            first = snap["actionables"][0]
            if isinstance(first, dict):
                reply_text += f" | next={first.get('command', '')}"
        reply = format_channel_reply(provider, reply_text, message)
        return {
            "ok": True,
            "provider": provider,
            "dry_run": True,
            "event_id": str(getattr(message, "event_id", "") or ""),
            "trace_id": trace_id,
            "control": "session",
            "reply": reply,
            "event_count": 0,
            "ack": {"received_at": datetime.now(timezone.utc).isoformat(), "provider": provider, "trace_id": trace_id},
            "progress": [{"step": "control", "status": "session"}],
            "lifecycle": _channel_lifecycle(["queued", "succeeded"], trace_id=trace_id),
            "final": {"text": reply_text, "reply": reply, "handoff": None},
            "session": {"key": session_key, "turns": int(snap.get("turns", 0))},
            "receipt": _build_channel_receipt(
                provider=provider,
                event_id=str(getattr(message, "event_id", "") or ""),
                phase="control",
                status="succeeded",
                trace_id=trace_id,
                detail=f"session turns={int(snap.get('turns', 0))}",
            ),
        }

    if lower.startswith("/approve ") or lower.startswith("审批 "):
        parts = text.split(maxsplit=2)
        if len(parts) < 2:
            reply_text = "usage: /approve CHG-xxxx [comment]"
            reply = format_channel_reply(provider, reply_text, message)
            return {
                "ok": False,
                "provider": provider,
                "dry_run": True,
                "trace_id": trace_id,
                "control": "approve",
                "reply": reply,
                "event_count": 0,
                "lifecycle": _channel_lifecycle(["queued", "blocked"], trace_id=trace_id),
                "final": {"text": reply_text, "reply": reply, "handoff": None},
                "receipt": _build_channel_receipt(
                    provider=provider,
                    event_id=str(getattr(message, "event_id", "") or ""),
                    phase="control",
                    status="blocked",
                    trace_id=trace_id,
                    detail="approve usage",
                ),
            }
        ticket_id = str(parts[1]).strip()
        comment = str(parts[2]).strip() if len(parts) > 2 else ""
        approver = str(getattr(message, "user_id", "") or "").strip() or "channel-user"
        store_path = Path(os.environ.get("LAZYSRE_APPROVAL_STORE", ".data/lsre-approvals.json")).expanduser()
        store = ApprovalStore(store_path)
        item = store.approve(ticket_id, approver=approver, comment=comment)
        if not item:
            reply_text = f"approval ticket not found: {ticket_id}"
            ok = False
            approval_data: dict[str, Any] = {"ticket_id": ticket_id, "status": "not_found"}
        else:
            ok = True
            remaining = max(0, int(item.required_approvers) - len(item.approvals))
            reply_text = (
                f"ticket={item.id} status={item.status} approvals={len(item.approvals)}/{item.required_approvers} remaining={remaining}"
            )
            approval_data = {
                "ticket_id": item.id,
                "status": item.status,
                "required_approvers": int(item.required_approvers),
                "current_approvals": len(item.approvals),
                "remaining_approvers": remaining,
            }
            if item.status == "approved":
                linked_actions = _channel_session_get_last_actionables(session_key=session_key)
                gated = [x for x in linked_actions if bool(x.get("requires_approval", False))]
                next_commands = [str(x.get("command", "")).strip() for x in (gated or linked_actions) if str(x.get("command", "")).strip()][:3]
                if next_commands:
                    reply_text += "\nnext commands:\n" + "\n".join([f"- {cmd}" for cmd in next_commands])
                    approval_data["next_commands"] = next_commands
                    approval_data["execution_templates"] = _build_execution_templates(
                        next_commands,
                        source="approve",
                        approval_ticket=item.id,
                        target_context=_channel_target_context(),
                    )
                approval_data["export_ticket"] = f"export LAZYSRE_APPROVAL_TICKET={item.id}"
        reply = format_channel_reply(provider, reply_text, message)
        return {
            "ok": ok,
            "provider": provider,
            "dry_run": True,
            "event_id": str(getattr(message, "event_id", "") or ""),
            "trace_id": trace_id,
            "control": "approve",
            "reply": reply,
            "event_count": 0,
            "ack": {"received_at": datetime.now(timezone.utc).isoformat(), "provider": provider, "trace_id": trace_id},
            "progress": [{"step": "control", "status": "approve"}],
            "lifecycle": _channel_lifecycle(["queued", "succeeded" if ok else "blocked"], trace_id=trace_id),
            "final": {"text": reply_text, "reply": reply, "handoff": None},
            "approval": approval_data,
            "receipt": _build_channel_receipt(
                provider=provider,
                event_id=str(getattr(message, "event_id", "") or ""),
                phase="control",
                status="succeeded" if ok else "blocked",
                trace_id=trace_id,
                detail=f"approve {ticket_id}",
            ),
        }

    if lower in {"/approvals", "approvals", "审批单", "查看审批"}:
        store_path = Path(os.environ.get("LAZYSRE_APPROVAL_STORE", ".data/lsre-approvals.json")).expanduser()
        store = ApprovalStore(store_path)
        rows = store.list(status="pending", limit=5)
        if not rows:
            reply_text = "no pending approvals"
        else:
            lines = []
            for item in rows:
                lines.append(
                    f"{item.id} {item.status} {len(item.approvals)}/{item.required_approvers} {item.risk_level} {item.reason[:40]}"
                )
            reply_text = "pending approvals:\n" + "\n".join(lines)
        reply = format_channel_reply(provider, reply_text, message)
        return {
            "ok": True,
            "provider": provider,
            "dry_run": True,
            "event_id": str(getattr(message, "event_id", "") or ""),
            "trace_id": trace_id,
            "control": "approvals",
            "reply": reply,
            "event_count": 0,
            "ack": {"received_at": datetime.now(timezone.utc).isoformat(), "provider": provider, "trace_id": trace_id},
            "progress": [{"step": "control", "status": "approvals"}],
            "lifecycle": _channel_lifecycle(["queued", "succeeded"], trace_id=trace_id),
            "final": {"text": reply_text, "reply": reply, "handoff": None},
            "receipt": _build_channel_receipt(
                provider=provider,
                event_id=str(getattr(message, "event_id", "") or ""),
                phase="control",
                status="succeeded",
                trace_id=trace_id,
                detail=f"pending={len(rows)}",
            ),
        }
    return None


def _create_channel_handoff(
    *,
    provider: str,
    instruction: str,
    reply: str,
    events: list[Any],
    user_id: str,
    chat_id: str,
    trace_id: str,
    run_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    handoff_id = str(uuid4())
    handoff_dir = Path(os.environ.get("LAZYSRE_CHANNEL_HANDOFF_DIR", ".data/channel-handoff")).expanduser()
    handoff_dir.mkdir(parents=True, exist_ok=True)
    handoff_file = handoff_dir / f"{handoff_id}.json"
    similar_cases = _search_memory_cases(instruction, limit=3)
    payload = {
        "id": handoff_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "user_id": user_id,
        "chat_id": chat_id,
        "trace_id": trace_id,
        "instruction": instruction,
        "reply": reply,
        "event_count": len(events),
        "similar_cases": similar_cases,
        "handoff_command": f'lazysre fix "{instruction}"',
        "run_artifact": run_artifact if isinstance(run_artifact, dict) else {},
    }
    handoff_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "id": handoff_id,
        "path": str(handoff_file),
        "trace_id": trace_id,
        "handoff_command": payload["handoff_command"],
        "similar_cases": similar_cases,
        "run_artifact": payload.get("run_artifact", {}),
    }


def _create_channel_run_artifact(
    *,
    provider: str,
    trace_id: str,
    user_id: str,
    chat_id: str,
    instruction: str,
    final_text: str,
    event_count: int,
    timeline: list[dict[str, Any]],
    actionables: dict[str, Any],
    execution_templates: dict[str, Any],
) -> dict[str, Any]:
    run_dir = Path(os.environ.get("LAZYSRE_CHANNEL_RUN_DIR", ".data/channel-runs")).expanduser()
    run_dir.mkdir(parents=True, exist_ok=True)
    file_stem = str(trace_id or "").replace("/", "_").replace(":", "_")
    if not file_stem:
        file_stem = str(uuid4())
    run_file = run_dir / f"{file_stem}.json"
    payload = {
        "schema_version": 1,
        "trace_id": trace_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "user_id": user_id,
        "chat_id": chat_id,
        "instruction": instruction,
        "final_text": final_text,
        "event_count": int(event_count),
        "timeline": timeline,
        "actionables": actionables,
        "execution_templates": execution_templates,
        "approval_snapshot": _channel_approval_snapshot(),
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    hmac_key = os.environ.get("LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY", "").strip()
    signature = ""
    if hmac_key:
        signature = hmac.new(hmac_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    payload["integrity"] = {
        "algorithm": "sha256",
        "digest": digest,
        "signed": bool(signature),
        "signature_algorithm": "hmac-sha256" if signature else "",
        "signature": signature,
    }
    run_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "trace_id": trace_id,
        "path": str(run_file),
        "size_bytes": run_file.stat().st_size if run_file.exists() else 0,
        "digest": digest,
        "signed": bool(signature),
    }


def _verify_channel_run_artifact(path: str | Path, *, hmac_key: str = "") -> dict[str, Any]:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        return {
            "ok": False,
            "path": str(file_path),
            "error": "artifact file not found",
        }
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "ok": False,
            "path": str(file_path),
            "error": f"invalid json: {exc}",
        }
    if not isinstance(payload, dict):
        return {"ok": False, "path": str(file_path), "error": "artifact payload must be an object"}
    required = {"schema_version", "trace_id", "instruction", "final_text", "integrity"}
    missing = [k for k in sorted(required) if k not in payload]
    if missing:
        return {
            "ok": False,
            "path": str(file_path),
            "error": f"missing required fields: {', '.join(missing)}",
        }
    integrity = payload.get("integrity", {})
    if not isinstance(integrity, dict):
        return {"ok": False, "path": str(file_path), "error": "integrity must be object"}
    digest = str(integrity.get("digest", "")).strip().lower()
    if not digest:
        return {"ok": False, "path": str(file_path), "error": "integrity.digest missing"}
    copy_payload = dict(payload)
    copy_payload.pop("integrity", None)
    canonical = json.dumps(copy_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest().lower()
    digest_match = secrets.compare_digest(digest, computed)
    signature = str(integrity.get("signature", "")).strip().lower()
    signed = bool(integrity.get("signed", False) or signature)
    signature_valid: bool | None
    if not signed:
        signature_valid = None
    elif not hmac_key.strip():
        signature_valid = False
    else:
        expected_sig = hmac.new(hmac_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest().lower()
        signature_valid = secrets.compare_digest(signature, expected_sig)
    ok = bool(digest_match and (signature_valid in {None, True}))
    return {
        "ok": ok,
        "path": str(file_path),
        "schema_version": int(payload.get("schema_version", 0) or 0),
        "trace_id": str(payload.get("trace_id", "")).strip(),
        "digest_match": digest_match,
        "signed": signed,
        "signature_valid": signature_valid,
    }


def _channel_approval_snapshot() -> dict[str, Any]:
    ticket = os.environ.get("LAZYSRE_APPROVAL_TICKET", "").strip()
    if not ticket:
        return {"ticket_id": "", "present": False}
    store_path = Path(os.environ.get("LAZYSRE_APPROVAL_STORE", ".data/lsre-approvals.json")).expanduser()
    store = ApprovalStore(store_path)
    item = store.get(ticket)
    if not item:
        return {"ticket_id": ticket, "present": False}
    return {
        "ticket_id": item.id,
        "present": True,
        "status": item.status,
        "risk_level": item.risk_level,
        "tenant": item.tenant,
        "environment": item.environment,
        "required_approvers": int(item.required_approvers),
        "current_approvals": len(item.approvals),
        "approved_at": item.approved_at,
    }


@app.get("/v1/channels/artifacts/verify")
async def verify_channel_artifact(path: str, hmac_key: str = "") -> dict[str, Any]:
    result = _verify_channel_run_artifact(path, hmac_key=hmac_key)
    if not bool(result.get("ok")):
        raise HTTPException(status_code=400, detail=result)
    return result


def _search_memory_cases(instruction: str, *, limit: int = 3) -> list[dict[str, Any]]:
    text = str(instruction or "").strip()
    if not text:
        return []
    try:
        rows = IncidentMemoryStore().search_similar(text, limit=max(1, min(limit, 6)))
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for item in rows:
        out.append(
            {
                "id": item.id,
                "score": round(item.score, 4),
                "symptom": item.symptom[:180],
                "root_cause": item.root_cause[:220],
                "fix_commands": item.fix_commands[:3],
            }
        )
    return out


def _compact_channel_timeline(events: list[Any], *, limit: int = 10) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in events:
        kind = str(getattr(item, "kind", "") or "").strip()
        if kind not in {"llm_turn", "tool_call", "tool_output", "auto_retry", "final", "max_steps"}:
            continue
        message = str(getattr(item, "message", "") or "").strip()
        data = getattr(item, "data", {}) or {}
        if not isinstance(data, dict):
            data = {}
        row: dict[str, Any] = {"kind": kind, "message": message}
        if "duration_ms" in data:
            row["duration_ms"] = data.get("duration_ms")
        if "step" in data:
            row["step"] = data.get("step")
        preview = str(data.get("output_preview", "")).strip()
        if preview:
            row["preview"] = preview[:120]
        call_id = str(data.get("call_id", "")).strip()
        if call_id:
            row["call_id"] = call_id
        rows.append(row)
    if len(rows) > limit:
        return rows[-limit:]
    return rows


def _build_channel_actionables(reply: str, *, approval_mode: str) -> dict[str, Any]:
    commands = _extract_commands_from_text(reply)[:6]
    assessed: list[dict[str, Any]] = []
    needs_approval = False
    for cmd in commands:
        argv = _command_to_argv(cmd)
        if not argv:
            continue
        policy = assess_command(argv, approval_mode=approval_mode)
        item = {
            "command": cmd,
            "risk_level": policy.risk_level,
            "requires_approval": bool(policy.requires_approval),
        }
        assessed.append(item)
        if policy.requires_approval:
            needs_approval = True
    hints: list[str] = []
    if needs_approval:
        ticket = os.environ.get("LAZYSRE_APPROVAL_TICKET", "").strip()
        if ticket:
            hints.append(f"high-risk command detected; current ticket={ticket}")
        else:
            hints.append("high-risk command detected; create ticket via: lazysre approval create --reason 'channel action'")
    if not assessed:
        hints.append("no executable command extracted; use handoff_command in response.handoff")
    return {
        "commands": assessed,
        "approval_mode": approval_mode,
        "needs_approval": needs_approval,
        "hints": hints[:4],
    }


def _build_execution_templates_from_actionables(
    actionables: dict[str, Any],
    *,
    source: str,
    approval_ticket: str,
    target_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    commands: list[str] = []
    values = actionables.get("commands", []) if isinstance(actionables, dict) else []
    if isinstance(values, list):
        for item in values:
            if not isinstance(item, dict):
                continue
            command = str(item.get("command", "")).strip()
            if command:
                commands.append(command)
    return _build_execution_templates(
        commands,
        source=source,
        approval_ticket=approval_ticket,
        target_context=target_context,
    )


def _build_execution_templates(
    commands: list[str],
    *,
    source: str,
    approval_ticket: str,
    target_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    templates: list[dict[str, Any]] = []
    ticket = str(approval_ticket or "").strip()
    context = target_context if isinstance(target_context, dict) else _channel_target_context()
    env_block = _render_environment_block(context)
    for idx, command in enumerate(commands[:6], start=1):
        cmd = str(command or "").strip()
        if not cmd:
            continue
        safe_quoted = cmd.replace('"', '\\"')
        cli = f'lazysre fix "{safe_quoted}"'
        execute_cli = cli + " --execute --apply"
        if ticket:
            execute_cli = f"LAZYSRE_APPROVAL_TICKET={ticket} " + execute_cli
        target = _infer_command_target(cmd)
        prerequisites = _build_command_prerequisites(cmd, target=target, target_context=context)
        rollback = _build_rollback_template(cmd, target_context=context)
        preflight_commands = _build_preflight_commands(cmd, target=target, target_context=context)
        verify_commands = _build_verify_commands(cmd, target=target, target_context=context)
        dry_run_api = {
            "path": "/v1/channels/generic/webhook",
            "method": "POST",
            "body": {"text": cmd},
        }
        execute_api = {
            "path": "/v1/channels/generic/webhook",
            "method": "POST",
            "body": {"text": cmd},
            "headers": {"X-LazySRE-Channel-Token": "${CHANNEL_TOKEN}"},
            "note": "channel webhook仍是dry-run入口；生产执行请走CLI execute或平台workflow审批流",
        }
        templates.append(
            {
                "id": f"act-{idx}",
                "command": cmd,
                "source": source,
                "target": target,
                "cli": {
                    "dry_run": cli,
                    "execute": execute_cli,
                },
                "api": {
                    "dry_run": dry_run_api,
                    "execute": execute_api,
                },
                "safety": {
                    "requires_ticket": _command_requires_ticket(cmd),
                    "approval_ticket": ticket,
                    "approval_required_hint": "set LAZYSRE_APPROVAL_TICKET before execute when risk is high/critical",
                },
                "prerequisites": prerequisites,
                "rollback_template": rollback,
                "preflight_commands": preflight_commands,
                "verify_commands": verify_commands,
                "task_sheet": {
                    "title": f"Execute action {idx}",
                    "objective": f"Safely run: {cmd}",
                    "steps": [
                        "1) Run dry-run first and capture output",
                        "2) Verify target state and blast radius",
                        "3) Apply execute command with approval ticket if required",
                        "4) Verify post-check signals; rollback if unhealthy",
                    ],
                    "dry_run_command": cli,
                    "execute_command": execute_cli,
                    "rollback_command": rollback.get("command", ""),
                },
                "environment": env_block,
            }
        )
    return {
        "items": templates,
        "count": len(templates),
    }


def _infer_command_target(command: str) -> dict[str, str]:
    text = str(command or "").strip()
    lowered = text.lower()
    if lowered.startswith("kubectl "):
        return {"platform": "kubernetes", "resource": _extract_k8s_resource_hint(text)}
    if lowered.startswith("docker "):
        return {"platform": "docker", "resource": _extract_docker_resource_hint(text)}
    if lowered.startswith("curl "):
        return {"platform": "http", "resource": _extract_url_hint(text)}
    if lowered.startswith("tail "):
        return {"platform": "host", "resource": "log-file"}
    return {"platform": "generic", "resource": "unknown"}


def _build_command_prerequisites(
    command: str,
    *,
    target: dict[str, str],
    target_context: dict[str, Any] | None = None,
) -> list[str]:
    platform = str(target.get("platform", "generic"))
    context = target_context if isinstance(target_context, dict) else {}
    target_cfg = context.get("target", {}) if isinstance(context.get("target", {}), dict) else {}
    active_profile = str(context.get("active_profile", "")).strip()
    items: list[str] = []
    if platform == "kubernetes":
        items.extend(
            [
                "kubectl cluster-info must be reachable",
                "current kube-context must match target cluster",
            ]
        )
        namespace = str(target_cfg.get("k8s_namespace", "")).strip()
        if namespace:
            items.append(f"expected namespace: {namespace}")
        k8s_context = str(target_cfg.get("k8s_context", "")).strip()
        if k8s_context:
            items.append(f"expected kube-context: {k8s_context}")
    elif platform == "docker":
        items.extend(
            [
                "docker daemon must be reachable",
                "target container/service must exist",
            ]
        )
        ssh_target = str(target_cfg.get("ssh_target", "")).strip()
        if ssh_target:
            items.append(f"remote target for docker checks: {ssh_target}")
    elif platform == "http":
        items.append("network path and DNS to target endpoint must be reachable")
        prom_url = str(target_cfg.get("prometheus_url", "")).strip()
        if prom_url:
            items.append(f"prometheus baseline endpoint: {prom_url}")
    else:
        items.append("target runtime command should be available in PATH")
    if active_profile:
        items.append(f"active target profile: {active_profile}")
    if _command_requires_ticket(command):
        items.append("approved ticket should be prepared for high-risk execution")
    return items


def _build_rollback_template(command: str, *, target_context: dict[str, Any] | None = None) -> dict[str, str]:
    context = target_context if isinstance(target_context, dict) else {}
    target_cfg = context.get("target", {}) if isinstance(context.get("target", {}), dict) else {}
    namespace = str(target_cfg.get("k8s_namespace", "")).strip()
    ns_flag = f" -n {namespace}" if namespace else ""
    argv = _command_to_argv(command)
    if not argv:
        return {"strategy": "manual", "command": ""}
    lowered = " ".join(argv).lower()
    if argv[:3] == ["kubectl", "rollout", "restart"] and len(argv) >= 4:
        return {"strategy": "k8s-rollout-undo", "command": f"kubectl rollout undo {argv[3]}{ns_flag}"}
    if argv[:3] == ["docker", "service", "update"]:
        service = argv[-1] if len(argv) >= 4 else "<service>"
        return {"strategy": "swarm-rollback", "command": f"docker service rollback {service}"}
    if "scale" in lowered and argv and argv[0] == "kubectl":
        return {"strategy": "k8s-scale-back", "command": f"kubectl scale <resource> --replicas=<previous>{ns_flag}"}
    return {"strategy": "manual", "command": ""}


def _build_preflight_commands(
    command: str,
    *,
    target: dict[str, str],
    target_context: dict[str, Any] | None = None,
) -> list[str]:
    platform = str(target.get("platform", "generic"))
    context = target_context if isinstance(target_context, dict) else {}
    target_cfg = context.get("target", {}) if isinstance(context.get("target", {}), dict) else {}
    checks: list[str] = []
    if platform == "kubernetes":
        checks.append("kubectl cluster-info")
        if str(target_cfg.get("k8s_namespace", "")).strip():
            checks.append(f"kubectl get pods -n {str(target_cfg.get('k8s_namespace', '')).strip()} --no-headers | head")
    elif platform == "docker":
        checks.append("docker info --format '{{.ServerVersion}}'")
        checks.append("docker service ls")
    elif platform == "http":
        checks.append("curl -sS --max-time 8 <target-url>")
    else:
        checks.append("command -v kubectl || command -v docker || command -v curl")
    if _command_requires_ticket(command):
        checks.append("echo $LAZYSRE_APPROVAL_TICKET")
    return checks[:4]


def _build_verify_commands(
    command: str,
    *,
    target: dict[str, str],
    target_context: dict[str, Any] | None = None,
) -> list[str]:
    platform = str(target.get("platform", "generic"))
    resource = str(target.get("resource", "")).strip()
    context = target_context if isinstance(target_context, dict) else {}
    target_cfg = context.get("target", {}) if isinstance(context.get("target", {}), dict) else {}
    checks: list[str] = []
    if platform == "kubernetes":
        namespace = str(target_cfg.get("k8s_namespace", "")).strip()
        ns_flag = f" -n {namespace}" if namespace else ""
        if resource:
            checks.append(f"kubectl rollout status {resource}{ns_flag} --timeout=120s")
        checks.append(f"kubectl get pods{ns_flag}")
    elif platform == "docker":
        checks.append("docker service ps <service> --no-trunc")
        checks.append("docker ps --format 'table {{.ID}}\\t{{.Status}}\\t{{.Names}}'")
    elif platform == "http":
        checks.append("curl -sS -o /dev/null -w '%{http_code}\\n' <target-url>")
    else:
        checks.append(f"echo verify: {command}")
    return checks[:4]


def _extract_k8s_resource_hint(command: str) -> str:
    argv = _command_to_argv(command)
    for token in reversed(argv):
        if "/" in token and not token.startswith("--"):
            return token
    if len(argv) >= 3:
        return argv[2]
    return "k8s-resource"


def _extract_docker_resource_hint(command: str) -> str:
    argv = _command_to_argv(command)
    for token in reversed(argv):
        if not token.startswith("-"):
            if token not in {"docker", "service", "container", "image", "logs", "ps", "update"}:
                return token
    return "docker-resource"


def _extract_url_hint(command: str) -> str:
    argv = _command_to_argv(command)
    for token in argv:
        if token.startswith("http://") or token.startswith("https://"):
            return token
    return "url"


def _command_requires_ticket(command: str) -> bool:
    argv = _command_to_argv(command)
    if not argv:
        return False
    decision = assess_command(argv, approval_mode=os.environ.get("LAZYSRE_CHANNEL_APPROVAL_MODE", "strict"))
    return bool(decision.requires_approval)


def _channel_target_context() -> dict[str, Any]:
    try:
        target = TargetEnvStore().load()
        safe_target = target.to_safe_dict()
    except Exception:
        safe_target = {}
    try:
        active_profile = ClusterProfileStore.default().get_active().strip()
    except Exception:
        active_profile = ""
    return {
        "active_profile": active_profile,
        "target": safe_target,
    }


def _render_environment_block(context: dict[str, Any]) -> dict[str, str]:
    target = context.get("target", {}) if isinstance(context.get("target", {}), dict) else {}
    return {
        "active_profile": str(context.get("active_profile", "")).strip(),
        "ssh_target": str(target.get("ssh_target", "")).strip(),
        "k8s_context": str(target.get("k8s_context", "")).strip(),
        "k8s_namespace": str(target.get("k8s_namespace", "")).strip(),
        "prometheus_url": str(target.get("prometheus_url", "")).strip(),
    }


def _build_channel_receipt(
    *,
    provider: str,
    event_id: str,
    phase: str,
    status: str,
    trace_id: str,
    detail: str,
) -> dict[str, Any]:
    state = _normalize_receipt_state(status)
    return {
        "id": str(uuid4()),
        "at": datetime.now(timezone.utc).isoformat(),
        "trace_id": str(trace_id or "").strip(),
        "provider": provider,
        "event_id": str(event_id or "").strip(),
        "phase": str(phase or "").strip() or "unknown",
        "status": state,
        "state": state,
        "detail": str(detail or "").strip(),
    }


def _normalize_receipt_state(status: str) -> str:
    text = str(status or "").strip().lower()
    if text in {"queued", "running", "succeeded", "blocked", "ignored"}:
        return text
    if text in {"ok", "success", "done"}:
        return "succeeded"
    if text in {"error", "failed", "deny", "denied"}:
        return "blocked"
    return "running"


def _channel_trace_id(*, provider: str, event_id: str) -> str:
    base = f"{provider.strip().lower()}:{str(event_id or '').strip()}"
    if not base.endswith(":"):
        return f"trc-{base}-{uuid4().hex[:8]}"
    return f"trc-{provider.strip().lower()}-{uuid4().hex[:10]}"


def _channel_lifecycle(states: list[str], *, trace_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, item in enumerate(states, start=1):
        state = _normalize_receipt_state(item)
        out.append(
            {
                "seq": idx,
                "state": state,
                "at": datetime.now(timezone.utc).isoformat(),
                "trace_id": trace_id,
            }
        )
    return out


def _extract_commands_from_text(text: str) -> list[str]:
    content = str(text or "")
    if not content.strip():
        return []
    found: list[str] = []
    block_matches = re.findall(r"```(?:bash|sh|shell)?\n(.*?)```", content, flags=re.DOTALL | re.IGNORECASE)
    for block in block_matches:
        for line in block.splitlines():
            cmd = line.strip()
            if _looks_like_command(cmd):
                found.append(cmd)
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith(("-", "*")):
            line = line[1:].strip()
        if _looks_like_command(line):
            found.append(line)
    out: list[str] = []
    seen: set[str] = set()
    for item in found:
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _looks_like_command(line: str) -> bool:
    text = str(line or "").strip()
    if not text:
        return False
    prefixes = ("kubectl ", "docker ", "curl ", "tail ", "lazysre ", "lsre ")
    return text.startswith(prefixes)


def _command_to_argv(command: str) -> list[str]:
    text = str(command or "").strip()
    if not text:
        return []
    try:
        import shlex

        return shlex.split(text)
    except Exception:
        return text.split()


@app.post("/v1/tasks", response_model=TaskRecord)
async def create_task(req: TaskCreateRequest) -> TaskRecord:
    return await task_service.create_task(req)


@app.get("/v1/tasks/{task_id}", response_model=TaskRecord)
async def get_task(task_id: str) -> TaskRecord:
    task = await task_service.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.get("/v1/tasks", response_model=list[TaskRecord])
async def list_tasks() -> list[TaskRecord]:
    return await task_service.list_tasks()


@app.post("/v1/tasks/{task_id}/cancel", response_model=TaskRecord)
async def cancel_task(task_id: str) -> TaskRecord:
    task = await task_service.cancel_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.post("/v1/tasks/{task_id}/rerun", response_model=TaskRecord)
async def rerun_task(task_id: str) -> TaskRecord:
    task = await task_service.rerun_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.get("/v1/memory/search", response_model=MemorySearchResponse)
async def search_memory(q: str, limit: int = 5) -> MemorySearchResponse:
    if not q.strip():
        raise HTTPException(status_code=400, detail="query must not be empty")
    if limit < 1:
        raise HTTPException(status_code=400, detail="limit must be >= 1")
    return await task_service.search_memory(query=q.strip(), limit=min(limit, 20))


@app.post("/v1/platform/agents", response_model=AgentDefinition)
async def create_agent(req: AgentCreateRequest) -> AgentDefinition:
    return await platform_service.create_agent(req)


@app.get("/v1/platform/agents", response_model=list[AgentDefinition])
async def list_agents() -> list[AgentDefinition]:
    return await platform_service.list_agents()


@app.post("/v1/platform/tools", response_model=OpsToolDefinition)
async def create_tool(req: ToolCreateRequest) -> OpsToolDefinition:
    try:
        return await platform_service.create_tool(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/platform/tools", response_model=list[OpsToolDefinition])
async def list_tools() -> list[OpsToolDefinition]:
    return await platform_service.list_tools()


@app.get("/v1/platform/tools/health", response_model=list[ToolHealthItem])
async def list_tools_health(timeout_sec: float = 6.0) -> list[ToolHealthItem]:
    timeout = max(1.0, min(timeout_sec, 20.0))
    return await platform_service.list_tools_health(timeout_sec=timeout)


@app.post("/v1/platform/bootstrap/environment", response_model=EnvironmentBootstrapResult)
async def bootstrap_environment(req: EnvironmentBootstrapRequest) -> EnvironmentBootstrapResult:
    try:
        return await platform_service.bootstrap_environment(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"bootstrap failed: {exc}") from exc


@app.post("/v1/platform/tools/{tool_id}/probe", response_model=ToolProbeResult)
async def probe_tool(tool_id: str, req: ToolProbeRequest) -> ToolProbeResult:
    try:
        return await platform_service.probe_tool(tool_id, req)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"tool probe failed: {exc}") from exc


@app.get("/v1/platform/templates", response_model=list[PlatformTemplate])
async def list_templates() -> list[PlatformTemplate]:
    return await platform_service.list_templates()


@app.get("/v1/platform/skills", response_model=list[SkillDefinition])
async def list_skills() -> list[SkillDefinition]:
    return await platform_service.list_skills()


@app.get("/v1/platform/skills/{skill_name}", response_model=SkillDefinition)
async def get_skill(skill_name: str) -> SkillDefinition:
    item = await platform_service.get_skill(skill_name)
    if not item:
        raise HTTPException(status_code=404, detail="skill not found")
    return item


@app.post("/v1/platform/skills", response_model=SkillDefinition)
async def create_skill(req: SkillCreateRequest) -> SkillDefinition:
    try:
        return await platform_service.create_skill(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/platform/skills/{skill_name}/run", response_model=SkillRunResult)
async def run_skill(skill_name: str, req: SkillRunRequest) -> SkillRunResult:
    try:
        return await platform_service.run_skill(skill_name, req)
    except ValueError as exc:
        msg = str(exc)
        code = 404 if "not found" in msg else 400
        raise HTTPException(status_code=code, detail=msg) from exc


@app.get("/v1/platform/overview", response_model=PlatformOverview)
async def platform_overview() -> PlatformOverview:
    return await platform_service.get_overview()


@app.get("/v1/platform/briefing", response_model=IncidentBriefing)
async def incident_briefing(
    workflow_id: str | None = None, timeout_sec: float = 4.0
) -> IncidentBriefing:
    timeout = max(1.0, min(timeout_sec, 20.0))
    return await platform_service.generate_incident_briefing(
        workflow_id=workflow_id, timeout_sec=timeout
    )


@app.get("/v1/platform/artifacts", response_model=list[ArtifactItem])
async def list_artifacts(kind: str = "all", limit: int = 40) -> list[ArtifactItem]:
    try:
        return await platform_service.list_artifacts(kind=kind, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/platform/artifacts/{kind}/{name}")
async def read_artifact(kind: str, name: str) -> PlainTextResponse:
    try:
        loaded = await platform_service.read_artifact(kind=kind, name=name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not loaded:
        raise HTTPException(status_code=404, detail="artifact not found")
    path, content = loaded
    media_type = (
        "application/json; charset=utf-8"
        if path.suffix.lower() == ".json"
        else "text/markdown; charset=utf-8"
        if path.suffix.lower() == ".md"
        else "text/plain; charset=utf-8"
    )
    return PlainTextResponse(content, media_type=media_type)


@app.post("/v1/platform/workflows", response_model=WorkflowDefinition)
async def create_workflow(req: WorkflowCreateRequest) -> WorkflowDefinition:
    try:
        return await platform_service.create_workflow(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/platform/workflows", response_model=list[WorkflowDefinition])
async def list_workflows() -> list[WorkflowDefinition]:
    return await platform_service.list_workflows()


@app.post("/v1/platform/quickstart", response_model=WorkflowDefinition)
async def quickstart(req: QuickstartRequest) -> WorkflowDefinition:
    return await platform_service.quickstart(req)


@app.post("/v1/platform/autodesign", response_model=WorkflowDefinition)
async def auto_design(req: AutoDesignRequest) -> WorkflowDefinition:
    try:
        return await platform_service.auto_design(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/platform/workflows/{workflow_id}/runs", response_model=WorkflowRun)
async def create_run(workflow_id: str, req: RunCreateRequest) -> WorkflowRun:
    run = await platform_service.create_run(workflow_id=workflow_id, req=req)
    if not run:
        raise HTTPException(status_code=404, detail="workflow not found")
    return run


@app.get("/v1/platform/runs", response_model=list[WorkflowRun])
async def list_runs(workflow_id: str | None = None) -> list[WorkflowRun]:
    return await platform_service.list_runs(workflow_id=workflow_id)


@app.get("/v1/platform/runs/compare", response_model=RunComparison)
async def compare_runs(left_run_id: str, right_run_id: str) -> RunComparison:
    try:
        return await platform_service.compare_runs(
            left_run_id=left_run_id,
            right_run_id=right_run_id,
        )
    except ValueError as exc:
        msg = str(exc)
        code = 404 if "not found" in msg else 400
        raise HTTPException(status_code=code, detail=msg) from exc


@app.get("/v1/platform/runs/{run_id}", response_model=WorkflowRun)
async def get_run(run_id: str) -> WorkflowRun:
    run = await platform_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return run


@app.get("/v1/platform/runs/{run_id}/report", response_model=None)
async def get_run_report(run_id: str, format: str = "markdown") -> Any:
    fmt = format.strip().lower()
    if fmt not in {"markdown", "json"}:
        raise HTTPException(status_code=400, detail="format must be markdown or json")

    if fmt == "json":
        report = await platform_service.get_run_report(run_id)
        if not report:
            raise HTTPException(status_code=404, detail="run not found")
        return report

    content = await platform_service.export_run_report_markdown(run_id)
    if content is None:
        raise HTTPException(status_code=404, detail="run not found")
    return PlainTextResponse(content, media_type="text/markdown; charset=utf-8")


@app.post("/v1/platform/runs/{run_id}/cancel", response_model=WorkflowRun)
async def cancel_run(run_id: str) -> WorkflowRun:
    run = await platform_service.cancel_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return run


@app.post("/v1/platform/runs/{run_id}/approval", response_model=WorkflowRun)
async def run_approval(run_id: str, req: RunApprovalRequest) -> WorkflowRun:
    try:
        run = await platform_service.approve_run(run_id, req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return run


@app.get("/v1/platform/runs/{run_id}/approval/advice", response_model=ApprovalAdvice)
async def run_approval_advice(run_id: str) -> ApprovalAdvice:
    try:
        advice = await platform_service.get_run_approval_advice(run_id)
    except ValueError as exc:
        msg = str(exc)
        code = 404 if "not found" in msg else 400
        raise HTTPException(status_code=code, detail=msg) from exc
    if not advice:
        raise HTTPException(status_code=404, detail="run not found")
    return advice


@app.get("/v1/platform/runs/{run_id}/events")
async def get_run_events(run_id: str) -> list[dict[str, object]]:
    run = await platform_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return [e.model_dump(mode="json") for e in run.events]


@app.get("/v1/platform/runs/{run_id}/stream")
async def stream_run(run_id: str) -> StreamingResponse:
    run = await platform_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    async def event_gen():
        index = 0
        while True:
            current = await platform_service.get_run(run_id)
            if not current:
                yield "event: end\ndata: {}\n\n"
                return
            events = current.events
            while index < len(events):
                payload = json.dumps(events[index].model_dump(mode="json"), ensure_ascii=False)
                yield f"data: {payload}\n\n"
                index += 1
            if current.status.value in ("completed", "failed", "canceled"):
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(event_gen(), media_type="text/event-stream")
