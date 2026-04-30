from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


def default_aiops_bridge_path() -> Path:
    return (Path.home() / ".lazysre" / "aiops_bridge.json").expanduser()


@dataclass(slots=True)
class AIOpsBridgeConfig:
    base_url: str = ""
    api_key_env: str = "LAZY_AIOPS_API_KEY"
    timeout_sec: int = 12
    verify_tls: bool = True
    updated_at: str = ""


class AIOpsBridgeStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = (path or default_aiops_bridge_path()).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> AIOpsBridgeConfig:
        if not self.path.exists():
            return AIOpsBridgeConfig()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return AIOpsBridgeConfig()
        if not isinstance(payload, dict):
            return AIOpsBridgeConfig()
        return AIOpsBridgeConfig(
            base_url=str(payload.get("base_url", "")).strip(),
            api_key_env=str(payload.get("api_key_env", "LAZY_AIOPS_API_KEY")).strip() or "LAZY_AIOPS_API_KEY",
            timeout_sec=max(3, min(int(payload.get("timeout_sec", 12) or 12), 120)),
            verify_tls=bool(payload.get("verify_tls", True)),
            updated_at=str(payload.get("updated_at", "")).strip(),
        )

    def save(self, config: AIOpsBridgeConfig) -> dict[str, object]:
        updated = AIOpsBridgeConfig(
            base_url=str(config.base_url).strip().rstrip("/"),
            api_key_env=str(config.api_key_env).strip() or "LAZY_AIOPS_API_KEY",
            timeout_sec=max(3, min(int(config.timeout_sec), 120)),
            verify_tls=bool(config.verify_tls),
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        self.path.write_text(json.dumps(asdict(updated), ensure_ascii=False, indent=2), encoding="utf-8")
        return asdict(updated)


class AIOpsBridgeClient:
    def __init__(self, config: AIOpsBridgeConfig, *, explicit_api_key: str = "") -> None:
        self.config = config
        self.base_url = str(config.base_url or "").strip().rstrip("/")
        env_name = str(config.api_key_env or "LAZY_AIOPS_API_KEY").strip()
        self.api_key = str(explicit_api_key or os.getenv(env_name, "")).strip()

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request_json(self, method: str, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.base_url:
            return {"ok": False, "error": "base_url is not configured"}
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(timeout=max(3, min(int(self.config.timeout_sec), 120)), verify=bool(self.config.verify_tls)) as client:
                resp = client.request(method.upper(), url, headers=self._headers(), params=params or None)
            body: Any
            try:
                body = resp.json()
            except Exception:
                body = {"text": resp.text[:500]}
            return {
                "ok": bool(resp.status_code < 400),
                "status_code": int(resp.status_code),
                "url": url,
                "body": body,
            }
        except Exception as exc:
            return {"ok": False, "status_code": 0, "url": url, "error": str(exc)}

    def health(self) -> dict[str, Any]:
        for path in ("/health", "/api/health", "/v1/health"):
            payload = self._request_json("GET", path)
            if payload.get("ok"):
                return payload
        return payload

    def list_skills(self, *, limit: int = 30) -> dict[str, Any]:
        cap = max(1, min(int(limit), 200))
        last: dict[str, Any] = {}
        for path in ("/api/v1/skills", "/v1/skills", "/skills"):
            payload = self._request_json("GET", path, params={"limit": cap})
            last = payload
            if not payload.get("ok"):
                continue
            body = payload.get("body")
            items = _extract_list_items(body)
            payload["items"] = items[:cap]
            payload["count"] = len(payload["items"])
            return payload
        return last or {"ok": False, "error": "no endpoint responded"}


def _extract_list_items(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return [item for item in body if isinstance(item, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("items", "skills", "data", "list", "results"):
        value = body.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _extract_list_items(value)
            if nested:
                return nested
    return []

