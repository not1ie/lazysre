from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def default_secrets_path() -> Path:
    raw = os.getenv("LAZYSRE_SECRETS_FILE", "~/.lazysre/secrets.json")
    return Path(raw).expanduser()


class SecretStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_secrets_path()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(payload, dict):
            return {}
        return payload

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)

    def get_openai_api_key(self) -> str:
        payload = self.load()
        return str(payload.get("openai_api_key", "")).strip()

    def set_openai_api_key(self, api_key: str) -> None:
        payload = self.load()
        payload["openai_api_key"] = str(api_key).strip()
        self.save(payload)

    def clear_openai_api_key(self) -> bool:
        payload = self.load()
        if "openai_api_key" not in payload:
            return False
        payload.pop("openai_api_key", None)
        self.save(payload)
        return True

    def masked_openai_api_key(self) -> str:
        raw = self.get_openai_api_key()
        if not raw:
            return ""
        if len(raw) <= 10:
            return "***"
        return f"{raw[:4]}...{raw[-4:]}"

