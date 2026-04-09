from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from lazysre.providers.registry import get_provider_spec


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

    def get_api_key(self, provider: str) -> str:
        spec = get_provider_spec(provider)
        payload = self.load()
        return str(payload.get(spec.secret_key, "")).strip()

    def set_api_key(self, provider: str, api_key: str) -> None:
        spec = get_provider_spec(provider)
        payload = self.load()
        payload[spec.secret_key] = str(api_key).strip()
        self.save(payload)

    def clear_api_key(self, provider: str) -> bool:
        spec = get_provider_spec(provider)
        payload = self.load()
        if spec.secret_key not in payload:
            return False
        payload.pop(spec.secret_key, None)
        self.save(payload)
        return True

    def masked_api_key(self, provider: str) -> str:
        raw = self.get_api_key(provider)
        if not raw:
            return ""
        if len(raw) <= 10:
            return "***"
        return f"{raw[:4]}...{raw[-4:]}"

    def get_openai_api_key(self) -> str:
        return self.get_api_key("openai")

    def set_openai_api_key(self, api_key: str) -> None:
        self.set_api_key("openai", api_key)

    def clear_openai_api_key(self) -> bool:
        return self.clear_api_key("openai")

    def masked_openai_api_key(self) -> str:
        return self.masked_api_key("openai")
