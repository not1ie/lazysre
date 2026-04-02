from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from lazysre.config import settings


@dataclass(slots=True)
class TargetEnvironment:
    prometheus_url: str = ""
    k8s_api_url: str = ""
    k8s_context: str = ""
    k8s_namespace: str = "default"
    k8s_bearer_token: str = ""
    k8s_verify_tls: bool = False

    def to_safe_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        token = str(payload.get("k8s_bearer_token", "")).strip()
        if token:
            payload["k8s_bearer_token"] = f"{token[:4]}...{token[-4:]}" if len(token) > 10 else "***"
        else:
            payload["k8s_bearer_token"] = ""
        return payload


class TargetEnvStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(settings.target_profile_file)

    def load(self) -> TargetEnvironment:
        base = TargetEnvironment(
            prometheus_url=settings.target_prometheus_url.strip(),
            k8s_api_url=settings.target_k8s_api_url.strip(),
            k8s_context=settings.target_k8s_context.strip(),
            k8s_namespace=settings.target_k8s_namespace.strip() or "default",
            k8s_bearer_token=settings.target_k8s_bearer_token.strip(),
            k8s_verify_tls=bool(settings.target_k8s_verify_tls),
        )
        if not self.path.exists():
            return base
        raw = self.path.read_text(encoding="utf-8").strip()
        if not raw:
            return base
        try:
            payload = json.loads(raw)
        except Exception:
            return base
        if not isinstance(payload, dict):
            return base
        return TargetEnvironment(
            prometheus_url=str(payload.get("prometheus_url", base.prometheus_url)).strip(),
            k8s_api_url=str(payload.get("k8s_api_url", base.k8s_api_url)).strip(),
            k8s_context=str(payload.get("k8s_context", base.k8s_context)).strip(),
            k8s_namespace=str(payload.get("k8s_namespace", base.k8s_namespace)).strip() or "default",
            k8s_bearer_token=str(payload.get("k8s_bearer_token", base.k8s_bearer_token)).strip(),
            k8s_verify_tls=bool(payload.get("k8s_verify_tls", base.k8s_verify_tls)),
        )

    def save(self, env: TargetEnvironment) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(asdict(env), ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)

    def update(self, **kwargs: Any) -> TargetEnvironment:
        current = self.load()
        for key, value in kwargs.items():
            if value is None:
                continue
            if not hasattr(current, key):
                continue
            setattr(current, key, value)
        current.k8s_namespace = (current.k8s_namespace or "default").strip() or "default"
        self.save(current)
        return current
