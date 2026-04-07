from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from lazysre.cli.target import TargetEnvironment, TargetEnvStore
from lazysre.config import settings


@dataclass(slots=True)
class ClusterProfileStore:
    path: Path

    @classmethod
    def default(cls) -> "ClusterProfileStore":
        return cls(Path(settings.target_profiles_file))

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"active": "", "profiles": {}}
        raw = self.path.read_text(encoding="utf-8").strip()
        if not raw:
            return {"active": "", "profiles": {}}
        try:
            payload = json.loads(raw)
        except Exception:
            return {"active": "", "profiles": {}}
        if not isinstance(payload, dict):
            return {"active": "", "profiles": {}}
        active = str(payload.get("active", "")).strip()
        profiles = payload.get("profiles", {})
        if not isinstance(profiles, dict):
            profiles = {}
        return {"active": active, "profiles": profiles}

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)

    def list_profiles(self) -> list[str]:
        payload = self.load()
        profiles = payload.get("profiles", {})
        if not isinstance(profiles, dict):
            return []
        return sorted(str(k) for k in profiles.keys() if str(k).strip())

    def get_active(self) -> str:
        payload = self.load()
        return str(payload.get("active", "")).strip()

    def get_profile(self, name: str) -> TargetEnvironment | None:
        payload = self.load()
        profiles = payload.get("profiles", {})
        if not isinstance(profiles, dict):
            return None
        raw = profiles.get(name, {})
        if not isinstance(raw, dict):
            return None
        return _env_from_dict(raw)

    def upsert_profile(self, name: str, env: TargetEnvironment, *, activate: bool) -> None:
        key = name.strip()
        if not key:
            return
        payload = self.load()
        profiles = payload.get("profiles", {})
        if not isinstance(profiles, dict):
            profiles = {}
        profiles[key] = asdict(env)
        payload["profiles"] = profiles
        if activate:
            payload["active"] = key
        self.save(payload)

    def remove_profile(self, name: str) -> bool:
        key = name.strip()
        if not key:
            return False
        payload = self.load()
        profiles = payload.get("profiles", {})
        if not isinstance(profiles, dict) or key not in profiles:
            return False
        del profiles[key]
        payload["profiles"] = profiles
        if str(payload.get("active", "")).strip() == key:
            payload["active"] = ""
        self.save(payload)
        return True

    def activate(self, name: str, *, target_profile_file: Path) -> bool:
        env = self.get_profile(name)
        if not env:
            return False
        payload = self.load()
        payload["active"] = name.strip()
        self.save(payload)
        TargetEnvStore(target_profile_file).save(env)
        return True


def _env_from_dict(raw: dict[str, Any]) -> TargetEnvironment:
    return TargetEnvironment(
        prometheus_url=str(raw.get("prometheus_url", "")).strip(),
        k8s_api_url=str(raw.get("k8s_api_url", "")).strip(),
        k8s_context=str(raw.get("k8s_context", "")).strip(),
        k8s_namespace=str(raw.get("k8s_namespace", "default")).strip() or "default",
        k8s_bearer_token=str(raw.get("k8s_bearer_token", "")).strip(),
        k8s_verify_tls=bool(raw.get("k8s_verify_tls", False)),
    )
