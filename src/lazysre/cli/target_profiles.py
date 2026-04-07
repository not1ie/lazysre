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

    def export_payload(self, *, names: list[str] | None = None) -> dict[str, Any]:
        payload = self.load()
        profiles = payload.get("profiles", {})
        if not isinstance(profiles, dict):
            profiles = {}

        selected_names = [x.strip() for x in (names or []) if x.strip()]
        selected: dict[str, Any] = {}
        if selected_names:
            for name in selected_names:
                raw = profiles.get(name, {})
                if isinstance(raw, dict):
                    selected[name] = asdict(_env_from_dict(raw))
        else:
            for name, raw in profiles.items():
                if not str(name).strip() or (not isinstance(raw, dict)):
                    continue
                selected[str(name)] = asdict(_env_from_dict(raw))

        active = str(payload.get("active", "")).strip()
        if active not in selected:
            active = ""
        return {"version": 1, "active": active, "profiles": selected}

    def import_payload(self, payload: dict[str, Any], *, merge: bool) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("invalid payload")

        raw_profiles = payload.get("profiles", payload)
        if not isinstance(raw_profiles, dict):
            raise ValueError("invalid payload: profiles must be an object")

        normalized: dict[str, Any] = {}
        for name, raw in raw_profiles.items():
            key = str(name).strip()
            if not key or (not isinstance(raw, dict)):
                continue
            normalized[key] = asdict(_env_from_dict(raw))
        if not normalized:
            raise ValueError("no valid profiles found in payload")

        current = self.load()
        current_profiles = current.get("profiles", {})
        if not isinstance(current_profiles, dict):
            current_profiles = {}

        before = {
            str(name): asdict(_env_from_dict(raw))
            for name, raw in current_profiles.items()
            if str(name).strip() and isinstance(raw, dict)
        }
        result_profiles = dict(before) if merge else {}
        created = 0
        updated = 0
        for name, env in normalized.items():
            previous = result_profiles.get(name)
            result_profiles[name] = env
            if previous is None:
                created += 1
            elif previous != env:
                updated += 1

        incoming_active = str(payload.get("active", "")).strip()
        if merge:
            active = str(current.get("active", "")).strip()
            if incoming_active and incoming_active in result_profiles:
                active = incoming_active
        else:
            active = incoming_active if incoming_active in result_profiles else ""

        self.save({"active": active, "profiles": result_profiles})
        return {
            "imported": len(normalized),
            "created": created,
            "updated": updated,
            "active": active,
            "total": len(result_profiles),
        }

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
