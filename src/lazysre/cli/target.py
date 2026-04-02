from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from lazysre.cli.executor import SafeExecutor
from lazysre.cli.types import ExecResult
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


async def probe_target_environment(
    target: TargetEnvironment,
    *,
    executor: SafeExecutor,
    timeout_sec: int = 6,
) -> dict[str, Any]:
    timeout = max(2, min(timeout_sec, 30))
    checks: dict[str, dict[str, Any]] = {}

    if target.prometheus_url.strip():
        prom_url = target.prometheus_url.strip().rstrip("/")
        res = await executor.run(
            ["curl", "-sS", "--max-time", str(timeout), f"{prom_url}/-/healthy"]
        )
        checks["prometheus"] = _serialize_probe_result(res, expect_substring="Prometheus")
    else:
        checks["prometheus"] = _missing_probe_result("target.prometheus_url is empty")

    k8s_cmd = _build_kubectl_probe_command(target, timeout_sec=timeout)
    if k8s_cmd:
        res = await executor.run(k8s_cmd)
        checks["kubernetes"] = _serialize_probe_result(res, expect_substring="Server Version")
    else:
        checks["kubernetes"] = _missing_probe_result("k8s target is not configured")

    docker_res = await executor.run(["docker", "info", "--format", "{{.ServerVersion}}"])
    checks["docker"] = _serialize_probe_result(docker_res, expect_substring=".")

    ok_count = sum(1 for item in checks.values() if bool(item.get("ok")))
    return {
        "target": target.to_safe_dict(),
        "summary": {
            "ok_count": ok_count,
            "total": len(checks),
            "all_ok": ok_count == len(checks),
        },
        "checks": checks,
    }


def _build_kubectl_probe_command(target: TargetEnvironment, *, timeout_sec: int) -> list[str]:
    if not (
        target.k8s_api_url.strip()
        or target.k8s_context.strip()
        or target.k8s_bearer_token.strip()
    ):
        return []
    cmd = ["kubectl"]
    if target.k8s_context.strip():
        cmd.extend(["--context", target.k8s_context.strip()])
    if target.k8s_api_url.strip():
        cmd.extend(["--server", target.k8s_api_url.strip()])
    if target.k8s_bearer_token.strip():
        cmd.extend(["--token", target.k8s_bearer_token.strip()])
    if target.k8s_api_url.strip() and (not target.k8s_verify_tls):
        cmd.append("--insecure-skip-tls-verify=true")
    cmd.extend(["version", "--request-timeout", f"{timeout_sec}s"])
    return cmd


def _serialize_probe_result(result: ExecResult, *, expect_substring: str) -> dict[str, Any]:
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    signal_ok = expect_substring.lower() in stdout.lower() if stdout else False
    dry_run_ok = bool(result.dry_run and result.ok)
    return {
        "ok": bool(result.ok and (dry_run_ok or signal_ok or not expect_substring)),
        "exit_code": result.exit_code,
        "command": result.command,
        "stdout_preview": _preview(stdout),
        "stderr_preview": _preview(stderr),
        "risk_level": result.risk_level,
    }


def _missing_probe_result(reason: str) -> dict[str, Any]:
    return {
        "ok": False,
        "exit_code": -1,
        "command": [],
        "stdout_preview": "",
        "stderr_preview": reason,
        "risk_level": "low",
    }


def _preview(text: str, limit: int = 240) -> str:
    if not text:
        return ""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
