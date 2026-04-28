from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import httpx

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass(slots=True)
class SLOItem:
    name: str
    target: str
    window: str
    metric_query: str
    data_source: str

    def target_ratio(self) -> float:
        return _parse_target_ratio(self.target)


@dataclass(slots=True)
class SLOSample:
    name: str
    target_ratio: float
    window: str
    data_source: str
    error_rates: dict[str, float]
    burn_rates: dict[str, float]
    status: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target_ratio": self.target_ratio,
            "window": self.window,
            "data_source": self.data_source,
            "error_rates": dict(self.error_rates),
            "burn_rates": dict(self.burn_rates),
            "status": self.status,
            "note": self.note,
        }


def default_slo_config_path() -> Path:
    return (Path.home() / ".lazysre" / "slos.yaml").expanduser()


def init_slo_config(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path
    payload = [
        {
            "name": "payment-availability",
            "target": "99.9%",
            "window": "30d",
            "metric_query": "sum(rate(http_requests_total{service=\"payment\",status=~\"5..\"}[5m])) / sum(rate(http_requests_total{service=\"payment\"}[5m]))",
            "data_source": "prometheus",
        },
        {
            "name": "gateway-error-rate-log",
            "target": "99.5%",
            "window": "30d",
            "metric_query": "/var/log/nginx/access.log",
            "data_source": "log_file",
        },
    ]
    text = _dump_yaml(payload)
    path.write_text(text, encoding="utf-8")
    return path


def load_slo_items(path: Path) -> list[SLOItem]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    data = _load_yaml(raw)
    if not isinstance(data, list):
        return []
    items: list[SLOItem] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "")).strip()
        target = str(row.get("target", "")).strip()
        window = str(row.get("window", "30d")).strip() or "30d"
        metric_query = str(row.get("metric_query", "")).strip()
        source = str(row.get("data_source", "mock")).strip().lower() or "mock"
        if not name or not target or not metric_query:
            continue
        items.append(
            SLOItem(
                name=name,
                target=target,
                window=window,
                metric_query=metric_query,
                data_source=source,
            )
        )
    return items


def evaluate_slo_items(
    *,
    items: list[SLOItem],
    prometheus_url: str,
    windows: list[str],
    now_fn: Callable[[], float] | None = None,
) -> list[SLOSample]:
    _ = now_fn
    selected_windows = [str(x).strip().lower() for x in windows if str(x).strip()]
    if not selected_windows:
        selected_windows = ["1h", "6h", "24h"]
    output: list[SLOSample] = []
    for item in items:
        target_ratio = item.target_ratio()
        error_budget = max(1e-8, 1.0 - target_ratio)
        error_rates: dict[str, float] = {}
        burn_rates: dict[str, float] = {}
        note = ""
        for window in selected_windows:
            rate, detail = _fetch_error_rate(
                item=item,
                window=window,
                prometheus_url=prometheus_url,
            )
            error_rates[window] = max(0.0, min(1.0, rate))
            burn_rates[window] = round(error_rates[window] / error_budget, 4)
            if detail:
                note = detail
        status = _derive_status(burn_rates)
        output.append(
            SLOSample(
                name=item.name,
                target_ratio=target_ratio,
                window=item.window,
                data_source=item.data_source,
                error_rates=error_rates,
                burn_rates=burn_rates,
                status=status,
                note=note,
            )
        )
    return output


def render_slo_status_text(samples: list[SLOSample]) -> str:
    if not samples:
        return "No SLO config loaded."
    lines = ["SLO Status"]
    for item in samples:
        burn_6h = item.burn_rates.get("6h", item.burn_rates.get("1h", 0.0))
        err_6h = item.error_rates.get("6h", item.error_rates.get("1h", 0.0))
        lines.append(
            f"- {item.name} status={item.status} target={item.target_ratio:.4f} "
            f"error={err_6h:.4f} burn={burn_6h:.2f} source={item.data_source}"
        )
    return "\n".join(lines)


def render_slo_burn_text(samples: list[SLOSample], *, window: str) -> str:
    lines = [f"SLO Burn Rate ({window})"]
    for item in samples:
        burn = item.burn_rates.get(window, 0.0)
        err = item.error_rates.get(window, 0.0)
        lines.append(f"- {item.name}: burn={burn:.2f} error_rate={err:.4f} status={item.status}")
    return "\n".join(lines)


def detect_burn_alert(samples: list[SLOSample]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for item in samples:
        b1 = float(item.burn_rates.get("1h", 0.0))
        b6 = float(item.burn_rates.get("6h", 0.0))
        b24 = float(item.burn_rates.get("24h", 0.0))
        critical = b1 >= 14.4 and b6 >= 6.0
        warning = b1 >= 6.0 or b6 >= 3.0 or b24 >= 1.0
        if critical or warning:
            alerts.append(
                {
                    "name": item.name,
                    "severity": "critical" if critical else "warning",
                    "burn_1h": round(b1, 4),
                    "burn_6h": round(b6, 4),
                    "burn_24h": round(b24, 4),
                    "target_ratio": item.target_ratio,
                    "note": item.note,
                }
            )
    return alerts


def post_webhook(url: str, payload: dict[str, Any], *, timeout_sec: int = 6) -> tuple[bool, str]:
    target = str(url or "").strip()
    if not target:
        return False, "webhook url is empty"
    try:
        response = httpx.post(target, json=payload, timeout=max(2, min(timeout_sec, 20)))
    except Exception as exc:
        return False, str(exc)
    if 200 <= int(response.status_code) < 300:
        return True, f"status={response.status_code}"
    return False, f"status={response.status_code} body={response.text[:160]}"


def _fetch_error_rate(*, item: SLOItem, window: str, prometheus_url: str) -> tuple[float, str]:
    source = item.data_source.strip().lower()
    if source == "prometheus":
        ratio, note = _prometheus_error_ratio(
            url=prometheus_url,
            query=item.metric_query,
            window=window,
        )
        return ratio, note
    if source == "log_file":
        ratio, note = _log_file_error_ratio(item.metric_query)
        return ratio, note
    return 0.001, "mock source"


def _prometheus_error_ratio(*, url: str, query: str, window: str) -> tuple[float, str]:
    base = str(url or "").strip().rstrip("/")
    if not base:
        return 0.0, "prometheus url missing"
    adapted = _inject_window(query, window)
    try:
        response = httpx.get(
            f"{base}/api/v1/query",
            params={"query": adapted},
            timeout=6,
        )
    except Exception as exc:
        return 0.0, f"prometheus request failed: {exc}"
    if response.status_code != 200:
        return 0.0, f"prometheus status={response.status_code}"
    try:
        payload = response.json()
    except Exception:
        return 0.0, "prometheus response not json"
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    result = data.get("result", []) if isinstance(data, dict) else []
    if not isinstance(result, list) or not result:
        return 0.0, "prometheus result empty"
    first = result[0]
    value = first.get("value", []) if isinstance(first, dict) else []
    if not isinstance(value, list) or len(value) < 2:
        return 0.0, "prometheus value missing"
    try:
        ratio = float(value[1])
    except Exception:
        return 0.0, "prometheus value parse failed"
    if ratio < 0:
        ratio = 0.0
    if ratio > 1:
        ratio = ratio / 100.0 if ratio <= 100 else 1.0
    return ratio, "prometheus ok"


def _log_file_error_ratio(path: str) -> tuple[float, str]:
    file_path = Path(str(path).strip()).expanduser()
    if not file_path.exists():
        return 0.0, f"log file not found: {file_path}"
    try:
        raw = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return 0.0, f"log file read failed: {exc}"
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return 0.0, "log file empty"
    error_count = 0
    for line in lines:
        lowered = line.lower()
        if (" error " in lowered) or ("exception" in lowered) or (" 5xx" in lowered) or (" status=5" in lowered):
            error_count += 1
    ratio = error_count / max(1, len(lines))
    return ratio, "log_file ok"


def _inject_window(query: str, window: str) -> str:
    win = str(window or "5m").strip().lower()
    if win not in {"1h", "6h", "24h"}:
        win = "5m"
    return re.sub(r"\[(?:\d+[smhdw])\]", f"[{win}]", str(query))


def _parse_target_ratio(target: str) -> float:
    text = str(target or "").strip()
    if not text:
        return 0.999
    if text.endswith("%"):
        try:
            return max(0.0, min(1.0, float(text[:-1].strip()) / 100.0))
        except Exception:
            return 0.999
    try:
        value = float(text)
    except Exception:
        return 0.999
    if value > 1.0:
        value = value / 100.0
    return max(0.0, min(1.0, value))


def _derive_status(burn_rates: dict[str, float]) -> str:
    b1 = float(burn_rates.get("1h", 0.0))
    b6 = float(burn_rates.get("6h", 0.0))
    b24 = float(burn_rates.get("24h", 0.0))
    if b1 >= 14.4 and b6 >= 6.0:
        return "critical"
    if b1 >= 6.0 or b6 >= 3.0 or b24 >= 1.0:
        return "warning"
    return "healthy"


def _dump_yaml(payload: Any) -> str:
    if yaml is None:
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    return str(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False))


def _load_yaml(raw: str) -> Any:
    text = str(raw or "").strip()
    if not text:
        return []
    if yaml is None:
        try:
            return json.loads(text)
        except Exception:
            return []
    try:
        return yaml.safe_load(text)
    except Exception:
        return []
