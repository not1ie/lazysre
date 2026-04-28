import json
from pathlib import Path

from typer.testing import CliRunner

from lazysre.cli.main import app
from lazysre.slo.engine import (
    SLOItem,
    default_slo_config_path,
    detect_burn_alert,
    evaluate_slo_items,
    init_slo_config,
    load_slo_items,
)


def test_slo_init_and_load(tmp_path: Path) -> None:
    config = tmp_path / "slos.yaml"
    init_slo_config(config)
    assert config.exists()
    items = load_slo_items(config)
    assert items
    assert any(item.name == "payment-availability" for item in items)


def test_slo_burn_rate_and_alert_detection() -> None:
    items = [
        SLOItem(
            name="mock-slo",
            target="99.9%",
            window="30d",
            metric_query="unused",
            data_source="mock",
        )
    ]
    samples = evaluate_slo_items(items=items, prometheus_url="", windows=["1h", "6h", "24h"])
    assert len(samples) == 1
    assert samples[0].burn_rates["1h"] >= 0.0
    alerts = detect_burn_alert(samples)
    assert isinstance(alerts, list)


def test_slo_cli_status_burn_and_alert(tmp_path: Path) -> None:
    cfg = tmp_path / "slos.yaml"
    cfg.write_text(
        """
- name: mock-api
  target: 99.9%
  window: 30d
  metric_query: "unused"
  data_source: mock
""".strip()
        + "\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    status = runner.invoke(app, ["slo", "status", "--config-file", str(cfg), "--json"])
    assert status.exit_code == 0
    status_payload = json.loads(status.stdout)
    assert status_payload["samples"]

    burn = runner.invoke(app, ["slo", "burn-rate", "--window", "1h", "--config-file", str(cfg), "--json"])
    assert burn.exit_code == 0
    burn_payload = json.loads(burn.stdout)
    assert burn_payload["window"] == "1h"
    assert burn_payload["samples"]

    alert = runner.invoke(app, ["slo", "alert", "--config-file", str(cfg), "--simulate", "--json"])
    assert alert.exit_code == 0
    alert_payload = json.loads(alert.stdout)
    assert isinstance(alert_payload.get("alerts", []), list)


def test_default_slo_config_path_points_home() -> None:
    path = default_slo_config_path()
    assert str(path).endswith(".lazysre/slos.yaml")
