from __future__ import annotations

from pathlib import Path

from lazysre.cli.incident import IncidentStore, render_incident_markdown


def test_incident_store_open_note_close_and_archive(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incident.json")
    rec = store.open_incident(
        title="支付服务响应慢",
        severity="high",
        assignee="sre-oncall",
        summary="error rate 在 5 分钟内明显上升",
        source="chat",
        tags=["payment", "p1"],
    )
    assert rec.id.startswith("INC-")
    assert rec.status == "open"
    assert rec.assignee == "sre-oncall"
    assert rec.severity == "high"

    rec = store.add_note("先执行 /scan 与 /brief", author="user")
    assert rec.timeline[-1]["kind"] == "note"
    assert "scan" in rec.timeline[-1]["message"]

    rec = store.set_severity("critical")
    assert rec.severity == "critical"
    rec = store.set_assignee("alice")
    assert rec.assignee == "alice"

    closed = store.close_incident(resolution="扩容后恢复")
    assert closed.status == "closed"
    assert closed.closed_at_utc
    assert "扩容后恢复" in closed.resolution
    assert store.active() is None

    rows = store.list_recent(limit=5)
    assert rows
    assert rows[0].id == closed.id
    assert rows[0].status == "closed"


def test_incident_store_rejects_second_active_incident(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incident.json")
    store.open_incident(title="k8s 节点异常", severity="medium")
    try:
        store.open_incident(title="第二个事故", severity="high")
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "active incident exists" in str(exc)


def test_render_incident_markdown_contains_core_sections(tmp_path: Path) -> None:
    store = IncidentStore(tmp_path / "incident.json")
    rec = store.open_incident(title="swarm 副本不足", severity="high")
    rec = store.add_note("检查 service logs", author="user")
    text = render_incident_markdown(rec)
    assert "# LazySRE Incident" in text
    assert "## Timeline" in text
    assert rec.id in text

