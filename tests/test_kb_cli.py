import json
from pathlib import Path

from typer.testing import CliRunner

import lazysre.cli.main as cli_main
from lazysre.cli.main import app


def test_kb_cli_add_list_search_show(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "knowledge.db"
    monkeypatch.setattr(cli_main, "_default_knowledge_db_path", lambda: db_path)

    note = tmp_path / "swarm-guide.md"
    note.write_text(
        "Swarm replica recovery playbook\\n"
        "Use docker service ps lazysre_lazysre --no-trunc to inspect failed tasks.\\n"
        "Then check docker service logs lazysre_lazysre --tail 200 for pull/auth errors.\\n",
        encoding="utf-8",
    )

    runner = CliRunner()

    added = runner.invoke(app, ["kb", "add", str(note)])
    assert added.exit_code == 0
    add_payload = json.loads(added.stdout)
    assert add_payload["documents"] == 1
    assert add_payload["chunks"] >= 1
    assert add_payload["added"] == 1
    assert add_payload["updated"] == 0
    assert add_payload["skipped"] == 0

    added_again = runner.invoke(app, ["kb", "add", str(note)])
    assert added_again.exit_code == 0
    add_again_payload = json.loads(added_again.stdout)
    assert add_again_payload["documents"] == 0
    assert add_again_payload["added"] == 0
    assert add_again_payload["updated"] == 0
    assert add_again_payload["skipped"] == 1

    listed = runner.invoke(app, ["kb", "list", "--json"])
    assert listed.exit_code == 0
    list_payload = json.loads(listed.stdout)
    assert len(list_payload) == 1
    doc_id = int(list_payload[0]["id"])

    searched = runner.invoke(app, ["kb", "search", "replica recovery", "--json"])
    assert searched.exit_code == 0
    search_payload = json.loads(searched.stdout)
    assert search_payload
    assert search_payload[0]["doc_id"] == doc_id

    filtered = runner.invoke(
        app,
        ["kb", "search", "replica recovery", "--source", "swarm-guide", "--min-score", "0.30", "--json"],
    )
    assert filtered.exit_code == 0
    filtered_payload = json.loads(filtered.stdout)
    assert filtered_payload
    assert all("swarm-guide" in item["source_path"] for item in filtered_payload)

    shown = runner.invoke(app, ["kb", "show", str(doc_id), "--json"])
    assert shown.exit_code == 0
    show_payload = json.loads(shown.stdout)
    assert show_payload["id"] == doc_id
    assert show_payload["chunks"]

    stats = runner.invoke(app, ["kb", "stats"])
    assert stats.exit_code == 0
    stats_payload = json.loads(stats.stdout)
    assert stats_payload["docs"] == 1
    assert stats_payload["chunks"] >= 1

    deleted = runner.invoke(app, ["kb", "delete", str(doc_id)])
    assert deleted.exit_code == 0
    deleted_payload = json.loads(deleted.stdout)
    assert deleted_payload["deleted_docs"] == 1
    assert deleted_payload["deleted_chunks"] >= 1


def test_kb_cli_prune(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "knowledge.db"
    monkeypatch.setattr(cli_main, "_default_knowledge_db_path", lambda: db_path)
    note = tmp_path / "tmp-prune.md"
    note.write_text("remove me", encoding="utf-8")
    runner = CliRunner()
    added = runner.invoke(app, ["kb", "add", str(note)])
    assert added.exit_code == 0
    note.unlink()

    pruned = runner.invoke(app, ["kb", "prune"])
    assert pruned.exit_code == 0
    payload = json.loads(pruned.stdout)
    assert payload["pruned_docs"] == 1
    assert payload["pruned_chunks"] >= 1


def test_kb_cli_rebuild(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "knowledge.db"
    monkeypatch.setattr(cli_main, "_default_knowledge_db_path", lambda: db_path)
    note = tmp_path / "tmp-rebuild.md"
    note.write_text("initial content", encoding="utf-8")
    runner = CliRunner()
    added = runner.invoke(app, ["kb", "add", str(note)])
    assert added.exit_code == 0
    note.write_text("updated content", encoding="utf-8")

    rebuilt = runner.invoke(app, ["kb", "rebuild"])
    assert rebuilt.exit_code == 0
    payload = json.loads(rebuilt.stdout)
    assert payload["scanned"] >= 1
    assert payload["updated"] >= 1
