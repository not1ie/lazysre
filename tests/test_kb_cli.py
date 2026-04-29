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

    shown = runner.invoke(app, ["kb", "show", str(doc_id), "--json"])
    assert shown.exit_code == 0
    show_payload = json.loads(shown.stdout)
    assert show_payload["id"] == doc_id
    assert show_payload["chunks"]
