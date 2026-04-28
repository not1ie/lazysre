import json
from pathlib import Path

from typer.testing import CliRunner

from lazysre.cli.main import app
from lazysre.topology.graph import TopologyGraph, analyze_impact, discover_topology


def test_discover_topology_with_mock_runner() -> None:
    def runner(cmd: list[str]) -> tuple[int, str, str]:
        key = " ".join(cmd)
        mapping: dict[str, tuple[int, str, str]] = {
            "docker service ls --format {{.ID}} {{.Name}}": (0, "a1 payment_api\nb2 redis_cache\n", ""),
            "docker service inspect a1 --format {{json .}}": (
                0,
                json.dumps({"Spec": {"Labels": {"depends_on": "redis_cache"}}}),
                "",
            ),
            "docker service inspect b2 --format {{json .}}": (0, json.dumps({"Spec": {"Labels": {}}}), ""),
            "kubectl get svc -A -o json": (
                0,
                json.dumps(
                    {
                        "items": [
                            {"metadata": {"namespace": "default", "name": "payment"}},
                            {"metadata": {"namespace": "default", "name": "redis"}},
                        ]
                    }
                ),
                "",
            ),
            "kubectl get deploy -A -o json": (
                0,
                json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"namespace": "default", "name": "checkout"},
                                "spec": {
                                    "template": {
                                        "metadata": {"labels": {"app": "checkout"}},
                                        "spec": {
                                            "containers": [
                                                {
                                                    "env": [
                                                        {
                                                            "name": "PAYMENT_URL",
                                                            "value": "http://payment.default.svc.cluster.local",
                                                        }
                                                    ]
                                                }
                                            ]
                                        },
                                    }
                                },
                            }
                        ]
                    }
                ),
                "",
            ),
        }
        return mapping.get(key, (1, "", "unknown command"))

    graph = discover_topology(target="prod-a", now_iso="2026-04-28T10:00:00+00:00", runner=runner)
    node_ids = {str(x.get("id", "")) for x in graph.nodes}
    assert "swarm:payment_api" in node_ids
    assert "swarm:redis_cache" in node_ids
    assert "k8s:default/svc/payment" in node_ids
    edges = {(str(x.get("source", "")), str(x.get("target", ""))) for x in graph.edges}
    assert ("swarm:payment_api", "swarm:redis_cache") in edges
    assert ("k8s:default/deploy/checkout", "k8s:default/svc/payment") in edges


def test_analyze_impact_chain() -> None:
    graph = TopologyGraph(
        env="prod",
        source="mock",
        generated_at="2026-04-28T10:00:00+00:00",
        nodes=[
            {"id": "svc-a", "kind": "service", "health": "green"},
            {"id": "svc-b", "kind": "service", "health": "green"},
            {"id": "svc-c", "kind": "service", "health": "green"},
        ],
        edges=[
            {"source": "svc-a", "target": "svc-b", "relation": "calls"},
            {"source": "svc-b", "target": "svc-c", "relation": "calls"},
        ],
        notes=[],
    )
    report = analyze_impact(graph, "svc-c", depth=2)
    assert "svc-b" in report["direct_dependents"]
    chains = report["transitive_impact_chain"]
    assert any(chain[0] == "svc-a" for chain in chains)


def test_cli_topology_discover_show_impact(tmp_path: Path, monkeypatch) -> None:
    import lazysre.cli.main as main_module

    def fake_discover_topology(*, target: str, now_iso: str):  # type: ignore[override]
        return TopologyGraph(
            env="qa",
            source="mock",
            generated_at=now_iso,
            nodes=[
                {"id": "svc-gateway", "kind": "service", "health": "green"},
                {"id": "svc-payment", "kind": "service", "health": "green"},
            ],
            edges=[{"source": "svc-gateway", "target": "svc-payment", "relation": "calls"}],
            notes=["mock"],
        )

    monkeypatch.setattr(main_module, "discover_topology", fake_discover_topology)
    monkeypatch.setattr(main_module, "_topology_store_path", lambda env: tmp_path / "topology" / f"{env}.json")

    runner = CliRunner()
    d = runner.invoke(app, ["topology", "discover", "--target", "qa", "--format", "json"])
    assert d.exit_code == 0
    payload = json.loads(d.stdout.split("Topology stored:")[0].strip())
    assert payload["env"] == "qa"

    s = runner.invoke(app, ["topology", "show", "payment", "--env", "qa"])
    assert s.exit_code == 0
    show_payload = json.loads(s.stdout)
    assert "svc-payment" in show_payload["matches"]

    i = runner.invoke(app, ["topology", "impact", "payment", "--env", "qa"])
    assert i.exit_code == 0
    impact_payload = json.loads(i.stdout)
    assert "svc-gateway" in impact_payload["direct_dependents"]
