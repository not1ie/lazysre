from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(slots=True)
class TopologyGraph:
    env: str
    source: str
    generated_at: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "env": self.env,
            "source": self.source,
            "generated_at": self.generated_at,
            "nodes": list(self.nodes),
            "edges": list(self.edges),
            "notes": list(self.notes),
        }


def discover_topology(
    *,
    target: str = "",
    now_iso: str,
    runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
) -> TopologyGraph:
    run = runner or _default_runner
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    notes: list[str] = []
    source = "none"

    swarm = _discover_swarm(run)
    if swarm:
        source = "swarm"
        nodes.extend(swarm["nodes"])
        edges.extend(swarm["edges"])
        notes.extend(swarm["notes"])

    k8s = _discover_k8s(run)
    if k8s:
        source = "k8s" if source == "none" else f"{source}+k8s"
        nodes.extend(k8s["nodes"])
        edges.extend(k8s["edges"])
        notes.extend(k8s["notes"])

    if source == "none":
        notes.append("no swarm/k8s topology detected; commands not available or no permission")

    env_name = _sanitize_env_name(target or source or "local")
    unique_nodes = _dedupe_nodes(nodes)
    unique_edges = _dedupe_edges(edges)
    _mark_node_health(unique_nodes, unique_edges)
    return TopologyGraph(
        env=env_name,
        source=source,
        generated_at=now_iso,
        nodes=unique_nodes,
        edges=unique_edges,
        notes=notes[:30],
    )


def analyze_impact(graph: TopologyGraph, service: str, *, depth: int = 2) -> dict[str, Any]:
    target = str(service or "").strip()
    if not target:
        return {
            "service": "",
            "direct_dependents": [],
            "transitive_impact_chain": [],
            "affected_slo_endpoints": [],
            "notes": ["service name required"],
        }
    norm = _node_key(target)
    reverse: dict[str, list[str]] = {}
    forward: dict[str, list[str]] = {}
    for edge in graph.edges:
        src = _node_key(str(edge.get("source", "")))
        dst = _node_key(str(edge.get("target", "")))
        if not src or not dst:
            continue
        forward.setdefault(src, []).append(dst)
        reverse.setdefault(dst, []).append(src)

    direct = sorted(set(reverse.get(norm, [])))
    chains: list[list[str]] = []
    visited: set[str] = set([norm])
    frontier = [(norm, [norm], 0)]
    while frontier:
        node, path, level = frontier.pop(0)
        if level >= max(1, depth):
            continue
        for dep in reverse.get(node, []):
            if dep in visited:
                continue
            visited.add(dep)
            new_path = [dep, *path]
            chains.append(new_path)
            frontier.append((dep, new_path, level + 1))
    slo_hits = _extract_slo_endpoint_hints(graph, nodes=[norm, *direct])
    return {
        "service": target,
        "direct_dependents": direct,
        "transitive_impact_chain": chains[:30],
        "affected_slo_endpoints": slo_hits,
        "notes": graph.notes[:8],
    }


def render_topology_ascii(graph: TopologyGraph) -> str:
    lines = [f"Topology [{graph.env}] source={graph.source}", ""]
    if not graph.nodes:
        lines.append("- no nodes")
        return "\n".join(lines)
    children: dict[str, list[str]] = {}
    for edge in graph.edges:
        src = str(edge.get("source", "")).strip()
        dst = str(edge.get("target", "")).strip()
        if src and dst:
            children.setdefault(src, []).append(dst)
    roots = [str(node.get("id", "")) for node in graph.nodes if str(node.get("id", "")) not in {x.get("target", "") for x in graph.edges}]
    roots = sorted([x for x in roots if x]) or sorted({str(node.get("id", "")) for node in graph.nodes if str(node.get("id", ""))})
    meta = {str(node.get("id", "")): node for node in graph.nodes if str(node.get("id", ""))}
    seen: set[str] = set()
    for root in roots:
        _render_tree(lines, root, children, meta, seen, prefix="")
    if graph.notes:
        lines.extend(["", "Notes:"])
        for item in graph.notes[:8]:
            lines.append(f"- {item}")
    return "\n".join(lines)


def _discover_swarm(run: Callable[[list[str]], tuple[int, str, str]]) -> dict[str, Any] | None:
    code, out, _ = run(["docker", "service", "ls", "--format", "{{.ID}} {{.Name}}"])
    if code != 0:
        return None
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if not lines:
        return None
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    notes: list[str] = []
    service_ids: list[str] = []
    id_to_name: dict[str, str] = {}
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        sid, name = parts
        service_ids.append(sid)
        id_to_name[sid] = name
        nodes.append({"id": f"swarm:{name}", "kind": "service", "platform": "swarm", "health": "unknown"})
    for sid in service_ids:
        code, raw, _ = run(["docker", "service", "inspect", sid, "--format", "{{json .}}"])
        if code != 0 or not raw.strip():
            continue
        try:
            row = json.loads(raw.strip())
        except Exception:
            continue
        spec = row.get("Spec", {}) if isinstance(row, dict) else {}
        labels = spec.get("Labels", {}) if isinstance(spec, dict) else {}
        if isinstance(labels, dict):
            deps = _parse_depends_labels(labels)
            current = f"swarm:{id_to_name.get(sid, sid)}"
            for dep in deps:
                dep_node = f"swarm:{dep}"
                edges.append({"source": current, "target": dep_node, "relation": "depends_on"})
    notes.append(f"swarm services discovered: {len(service_ids)}")
    return {"nodes": nodes, "edges": edges, "notes": notes}


def _discover_k8s(run: Callable[[list[str]], tuple[int, str, str]]) -> dict[str, Any] | None:
    code, svc_out, _ = run(["kubectl", "get", "svc", "-A", "-o", "json"])
    if code != 0:
        return None
    code2, dep_out, _ = run(["kubectl", "get", "deploy", "-A", "-o", "json"])
    if code2 != 0:
        return None
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    notes: list[str] = []
    try:
        svc_payload = json.loads(svc_out)
        dep_payload = json.loads(dep_out)
    except Exception:
        return None
    services: dict[str, dict[str, str]] = {}
    for item in svc_payload.get("items", []):
        if not isinstance(item, dict):
            continue
        meta = item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {}
        ns = str(meta.get("namespace", "default")).strip()
        name = str(meta.get("name", "")).strip()
        if not name:
            continue
        node_id = f"k8s:{ns}/svc/{name}"
        nodes.append({"id": node_id, "kind": "service", "platform": "k8s", "health": "unknown"})
        services[f"{ns}:{name}"] = {"id": node_id, "ns": ns, "name": name}
    for item in dep_payload.get("items", []):
        if not isinstance(item, dict):
            continue
        meta = item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {}
        spec = item.get("spec", {}) if isinstance(item.get("spec", {}), dict) else {}
        tpl = spec.get("template", {}) if isinstance(spec.get("template", {}), dict) else {}
        pod_spec = tpl.get("spec", {}) if isinstance(tpl.get("spec", {}), dict) else {}
        ns = str(meta.get("namespace", "default")).strip()
        name = str(meta.get("name", "")).strip()
        if not name:
            continue
        dep_node = f"k8s:{ns}/deploy/{name}"
        nodes.append({"id": dep_node, "kind": "deployment", "platform": "k8s", "health": "unknown"})
        env_refs: list[str] = []
        for c in pod_spec.get("containers", []) if isinstance(pod_spec.get("containers", []), list) else []:
            if not isinstance(c, dict):
                continue
            for env in c.get("env", []) if isinstance(c.get("env", []), list) else []:
                if not isinstance(env, dict):
                    continue
                val = str(env.get("value", "")).strip()
                if val:
                    env_refs.extend(_extract_service_refs_from_text(val))
        labels = tpl.get("metadata", {}).get("labels", {}) if isinstance(tpl.get("metadata", {}), dict) else {}
        if isinstance(labels, dict):
            for value in labels.values():
                env_refs.extend(_extract_service_refs_from_text(str(value)))
        for ref in sorted(set(env_refs)):
            key = f"{ns}:{ref}" if ":" not in ref else ref
            target = services.get(key)
            if not target:
                continue
            edges.append({"source": dep_node, "target": target["id"], "relation": "calls"})
    notes.append(
        f"k8s services={len(services)} deployments={len(dep_payload.get('items', [])) if isinstance(dep_payload.get('items', []), list) else 0}"
    )
    return {"nodes": nodes, "edges": edges, "notes": notes}


def _extract_service_refs_from_text(text: str) -> list[str]:
    raw = str(text or "")
    matches = []
    for m in re_findall(r"\b([a-z0-9][a-z0-9-]{1,62})\.([a-z0-9-]{1,62})\.svc(?:\.cluster\.local)?\b", raw.lower()):
        svc, ns = m
        matches.append(f"{ns}:{svc}")
    for m in re_findall(r"\b([a-z0-9][a-z0-9-]{1,62})\b", raw.lower()):
        if m in {"http", "https", "tcp", "udp", "localhost"}:
            continue
        if m.endswith("-service") or m.endswith("-svc") or m in {"payment", "order", "gateway", "api"}:
            matches.append(m)
    return matches


def _parse_depends_labels(labels: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, value in labels.items():
        k = str(key).strip().lower()
        if all(token not in k for token in ("depend", "upstream", "requires")):
            continue
        raw = str(value).strip()
        if not raw:
            continue
        for item in raw.replace(";", ",").split(","):
            name = item.strip()
            if name:
                out.append(name)
    return out


def _sanitize_env_name(value: str) -> str:
    text = str(value or "").strip().lower()
    text = "".join(ch if (ch.isalnum() or ch in "-_.") else "-" for ch in text)
    text = text.strip("-")
    return text[:80] or "local"


def _node_key(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return text


def _dedupe_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for node in nodes:
        key = str(node.get("id", "")).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(node)
    out.sort(key=lambda x: str(x.get("id", "")))
    return out


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for edge in edges:
        src = str(edge.get("source", "")).strip()
        dst = str(edge.get("target", "")).strip()
        rel = str(edge.get("relation", "")).strip() or "link"
        if not src or not dst:
            continue
        key = f"{src}|{dst}|{rel}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"source": src, "target": dst, "relation": rel})
    out.sort(key=lambda x: (str(x.get("source", "")), str(x.get("target", ""))))
    return out


def _mark_node_health(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    inbound: dict[str, int] = {}
    outbound: dict[str, int] = {}
    for edge in edges:
        src = str(edge.get("source", ""))
        dst = str(edge.get("target", ""))
        outbound[src] = outbound.get(src, 0) + 1
        inbound[dst] = inbound.get(dst, 0) + 1
    for node in nodes:
        node_id = str(node.get("id", ""))
        out_deg = outbound.get(node_id, 0)
        in_deg = inbound.get(node_id, 0)
        if out_deg == 0 and in_deg == 0:
            node["health"] = "yellow"
        else:
            node["health"] = "green"


def _extract_slo_endpoint_hints(graph: TopologyGraph, *, nodes: list[str]) -> list[str]:
    hints: list[str] = []
    lowers = [x.lower() for x in nodes]
    for edge in graph.edges:
        src = str(edge.get("source", "")).lower()
        dst = str(edge.get("target", "")).lower()
        if any(n in src or n in dst for n in lowers):
            relation = str(edge.get("relation", ""))
            hints.append(f"{src} -> {dst} ({relation})")
    return hints[:12]


def _render_tree(
    lines: list[str],
    node: str,
    children: dict[str, list[str]],
    meta: dict[str, dict[str, Any]],
    seen: set[str],
    *,
    prefix: str,
) -> None:
    health = str(meta.get(node, {}).get("health", "unknown"))
    mark = {"green": "G", "yellow": "Y", "red": "R"}.get(health, "U")
    lines.append(f"{prefix}- [{mark}] {node}")
    if node in seen:
        return
    seen.add(node)
    for child in sorted(set(children.get(node, []))):
        _render_tree(lines, child, children, meta, seen, prefix=f"{prefix}  ")


def _default_runner(cmd: list[str]) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=8)
    except Exception as exc:
        return 1, "", str(exc)
    return int(proc.returncode), str(proc.stdout), str(proc.stderr)


def re_findall(pattern: str, text: str) -> list[Any]:
    import re

    return re.findall(pattern, text)
