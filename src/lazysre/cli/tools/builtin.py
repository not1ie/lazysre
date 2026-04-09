from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime, timedelta

from lazysre.cli.executor import SafeExecutor
from lazysre.cli.registry import ToolDefinition
from lazysre.cli.target import TargetEnvStore
from lazysre.cli.types import ExecResult, ToolSpec
from lazysre.cli.tools.redact import redact_and_compress


def builtin_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            spec=ToolSpec(
                name="get_cluster_context",
                description=(
                    "Collect cluster context: namespaces, unhealthy pods and recent events. "
                    "Output is sanitized and compressed for token safety."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string"},
                        "event_limit": {"type": "integer", "default": 30},
                    },
                    "additionalProperties": False,
                },
            ),
            handler=_get_cluster_context,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="fetch_service_logs",
                description=(
                    "Fetch service/pod logs by keyword and time window. "
                    "Output is sanitized and compressed for token safety."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "namespace": {"type": "string", "default": "default"},
                        "service": {"type": "string"},
                        "pod": {"type": "string"},
                        "container": {"type": "string"},
                        "keyword": {"type": "string"},
                        "since_minutes": {"type": "integer", "default": 20},
                        "limit": {"type": "integer", "default": 200},
                    },
                    "additionalProperties": False,
                },
            ),
            handler=_fetch_service_logs,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="get_metrics",
                description=(
                    "Query Prometheus range API for key metrics. "
                    "Output is sanitized and compressed for token safety."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "prometheus_url": {"type": "string"},
                        "query": {"type": "string"},
                        "window_minutes": {"type": "integer", "default": 15},
                        "step_sec": {"type": "integer", "default": 30},
                        "timeout_sec": {"type": "integer", "default": 10},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
            handler=_get_metrics,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="get_swarm_context",
                description=(
                    "Collect Docker Swarm context: node state, service replica health, "
                    "failed tasks and recent service task status. Read-only and compressed."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "service": {"type": "string", "description": "Optional service name filter"},
                        "include_logs": {"type": "boolean", "default": False},
                        "tail": {"type": "integer", "default": 80},
                    },
                    "additionalProperties": False,
                },
            ),
            handler=_get_swarm_context,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="fetch_swarm_service_logs",
                description=(
                    "Fetch Docker Swarm service logs by service name, keyword and time window. "
                    "Output is sanitized and compressed."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "service": {"type": "string"},
                        "keyword": {"type": "string"},
                        "since": {"type": "string", "default": "30m"},
                        "tail": {"type": "integer", "default": 200},
                    },
                    "required": ["service"],
                    "additionalProperties": False,
                },
            ),
            handler=_fetch_swarm_service_logs,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="kubectl",
                description="Run read-only or operational kubectl subcommands.",
                parameters={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "kubectl subcommand body"},
                        "context": {"type": "string"},
                        "namespace": {"type": "string"},
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_kubectl,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="docker",
                description="Run docker subcommands for container/service diagnostics.",
                parameters={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "docker subcommand body"}
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_docker,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="curl",
                description="Call HTTP endpoints for health checks or API diagnostics.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "headers": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "header lines like Key: Value",
                        },
                        "data": {"type": "string"},
                        "timeout_sec": {"type": "integer", "default": 10},
                    },
                    "required": ["url"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_curl,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="logs",
                description="Read local log files with tail for troubleshooting.",
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "lines": {"type": "integer", "default": 100},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_logs,
        ),
    ]


def tool_pack() -> list[ToolDefinition]:
    return builtin_tools()


async def _get_cluster_context(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    target = TargetEnvStore().load()
    namespace = str(args.get("namespace", "")).strip() or target.k8s_namespace
    event_limit = int(args.get("event_limit", 30) or 30)
    event_limit = max(1, min(event_limit, 200))

    ns_cmd = [*_kubectl_base(target, namespace=""), "get", "namespaces", "-o", "json"]
    pods_cmd = [*_kubectl_base(target, namespace=""), "get", "pods", "-A", "-o", "json"]
    events_cmd = [*_kubectl_base(target, namespace=""), "get", "events", "-A", "--sort-by=.metadata.creationTimestamp", "-o", "json"]
    if namespace:
        pods_cmd = [*_kubectl_base(target, namespace=namespace), "get", "pods", "-o", "json"]
        events_cmd = [*_kubectl_base(target, namespace=namespace), "get", "events", "--sort-by=.metadata.creationTimestamp", "-o", "json"]

    ns_res = await executor.run(ns_cmd)
    pods_res = await executor.run(pods_cmd)
    events_res = await executor.run(events_cmd)

    namespace_count, abnormal_pods, abnormal_text = _summarize_pods(pods_res.stdout, namespace)
    events_text = _summarize_events(events_res.stdout, limit=event_limit)

    summary = {
        "scope": namespace or "all",
        "namespace_count": namespace_count,
        "abnormal_pod_count": len(abnormal_pods),
        "abnormal_pods": abnormal_pods[:40],
        "recent_events": events_text,
        "probe": {
            "namespaces_ok": ns_res.ok,
            "pods_ok": pods_res.ok,
            "events_ok": events_res.ok,
        },
    }
    rendered = redact_and_compress(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n" + abnormal_text,
        max_lines=180,
        max_chars=12000,
    )
    return ExecResult(
        ok=(ns_res.ok and pods_res.ok and events_res.ok),
        command=["observer/get_cluster_context"],
        stdout=rendered,
        stderr="\n".join(x for x in [ns_res.stderr, pods_res.stderr, events_res.stderr] if x)[:1500],
        exit_code=0 if (ns_res.ok and pods_res.ok and events_res.ok) else 1,
        dry_run=executor.dry_run,
        risk_level="low",
        policy_reasons=["context observer read-only bundle"],
    )


async def _fetch_service_logs(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    target_env = TargetEnvStore().load()
    namespace = str(args.get("namespace", "")).strip() or target_env.k8s_namespace
    service = str(args.get("service", "")).strip()
    pod = str(args.get("pod", "")).strip()
    container = str(args.get("container", "")).strip()
    keyword = str(args.get("keyword", "")).strip().lower()
    since_minutes = int(args.get("since_minutes", 20) or 20)
    limit = int(args.get("limit", 200) or 200)
    since_minutes = max(1, min(since_minutes, 24 * 60))
    limit = max(20, min(limit, 2000))

    target = pod or (f"deploy/{service}" if service else "")
    if not target:
        return ExecResult(
            ok=False,
            command=["observer/fetch_service_logs"],
            stderr="missing service or pod",
            exit_code=2,
            dry_run=executor.dry_run,
            risk_level="low",
        )

    cmd = [*_kubectl_base(target_env, namespace=namespace), "logs", target, "--since", f"{since_minutes}m", "--tail", str(limit)]
    if container:
        cmd.extend(["-c", container])
    res = await executor.run(cmd)
    text = res.stdout
    if keyword and text:
        filtered = [line for line in text.splitlines() if keyword in line.lower()]
        text = "\n".join(filtered) if filtered else "(no lines matched keyword)"
    compact = redact_and_compress(text, max_lines=180, max_chars=12000)
    return ExecResult(
        ok=res.ok,
        command=["observer/fetch_service_logs"],
        stdout=compact,
        stderr=redact_and_compress(res.stderr, max_lines=60, max_chars=1800),
        exit_code=res.exit_code,
        dry_run=res.dry_run,
        risk_level="low",
        policy_reasons=["log observer read-only bundle"],
    )


async def _get_metrics(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    target = TargetEnvStore().load()
    prom_url = str(args.get("prometheus_url", "")).strip().rstrip("/") or target.prometheus_url.rstrip("/")
    query = str(args.get("query", "")).strip()
    window_minutes = int(args.get("window_minutes", 15) or 15)
    step_sec = int(args.get("step_sec", 30) or 30)
    timeout_sec = int(args.get("timeout_sec", 10) or 10)

    if not query:
        return ExecResult(
            ok=False,
            command=["observer/get_metrics"],
            stderr="query is required",
            exit_code=2,
            dry_run=executor.dry_run,
            risk_level="low",
        )
    if not prom_url:
        return ExecResult(
            ok=False,
            command=["observer/get_metrics"],
            stderr="prometheus_url is missing. set LAZYSRE_TARGET_PROMETHEUS_URL or use lsre target set --prometheus-url",
            exit_code=2,
            dry_run=executor.dry_run,
            risk_level="low",
        )

    window_minutes = max(1, min(window_minutes, 12 * 60))
    step_sec = max(5, min(step_sec, 300))
    timeout_sec = max(1, min(timeout_sec, 60))

    end = datetime.now(UTC)
    start = end - timedelta(minutes=window_minutes)
    url = (
        f"{prom_url}/api/v1/query_range"
        f"?query={_url_quote(query)}"
        f"&start={_url_quote(start.isoformat())}"
        f"&end={_url_quote(end.isoformat())}"
        f"&step={step_sec}"
    )
    cmd = ["curl", "-sS", "--max-time", str(timeout_sec), url]
    res = await executor.run(cmd)
    summary = _summarize_prom_response(res.stdout, query=query)
    compact = redact_and_compress(summary, max_lines=160, max_chars=9000)
    return ExecResult(
        ok=res.ok,
        command=["observer/get_metrics"],
        stdout=compact,
        stderr=redact_and_compress(res.stderr, max_lines=50, max_chars=1600),
        exit_code=res.exit_code,
        dry_run=res.dry_run,
        risk_level="low",
        policy_reasons=["metrics observer read-only bundle"],
    )


async def _get_swarm_context(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    service_filter = str(args.get("service", "")).strip()
    include_logs = bool(args.get("include_logs", False))
    tail = max(20, min(int(args.get("tail", 80) or 80), 500))

    info_res = await executor.run(["docker", "info", "--format", "{{json .Swarm}}"])
    services_cmd = ["docker", "service", "ls", "--format", "{{.Name}}\t{{.Mode}}\t{{.Replicas}}\t{{.Image}}"]
    services_res = await executor.run(services_cmd)
    nodes_res = await executor.run(["docker", "node", "ls", "--format", "{{.Hostname}}\t{{.Status}}\t{{.Availability}}\t{{.ManagerStatus}}"])

    service_rows = _parse_swarm_service_rows(services_res.stdout)
    if service_filter:
        service_rows = [
            row
            for row in service_rows
            if service_filter.lower() in str(row.get("name", "")).lower()
        ]
    unhealthy = [row for row in service_rows if bool(row.get("unhealthy"))]

    task_summaries: list[dict[str, object]] = []
    log_snippets: list[dict[str, str]] = []
    selected_services = [str(row.get("name", "")) for row in (unhealthy or service_rows) if str(row.get("name", "")).strip()]
    for service_name in selected_services[:8]:
        ps_res = await executor.run(
            [
                "docker",
                "service",
                "ps",
                service_name,
                "--no-trunc",
                "--format",
                "{{.Name}}\t{{.CurrentState}}\t{{.Error}}\t{{.Node}}",
            ]
        )
        task_summaries.append(
            {
                "service": service_name,
                "ok": ps_res.ok,
                "tasks": _summarize_swarm_tasks(ps_res.stdout),
                "stderr": ps_res.stderr[:500],
            }
        )
        if include_logs:
            logs_res = await executor.run(["docker", "service", "logs", "--tail", str(tail), service_name])
            log_snippets.append(
                {
                    "service": service_name,
                    "ok": str(logs_res.ok),
                    "logs": redact_and_compress(logs_res.stdout, max_lines=80, max_chars=5000),
                    "stderr": redact_and_compress(logs_res.stderr, max_lines=20, max_chars=1200),
                }
            )

    summary = {
        "swarm": _summarize_swarm_info(info_res.stdout),
        "nodes": _summarize_swarm_nodes(nodes_res.stdout),
        "services_count": len(service_rows),
        "unhealthy_services_count": len(unhealthy),
        "unhealthy_services": unhealthy[:30],
        "services": service_rows[:60],
        "task_summaries": task_summaries,
        "log_snippets": log_snippets,
        "probe": {
            "info_ok": info_res.ok,
            "services_ok": services_res.ok,
            "nodes_ok": nodes_res.ok,
        },
    }
    stderr = "\n".join(x for x in [info_res.stderr, services_res.stderr, nodes_res.stderr] if x)
    rendered = redact_and_compress(json.dumps(summary, ensure_ascii=False, indent=2), max_lines=220, max_chars=14000)
    ok = bool(info_res.ok and services_res.ok and nodes_res.ok)
    return ExecResult(
        ok=ok,
        command=["observer/get_swarm_context"],
        stdout=rendered,
        stderr=redact_and_compress(stderr, max_lines=50, max_chars=1800),
        exit_code=0 if ok else 1,
        dry_run=executor.dry_run,
        risk_level="low",
        policy_reasons=["swarm observer read-only bundle"],
    )


async def _fetch_swarm_service_logs(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    service = str(args.get("service", "")).strip()
    if not service:
        return ExecResult(
            ok=False,
            command=["observer/fetch_swarm_service_logs"],
            stderr="missing service",
            exit_code=2,
            dry_run=executor.dry_run,
            risk_level="low",
        )
    keyword = str(args.get("keyword", "")).strip().lower()
    since = str(args.get("since", "30m") or "30m").strip()
    tail = max(20, min(int(args.get("tail", 200) or 200), 2000))
    cmd = ["docker", "service", "logs", "--since", since, "--tail", str(tail), service]
    res = await executor.run(cmd)
    text = res.stdout
    if keyword and text:
        filtered = [line for line in text.splitlines() if keyword in line.lower()]
        text = "\n".join(filtered) if filtered else "(no lines matched keyword)"
    compact = redact_and_compress(text, max_lines=180, max_chars=12000)
    return ExecResult(
        ok=res.ok,
        command=["observer/fetch_swarm_service_logs"],
        stdout=compact,
        stderr=redact_and_compress(res.stderr, max_lines=50, max_chars=1600),
        exit_code=res.exit_code,
        dry_run=res.dry_run,
        risk_level="low",
        policy_reasons=["swarm log observer read-only bundle"],
    )


async def _run_kubectl(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    command = str(args.get("command", "")).strip()
    if not command:
        return ExecResult(ok=False, command=["kubectl"], stderr="missing command", exit_code=2)
    target = TargetEnvStore().load()
    context = str(args.get("context", "")).strip()
    namespace = str(args.get("namespace", "")).strip()
    cmd = _kubectl_base(target, namespace=namespace, context=context or target.k8s_context)
    cmd.extend(shlex.split(command))
    return await executor.run(cmd)


async def _run_docker(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    command = str(args.get("command", "")).strip()
    if not command:
        return ExecResult(ok=False, command=["docker"], stderr="missing command", exit_code=2)
    cmd = ["docker", *shlex.split(command)]
    return await executor.run(cmd)


async def _run_curl(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    url = str(args.get("url", "")).strip()
    if not url:
        return ExecResult(ok=False, command=["curl"], stderr="missing url", exit_code=2)
    method = str(args.get("method", "GET")).strip().upper() or "GET"
    timeout_sec = int(args.get("timeout_sec", 10) or 10)
    headers = args.get("headers", [])
    data = str(args.get("data", "")).strip()

    cmd = ["curl", "-sS", "--max-time", str(max(1, min(timeout_sec, 60)))]
    if method != "GET":
        cmd.extend(["-X", method])
    if isinstance(headers, list):
        for header in headers:
            line = str(header).strip()
            if line:
                cmd.extend(["-H", line])
    if data:
        cmd.extend(["--data", data])
    cmd.append(url)
    return await executor.run(cmd)


async def _run_logs(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    path = str(args.get("path", "")).strip()
    if not path:
        return ExecResult(ok=False, command=["tail"], stderr="missing path", exit_code=2)
    lines = int(args.get("lines", 100) or 100)
    lines = max(1, min(lines, 2000))
    cmd = ["tail", "-n", str(lines), path]
    return await executor.run(cmd)


def _summarize_pods(raw: str, namespace: str) -> tuple[int, list[dict[str, object]], str]:
    try:
        payload = json.loads(raw) if raw.strip().startswith("{") else {}
    except Exception:
        payload = {}
    items = payload.get("items", []) if isinstance(payload, dict) else []
    abnormal: list[dict[str, object]] = []
    ns_set: set[str] = set()
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        meta = item.get("metadata", {}) or {}
        status = item.get("status", {}) or {}
        ns = str(meta.get("namespace", namespace or "default"))
        ns_set.add(ns)
        name = str(meta.get("name", ""))
        phase = str(status.get("phase", "Unknown"))
        restarts = 0
        for cs in status.get("containerStatuses", []) if isinstance(status.get("containerStatuses", []), list) else []:
            if isinstance(cs, dict):
                restarts += int(cs.get("restartCount", 0) or 0)
        ready = all(
            bool(cs.get("ready", False))
            for cs in status.get("containerStatuses", [])
            if isinstance(cs, dict)
        )
        if phase not in {"Running", "Succeeded"} or restarts >= 3 or (not ready):
            abnormal.append(
                {
                    "namespace": ns,
                    "pod": name,
                    "phase": phase,
                    "restarts": restarts,
                    "ready": ready,
                }
            )
    detail = "\n".join(
        f"- {x['namespace']}/{x['pod']} phase={x['phase']} restarts={x['restarts']} ready={x['ready']}"
        for x in abnormal[:80]
    )
    return len(ns_set) if ns_set else (1 if namespace else 0), abnormal, detail


def _summarize_events(raw: str, limit: int = 30) -> list[str]:
    try:
        payload = json.loads(raw) if raw.strip().startswith("{") else {}
    except Exception:
        payload = {}
    items = payload.get("items", []) if isinstance(payload, dict) else []
    rows: list[str] = []
    for item in (items[-limit:] if isinstance(items, list) else []):
        if not isinstance(item, dict):
            continue
        meta = item.get("metadata", {}) or {}
        involved = item.get("involvedObject", {}) or {}
        rows.append(
            f"{meta.get('creationTimestamp','-')} "
            f"{involved.get('kind','?')}/{involved.get('name','?')} "
            f"{item.get('type','-')} {item.get('reason','-')} {item.get('message','')}"
        )
    return rows[-limit:]


def _summarize_prom_response(raw: str, *, query: str) -> str:
    try:
        payload = json.loads(raw) if raw.strip().startswith("{") else {}
    except Exception:
        payload = {}
    status = payload.get("status", "unknown") if isinstance(payload, dict) else "unknown"
    result = (
        payload.get("data", {}).get("result", [])
        if isinstance(payload, dict) and isinstance(payload.get("data", {}), dict)
        else []
    )
    lines = [f"query={query}", f"status={status}", f"series_count={len(result) if isinstance(result, list) else 0}"]
    if isinstance(result, list):
        for item in result[:20]:
            if not isinstance(item, dict):
                continue
            metric = item.get("metric", {})
            values = item.get("values", [])
            label_preview = ",".join(f"{k}={v}" for k, v in list(metric.items())[:4]) if isinstance(metric, dict) else ""
            last = values[-1][1] if isinstance(values, list) and values and isinstance(values[-1], list) and len(values[-1]) > 1 else "-"
            lines.append(f"- {label_preview} last={last}")
    return "\n".join(lines)


def _parse_swarm_service_rows(raw: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, mode, replicas, image = parts[:4]
        desired = 0
        running = 0
        if "/" in replicas:
            left, right = replicas.split("/", 1)
            running = _safe_int(left)
            desired = _safe_int(right)
        rows.append(
            {
                "name": name,
                "mode": mode,
                "replicas": replicas,
                "running": running,
                "desired": desired,
                "image": image,
                "unhealthy": desired > 0 and running < desired,
            }
        )
    return rows


def _summarize_swarm_info(raw: str) -> dict[str, object]:
    try:
        payload = json.loads(raw) if raw.strip().startswith("{") else {}
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return {
        "local_node_state": payload.get("LocalNodeState", ""),
        "control_available": payload.get("ControlAvailable", False),
        "node_id": payload.get("NodeID", ""),
        "error": payload.get("Error", ""),
    }


def _summarize_swarm_nodes(raw: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append(
            {
                "hostname": parts[0],
                "status": parts[1],
                "availability": parts[2],
                "manager_status": parts[3],
            }
        )
    return rows[:80]


def _summarize_swarm_tasks(raw: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, current_state, error, node = parts[:4]
        rows.append(
            {
                "name": name,
                "state": current_state,
                "error": error,
                "node": node,
            }
        )
    return rows[:40]


def _safe_int(value: str) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def _url_quote(value: str) -> str:
    # keep dependencies minimal
    from urllib.parse import quote

    return quote(value, safe="")


def _kubectl_base(target, *, namespace: str = "", context: str = "") -> list[str]:
    cmd = ["kubectl"]
    selected_context = context.strip() if context else str(getattr(target, "k8s_context", "")).strip()
    if selected_context:
        cmd.extend(["--context", selected_context])
    api_url = str(getattr(target, "k8s_api_url", "")).strip()
    if api_url:
        cmd.extend(["--server", api_url])
    token = str(getattr(target, "k8s_bearer_token", "")).strip()
    if token:
        cmd.extend(["--token", token])
    verify_tls = bool(getattr(target, "k8s_verify_tls", False))
    if (not verify_tls) and api_url:
        cmd.append("--insecure-skip-tls-verify=true")
    if namespace.strip():
        cmd.extend(["-n", namespace.strip()])
    return cmd
