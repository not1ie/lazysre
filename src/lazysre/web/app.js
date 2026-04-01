const state = {
  templates: [],
  tools: [],
  toolHealth: {},
  agents: [],
  workflows: [],
  runs: [],
  selectedWorkflowId: null,
  selectedRunId: null,
  eventSource: null,
  runPoller: null,
};

const $ = (id) => document.getElementById(id);

const els = {
  missionForm: $("mission-form"),
  missionObjective: $("mission-objective"),
  missionMode: $("mission-mode"),
  templateSelect: $("template-select"),
  workflowName: $("workflow-name"),
  envForm: $("env-form"),
  envMonitoringIp: $("env-monitoring-ip"),
  envMonitoringPort: $("env-monitoring-port"),
  envK8sUrl: $("env-k8s-url"),
  envK8sVerifyTls: $("env-k8s-verify-tls"),
  envK8sToken: $("env-k8s-token"),
  toolForm: $("tool-form"),
  toolName: $("tool-name"),
  toolKind: $("tool-kind"),
  toolBaseUrl: $("tool-base-url"),
  toolDefaultQuery: $("tool-default-query"),
  toolHeadersJson: $("tool-headers-json"),
  toolVerifyTls: $("tool-verify-tls"),
  toolPermission: $("tool-permission"),
  refreshToolHealth: $("refresh-tool-health"),
  toolList: $("tool-list"),
  refreshAll: $("refresh-all"),
  refreshWorkflows: $("refresh-workflows"),
  refreshRuns: $("refresh-runs"),
  workflowList: $("workflow-list"),
  workflowCanvas: $("workflow-canvas"),
  runForm: $("run-form"),
  actorPermission: $("actor-permission"),
  runInput: $("run-input"),
  toolQueriesInput: $("tool-queries-input"),
  cancelRunBtn: $("cancel-run-btn"),
  approvalForm: $("approval-form"),
  approverName: $("approver-name"),
  approvalComment: $("approval-comment"),
  approveBtn: $("approve-btn"),
  rejectBtn: $("reject-btn"),
  runList: $("run-list"),
  eventLog: $("event-log"),
  outputsGrid: $("outputs-grid"),
  activeSummary: $("active-summary"),
  agentsCount: $("agents-count"),
  workflowsCount: $("workflows-count"),
  runsCount: $("runs-count"),
  successRate: $("success-rate"),
};

async function api(path, options = {}) {
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!resp.ok) {
    let msg = String(resp.status);
    try {
      const body = await resp.json();
      msg = body.detail || JSON.stringify(body);
    } catch {
      msg = await resp.text();
    }
    throw new Error(msg);
  }
  const ct = resp.headers.get("content-type") || "";
  if (ct.includes("application/json")) return await resp.json();
  return await resp.text();
}

function escapeHtml(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function ts() {
  return new Date().toLocaleTimeString("zh-CN", { hour12: false });
}

function log(msg) {
  els.eventLog.textContent += `${msg}\n`;
  els.eventLog.scrollTop = els.eventLog.scrollHeight;
}

function setSummary(text) {
  els.activeSummary.textContent = text;
}

function renderCounters(overview) {
  els.agentsCount.textContent = String(overview.total_agents);
  els.workflowsCount.textContent = String(overview.total_workflows);
  els.runsCount.textContent = String(overview.total_runs);
  els.successRate.textContent = `${Math.round((overview.success_rate || 0) * 100)}%`;
}

function renderTemplateOptions() {
  els.templateSelect.innerHTML = "";
  for (const tpl of state.templates) {
    const opt = document.createElement("option");
    opt.value = tpl.slug;
    opt.textContent = `${tpl.name} · ${tpl.description}`;
    els.templateSelect.appendChild(opt);
  }
  els.templateSelect.disabled = els.missionMode.value !== "template";
}

function renderTools() {
  els.toolList.innerHTML = "";
  for (const tool of state.tools) {
    const headerCount = Object.keys(tool.headers || {}).length;
    const health = state.toolHealth[tool.id];
    const healthText = health
      ? health.ok
        ? `ok ${health.latency_ms}ms`
        : `error ${health.latency_ms}ms`
      : "unknown";
    const row = document.createElement("div");
    row.className = "row-item";
    row.innerHTML = `
      <div class="title">${escapeHtml(tool.name)}</div>
      <div class="meta">${escapeHtml(tool.kind)} · perm=${escapeHtml(tool.required_permission)} · headers=${headerCount} · health=${escapeHtml(healthText)}</div>
    `;
    els.toolList.appendChild(row);
  }
  if (!state.tools.length) {
    els.toolList.innerHTML = `<div class="row-item"><div class="meta">暂无工具，可先注册 Prometheus/K8s/日志工具。</div></div>`;
  }
}

function renderWorkflows() {
  els.workflowList.innerHTML = "";
  for (const wf of state.workflows) {
    const row = document.createElement("div");
    row.className = `row-item ${wf.id === state.selectedWorkflowId ? "active" : ""}`;
    row.innerHTML = `
      <div class="title">${escapeHtml(wf.name)}</div>
      <div class="meta">${escapeHtml(wf.id.slice(0, 8))} · ${wf.nodes.length} nodes</div>
    `;
    row.onclick = async () => {
      state.selectedWorkflowId = wf.id;
      state.selectedRunId = null;
      closeStream();
      stopRunPoller();
      renderWorkflows();
      renderCanvas(wf);
      await refreshRuns();
      updateApprovalForm(null);
      setSummary(`已选择 workflow: ${wf.name}`);
    };
    els.workflowList.appendChild(row);
  }
  if (!state.workflows.length) {
    els.workflowList.innerHTML = `<div class="row-item"><div class="meta">暂无 workflow</div></div>`;
  }
}

function renderCanvas(workflow) {
  if (!workflow) {
    els.workflowCanvas.innerHTML = `<div class="row-item"><div class="meta">等待工作流...</div></div>`;
    return;
  }
  els.workflowCanvas.innerHTML = "";
  for (const node of workflow.nodes) {
    const row = document.createElement("article");
    row.className = "node-card";
    row.innerHTML = `
      <h3>${escapeHtml(node.id)}</h3>
      <p>${escapeHtml(node.instruction)}</p>
      <div class="pipe">tool=${escapeHtml(node.tool_binding || "none")} | perm=${escapeHtml(node.required_permission)} | approval=${node.requires_approval ? "yes" : "no"}</div>
      <div class="pipe">next: ${escapeHtml((node.next_nodes || []).join(", ") || "end")}</div>
    `;
    els.workflowCanvas.appendChild(row);
  }
}

function statusColor(status) {
  if (status === "completed") return "color:#1b8877";
  if (status === "failed") return "color:#bd3b2f";
  if (status === "canceled") return "color:#a55e16";
  if (status === "waiting_approval") return "color:#d47f1a";
  if (status === "running") return "color:#237593";
  return "color:#60737a";
}

function renderRuns() {
  els.runList.innerHTML = "";
  for (const run of state.runs) {
    const row = document.createElement("div");
    row.className = `row-item ${run.id === state.selectedRunId ? "active" : ""}`;
    row.innerHTML = `
      <div class="title">${escapeHtml(run.id.slice(0, 8))}</div>
      <div class="meta" style="${statusColor(run.status)}">${escapeHtml(run.status)}</div>
    `;
    row.onclick = async () => {
      state.selectedRunId = run.id;
      renderRuns();
      await loadRunDetail(run.id);
      openStream(run.id);
    };
    els.runList.appendChild(row);
  }
  if (!state.runs.length) {
    els.runList.innerHTML = `<div class="row-item"><div class="meta">暂无 run</div></div>`;
  }
}

function renderOutputs(outputs) {
  els.outputsGrid.innerHTML = "";
  const entries = Object.entries(outputs || {});
  if (!entries.length) {
    els.outputsGrid.innerHTML = `<div class="row-item"><div class="meta">暂无节点输出</div></div>`;
    return;
  }
  for (const [node, out] of entries) {
    const card = document.createElement("article");
    card.className = "output-card";
    card.innerHTML = `
      <h4>${escapeHtml(node)}</h4>
      <p>${escapeHtml(String(out).slice(0, 360))}</p>
    `;
    els.outputsGrid.appendChild(card);
  }
}

function updateApprovalForm(run) {
  const waiting = run && run.status === "waiting_approval";
  els.approvalForm.style.display = waiting ? "grid" : "none";
  if (waiting) {
    const node = run.pending_node_id || "-";
    setSummary(`run ${run.id.slice(0, 8)} 等待审批: node=${node}`);
  }
}

async function loadOverview() {
  const overview = await api("/v1/platform/overview");
  renderCounters(overview);
}

async function loadTemplates() {
  state.templates = await api("/v1/platform/templates");
  renderTemplateOptions();
}

async function loadTools() {
  state.tools = await api("/v1/platform/tools");
  renderTools();
}

async function loadToolHealth() {
  const healths = await api("/v1/platform/tools/health");
  const map = {};
  for (const item of healths || []) {
    map[item.tool_id] = item;
  }
  state.toolHealth = map;
  renderTools();
}

async function loadAgents() {
  state.agents = await api("/v1/platform/agents");
}

async function loadWorkflows() {
  state.workflows = await api("/v1/platform/workflows");
  if (!state.selectedWorkflowId && state.workflows.length) {
    state.selectedWorkflowId = state.workflows[0].id;
  }
}

async function refreshRuns() {
  const q = state.selectedWorkflowId
    ? `?workflow_id=${encodeURIComponent(state.selectedWorkflowId)}`
    : "";
  state.runs = await api(`/v1/platform/runs${q}`);
  if (!state.runs.find((x) => x.id === state.selectedRunId)) {
    state.selectedRunId = state.runs[0]?.id || null;
  }
  renderRuns();
}

async function loadRunDetail(runId) {
  const run = await api(`/v1/platform/runs/${runId}`);
  renderOutputs(run.outputs || {});
  updateApprovalForm(run);
  setSummary(
    `run=${run.id.slice(0, 8)} status=${run.status} workflow=${run.workflow_id.slice(0, 8)}`
  );
  if (["completed", "failed", "canceled"].includes(run.status)) {
    stopRunPoller();
  } else {
    startRunPoller();
  }
  return run;
}

function closeStream() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
}

function openStream(runId) {
  closeStream();
  els.eventLog.textContent = "";
  log(`[${ts()}] subscribe run=${runId.slice(0, 8)}`);
  const es = new EventSource(`/v1/platform/runs/${runId}/stream`);
  state.eventSource = es;

  es.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      const t = data.timestamp ? new Date(data.timestamp).toLocaleTimeString("zh-CN") : ts();
      log(`[${t}] ${data.kind}: ${data.message}`);
    } catch {
      log(`[${ts()}] ${evt.data}`);
    }
  };

  es.addEventListener("end", () => {
    log(`[${ts()}] stream closed`);
    closeStream();
    refreshRuns();
    loadOverview();
  });

  es.onerror = () => {
    log(`[${ts()}] stream disconnected`);
    closeStream();
  };
}

function startRunPoller() {
  if (state.runPoller) return;
  state.runPoller = window.setInterval(async () => {
    try {
      if (state.selectedRunId) {
        await loadRunDetail(state.selectedRunId);
      }
      await refreshRuns();
      await loadOverview();
    } catch (err) {
      console.error(err);
    }
  }, 2400);
}

function stopRunPoller() {
  if (!state.runPoller) return;
  window.clearInterval(state.runPoller);
  state.runPoller = null;
}

async function createWorkflowFromMission() {
  const objective = els.missionObjective.value.trim();
  const name = els.workflowName.value.trim();
  const mode = els.missionMode.value;
  if (!objective) {
    alert("请输入目标");
    return;
  }

  let workflow;
  if (mode === "quickstart") {
    workflow = await api("/v1/platform/quickstart", {
      method: "POST",
      body: JSON.stringify({ objective, name: name || "Quickstart Mission" }),
    });
  } else if (mode === "template") {
    workflow = await api("/v1/platform/autodesign", {
      method: "POST",
      body: JSON.stringify({
        objective,
        name: name || undefined,
        template_slug: els.templateSelect.value || undefined,
      }),
    });
  } else {
    workflow = await api("/v1/platform/autodesign", {
      method: "POST",
      body: JSON.stringify({ objective, name: name || undefined }),
    });
  }

  state.selectedWorkflowId = workflow.id;
  await loadAgents();
  await loadWorkflows();
  renderWorkflows();
  renderCanvas(workflow);
  await refreshRuns();
  await loadOverview();
  setSummary(`workflow created: ${workflow.name}`);
}

async function createTool() {
  let headers = {};
  try {
    headers = JSON.parse(els.toolHeadersJson.value || "{}");
  } catch {
    alert("Headers JSON 格式错误");
    return;
  }
  if (headers && typeof headers !== "object") {
    alert("Headers JSON 必须是对象");
    return;
  }
  const payload = {
    name: els.toolName.value.trim(),
    kind: els.toolKind.value,
    base_url: els.toolBaseUrl.value.trim(),
    headers,
    default_query: els.toolDefaultQuery.value.trim(),
    verify_tls: els.toolVerifyTls.value === "true",
    required_permission: els.toolPermission.value,
  };
  if (!payload.name || !payload.base_url) {
    alert("Tool 名称和 URL 必填");
    return;
  }
  await api("/v1/platform/tools", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  await loadTools();
  await loadToolHealth();
  setSummary(`tool registered: ${payload.name}`);
}

async function bootstrapEnvironment() {
  const monitoringIp = els.envMonitoringIp.value.trim();
  const monitoringPort = Number.parseInt(els.envMonitoringPort.value.trim(), 10);
  const k8sApiUrl = els.envK8sUrl.value.trim();
  const k8sVerifyTls = els.envK8sVerifyTls.value === "true";
  const k8sToken = els.envK8sToken.value.trim();
  if (!monitoringIp || !k8sApiUrl || Number.isNaN(monitoringPort)) {
    alert("请完整填写监控与 K8s 环境参数");
    return;
  }

  const resp = await api("/v1/platform/bootstrap/environment", {
    method: "POST",
    body: JSON.stringify({
      monitoring_ip: monitoringIp,
      monitoring_port: monitoringPort,
      k8s_api_url: k8sApiUrl,
      k8s_verify_tls: k8sVerifyTls,
      k8s_bearer_token: k8sToken,
      create_mission_workflow: true,
      workflow_name: "Prod Autonomous Incident",
    }),
  });

  await refreshAll();
  if (resp.workflow && resp.workflow.id) {
    state.selectedWorkflowId = resp.workflow.id;
    renderWorkflows();
    renderCanvas(resp.workflow);
  }

  const probeLines = Object.entries(resp.probe_results || {})
    .slice(0, 4)
    .map(([, v]) => v)
    .join(" | ");
  setSummary(`环境引导完成，primaryTool=${(resp.primary_tool_id || "").slice(0, 8)} ${probeLines}`);
}

async function approveOrReject(action) {
  if (!state.selectedRunId) {
    alert("请先选择 run");
    return;
  }
  try {
    await api(`/v1/platform/runs/${state.selectedRunId}/approval`, {
      method: "POST",
      body: JSON.stringify({
        action,
        approver: els.approverName.value.trim() || "oncall",
        comment: els.approvalComment.value.trim(),
      }),
    });
    log(`[${ts()}] approval action=${action}`);
    await refreshRuns();
    await loadOverview();
    await loadRunDetail(state.selectedRunId);
    openStream(state.selectedRunId);
  } catch (err) {
    alert(`审批失败: ${err.message}`);
  }
}

async function refreshAll() {
  await Promise.all([
    loadOverview(),
    loadTemplates(),
    loadTools(),
    loadToolHealth(),
    loadAgents(),
    loadWorkflows(),
  ]);
  renderWorkflows();
  const wf = state.workflows.find((x) => x.id === state.selectedWorkflowId) || state.workflows[0];
  if (wf) {
    state.selectedWorkflowId = wf.id;
    renderCanvas(wf);
  } else {
    renderCanvas(null);
  }
  await refreshRuns();
  updateApprovalForm(null);
}

els.missionMode.addEventListener("change", renderTemplateOptions);

els.missionForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await createWorkflowFromMission();
  } catch (err) {
    alert(`创建 workflow 失败: ${err.message}`);
  }
});

els.toolForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await createTool();
  } catch (err) {
    alert(`注册 tool 失败: ${err.message}`);
  }
});

els.envForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await bootstrapEnvironment();
  } catch (err) {
    alert(`环境引导失败: ${err.message}`);
  }
});

els.runForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.selectedWorkflowId) {
    alert("请先创建或选择 workflow");
    return;
  }
  let input = {};
  let toolQueries = {};
  try {
    input = JSON.parse(els.runInput.value || "{}");
  } catch {
    alert("Run Input JSON 格式错误");
    return;
  }
  try {
    toolQueries = JSON.parse(els.toolQueriesInput.value || "{}");
  } catch {
    alert("Tool Queries JSON 格式错误");
    return;
  }

  input.actor_permission = els.actorPermission.value;
  input.tool_queries = toolQueries;

  try {
    const run = await api(`/v1/platform/workflows/${state.selectedWorkflowId}/runs`, {
      method: "POST",
      body: JSON.stringify({ input }),
    });
    state.selectedRunId = run.id;
    await refreshRuns();
    await loadOverview();
    await loadRunDetail(run.id);
    openStream(run.id);
  } catch (err) {
    alert(`启动失败: ${err.message}`);
  }
});

els.cancelRunBtn.addEventListener("click", async () => {
  if (!state.selectedRunId) {
    alert("当前没有选中的 run");
    return;
  }
  try {
    await api(`/v1/platform/runs/${state.selectedRunId}/cancel`, { method: "POST" });
    log(`[${ts()}] cancel requested`);
    await refreshRuns();
    await loadOverview();
  } catch (err) {
    alert(`取消失败: ${err.message}`);
  }
});

els.approveBtn.addEventListener("click", () => approveOrReject("approve"));
els.rejectBtn.addEventListener("click", () => approveOrReject("reject"));

els.refreshAll.addEventListener("click", async () => {
  await refreshAll();
  setSummary("数据已刷新");
});

els.refreshToolHealth.addEventListener("click", async () => {
  try {
    await loadToolHealth();
    setSummary("工具健康探测已完成");
  } catch (err) {
    alert(`探测失败: ${err.message}`);
  }
});

els.refreshWorkflows.addEventListener("click", async () => {
  await loadWorkflows();
  renderWorkflows();
  const wf = state.workflows.find((x) => x.id === state.selectedWorkflowId) || state.workflows[0];
  renderCanvas(wf || null);
});

els.refreshRuns.addEventListener("click", async () => {
  await refreshRuns();
  if (state.selectedRunId) {
    await loadRunDetail(state.selectedRunId);
  }
});

window.addEventListener("beforeunload", () => {
  closeStream();
  stopRunPoller();
});

refreshAll().catch((err) => {
  console.error(err);
  setSummary(`初始化失败: ${err.message}`);
});
