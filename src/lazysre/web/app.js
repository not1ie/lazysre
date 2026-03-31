const state = {
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
  formQuickstart: $("quickstart-form"),
  flowName: $("flow-name"),
  flowObjective: $("flow-objective"),
  workflowList: $("workflow-list"),
  refreshWorkflows: $("refresh-workflows"),
  runForm: $("run-form"),
  runInput: $("run-input"),
  runList: $("run-list"),
  refreshRuns: $("refresh-runs"),
  cancelRunBtn: $("cancel-run-btn"),
  activeSummary: $("active-summary"),
  eventLog: $("event-log"),
  outputsGrid: $("outputs-grid"),
  agentsCount: $("agents-count"),
  workflowsCount: $("workflows-count"),
  runsCount: $("runs-count"),
};

async function api(path, options = {}) {
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!resp.ok) {
    let detail = `${resp.status}`;
    try {
      const body = await resp.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      detail = await resp.text();
    }
    throw new Error(detail);
  }
  const ctype = resp.headers.get("content-type") || "";
  if (ctype.includes("application/json")) {
    return await resp.json();
  }
  return await resp.text();
}

function stamp() {
  return new Date().toLocaleTimeString("zh-CN", { hour12: false });
}

function logLine(line) {
  els.eventLog.textContent += `${line}\n`;
  els.eventLog.scrollTop = els.eventLog.scrollHeight;
}

function setSummary(text) {
  els.activeSummary.textContent = text;
}

function renderCounters() {
  els.agentsCount.textContent = String(state.agents.length);
  els.workflowsCount.textContent = String(state.workflows.length);
  els.runsCount.textContent = String(state.runs.length);
}

function renderWorkflows() {
  els.workflowList.innerHTML = "";
  for (const wf of state.workflows) {
    const item = document.createElement("div");
    item.className = `item ${wf.id === state.selectedWorkflowId ? "active" : ""}`;
    item.innerHTML = `
      <div class="title">${escapeHtml(wf.name)}</div>
      <div class="meta">${escapeHtml(wf.id.slice(0, 8))} · ${wf.nodes.length} nodes</div>
    `;
    item.onclick = async () => {
      closeStream();
      stopRunPoller();
      state.selectedWorkflowId = wf.id;
      state.selectedRunId = null;
      setSummary(`已选择 Workflow: ${wf.name}`);
      await refreshRuns();
      renderWorkflows();
    };
    els.workflowList.appendChild(item);
  }
  if (!state.workflows.length) {
    els.workflowList.innerHTML = `<div class="meta">暂无 workflow，可先运行 Quickstart。</div>`;
  }
}

function statusColor(status) {
  if (status === "completed") return "color:#0f8a74";
  if (status === "failed") return "color:#be3a2e";
  if (status === "canceled") return "color:#9f5f10";
  return "color:#5f6f6c";
}

function renderRuns() {
  els.runList.innerHTML = "";
  for (const run of state.runs) {
    const item = document.createElement("div");
    item.className = `item ${run.id === state.selectedRunId ? "active" : ""}`;
    item.innerHTML = `
      <div class="title">${escapeHtml(run.id.slice(0, 8))}</div>
      <div class="meta" style="${statusColor(run.status)}">${escapeHtml(run.status)}</div>
    `;
    item.onclick = async () => {
      state.selectedRunId = run.id;
      await loadRunDetail(run.id);
      openStream(run.id);
      renderRuns();
    };
    els.runList.appendChild(item);
  }
  if (!state.runs.length) {
    els.runList.innerHTML = `<div class="meta">当前 workflow 还没有 run。</div>`;
  }
}

function renderOutputs(outputs) {
  els.outputsGrid.innerHTML = "";
  const entries = Object.entries(outputs || {});
  if (!entries.length) {
    els.outputsGrid.innerHTML = `<div class="meta">暂无节点输出。</div>`;
    return;
  }
  for (const [nodeId, text] of entries) {
    const div = document.createElement("div");
    div.className = "output-card";
    div.innerHTML = `
      <h3>${escapeHtml(nodeId)}</h3>
      <p>${escapeHtml(String(text).slice(0, 480))}</p>
    `;
    els.outputsGrid.appendChild(div);
  }
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
  if (!state.selectedRunId) {
    closeStream();
    stopRunPoller();
    renderOutputs({});
  }
  renderRuns();
  renderCounters();
}

async function loadRunDetail(runId) {
  const run = await api(`/v1/platform/runs/${runId}`);
  renderOutputs(run.outputs || {});
  setSummary(
    `Run ${run.id.slice(0, 8)} · ${run.status} · workflow=${run.workflow_id.slice(0, 8)}`
  );
  if (run.status === "completed" || run.status === "failed" || run.status === "canceled") {
    stopRunPoller();
  } else {
    startRunPoller();
  }
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
  logLine(`[${stamp()}] streaming run ${runId.slice(0, 8)}...`);
  const es = new EventSource(`/v1/platform/runs/${runId}/stream`);
  state.eventSource = es;

  es.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      const t = data.timestamp ? new Date(data.timestamp).toLocaleTimeString("zh-CN") : stamp();
      logLine(`[${t}] ${data.kind}: ${data.message}`);
    } catch {
      logLine(`[${stamp()}] ${evt.data}`);
    }
  };
  es.addEventListener("end", () => {
    logLine(`[${stamp()}] stream ended`);
    closeStream();
    refreshRuns();
  });
  es.onerror = () => {
    logLine(`[${stamp()}] stream disconnected`);
    closeStream();
  };
}

function startRunPoller() {
  if (state.runPoller) return;
  state.runPoller = window.setInterval(async () => {
    if (!state.selectedRunId) return;
    try {
      await loadRunDetail(state.selectedRunId);
      await refreshRuns();
    } catch (err) {
      console.error(err);
    }
  }, 2200);
}

function stopRunPoller() {
  if (!state.runPoller) return;
  window.clearInterval(state.runPoller);
  state.runPoller = null;
}

function escapeHtml(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function refreshAll() {
  await loadAgents();
  await loadWorkflows();
  renderWorkflows();
  await refreshRuns();
  renderCounters();
  if (state.selectedRunId) {
    await loadRunDetail(state.selectedRunId);
  }
}

els.formQuickstart.addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    name: els.flowName.value.trim(),
    objective: els.flowObjective.value.trim(),
  };
  try {
    const wf = await api("/v1/platform/quickstart", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    await loadAgents();
    await loadWorkflows();
    state.selectedWorkflowId = wf.id;
    renderWorkflows();
    await refreshRuns();
    renderCounters();
    setSummary(`Quickstart 成功，workflow=${wf.id.slice(0, 8)}`);
  } catch (err) {
    alert(`Quickstart 失败: ${err.message}`);
  }
});

els.runForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.selectedWorkflowId) {
    alert("请先选择一个 workflow");
    return;
  }
  let input = {};
  try {
    input = JSON.parse(els.runInput.value || "{}");
  } catch {
    alert("Input JSON 格式不正确");
    return;
  }
  try {
    const run = await api(`/v1/platform/workflows/${state.selectedWorkflowId}/runs`, {
      method: "POST",
      body: JSON.stringify({ input }),
    });
    state.selectedRunId = run.id;
    await refreshRuns();
    await loadRunDetail(run.id);
    openStream(run.id);
  } catch (err) {
    alert(`启动 run 失败: ${err.message}`);
  }
});

els.cancelRunBtn.addEventListener("click", async () => {
  if (!state.selectedRunId) {
    alert("没有可取消的 run");
    return;
  }
  try {
    await api(`/v1/platform/runs/${state.selectedRunId}/cancel`, { method: "POST" });
    logLine(`[${stamp()}] cancel requested`);
    await refreshRuns();
  } catch (err) {
    alert(`取消失败: ${err.message}`);
  }
});

els.refreshWorkflows.addEventListener("click", async () => {
  await loadAgents();
  await loadWorkflows();
  renderWorkflows();
  renderCounters();
});

els.refreshRuns.addEventListener("click", async () => {
  await refreshRuns();
  if (state.selectedRunId) await loadRunDetail(state.selectedRunId);
});

window.addEventListener("beforeunload", () => {
  closeStream();
  stopRunPoller();
});

refreshAll().catch((err) => {
  console.error(err);
  setSummary(`初始化失败: ${err.message}`);
});
