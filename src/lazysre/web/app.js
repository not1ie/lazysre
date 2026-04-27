import { createApp } from "https://cdn.jsdelivr.net/npm/vue@3.5.13/dist/vue.esm-browser.prod.js";

const DEFAULT_SKILL = {
  name: "team-nginx-check",
  title: "团队 Nginx 巡检",
  category: "custom",
  description: "检查团队服务器上的 Nginx 配置和错误日志",
  variablesJson: JSON.stringify({ ssh_target: "root@192.168.10.101" }, null, 2),
  readCommands: "lazysre remote {ssh_target} --scenario nginx --logs",
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
  if (options.rawText) return await resp.text();
  const ct = resp.headers.get("content-type") || "";
  if (ct.includes("application/json")) return await resp.json();
  return await resp.text();
}

function shortId(value) {
  return String(value || "-").slice(0, 8);
}

function formatSkillResult(result) {
  const lines = [];
  lines.push(`skill=${result.skill?.name || "-"} status=${result.status} mode=${result.dry_run ? "dry-run" : "execute"}`);
  lines.push("");
  for (const group of ["read", "apply", "verify", "rollback"]) {
    const rows = result.commands?.[group] || [];
    if (!rows.length) continue;
    lines.push(`[${group}]`);
    for (const command of rows) lines.push(`- ${command}`);
    lines.push("");
  }
  if ((result.outputs || []).length) {
    lines.push("[outputs]");
    for (const item of result.outputs || []) {
      lines.push(`$ ${item.command}`);
      lines.push(`exit=${item.exit_code}`);
      if (item.stdout) lines.push(String(item.stdout).slice(0, 1600));
      if (item.stderr) lines.push(String(item.stderr).slice(0, 900));
    }
    lines.push("");
  }
  if ((result.next_actions || []).length) {
    lines.push("[next]");
    for (const item of result.next_actions || []) lines.push(`- ${item}`);
  }
  return lines.join("\n");
}

function formatBriefing(briefing) {
  const lines = [];
  lines.push(`severity=${briefing.severity}`);
  lines.push(briefing.headline || "");
  lines.push("");
  lines.push("Recommendations:");
  for (const item of briefing.recommendations || []) lines.push(`- ${item}`);
  lines.push("");
  lines.push("Tools:");
  for (const tool of briefing.tool_snapshot || []) {
    lines.push(`- ${tool.name} ${tool.ok ? "ok" : "error"} ${tool.latency_ms}ms ${tool.error || ""}`);
  }
  return lines.join("\n");
}

createApp({
  data() {
    return {
      activeView: "skills",
      statusText: "正在初始化...",
      overview: {},
      templates: [],
      skills: [],
      tools: [],
      toolHealth: [],
      workflows: [],
      runs: [],
      selectedSkillName: "",
      selectedWorkflowId: "",
      selectedRunId: "",
      skillFilter: "all",
      skillVarsJson: JSON.stringify({ ssh_target: "root@192.168.10.101" }, null, 2),
      skillResult: "",
      briefing: "",
      runOutput: "",
      customSkill: { ...DEFAULT_SKILL },
      mission: {
        objective: "定位并缓解 gateway 5xx 抖动，输出修复和回滚步骤",
        mode: "autodesign",
        name: "Prod Mission Flow",
        template: "incident-response",
      },
      toolForm: {
        name: "Prometheus Prod",
        kind: "prometheus",
        base_url: "http://prometheus:9090",
        default_query: "up",
        required_permission: "read",
      },
    };
  },
  computed: {
    successRate() {
      return `${Math.round((Number(this.overview.success_rate) || 0) * 100)}%`;
    },
    skillCategories() {
      return [...new Set(this.skills.map((item) => item.category).filter(Boolean))].slice(0, 8);
    },
    filteredSkills() {
      if (this.skillFilter === "all") return this.skills;
      return this.skills.filter((item) => item.category === this.skillFilter);
    },
    selectedSkill() {
      return this.skills.find((item) => item.name === this.selectedSkillName) || null;
    },
    selectedWorkflow() {
      return this.workflows.find((item) => item.id === this.selectedWorkflowId) || null;
    },
    toolHealthMap() {
      const out = {};
      for (const item of this.toolHealth || []) out[item.tool_id] = item;
      return out;
    },
  },
  async mounted() {
    await this.refreshAll();
  },
  methods: {
    shortId,
    async safe(action, label) {
      try {
        await action();
      } catch (err) {
        this.statusText = `${label}失败: ${err.message}`;
        window.alert(`${label}失败: ${err.message}`);
      }
    },
    async refreshAll() {
      await this.safe(async () => {
        await Promise.all([
          this.loadOverview(),
          this.loadTemplates(),
          this.loadSkills(),
          this.loadTools(),
          this.loadToolHealth(),
          this.loadWorkflows(),
        ]);
        await this.refreshRuns();
        this.statusText = "数据已刷新";
      }, "刷新");
    },
    async loadOverview() {
      this.overview = await api("/v1/platform/overview");
    },
    async loadTemplates() {
      this.templates = await api("/v1/platform/templates");
      if (!this.mission.template && this.templates[0]) this.mission.template = this.templates[0].slug;
    },
    async loadSkills() {
      this.skills = await api("/v1/platform/skills");
      if (!this.selectedSkillName && this.skills[0]) this.selectSkill(this.skills[0]);
    },
    async loadTools() {
      this.tools = await api("/v1/platform/tools");
    },
    async loadToolHealth() {
      this.toolHealth = await api("/v1/platform/tools/health");
      this.statusText = "工具健康探测完成";
    },
    async loadWorkflows() {
      this.workflows = await api("/v1/platform/workflows");
      if (!this.selectedWorkflowId && this.workflows[0]) this.selectedWorkflowId = this.workflows[0].id;
    },
    async refreshRuns() {
      const q = this.selectedWorkflowId ? `?workflow_id=${encodeURIComponent(this.selectedWorkflowId)}` : "";
      this.runs = await api(`/v1/platform/runs${q}`);
      if (!this.runs.find((item) => item.id === this.selectedRunId)) {
        this.selectedRunId = this.runs[0]?.id || "";
      }
    },
    selectSkill(skill) {
      this.selectedSkillName = skill.name;
      this.skillVarsJson = JSON.stringify(skill.variables || {}, null, 2);
      this.skillResult = "";
      this.statusText = `已选择 Skill: ${skill.title}`;
    },
    async runSelectedSkill() {
      await this.safe(async () => {
        if (!this.selectedSkillName) throw new Error("请先选择 Skill");
        const variables = JSON.parse(this.skillVarsJson || "{}");
        const result = await api(`/v1/platform/skills/${encodeURIComponent(this.selectedSkillName)}/run`, {
          method: "POST",
          body: JSON.stringify({ variables, dry_run: true, apply: false, timeout_sec: 20 }),
        });
        this.skillResult = formatSkillResult(result);
        this.statusText = `Skill dry-run 已生成: ${this.selectedSkillName}`;
      }, "运行 Skill");
    },
    async copySkillCommand() {
      if (!this.selectedSkillName) return;
      let vars = {};
      try {
        vars = JSON.parse(this.skillVarsJson || "{}");
      } catch {
        vars = {};
      }
      const args = Object.entries(vars)
        .map(([key, value]) => `--var ${key}=${String(value)}`)
        .join(" ");
      const command = `lazysre skill run ${this.selectedSkillName}${args ? ` ${args}` : ""}`;
      await navigator.clipboard?.writeText(command);
      this.statusText = `已复制: ${command}`;
    },
    async saveCustomSkill() {
      await this.safe(async () => {
        const variables = JSON.parse(this.customSkill.variablesJson || "{}");
        const readCommands = String(this.customSkill.readCommands || "")
          .split("\n")
          .map((item) => item.trim())
          .filter(Boolean);
        if (!this.customSkill.name.trim() || !this.customSkill.title.trim() || !readCommands.length) {
          throw new Error("名称、标题和只读命令必填");
        }
        const skill = await api("/v1/platform/skills", {
          method: "POST",
          body: JSON.stringify({
            name: this.customSkill.name.trim(),
            title: this.customSkill.title.trim(),
            description: this.customSkill.description.trim(),
            category: this.customSkill.category.trim() || "custom",
            mode: "diagnose",
            risk_level: "low",
            required_permission: "read",
            instruction: this.customSkill.title.trim(),
            variables,
            read_commands: readCommands,
            tags: ["custom", "web", this.customSkill.category.trim()].filter(Boolean),
          }),
        });
        await this.loadSkills();
        const selected = this.skills.find((item) => item.name === skill.name);
        if (selected) this.selectSkill(selected);
        this.statusText = `自定义 Skill 已保存: ${skill.name}`;
      }, "保存 Skill");
    },
    resetCustomSkill() {
      this.customSkill = { ...DEFAULT_SKILL };
    },
    async createWorkflow() {
      await this.safe(async () => {
        const payload = { objective: this.mission.objective, name: this.mission.name || undefined };
        let workflow;
        if (this.mission.mode === "quickstart") {
          workflow = await api("/v1/platform/quickstart", { method: "POST", body: JSON.stringify(payload) });
        } else {
          workflow = await api("/v1/platform/autodesign", {
            method: "POST",
            body: JSON.stringify({ ...payload, template_slug: this.mission.mode === "template" ? this.mission.template : undefined }),
          });
        }
        await this.loadWorkflows();
        this.selectWorkflow(workflow);
        await this.loadOverview();
        this.statusText = `Workflow 已生成: ${workflow.name}`;
      }, "生成 Workflow");
    },
    selectWorkflow(workflow) {
      this.selectedWorkflowId = workflow.id;
      this.selectedRunId = "";
      this.refreshRuns();
    },
    async createTool() {
      await this.safe(async () => {
        await api("/v1/platform/tools", {
          method: "POST",
          body: JSON.stringify({ ...this.toolForm, headers: {}, verify_tls: true }),
        });
        await this.loadTools();
        await this.loadToolHealth();
        this.statusText = `Tool 已注册: ${this.toolForm.name}`;
      }, "注册 Tool");
    },
    async startRun() {
      await this.safe(async () => {
        if (!this.selectedWorkflowId) throw new Error("请先选择 Workflow");
        const run = await api(`/v1/platform/workflows/${this.selectedWorkflowId}/runs`, {
          method: "POST",
          body: JSON.stringify({ input: { actor_permission: "read" } }),
        });
        this.selectedRunId = run.id;
        await this.refreshRuns();
        await this.loadRunDetail(run.id);
        await this.loadOverview();
        this.activeView = "runs";
      }, "启动 Run");
    },
    async loadRunDetail(runId) {
      await this.safe(async () => {
        const run = await api(`/v1/platform/runs/${runId}`);
        this.selectedRunId = run.id;
        this.runOutput = JSON.stringify({ status: run.status, summary: run.summary, outputs: run.outputs, error: run.error }, null, 2);
        this.statusText = `Run ${shortId(run.id)} 状态: ${run.status}`;
      }, "加载 Run");
    },
    async generateBriefing() {
      await this.safe(async () => {
        const q = this.selectedWorkflowId ? `?workflow_id=${encodeURIComponent(this.selectedWorkflowId)}&timeout_sec=4` : "?timeout_sec=4";
        const briefing = await api(`/v1/platform/briefing${q}`);
        this.briefing = formatBriefing(briefing);
        this.runOutput = this.briefing;
        this.statusText = `故障简报已生成: ${briefing.severity}`;
      }, "生成简报");
    },
  },
}).mount("#app");
