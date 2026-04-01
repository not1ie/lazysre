# LazySRE

LazySRE 是一个纯 AI 驱动的运维平台，目标是让用户只输入目标，系统自动完成：

1. 任务规划（Planner）
2. 工具执行（Worker）
3. 结果反思（Critic）
4. 记忆沉淀（Memory）
5. 任务控制（取消、重跑）
6. 本地持久化（重启后恢复任务记录）
7. 多智能体工作流平台（Agent Registry + Workflow DAG + Run Engine）
8. AI 自动编排（Auto-Design）
9. 场景模板库（Incident/Release/Cost/SLO）
10. 平台总览指标（成功率、活跃运行数）

## 架构

```
API -> TaskService -> AgentRuntime
                      |- Planner
                      |- Worker (Tool Registry)
                      |- Critic
                      |- Memory

API -> PlatformService -> WorkflowEngine
                          |- Agent Registry
                          |- Workflow DAG
                          |- Run/Event Store
                          |- SSE Stream
```

## 快速启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn lazysre.main:app --reload
```

启动后可直接打开控制台（Ops Brain）：

- `http://127.0.0.1:8000/`

## 环境变量

复制 `.env.example` 到 `.env` 后按需调整。

- `LAZYSRE_MODEL_MODE`:
  - `heuristic`：内置规则规划（默认）
  - `openai`：调用 OpenAI 规划（需 `OPENAI_API_KEY`）
- `LAZYSRE_DATA_DIR`：任务持久化目录（默认 `.data`）
- `LAZYSRE_TASK_STORE_FILE`：任务存储文件名（默认 `tasks.json`）
- `LAZYSRE_PLATFORM_STORE_FILE`：平台存储文件名（默认 `platform.json`）
- `OPENAI_API_KEY`：可选

## API 示例

创建任务：

```bash
curl -X POST http://127.0.0.1:8000/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "objective": "检查线上 API 5xx 升高的根因并给出修复建议",
    "context": {
      "service": "gateway",
      "cluster": "prod-sh"
    }
  }'
```

查询任务：

```bash
curl http://127.0.0.1:8000/v1/tasks/<task_id>
```

取消任务：

```bash
curl -X POST http://127.0.0.1:8000/v1/tasks/<task_id>/cancel
```

重跑任务：

```bash
curl -X POST http://127.0.0.1:8000/v1/tasks/<task_id>/rerun
```

检索记忆：

```bash
curl "http://127.0.0.1:8000/v1/memory/search?q=5xx&limit=5"
```

## 平台 API（类似 OpenOcta 形态）

平台总览与模板：

```bash
curl http://127.0.0.1:8000/v1/platform/overview
curl http://127.0.0.1:8000/v1/platform/templates
```

一键创建默认多智能体流程：

```bash
curl -X POST http://127.0.0.1:8000/v1/platform/quickstart \
  -H "Content-Type: application/json" \
  -d '{"name":"Prod Incident Flow","objective":"定位并修复 gateway 5xx 异常"}'
```

基于目标自动生成 Workflow（推荐）：

```bash
curl -X POST http://127.0.0.1:8000/v1/platform/autodesign \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Prod Auto Mission",
    "objective":"定位并缓解 gateway 5xx 抖动，输出风险评估与回滚方案",
    "template_slug":"incident-response"
  }'
```

列出 Agents / Workflows：

```bash
curl http://127.0.0.1:8000/v1/platform/agents
curl http://127.0.0.1:8000/v1/platform/workflows
```

启动工作流 Run：

```bash
curl -X POST http://127.0.0.1:8000/v1/platform/workflows/<workflow_id>/runs \
  -H "Content-Type: application/json" \
  -d '{"input":{"service":"gateway","cluster":"prod-sh"}}'
```

查看 Run 与事件：

```bash
curl http://127.0.0.1:8000/v1/platform/runs/<run_id>
curl http://127.0.0.1:8000/v1/platform/runs/<run_id>/events
```

实时订阅 Run 事件（SSE）：

```bash
curl -N http://127.0.0.1:8000/v1/platform/runs/<run_id>/stream
```

## 部署到 Kubernetes

示例清单：

- `deploy/k8s/lazysre.yaml`

一键远程部署脚本（需要目标机已配置 `kubectl`）：

```bash
./scripts/deploy_remote_k8s.sh root@<master-ip>
```

默认会创建：

1. Namespace: `lazysre`
2. Deployment: `lazysre`（1 副本）
3. Service: NodePort `32080`

部署后访问：

- `http://<任意集群节点IP>:32080/`

## 部署到 Docker Swarm

Swarm Stack 文件：

- `deploy/swarm/lazysre-stack.yml`

远程部署脚本：

```bash
./scripts/deploy_remote_swarm.sh root@<swarm-manager-ip>
```

默认发布端口：

- `32080`

## 下一步建议

1. 接入真实 SRE 工具（K8s、Prometheus、日志系统）
2. 为 Auto-Design 增加约束（工具权限、风险级别、审批门禁）
3. 增加任务队列与持久化存储（PostgreSQL + Redis）
