# LazySRE

LazySRE 是一个纯 AI 驱动的智能体平台 MVP，目标是让用户只输入目标，系统自动完成：

1. 任务规划（Planner）
2. 工具执行（Worker）
3. 结果反思（Critic）
4. 记忆沉淀（Memory）
5. 任务控制（取消、重跑）
6. 本地持久化（重启后恢复任务记录）
7. 多智能体工作流平台（Agent Registry + Workflow DAG + Run Engine）

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

启动后可直接打开控制台：

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

一键创建默认多智能体流程：

```bash
curl -X POST http://127.0.0.1:8000/v1/platform/quickstart \
  -H "Content-Type: application/json" \
  -d '{"name":"Prod Incident Flow","objective":"定位并修复 gateway 5xx 异常"}'
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

## 下一步建议

1. 接入真实 SRE 工具（K8s、Prometheus、日志系统）
2. 增加任务队列与持久化存储（PostgreSQL + Redis）
3. 加入多智能体协作（诊断 Agent、修复 Agent、复盘 Agent）
