# LazySRE

LazySRE 是一个纯 AI 驱动的智能体平台 MVP，目标是让用户只输入目标，系统自动完成：

1. 任务规划（Planner）
2. 工具执行（Worker）
3. 结果反思（Critic）
4. 记忆沉淀（Memory）

## 架构

```
API -> TaskService -> AgentRuntime
                      |- Planner
                      |- Worker (Tool Registry)
                      |- Critic
                      |- Memory
```

## 快速启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn lazysre.main:app --reload
```

## 环境变量

复制 `.env.example` 到 `.env` 后按需调整。

- `LAZYSRE_MODEL_MODE`:
  - `heuristic`：内置规则规划（默认）
  - `openai`：调用 OpenAI 规划（需 `OPENAI_API_KEY`）
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

## 下一步建议

1. 接入真实 SRE 工具（K8s、Prometheus、日志系统）
2. 增加任务队列与持久化存储（PostgreSQL + Redis）
3. 加入多智能体协作（诊断 Agent、修复 Agent、复盘 Agent）

