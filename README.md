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
11. 工具接入层（Prometheus/K8s/Logs/HTTP）
12. 权限门禁与审批流（read/write/admin + run approval）

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

## CLI 模式（lsre）

安装后可直接使用：

```bash
lsre "检查 k8s pod 状态"
lsre chat
```

执行控制（默认 dry-run）：

```bash
lsre --provider mock "重启异常容器"
lsre --execute --approval-mode balanced --approve --provider mock "重启异常容器"
lsre --execute --interactive-approval --provider mock "为什么支付服务响应变慢了？"
lsre chat --stream-output
lsre fix "为什么支付服务响应变慢了？"
lsre fix "为什么支付服务响应变慢了？" --apply --execute
lsre target show
lsre target set --prometheus-url http://92.168.69.176:9090 --k8s-api-url https://192.168.10.1:6443 --k8s-skip-tls-verify
lsre target probe --timeout-sec 8
lsre history show --limit 8
lsre history export --output .data/lsre-session-history.md
lsre --provider mock --deny-tool docker "重启异常容器"
lsre --tool-pack builtin --remote-gateway edge=http://127.0.0.1:18080 "检查远端主机状态"
lsre --tool-pack module:your_pkg.your_pack:tool_pack "执行自定义工具包任务"
lsre pack list --index ./marketplace.json
lsre pack pin your_pack --version 1.2.0 --index ./marketplace.json --hmac-key "<secret>" --require-signature
lsre pack show
lsre --tool-pack locked:your_pack "执行锁定版本工具包任务"
```

说明：

1. `--execute` 才会真正执行命令；默认仅预演。
2. 风险策略 `--approval-mode`：`strict|balanced|permissive`。
3. 高风险命令在执行模式下需要 `--approve`。
4. 每次工具执行都会写入审计日志（默认 `.data/lsre-audit.jsonl`）。
5. 可通过 `--deny-tool` 和 `--deny-prefix` 禁用指定工具。
6. 可通过 `--tool-pack` 加载本地模块工具包，通过 `--remote-gateway` 注册远端执行网关工具。
7. 可通过 `lsre pack pin` 将 marketplace 包锁定到 `.data/lsre-tool-lock.json` 并在运行时使用 `locked:<name>` 加载。
8. `pack pin` 支持 `--require-signature` + `--hmac-key` 做签名校验，支持 `digest_sha256` 做本地模块完整性校验。
9. 内置 Observer 工具：`get_cluster_context`、`fetch_service_logs`、`get_metrics`，输出会自动脱敏和压缩，避免 token 溢出。
10. 执行模式下高风险写操作会生成“变更风险报告”，并等待控制台 `y/n` 确认（可用 `--no-interactive-approval` 关闭）。
11. 支持 Session 历史记忆（默认 `.data/lsre-session.json`），可处理“重启它”这类指代。
12. `target` 子命令可持久化目标环境（默认 `.data/lsre-target.json`），Observer 工具会自动使用这些默认值。
13. 支持流式 token 输出（`--stream-output`）和执行时间线（LLM 轮次 + 工具耗时）。
14. 支持 `target probe` 一键检测 Prometheus/Kubernetes/Docker 连通性并输出报告。
15. 支持 `history` 子命令管理会话历史（show/clear/export）。
16. 支持 `fix` 自动修复模式：生成 Root Cause/Fix Plan/Apply Commands/Rollback Commands，并可 `--apply` 分步确认执行。
17. `fix --apply --execute` 会在每一步执行前展示风险报告并等待 `y/n` 确认。

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
curl "http://127.0.0.1:8000/v1/platform/briefing?timeout_sec=4"
```

说明：

- 调用 `briefing` 会自动将简报写入 `artifacts/briefings/*.md|*.json`
- 每个 Run 在结束（completed/failed/canceled）后会自动写入 `artifacts/postmortems/run-<run_id>-postmortem.md`

目标环境一键引导（推荐，自动创建/更新 Prom + K8s 工具并生成生产故障流程）：

```bash
curl -X POST http://127.0.0.1:8000/v1/platform/bootstrap/environment \
  -H "Content-Type: application/json" \
  -d '{
    "monitoring_ip":"92.168.69.176",
    "monitoring_port":9090,
    "k8s_api_url":"https://192.168.10.1:6443",
    "k8s_verify_tls":false,
    "k8s_bearer_token":"<k8s-service-account-token>",
    "create_mission_workflow":true,
    "workflow_name":"Prod Autonomous Incident"
  }'
```

注册工具与连通性探测：

```bash
curl -X POST http://127.0.0.1:8000/v1/platform/tools \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Prometheus Prod",
    "kind":"prometheus",
    "base_url":"http://prometheus:9090",
    "headers":{"X-Scope-OrgID":"prod"},
    "verify_tls":true,
    "default_query":"up",
    "required_permission":"read"
  }'

curl http://127.0.0.1:8000/v1/platform/tools
curl "http://127.0.0.1:8000/v1/platform/tools/health?timeout_sec=6"
curl -X POST http://127.0.0.1:8000/v1/platform/tools/<tool_id>/probe \
  -H "Content-Type: application/json" \
  -d '{"query":"up"}'
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
curl "http://127.0.0.1:8000/v1/platform/runs/<run_id>/report?format=json"
curl "http://127.0.0.1:8000/v1/platform/runs/<run_id>/report?format=markdown"
```

实时订阅 Run 事件（SSE）：

```bash
curl -N http://127.0.0.1:8000/v1/platform/runs/<run_id>/stream
```

对等待审批的 Run 进行审批：

```bash
curl -X POST http://127.0.0.1:8000/v1/platform/runs/<run_id>/approval \
  -H "Content-Type: application/json" \
  -d '{"action":"approve","approver":"oncall.lead","comment":"风险可控，批准执行"}'
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

推荐流程（镜像仓库模式，远端只拉取）：

1. 本地构建并推送镜像（默认仓库为阿里云 `lazyops/lazyopsatest`）：

```bash
./scripts/build_push_registry.sh
```

也可以显式指定 tag：

```bash
./scripts/build_push_registry.sh crpi-iihofxt94xlrdrvd.cn-shanghai.personal.cr.aliyuncs.com/lazyops/lazyopsatest 20260402120000
```

2. 远端 Swarm 拉取并部署：

```bash
./scripts/deploy_remote_swarm_registry.sh root@<swarm-manager-ip> crpi-iihofxt94xlrdrvd.cn-shanghai.personal.cr.aliyuncs.com/lazyops/lazyopsatest:<tag>
```

兼容旧流程（在远端构建镜像）：

```bash
./scripts/deploy_remote_swarm.sh root@<swarm-manager-ip>
```

说明：

1. 仓库模式下，服务端只执行 `docker pull + docker stack deploy`
2. 远端构建模式下，脚本会上传源码并在远端 `docker build`
3. 若镜像仓库是私有仓库，请先在本地和目标服务器执行 `docker login`
4. 容器启动阶段不再执行在线 `pip install`

默认发布端口：

- `32080`

## CLI 发布与镜像

构建 Python 包（wheel/sdist）：

```bash
./scripts/release_cli.sh
```

构建并推送 CLI 镜像（默认推送到阿里云仓库）：

```bash
./scripts/build_push_cli_registry.sh
```

指定仓库与 tag：

```bash
./scripts/build_push_cli_registry.sh crpi-iihofxt94xlrdrvd.cn-shanghai.personal.cr.aliyuncs.com/lazyops/lazyopsatest cli-20260402180000
```

## 下一步建议

1. 接入真实 SRE 工具（K8s、Prometheus、日志系统）
2. 为 Auto-Design 增加约束（工具权限、风险级别、审批门禁）
3. 增加任务队列与持久化存储（PostgreSQL + Redis）
