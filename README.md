# LazySRE

LazySRE 是一个 AI-native 运维 CLI。
核心定位是：**本机运行控制台 + 远程环境只读诊断 + 审批后可控执行**。

当前主线已收敛为：
- CLI（默认全屏 TUI）
- Chat 模式（纯终端对话）
- IM Channel Gateway（飞书/钉钉/Telegram/QQ OneBot webhook）

> Web UI 分支已移除，不再作为主入口。

## 设计原则

- 默认 `dry-run`，先观察证据再给修复计划
- 高风险动作必须显式 `--execute`，并经过审批门禁
- 目标环境优先远程采集（SSH/API），不要求在生产机安装 LazySRE

## 安装

### 方式 1：npm（推荐，跨平台）

```bash
npm install -g lazysre
lazysre --help
```

### 方式 2：pipx（Python 用户）

```bash
pipx install "git+https://github.com/not1ie/lazysre.git"
lazysre --help
```

## 快速开始

```bash
# 直接进入全屏 TUI
lazysre

# 先用 mock 验证全流程（无真实 API Key）
lazysre --provider mock

# 纯终端聊天模式
lazysre chat
```

在 TUI 内可直接输入自然语言，例如：
- `检查当前环境有什么异常`
- `列出 swarm 不健康 service`
- `帮我做一份修复计划`

## 常用命令

```bash
# 连接远程目标（只读探测）
lazysre connect root@192.168.10.101

# 远程诊断（支持场景采集）
lazysre remote --logs
lazysre remote --scenario all --json

# 快速总览
lazysre brief
lazysre scan

# 行动清单与执行
lazysre actions
lazysre actions --run 1

# 闭环修复（默认 dry-run）
lazysre remediate "修复 swarm 副本不足"
lazysre --execute remediate "修复 swarm 副本不足" --apply
```

## Skill 执行内核（Execution-first）

`lazysre skill` 现在支持完整执行闭环：
- `precheck`：执行前依赖检查
- `read`：只读证据采集
- `apply`：变更动作
- `verify/postcheck`：变更后验证
- `rollback`：失败自动回滚（可关闭）

示例：

```bash
# dry-run 生成计划与证据图
lazysre skill run swarm-health

# 执行并在失败时自动回滚，导出证据链
lazysre skill run swarm-health --apply --execute --auto-rollback --evidence-file .data/skill-evidence.json

# apply 前默认会做 preflight 风险评分（高风险会拦截）
lazysre skill run swarm-health --apply --execute

# 紧急情况可显式跳过 preflight
lazysre skill run swarm-health --apply --execute --skip-preflight

# 生成执行路径图（Mermaid）
lazysre skill graph swarm-health --apply --output .data/swarm-skill-graph.md
```

## 故障时间轴（Timeline）

```bash
# 自动读取 .data/skill-evidence.json 或最新 channel-runs artifact
lazysre timeline

# 指定证据文件
lazysre timeline --evidence-file .data/skill-evidence.json

# 指定 trace/incident 标识（从 .data/channel-runs 检索）
lazysre timeline --incident-id trc-xxxx

# 输出 Mermaid（可贴 GitHub/Confluence）
lazysre timeline --evidence-file .data/skill-evidence.json --format mermaid

# 对比两次故障
lazysre timeline --evidence-file .data/a.json --compare .data/b.json --format json

# 多次同类故障横向对比（基线 + 多候选）
lazysre timeline --evidence-file .data/base.json --compare .data/case1.json --compare .data/case2.json --format rich
```

支持阶段：`precheck / tool_call / llm_response / apply / verify / rollback`，并标注根因推断时刻、首次修复动作时刻与 `MTTD/MTTR`。

## Preflight 风险评分

```bash
# 单命令风险评分（含 maintenance window、7d 成功率、依赖健康、历史故障）
lazysre preflight --command "kubectl rollout restart deploy/payment" --context prod

# 从修复计划文件抽取命令评分
lazysre preflight --plan-file .data/remediation-plan.json --json
```

当 `risk_score >= 70` 时，会在输出中标记审批升级建议（strict/审批单号）。

## Incident Runbook（版本化 YAML）

```bash
# 从历史故障生成 runbook（v1/v2... 自动递增）
lazysre runbook generate \
  --from-incident CHG-20260428-001 \
  --incident-file .data/lsre-incident.json \
  --evidence-file .data/skill-evidence.json

# 查看模板 runbook + 生成 runbook
lazysre runbook list

# 仅查看生成 runbook
lazysre runbook list --generated-only

# 查看生成 runbook 最新版 / 指定版本
lazysre runbook show swarm-api-timeout-spike --generated
lazysre runbook show swarm-api-timeout-spike --generated --version v2

# 对比两个版本
lazysre runbook diff swarm-api-timeout-spike --version v1 --version v2

# 执行 fix runbook 时默认 preflight 门禁（高风险阻断）
lazysre runbook run payment-latency-fix --apply --execute

# 紧急情况可显式跳过 preflight
lazysre runbook run payment-latency-fix --apply --execute --skip-preflight
```

生成 runbook 默认存储在 `~/.lazysre/runbooks/<name>/vN.yaml`，字段包含：
`trigger_patterns / diagnosis_steps / remediation_steps / verify_steps / rollback_steps`。

`lazysre skill run` 执行时会自动检索相似生成 runbook，并提示参考版本。

## 服务拓扑与影响分析

```bash
# 自动发现拓扑（Swarm/K8s），并落盘到 ~/.lazysre/topology/<env>.json
lazysre topology discover --target prod --format rich

# 导出 dot 图（可配合 graphviz）
lazysre topology discover --target prod --format dot --output .data/topology.dot

# 查询节点命中
lazysre topology show payment --env prod

# 分析某服务故障影响链（默认 2 跳）
lazysre topology impact payment --env prod --depth 2

# 结合策略文件中的 SLO/SLA 端点定义，输出影响端点提示
lazysre topology impact payment --env prod --policy-file .data/lsre-policy.json
```

## SLO 看护与预算燃烧

```bash
# 初始化 SLO 配置
lazysre slo init

# 查看当前 SLO 状态
lazysre slo status

# 查看 1h/6h/24h 燃烧率
lazysre slo burn-rate --window 1h
lazysre slo burn-rate --window 6h
lazysre slo burn-rate --window 24h

# 触发告警评估（--simulate 可演练）
lazysre slo alert --simulate
```

默认配置文件：`~/.lazysre/slos.yaml`。  
当 burn-rate 超阈值时，会联动：
- 创建/更新 incident ticket
- 推荐相似 runbook
- 可选推送到 `LAZYSRE_CHANNEL_WEBHOOK_URL`

## 模型与 Key 配置

```bash
# 本地保存 key（不会写入 git）
lazysre login --provider openai
lazysre login --provider anthropic
lazysre login --provider gemini
lazysre login --provider deepseek
lazysre login --provider qwen
lazysre login --provider kimi

# 查看当前 provider 状态
lazysre status
```

## IM 网关（替代终端对话入口）

```bash
# 启动 webhook 网关（默认 dry-run + strict）
lazysre gateway --host 127.0.0.1 --port 8010 --provider mock

# 生成某个渠道的接入配方（URL/Header/测试curl）
lazysre channel-recipe --provider feishu --base-url http://127.0.0.1:8010

# 本地直接模拟 webhook 消息并查看返回（不依赖公网）
lazysre channel-test --provider telegram --text "检查 k8s 集群是否异常" --json
```

支持 webhook 路径：

```text
POST /v1/channels/feishu/webhook
POST /v1/channels/dingtalk/webhook
POST /v1/channels/telegram/webhook
POST /v1/channels/onebot/webhook
POST /v1/channels/generic/webhook
```

说明：
- 网关只做自然语言接入与诊断回复
- 生产变更仍建议回到 CLI 审批执行
- 不在消息通道内存储 SSH 密码
- 每次 webhook 会生成本地 handoff ticket（含 `handoff_command`），便于从 IM 一键转入 CLI 闭环
- webhook 响应会附带相似历史案例（若命中），用于快速复用修复路径
- 支持 webhook 事件去重（默认 900 秒窗口），可通过 `LAZYSRE_CHANNEL_DEDUP_TTL_SEC` 调整
- 每个会话自动维护短上下文（默认最近 12 轮，LLM 注入最近 4 轮）

建议开启 provider 级验签（按需配置）：

```bash
# 通用入站 token（所有 provider 可共用）
export LAZYSRE_CHANNEL_TOKEN="your-shared-token"

# Telegram: 校验 X-Telegram-Bot-Api-Secret-Token
export LAZYSRE_TELEGRAM_SECRET_TOKEN="your-telegram-secret"

# Feishu: 校验 payload token（可选）
export LAZYSRE_FEISHU_VERIFICATION_TOKEN="your-feishu-token"

# OneBot/QQ: 校验 X-Signature (sha1=...)
export LAZYSRE_ONEBOT_SECRET="your-onebot-secret"
```

会话与控制命令：

```text
/reset                      # 清空当前 chat/user 会话上下文
/session                    # 查看当前会话轮次与最近输入
/approve CHG-xxxx [comment] # 在渠道内审批票据
/approvals                  # 查看最近待审批票据
```

Webhook 响应包含标准阶段字段：
- `ack`：接收确认（含 `event_id`/duplicate）
- `progress`：处理步骤
- `final`：最终文本、渠道回复体、handoff 信息
- `timeline`：压缩后的事件轨迹（llm/tool/重试/完成）
- `actionables`：从回复自动提取的命令建议与审批提示
- `receipt`：统一回执（id/phase/status/detail），适合机器人侧状态机
- `execution_templates`：可直接渲染为“下一步”按钮的执行模板（dry-run/execute）
- `trace_id`：单次请求链路标识（贯穿 ack/final/receipt/handoff）
- `lifecycle`：状态阶段列表（`queued/running/succeeded/blocked/ignored`）
- `artifacts.run`：本次请求的落盘执行记录（默认目录 `.data/channel-runs`）
- `execution_templates.items[*]` 额外包含：
  - `target`（平台与资源识别）
  - `environment`（active profile / ssh target / k8s context / namespace / prometheus）
  - `prerequisites`（执行前检查项）
  - `preflight_commands`（可直接执行的前置检查命令）
  - `verify_commands`（执行后验证命令）
  - `rollback_template`（回滚命令模板）
  - `task_sheet`（目标、步骤、dry-run/execute/rollback）

审批联动：
- `/approve CHG-xxxx` 成功后会返回 `approval` 结构
- 若当前会话有最近 `actionables`，会附带 `next_commands` 建议下一步执行命令
- `/approve` 返回内含 `approval.execution_templates`，可直接转成 CLI 或 API 执行请求

审计回放：
- 每次 webhook 请求会生成 run artifact，包含 `timeline/actionables/execution_templates/final_text`
- 可通过 `trace_id` 关联 `handoff` 与 `run artifact`，用于 IM 侧“查看详情”按钮
- run artifact 内含 `integrity`（`sha256 digest`），可选开启 `LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY` 生成 `hmac-sha256 signature`
- 若存在 `LAZYSRE_APPROVAL_TICKET`，artifact 会记录 `approval_snapshot`（审批状态快照）

校验 run artifact（推荐）：

```bash
# 本地离线校验
lazysre verify-artifact .data/channel-runs/trc-xxxx.json

# 若启用签名，附带 HMAC key
lazysre verify-artifact .data/channel-runs/trc-xxxx.json --hmac-key "$LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY"

# 网关 API 校验（成功返回 200，失败返回 400 + detail）
curl -sS "http://127.0.0.1:8010/v1/channels/artifacts/verify?path=.data/channel-runs/trc-xxxx.json"
```

## 多租户策略中心（Policy Center）

```bash
# 初始化策略文件
lazysre policy init

# 查看当前策略
lazysre policy show

# 设置默认上下文（租户/环境/角色）
lazysre policy context --tenant acme --environment prod --actor-role operator

# 环境门禁：从 medium 开始强制审批；critical 必须带审批单号
lazysre policy guard --tenant acme --environment prod --min-approval-risk medium --require-ticket-for-critical

# 角色风险上限
lazysre policy role --tenant acme --environment prod --role viewer --max-risk low
```

当策略要求 `critical` 审批单号时，执行前设置：

```bash
export LAZYSRE_APPROVAL_TICKET=CHG-2026-001
```

推荐使用内置审批单命令而不是手填：

```bash
# 1) 创建审批单（建议加作用域，限制命令前缀和目标）
lazysre approval create \
  --reason "重启 payment 服务缓解故障" \
  --risk-level critical \
  --requester alice \
  --command-prefix "kubectl rollout restart" \
  --target-hint "deploy/payment" \
  --scope-note "仅允许重启 payment 部署"

# 2) 审批通过
lazysre approval approve CHG-xxxx --approver bob --comment "同意执行"

# 3) 激活到当前 shell
lazysre approval use CHG-xxxx
```

作用域票据会在执行时自动校验：
- `tenant/environment/actor-role` 必须匹配
- 票据风险等级不能低于当前命令风险
- `command-prefix/target-hint` 不匹配会拒绝执行

生产建议：在 `policy guard` 中设置双人审批

```bash
lazysre policy guard --tenant acme --environment prod \
  --high-risk-min-approvers 2 \
  --critical-risk-min-approvers 2 \
  --require-ticket-for-critical
```

## 自动复盘模板

```bash
# 基于 incident + 可选 evidence 自动输出复盘文档
lazysre incident postmortem --evidence-file .data/skill-evidence.json
```

## 安全建议

- 不要把 API Key、SSH 密码写入仓库
- 每次发布前运行：

```bash
lazysre secret-scan --staged
lazysre preflight --strict
```

## 开发与测试

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest -q
```

## 版本

```bash
npm view lazysre version
lazysre --version
```
