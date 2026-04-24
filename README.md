# LazySRE

LazySRE 是一个纯 AI 驱动的 SRE/运维 CLI 工具。  
目标是让你用自然语言驱动排障、诊断、修复与回滚，而不是手工拼接一堆命令。

## 推荐使用方式：本机控制台，远程只读观察

LazySRE 默认按“控制台 / 目标环境”分层：

- 在 Mac/Windows/Linux 笔记本上运行 `lazysre`：只作为 AI 运维控制台。
- 服务器、Docker Swarm、K8s、Prometheus 是目标环境：优先通过 SSH/API 只读采集证据。
- 目标服务器不需要安装 LazySRE：只要能 SSH，LazySRE 就能从本机发起只读诊断。
- 默认 `dry-run`：高风险动作只生成计划和影响评估，不直接修改生产。
- 真正执行写操作必须显式加 `--execute`，并经过确认门禁。

典型流程：

```bash
# 本机启动 TUI
lazysre

# TUI 中先连接目标服务器，只读 SSH 体检并保存默认目标
/connect root@192.168.10.101

# 后续直接远程观察，不需要再输入目标
/remote --logs

# 需要修复时先生成计划，不直接执行
/remediate 修复 swarm 副本不足
```

## 1 分钟上手

```bash
# 1) 安装（跨平台：Windows/macOS/Linux）
npm install -g lazysre

# 2) 验证安装
lazysre --help

# 3) 直接启动（默认进入全屏 TUI）
lazysre
```

首次建议先这样用（不需要任何 API Key）：

```bash
lazysre --provider mock
```

进入后直接输入自然语言即可，例如：
- `检查当前环境有什么异常`
- `列出 Docker Swarm 不健康的 service`
- `为什么最近请求变慢了`

TUI 内常用命令：
- `/connect <user>@<host>`：只读 SSH 体检目标服务器，成功后保存默认远程目标
- `/remote --logs`：只读诊断已保存的远程 Docker/Swarm 目标
- `/remote --scenario all`：只读采集 Linux/Nginx/数据库/GPU/AI/CI/CD 场景证据
- `/scan`：检查本机控制台依赖（Docker/kubectl/Prometheus 配置），不是生产扫描
- `/brief`：生成本机控制台 + 远程目标总览
- `/next`：执行系统推荐的下一步
- `/retry`：重试上一条输入
- `/history`：查看并重放最近输入（默认展示最近 12 条，支持 `/history 关键字` 筛选）
- `/providers`：查看模型配置状态
- `/doctor`：运行运行环境体检（支持 `/doctor strict`、`/doctor install`）
- `/preflight`：发布前一键体检（`install-doctor + doctor + secret-scan`）
- `/preflight --strict`：严格门禁（`warn/error` 都拦截）
- `/preflight --all-files`：扫描全仓库（默认仅扫描暂存区）
- `/secret-scan`：快速检查当前工作区是否存在疑似密钥泄漏（输出脱敏）
- `/secret-scan --staged`：仅检查当前 Git 暂存区文件（发布前推荐）
- `chat` 模式支持终端方向键历史输入（readline），并默认跳过敏感内容入历史
- 口语快捷：直接输入 `继续` / `重试` / `历史` / `帮助` / `扫描` / `简报` 也会自动映射到对应命令
- 口语快捷：`体检`、`安装检查`、`密钥检查`、`泄漏检查` 也可直接触发 `/doctor` 或 `/secret-scan`
- 口语快捷：`暂存区泄漏检查` 可直接触发 `/secret-scan --staged`
- 无斜杠命令：`do 1` / `go 2` / `history 第二条` / `provider gemini` / `ui expert` / `help full` 也可直接识别
- 错拼容错：`provders`、`pannel next`、`quikstart` 等常见拼写错误会自动纠正
- 数字快捷：直接输入 `1/2/3...`，若存在对应动作会执行 `/do n`；否则 `1-4` 走 `/go n`
- 直接输入序号也支持容错：`①/#1/no.2/第1步` 会按快捷动作解析
- 序号容错：`/do`、`/go`、`/history` 支持 `第1步/第一步/③/#1/no.2` 等写法
- 首屏输入框留空时直接按 Enter：自动执行当前建议下一步（新手一键启动）
- 默认 UI 使用简洁视图：只展示控制台状态、远程目标、下一步动作和少量关键信号；需要完整诊断细节时再输入 `/ui expert`

## 怎么确认拿到最新 Node 版本

```bash
# 查看 npm registry 上的最新版本
npm view lazysre version

# 查看本机已安装版本
lazysre --version
```

如果两者一致，说明你已经拿到最新版本。

## 常见问题（用户侧）

- `npm view` 或 `npm install` 报网络/代理错误：
检查并清理异常代理变量 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 后重试。
- 启动后 provider 不可用：
先用 `--provider mock` 体验完整流程，再执行 `lazysre login --provider <openai|anthropic|gemini|deepseek|qwen|kimi>` 配置真实 key。
- 真实 provider 临时不可用：
`lazysre/lsre` 会自动降级到 `mock` 保证流程可继续；如需禁用自动降级，可设置 `LAZYSRE_DISABLE_MOCK_FALLBACK=1`。
- 终端不支持全屏：
可用 `lazysre tui --demo` 查看文本预览，或直接 `lsre chat`。
- 担心误提交密钥：
运行 `lazysre install-doctor` 或 `lazysre doctor`，会附带 `workspace_secret_scan` 预检（输出脱敏）。

## 封版状态（v0.1.2）

- 默认 `lazysre`/`lsre` 进入全屏 TUI，可直接自然语言交互
- TUI 支持 `Tab` 补全、`↑/↓` 历史（输入前缀时自动筛选匹配项）、`Shift+N/T/U/R` 快捷闭环（`/next`、`/trace`、`/undo`、`/retry`）
- TUI 输入编辑增强：支持 `Ctrl-A/E`（行首/行尾）、`Ctrl-U/K`（删左/删右）、`Ctrl-W`（删前一个词）
- 方向键兼容增强：当终端把 `↑/↓/←/→` 当普通字符输入时，也会自动映射为历史/光标操作
- 兼容更多终端方向键序列（含 `ESC[1;5A` 等修饰键形式），减少“方向键无响应”情况
- TUI 输入历史持久化：重启后 `↑/↓` 仍可回看最近输入（自动脱敏）
- TUI `simple` 模式会自动把长输出压缩为结果卡片（状态/结论/命令/下一步），降低新手阅读成本
- `/help` 在 TUI 中输出精简“Quick Help”，`/help full` 可回到完整说明（F1/? 仍可看完整帮助）
- TUI 会记住上次的 `panel/ui` 模式，重启后自动恢复到你上一次的操作视图
- slash 命令容错增强：未知命令会直接提示最可能的正确命令（不再误触发模型调用）
- 执行阶段加入运行中进度动画，避免“无响应”感知
- Provider 就绪判断与当前 active provider 对齐，`mock` 明确标记为可用
- 真实 provider 失败时自动降级到 `mock`，并保留脱敏错误原因（TUI/chat 会话都会自动切到 mock，避免重复降级打断）
- chat 模式支持跨会话历史预热，`/history` 与 `/retry` 重启后仍可用
- 输入/输出链路补充敏感信息脱敏（key/token/password）
- Provider 错误提示增强：Gemini/OpenAI/Anthropic/兼容网关异常会输出脱敏且可执行的修复建议
- install-doctor 增加代理环境预检（自动识别 SOCKS 代理并提示 `httpx[socks]`）
- install-doctor / doctor 增加工作区密钥泄漏预检（workspace_secret_scan，输出脱敏文件:行号）
- 当前封版基线测试：`333 passed`

## 安装方式（开箱即用）

```bash
# 方式1：npm 全局安装（Windows/macOS/Linux，安装后可直接输入 lazysre）
npm install -g lazysre

# 推荐：pipx 全局安装（安装后可直接输入 lazysre）
pipx install "git+https://github.com/not1ie/lazysre.git"

# 或者一键脚本（自动使用 pipx，若无 pipx 则回退到 venv）
curl -fsSL https://raw.githubusercontent.com/not1ie/lazysre/main/scripts/install_user.sh | bash

# 启动
lazysre
# 默认直接进入全屏 TUI（类似 Gemini / Claude Code）
# 首次启动会自动生成只读 LazySRE Brief，并给出下一步命令
lazysre tui
lazysre tui --demo
# TUI 内支持 Tab 自动补全、Up/Down 历史、Shift+N/T/U/R 快捷动作、空输入 Enter 自动下一步、/history 历史重放、Ctrl-L 清屏、F2/1-4 面板切换、/refresh 刷新总览、/providers 查看模型配置，并显示左侧面板标签条、面板上下文提示、Action Bar、最近活动时间线、阶段化 Trace Summary、执行时间线、建议动作、命令轨迹和底部状态栏
# 兼容短命令
lsre
# 或 python 模块方式
python -m lazysre
# 安装环境自检
lazysre install-doctor
# 发布前一键门禁（默认只扫暂存区）
lazysre preflight
# 严格门禁 + 全仓扫描
lazysre preflight --strict --all-files
# 代码密钥泄漏预检（全仓库 / 仅暂存区）
lazysre secret-scan
lazysre secret-scan --staged
# 一条命令获取本机/远程总览简报
lazysre brief
# 零配置环境扫描（安装后也会自动跑一次，不需要 K8s token）
lazysre scan
# 输出包含 AI Briefing：可纳管目标、关键问题和推荐下一步
# Docker Swarm 健康检查（服务副本、任务失败证据、可选日志）
lazysre swarm --logs
# 远程服务器只读诊断（目标机无需安装 LazySRE，只需可 SSH）
lazysre remote root@192.168.10.101 --logs
# 远程场景 Pack：Linux/Nginx/数据库/GPU/AI/CI/CD，只读采集证据，并给出分级结论和下一步
lazysre remote root@192.168.10.101 --scenario linux --scenario nginx
lazysre remote root@192.168.10.101 --scenario all --json
# 首次连接体检：SSH 连通后自动保存默认远程目标
lazysre connect root@192.168.10.101
# 输出包含 AI Briefing：连通性、Docker/Swarm 状态、关键证据和下一步命令
# 保存默认远程目标后，后续可以直接 lazysre remote
lazysre target set --ssh-target root@192.168.10.101
lazysre remote --logs
# 持续巡检（默认会把异常摘要写入长期记忆，可用 --no-remember 关闭）
lazysre watch --count 1
# 把最近一次巡检转换成编号行动清单
lazysre actions
# 直接运行第 1 个建议（默认 dry-run，真实执行需加全局 --execute）
lazysre actions --run 1
# 自动驾驶：扫描 -> 巡检 -> 行动清单，可选生成修复计划
lazysre autopilot
# 远程自动驾驶：通过 SSH 诊断远程 Docker/Swarm
lazysre autopilot --remote root@192.168.10.101 --logs
# 生产闭环修复：Observe -> Plan -> Apply -> Verify -> Rollback Advice
lazysre remediate "修复 swarm 副本不足"
lazysre --execute remediate "修复 swarm 副本不足" --apply --rollback-on-failure
lazysre remediate "修复 swarm 副本不足" --report-md .data/remediate.md --report-json .data/remediate.json
# 首次启动向导（安装检查+LLM Key+目标连通性）
lazysre setup
# 交互式初始化（更像 Gemini/Claude：一步步填完即可）
lazysre init
# 一键快速就绪（推荐，自动修复常见问题）
lazysre quickstart
# quickstart / setup 会自动吸收本机已发现的 kubeconfig context、namespace、Prometheus 地址到 profile
# 本地保存模型 Key（后续无需每次 export）
lazysre login --provider openai
lazysre login --provider anthropic
lazysre login --provider gemini
lazysre login --provider deepseek
lazysre login --provider qwen
lazysre login --provider kimi
```

说明：`npm install -g lazysre` 安装的是跨平台启动器；首次运行会自动检查并安装 Python 版 LazySRE 内核。  
`scripts/install_user.sh` 安装成功后默认执行一次 `lazysre brief --no-remote`，只读识别本机 Docker/Swarm、kubectl kubeconfig、Prometheus 常见地址和模型 Key 状态，并给出结论与下一步；它不需要手填 K8s token，也不会执行写操作。
可选环境变量：
- `LAZYSRE_PIP_INDEX_URL`：指定 pip 镜像源
- `LAZYSRE_PIP_EXTRA_INDEX_URL`：额外镜像源
- `LAZYSRE_PIP_TRUSTED_HOST`：可信 host（逗号分隔）
- `LAZYSRE_PIP_SOURCE`：指定安装源（支持本地目录、tgz、git URL）
- `LAZYSRE_NO_AUTO_INSTALL=1`：禁止启动器自动安装 Python 内核
- `LAZYSRE_POST_INSTALL_BRIEF=0`：一键脚本安装后不自动生成启动总览
- `LAZYSRE_POST_INSTALL_SCAN=0`：兼容旧变量，同样会跳过安装后总览
- `LAZYSRE_SSH_CONFIG`：远程诊断 SSH 配置文件；默认使用 `/dev/null` 隔离坏配置，设为 `default` 可恢复读取用户 SSH config

国内服务器说明：`scripts/install_user.sh` 默认使用阿里云 PyPI 镜像安装 Python 依赖；如果服务器不能访问 GitHub，可先在本地打包上传源码，再执行 `LAZYSRE_PIP_SOURCE=/opt/lazysre-src scripts/install_user.sh`。

## 支持的模型 Provider

```bash
# 自动选择已配置的真实 Provider，否则回退 mock
lazysre --provider auto chat

# 原生 Provider
lazysre --provider openai chat
lazysre --provider anthropic chat
lazysre --provider gemini chat

# OpenAI-compatible Provider
lazysre --provider deepseek chat
lazysre --provider qwen chat
lazysre --provider kimi chat
lazysre --provider compatible chat
```

可用环境变量：`OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`GEMINI_API_KEY`、`GOOGLE_API_KEY`、`DEEPSEEK_API_KEY`、`DASHSCOPE_API_KEY`、`QWEN_API_KEY`、`MOONSHOT_API_KEY`、`KIMI_API_KEY`、`OPENAI_COMPATIBLE_API_KEY`。

接任意 OpenAI-compatible 网关：

```bash
lazysre login --provider compatible \
  --api-key <token> \
  --base-url https://oneapi.example.com/v1 \
  --model gpt-4o-mini

lazysre --provider compatible
```

## 项目介绍

项目主命令是 `lsre`，围绕“观察 -> 推理 -> 执行 -> 回滚”闭环设计：

- AI 调度：支持 Function Calling，让模型自动选择工具调用顺序
- 观察者工具集：内置 K8s / Logs / Metrics 观测能力
- Docker Swarm 观察者：内置 service/node/task/logs 健康检查能力
- 远程 SSH 观察者：无需在目标机安装 LazySRE，也能只读诊断 Docker/Swarm
- 持续巡检：`watch` 可定期扫描环境并输出异常摘要/JSONL
- 行动收件箱：`actions` 将最近巡检结果转换成编号建议、模板命令与风险提示
- 自动驾驶：`autopilot` 串起扫描、巡检、行动清单和修复计划
- 全屏 TUI：`tui` 提供类似 Claude Code 的左右分区交互，支持自然语言、快捷命令、最近活动时间线、命令轨迹、底部状态栏和同屏结果流
- 生产闭环修复：`remediate` 串起 Observe -> Plan -> Apply -> Verify -> Rollback Advice
- 异常记忆：`watch` 发现的问题会写入长期记忆，后续相似诊断会自动引用历史经验
- 安全执行器：支持 Dry-run、风险分级、审批确认、审计日志
- ReAct 风格修复：支持自动生成修复计划与回滚命令
- Runbook 工作流：内置模板化诊断/修复，一键执行标准排障流程
- 多集群 Profile：支持保存/切换多套目标环境配置
- 长期记忆 RAG：成功修复案例会写入 `~/.lazysre/history_db`，后续诊断优先检索相似历史
- 会话记忆：支持上下文延续（如“重启它”）
- 终端体验：支持流式输出与执行时间线

## 核心命令

```bash
# 对话与诊断
lazysre
# 直接启动默认进入 TUI
lsre
lsre chat
lsre "检查 k8s pod 状态"
# 全屏 TUI 与闭环修复
lsre tui
lsre remediate "修复当前巡检发现的问题"
# chat 快捷命令
# /help /activity /focus /do [n] /trace /timeline /panel [overview|activity|timeline|providers|next|1-4] /go [1-4] /mode /mode execute|dry-run /context /reset /undo /quickstart /init /login /providers /provider <name> /setup /status /status probe /brief /scan /swarm /connect /remote /watch /actions /autopilot /remediate /tui /doctor [/doctor fix] [/doctor strict] /preflight [--strict] [--all-files]
# /template [list|show|run|name] [args]
# /runbook [list|show|render|run|add|remove|export|import|name] [args] /report [args] /fix <问题> /apply /approve [1,3-4] /memory [query]
# 示例: /template run k8s-crashloopbackoff --apply --var namespace=prod --var pod=payment-6c8b7
# 示例: /runbook run payment-latency-fix --apply service=payment
# 示例: /report --format json --no-memory --push-to-git

# 自动修复模式（先生成修复与回滚计划）
lsre fix "为什么支付服务响应变慢了？"
lsre fix "为什么支付服务响应变慢了？" --export-plan-md .data/fix.md --export-plan-json .data/fix.json

# 分步执行修复（每步确认）
lsre fix "为什么支付服务响应变慢了？" --apply --execute
lsre fix "为什么支付服务响应变慢了？" --apply --execute --allow-high-risk
lsre fix "为什么支付服务响应变慢了？" --apply --execute --auto-approve-low-risk
# 审批队列与指定步骤执行
lsre approve
lsre approve --steps 1,3-4 --execute
lsre approve --steps 2 --execute --yes --allow-high-risk

# 目标环境配置与连通性探针
lsre target show
lsre target set --prometheus-url http://92.168.69.176:9090 --k8s-api-url https://192.168.10.1:6443 --k8s-skip-tls-verify
lsre target set --ssh-target root@192.168.10.101
lsre target probe --json
# 运行时状态总览
lsre status
lsre status --probe --json
# 一条命令汇总本机 scan 和默认远程目标
lsre brief
lsre brief --json
# 零配置自动发现：Docker/Swarm/K8s/Prometheus/Provider Key（只读，无需 K8s token）
lsre scan
lsre scan --json
# scan/remote/connect 的输出都包含 AI Briefing，优先看结论和下一步命令
# Docker Swarm 一等公民：检查 service 副本、节点、任务失败证据
lsre swarm
lsre swarm --logs
lsre swarm --service lazysre_lazysre --logs
# 远程 Docker/Swarm 只读诊断（通过 SSH 执行 docker 观察命令）
lsre connect root@192.168.10.101
lsre connect
lsre remote root@192.168.10.101
lsre remote root@192.168.10.101 --logs
lsre remote root@192.168.10.101 --service lazysre_lazysre --logs
lsre remote root@192.168.10.101 --scenario linux --scenario nginx --scenario db
lsre remote root@192.168.10.101 --scenario gpu --scenario ai
lsre remote root@192.168.10.101 --scenario all
lsre remote root@192.168.10.101 --report-md .data/remote-101.md
# 已保存 ssh_target 后可省略主机
lsre remote --logs
# 持续巡检、JSONL 留痕与异常记忆
lsre watch --count 1
lsre watch --count 10 --interval-sec 60 --output .data/watch.jsonl
lsre watch --count 1 --no-remember
lsre watch --count 1 --report-md .data/watch-report.md
# 巡检后的下一步行动清单
lsre actions
lsre actions --json
lsre actions --report-md .data/actions.md
lsre actions --run 1
# 自动驾驶：一次跑完整观察链路，并可导出报告或生成修复计划
lsre autopilot
lsre autopilot "帮我看下当前服务器有没有问题" --json
lsre autopilot --report-md .data/autopilot.md
lsre autopilot "修复巡检发现的问题" --fix
lsre autopilot --remote root@192.168.10.101 --logs --report-md .data/remote-autopilot.md
lsre autopilot --remote @target --logs
# 直接消费最新巡检证据生成修复计划
lsre fix "修复巡检发现的问题"
# 闭环修复会先只读诊断，再执行修复，再只读验证；失败时可自动给出/执行回滚路径
lsre remediate "修复巡检发现的问题"
lsre --execute remediate "修复巡检发现的问题" --apply --rollback-on-failure
lsre remediate "修复巡检发现的问题" --report-md .data/remediate.md
# 环境预检（依赖/配置/连通性）
lsre doctor
lsre doctor --json
lsre doctor --auto-fix
lsre doctor --auto-fix --write-backup
lsre doctor --strict
# 安装/发布环境自检（python/node/npm/gh）
lsre install-doctor
# 发布前一键门禁（install-doctor + doctor + secret-scan）
lsre preflight
lsre preflight --strict
lsre preflight --strict --all-files
# 本地登录（保存模型 Key 到 ~/.lazysre/secrets.json）
lsre login --provider openai
lsre login --provider deepseek
lsre logout --provider deepseek
# 交互式初始化（推荐第一次使用）
lsre init
# 一键快速就绪（自动补齐配置 + 自动修复 + 连通性检查）
lsre quickstart
# 首次启动向导（建议首次使用执行）
lsre setup
lsre setup --dry-run-probe
# 一键自动修复环境（doctor）
lsre doctor --autofix
# CI 可读取 gate 字段：blocking_checks / exit_code_advice
lsre doctor --strict --json

# 一键修复模板库（内置 CrashLoopBackOff / ImagePullBackOff / High CPU / OOM 等）
lsre template list
lsre template show k8s-crashloopbackoff
lsre template show swarm-replicas-unhealthy
lsre template show swarm-image-pull-failed
lsre template run k8s-crashloopbackoff --var namespace=prod --var pod=payment-6c8b7 --apply --execute
lsre template run swarm-replicas-unhealthy --var service=lazysre_lazysre --apply --execute

# Runbook 工作流
lsre runbook list
lsre runbook list --custom-only
lsre runbook show payment-latency-fix
# 预览渲染（会自动注入当前 target 的 namespace/context 等变量）
lsre runbook render payment-latency-fix
lsre runbook run payment-latency-fix --var service=payment --var namespace=prod --var p95_ms=450
lsre runbook run payment-latency-fix --apply --execute
# 新增/覆盖自定义 runbook（可覆盖同名内置模板）
lsre runbook add payment-latency-fix --title "支付延迟修复(增强版)" --mode fix --instruction "修复 {namespace} 的 {service}" --var namespace=prod --var service=payment --force
lsre runbook remove payment-latency-fix --yes
# 导入/导出 runbook（团队共享）
lsre runbook export --scope custom --output .data/runbooks-share.json
lsre runbook import --input .data/runbooks-share.json --merge

# 多集群 Target Profiles
lsre target profile save prod --activate
lsre target profile list
lsre target profile current
lsre target profile use prod
lsre target profile show @active
lsre target profile export --output .data/profiles-share.json
lsre target profile import --input .data/profiles-share.json --merge --activate @active

# 复盘报告导出
lsre report --format markdown
lsre report --format json --include-doctor
lsre report --format markdown --push-to-git

# 会话历史
lsre history show --limit 10
lsre history export --output .data/lsre-session-history.md
# 长期记忆库（RAG 案例）
lsre memory show --limit 10
lsre memory search "payment latency" --limit 5
```

说明：直接运行 `lsre` 会进入“零学习”自然语言模式。  
你可以直接说：
- “帮我看下当前状态”
- “自动检测当前环境并列出问题”
- “看看服务器上的服务有没有异常”
- “远程诊断 root@192.168.10.101 的 docker swarm”
- “为什么 lazysre_lazysre 服务副本不足”
- “开始巡检一下”
- “下一步做什么 / 给我推荐动作 / 生成行动清单”
- “执行第1个建议 / 运行第2个动作”
- “自动驾驶排查一下 / 一键巡检并诊断 / 从巡检到修复”
- “做一次环境体检”
- “导出复盘报告”
- “一键修复 CrashLoopBackOff”
- “修复环境”（会走 quickstart 自动修复）
- “切换到执行模式” / “切回dry-run”
- “你记住了什么”（查看最近记忆的 pod/service/namespace）
- “重置一下”（会重置引导和聊天模式记忆）
- “回滚刚才修复”（执行最近计划的 rollback 命令）
- “看它日志 / 重启它 / 扩容到3”（会自动从会话记忆补全对象）
- “看审批队列 / 执行第1步 / 执行步骤:1,3-4”（不记 `/approve` 也能执行计划步骤）
- “先只跑只读步骤再执行写操作 / 解释第2步为什么执行”（自然语言策略与计划讲解）
- “把 namespace 设成 prod / 把 prometheus 设成 http://92.168.69.176:9090 / 查看目标配置”
- “保存当前为 prod 并切换 / 切到 prod 集群 / 看看当前profile / 列出所有profile”
- “导出profile到 .data/profiles.json / 从 .data/profiles.json 导入profile / 删除profile prod（会二次确认）”
- “/quikstart /stauts /templete” 会自动纠错；runbook 会从文本和会话自动补全变量（如 namespace/service/p95）

聊天模式会记住你上次选择的执行模式（execute/dry-run），下次启动自动沿用。
一键修复时会自动从输入文本和会话记忆补全参数（如 namespace/pod/workload）。
如果你说“自动修复 xxx”，会直接进入“生成并执行”流程（按当前执行模式）。

执行策略：低风险命令默认自动执行；中高风险命令会弹出确认。

## 联系方式

有工作推荐请联系：`slpsz1774190386@gmail.com`

微信二维码：

![微信二维码](https://raw.githubusercontent.com/not1ie/lazy_aiops/main/docs/wechat-qrcode.png)
