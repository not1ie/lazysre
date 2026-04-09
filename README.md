# LazySRE

LazySRE 是一个纯 AI 驱动的 SRE/运维 CLI 工具。  
目标是让你用自然语言驱动排障、诊断、修复与回滚，而不是手工拼接一堆命令。

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
# 首次直接启动会自动生成只读 LazySRE Brief，并给出下一步命令
# 全屏 TUI（类似 Claude Code 的左右分区交互；不支持全屏时可用 --demo 预览）
lazysre tui
lazysre tui --demo
# 兼容短命令
lsre
# 或 python 模块方式
python -m lazysre
# 安装环境自检
lazysre install-doctor
# 一条命令获取本机/远程总览简报
lazysre brief
# 零配置环境扫描（安装后也会自动跑一次，不需要 K8s token）
lazysre scan
# 输出包含 AI Briefing：可纳管目标、关键问题和推荐下一步
# Docker Swarm 健康检查（服务副本、任务失败证据、可选日志）
lazysre swarm --logs
# 远程服务器只读诊断（目标机无需安装 LazySRE，只需可 SSH）
lazysre remote root@192.168.10.101 --logs
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
# 首次启动向导（安装检查+LLM Key+目标连通性）
lazysre setup
# 交互式初始化（更像 Gemini/Claude：一步步填完即可）
lazysre init
# 一键快速就绪（推荐，自动修复常见问题）
lazysre quickstart
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
```

可用环境变量：`OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`GEMINI_API_KEY`、`GOOGLE_API_KEY`、`DEEPSEEK_API_KEY`、`DASHSCOPE_API_KEY`、`QWEN_API_KEY`、`MOONSHOT_API_KEY`、`KIMI_API_KEY`。

## npm 发布（维护者）

```bash
# 1) 首次先跑发布前检查（Node/npm、pack、npm auth、NPM_TOKEN 等）
./scripts/check_npm_release.sh

# 2) 配置仓库 Secret: NPM_TOKEN
# 3) 本地执行发版脚本（会先做 preflight，然后更新 package.json、打 tag、推送）
./scripts/release_npm.sh 0.1.1
```

发布机制：
- GitHub Actions 监听 tag `npm-v*`
- 自动校验 tag 与 `package.json` 版本一致
- 自动执行 `npm publish --access public`

## 项目介绍

项目主命令是 `lsre`，围绕“观察 -> 推理 -> 执行 -> 回滚”闭环设计：

- AI 调度：支持 Function Calling，让模型自动选择工具调用顺序
- 观察者工具集：内置 K8s / Logs / Metrics 观测能力
- Docker Swarm 观察者：内置 service/node/task/logs 健康检查能力
- 远程 SSH 观察者：无需在目标机安装 LazySRE，也能只读诊断 Docker/Swarm
- 持续巡检：`watch` 可定期扫描环境并输出异常摘要/JSONL
- 行动收件箱：`actions` 将最近巡检结果转换成编号建议、模板命令与风险提示
- 自动驾驶：`autopilot` 串起扫描、巡检、行动清单和修复计划
- 全屏 TUI：`tui` 提供类似 Claude Code 的左右分区交互，支持自然语言、快捷命令和同屏结果流
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
lsre
lsre chat
lsre "检查 k8s pod 状态"
# 全屏 TUI 与闭环修复
lsre tui
lsre remediate "修复当前巡检发现的问题"
# chat 快捷命令
# /help /mode /mode execute|dry-run /context /reset /undo /quickstart /init /login /setup /status /status probe /brief /scan /swarm /connect /remote /watch /actions /autopilot /remediate /tui /doctor [/doctor fix] [/doctor strict]
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
# 环境预检（依赖/配置/连通性）
lsre doctor
lsre doctor --json
lsre doctor --auto-fix
lsre doctor --auto-fix --write-backup
lsre doctor --strict
# 安装/发布环境自检（python/node/npm/gh）
lsre install-doctor
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
