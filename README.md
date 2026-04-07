# LazySRE

LazySRE 是一个纯 AI 驱动的 SRE/运维 CLI 工具。  
目标是让你用自然语言驱动排障、诊断、修复与回滚，而不是手工拼接一堆命令。

## 项目介绍

项目主命令是 `lsre`，围绕“观察 -> 推理 -> 执行 -> 回滚”闭环设计：

- AI 调度：支持 Function Calling，让模型自动选择工具调用顺序
- 观察者工具集：内置 K8s / Logs / Metrics 观测能力
- 安全执行器：支持 Dry-run、风险分级、审批确认、审计日志
- ReAct 风格修复：支持自动生成修复计划与回滚命令
- 长期记忆 RAG：成功修复案例会写入 `~/.lazysre/history_db`，后续诊断优先检索相似历史
- 会话记忆：支持上下文延续（如“重启它”）
- 终端体验：支持流式输出与执行时间线

## 核心命令

```bash
# 对话与诊断
lsre
lsre chat
lsre "检查 k8s pod 状态"
# chat 快捷命令
# /help /status /status probe /doctor [/doctor fix] [/doctor strict] /fix <问题> /apply /approve [1,3-4] /memory [query]

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
lsre target probe --json
# 运行时状态总览
lsre status
lsre status --probe --json
# 环境预检（依赖/配置/连通性）
lsre doctor
lsre doctor --json
lsre doctor --auto-fix
lsre doctor --auto-fix --write-backup
lsre doctor --strict
# CI 可读取 gate 字段：blocking_checks / exit_code_advice
lsre doctor --strict --json

# 会话历史
lsre history show --limit 10
lsre history export --output .data/lsre-session-history.md
# 长期记忆库（RAG 案例）
lsre memory show --limit 10
lsre memory search "payment latency" --limit 5
```

说明：直接运行 `lsre` 会进入自然语言助手模式。  
在对话中你可以直接说“修复 xxx”来生成计划，说“执行修复计划”来执行最近一次修复计划。

## 联系方式

有工作推荐请联系：`slpsz1774190386@gmail.com`

微信二维码：

![微信二维码](https://raw.githubusercontent.com/not1ie/lazy_aiops/main/docs/wechat-qrcode.png)
