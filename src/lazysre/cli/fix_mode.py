from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class FixPlan:
    apply_commands: list[str]
    rollback_commands: list[str]


def compose_fix_instruction(user_instruction: str) -> str:
    base = user_instruction.strip()
    return (
        f"{base}\n\n"
        "你现在处于 LazySRE 自动修复模式。\n"
        "要求：先使用可用工具完成证据采集，再输出可执行修复方案。\n"
        "必须使用 Markdown 严格包含以下章节：\n"
        "## Root Cause\n"
        "## Fix Plan\n"
        "## Apply Commands\n"
        "```bash\n"
        "# 每行一条命令\n"
        "```\n"
        "## Rollback Commands\n"
        "```bash\n"
        "# 每行一条命令\n"
        "```\n"
        "限制：命令尽量使用 kubectl/docker/curl，避免危险的全局破坏动作。"
    )


def extract_fix_plan(markdown_text: str) -> FixPlan:
    text = markdown_text or ""
    apply_text = _extract_section(text, ("apply commands", "建议执行命令", "修复命令"))
    rollback_text = _extract_section(text, ("rollback commands", "回滚命令", "回滚方案"))

    apply_commands = _extract_commands_from_text(apply_text or text)
    rollback_commands = _extract_commands_from_text(rollback_text)

    if rollback_commands:
        return FixPlan(apply_commands=apply_commands, rollback_commands=rollback_commands)

    # fallback: if there are multiple fenced blocks, use last block as rollback.
    blocks = _extract_code_blocks(text)
    if len(blocks) >= 2:
        all_apply = _extract_commands_from_text("\n".join(blocks[:-1]))
        last_rollback = _extract_commands_from_text(blocks[-1])
        if all_apply and last_rollback:
            return FixPlan(apply_commands=all_apply, rollback_commands=last_rollback)

    return FixPlan(apply_commands=apply_commands, rollback_commands=[])


def _extract_section(text: str, headings: tuple[str, ...]) -> str:
    heading_pattern = "|".join(re.escape(x) for x in headings)
    regex = re.compile(
        rf"(?ims)^##\s*(?:{heading_pattern})\s*$\n(?P<body>.*?)(?=^##\s+|\Z)"
    )
    match = regex.search(text)
    if not match:
        return ""
    return match.group("body").strip()


def _extract_code_blocks(text: str) -> list[str]:
    regex = re.compile(r"```(?:bash|sh|shell)?\s*\n(.*?)```", flags=re.IGNORECASE | re.DOTALL)
    return [x.strip() for x in regex.findall(text) if x.strip()]


def _extract_commands_from_text(text: str) -> list[str]:
    commands: list[str] = []
    blocks = _extract_code_blocks(text)
    sources = blocks if blocks else [text]
    for source in sources:
        for raw in source.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("- "):
                line = line[2:].strip()
            commands.append(line)
    # dedupe but preserve order
    deduped: list[str] = []
    seen: set[str] = set()
    for cmd in commands:
        if cmd in seen:
            continue
        deduped.append(cmd)
        seen.add(cmd)
    return deduped
