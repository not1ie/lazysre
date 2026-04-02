from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from lazysre.cli.types import ExecResult


@dataclass(slots=True)
class SafeExecutor:
    dry_run: bool = True
    timeout_sec: float = 20.0
    allowed_binaries: set[str] = field(
        default_factory=lambda: {"kubectl", "docker", "curl", "tail"}
    )

    async def run(self, command: list[str]) -> ExecResult:
        if not command:
            return ExecResult(
                ok=False,
                command=command,
                stderr="empty command",
                exit_code=1,
                dry_run=self.dry_run,
            )
        binary = command[0]
        if binary not in self.allowed_binaries:
            return ExecResult(
                ok=False,
                command=command,
                stderr=f"blocked command: {binary}",
                exit_code=126,
                dry_run=self.dry_run,
                blocked=True,
            )

        if self.dry_run:
            return ExecResult(
                ok=True,
                command=command,
                stdout=f"[dry-run] {' '.join(command)}",
                exit_code=0,
                dry_run=True,
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_sec)
        except TimeoutError:
            return ExecResult(
                ok=False,
                command=command,
                stderr=f"timeout after {self.timeout_sec}s",
                exit_code=124,
                dry_run=False,
            )
        except FileNotFoundError:
            return ExecResult(
                ok=False,
                command=command,
                stderr=f"binary not found: {binary}",
                exit_code=127,
                dry_run=False,
            )

        return ExecResult(
            ok=(proc.returncode == 0),
            command=command,
            stdout=stdout.decode("utf-8", errors="replace").strip(),
            stderr=stderr.decode("utf-8", errors="replace").strip(),
            exit_code=int(proc.returncode or 0),
            dry_run=False,
        )

