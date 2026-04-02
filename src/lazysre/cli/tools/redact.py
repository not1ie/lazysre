from __future__ import annotations

import re

_IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BEARER_RE = re.compile(r"\b(Bearer\s+)[A-Za-z0-9\-._~+/]+=*\b", flags=re.IGNORECASE)
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{24,}\b")


def redact_text(text: str) -> str:
    out = text
    out = _IP_RE.sub(_mask_ip, out)
    out = _EMAIL_RE.sub("[redacted-email]", out)
    out = _BEARER_RE.sub(r"\1[redacted-token]", out)
    out = _HEX_RE.sub("[redacted-hex]", out)
    return out


def compress_text(text: str, *, max_lines: int = 120, max_chars: int = 8000) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) > max_lines:
        head = lines[: max_lines // 2]
        tail = lines[-max_lines // 2 :]
        lines = head + ["...<snip>..."] + tail
    merged = "\n".join(lines)
    if len(merged) > max_chars:
        half = max_chars // 2
        merged = merged[:half] + "\n...<snip>...\n" + merged[-half:]
    return merged


def redact_and_compress(text: str, *, max_lines: int = 120, max_chars: int = 8000) -> str:
    return compress_text(redact_text(text), max_lines=max_lines, max_chars=max_chars)


def _mask_ip(match: re.Match[str]) -> str:
    raw = match.group(0)
    parts = raw.split(".")
    if len(parts) != 4:
        return "[redacted-ip]"
    return f"{parts[0]}.{parts[1]}.*.*"

