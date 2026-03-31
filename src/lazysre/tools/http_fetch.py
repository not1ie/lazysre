from typing import Any

import httpx

from lazysre.tools.base import Tool


class HTTPFetchTool(Tool):
    name = "http_fetch"
    description = "Fetch text snippets from a URL."

    async def run(self, instruction: str, context: dict[str, Any]) -> str:
        url = instruction.strip()
        if not url.startswith(("http://", "https://")):
            return "http_fetch 仅支持 http/https URL。"

        timeout = float(context.get("http_timeout", 8.0))
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            body = " ".join(resp.text.split())
        return body[:600]

