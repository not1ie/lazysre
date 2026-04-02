from __future__ import annotations

import hashlib
import hmac
import importlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx


@dataclass(slots=True)
class MarketplacePack:
    name: str
    version: str
    module: str
    digest_sha256: str
    description: str = ""
    signature: str = ""


@dataclass(slots=True)
class LockedPack:
    name: str
    version: str
    module: str
    digest_sha256: str
    source: str
    signature: str = ""


class ToolPackLockStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def list(self) -> list[LockedPack]:
        payload = self._read_payload()
        items = payload.get("packs", [])
        output: list[LockedPack] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            output.append(
                LockedPack(
                    name=str(item.get("name", "")),
                    version=str(item.get("version", "")),
                    module=str(item.get("module", "")),
                    digest_sha256=str(item.get("digest_sha256", "")),
                    source=str(item.get("source", "")),
                    signature=str(item.get("signature", "")),
                )
            )
        return output

    def get(self, name: str) -> LockedPack | None:
        target = name.strip().lower()
        for pack in self.list():
            if pack.name.strip().lower() == target:
                return pack
        return None

    def upsert(self, pack: LockedPack) -> None:
        packs = self.list()
        replaced = False
        for idx, item in enumerate(packs):
            if item.name.strip().lower() == pack.name.strip().lower():
                packs[idx] = pack
                replaced = True
                break
        if not replaced:
            packs.append(pack)
        self._write_payload({"packs": [asdict(x) for x in packs]})

    def _read_payload(self) -> dict[str, Any]:
        if not self._path.exists():
            return {"packs": []}
        raw = self._path.read_text(encoding="utf-8").strip()
        if not raw:
            return {"packs": []}
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {"packs": []}
        if "packs" not in data or not isinstance(data["packs"], list):
            data["packs"] = []
        return data

    def _write_payload(self, payload: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp = self._path.with_suffix(self._path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self._path)


async def load_marketplace_index(source: str) -> list[MarketplacePack]:
    raw = await _read_source(source)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("marketplace index must be an object")
    packs_raw = data.get("packs", [])
    if not isinstance(packs_raw, list):
        raise ValueError("marketplace index packs must be list")
    output: list[MarketplacePack] = []
    for item in packs_raw:
        if not isinstance(item, dict):
            continue
        output.append(
            MarketplacePack(
                name=str(item.get("name", "")).strip(),
                version=str(item.get("version", "")).strip(),
                module=str(item.get("module", "")).strip(),
                digest_sha256=str(item.get("digest_sha256", "")).strip().lower(),
                description=str(item.get("description", "")).strip(),
                signature=str(item.get("signature", "")).strip().lower(),
            )
        )
    return [x for x in output if x.name and x.version and x.module]


def find_marketplace_pack(
    packs: list[MarketplacePack], *, name: str, version: str | None = None
) -> MarketplacePack | None:
    target_name = name.strip().lower()
    candidates = [x for x in packs if x.name.strip().lower() == target_name]
    if not candidates:
        return None
    if version:
        target_version = version.strip().lower()
        for item in candidates:
            if item.version.strip().lower() == target_version:
                return item
        return None
    return sorted(candidates, key=lambda x: x.version, reverse=True)[0]


def compute_module_digest(module_spec: str) -> str:
    module_name, _, _factory = module_spec.partition(":")
    if not module_name:
        raise ValueError("empty module name in module_spec")
    module = importlib.import_module(module_name)
    module_file = getattr(module, "__file__", None)
    if not module_file:
        raise ValueError(f"module has no __file__: {module_name}")
    path = Path(module_file)
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest()


def verify_pack_signature(pack: MarketplacePack, hmac_key: str) -> bool:
    if not pack.signature or not hmac_key:
        return False
    expected = sign_pack_record(pack, hmac_key)
    return hmac.compare_digest(expected, pack.signature.lower())


def sign_pack_record(pack: MarketplacePack, hmac_key: str) -> str:
    message = f"{pack.name}|{pack.version}|{pack.module}|{pack.digest_sha256}".encode("utf-8")
    return hmac.new(hmac_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


async def _read_source(source: str) -> str:
    src = source.strip()
    if not src:
        raise ValueError("source is empty")
    parsed = urlparse(src)
    if parsed.scheme in {"http", "https"}:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(src)
            resp.raise_for_status()
            return resp.text
    path = Path(src)
    if path.exists():
        return path.read_text(encoding="utf-8")
    raise ValueError(f"index source not found: {source}")

