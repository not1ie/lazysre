import json
from pathlib import Path

import pytest

from lazysre.cli.tools.marketplace import (
    LockedPack,
    MarketplacePack,
    ToolPackLockStore,
    compute_module_digest,
    find_marketplace_pack,
    load_marketplace_index,
    sign_pack_record,
    verify_pack_signature,
)
from lazysre.cli.tools.packs import load_tool_packs


async def test_marketplace_index_load_find_and_verify_signature(tmp_path: Path) -> None:
    digest = compute_module_digest("lazysre.cli.tools.builtin:tool_pack")
    pack = MarketplacePack(
        name="builtin_pack",
        version="1.0.0",
        module="lazysre.cli.tools.builtin:tool_pack",
        digest_sha256=digest,
        description="builtin tools",
    )
    key = "secret-key-123"
    pack.signature = sign_pack_record(pack, key)
    index_path = tmp_path / "market.json"
    index_path.write_text(
        json.dumps(
            {
                "packs": [
                    {
                        "name": pack.name,
                        "version": pack.version,
                        "module": pack.module,
                        "digest_sha256": pack.digest_sha256,
                        "description": pack.description,
                        "signature": pack.signature,
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    packs = await load_marketplace_index(str(index_path))
    assert len(packs) == 1
    selected = find_marketplace_pack(packs, name="builtin_pack")
    assert selected is not None
    assert verify_pack_signature(selected, key) is True


def test_lock_store_and_locked_pack_loader(tmp_path: Path) -> None:
    lock_path = tmp_path / "lock.json"
    store = ToolPackLockStore(lock_path)
    digest = compute_module_digest("lazysre.cli.tools.builtin:tool_pack")
    store.upsert(
        LockedPack(
            name="builtin_pack",
            version="1.0.0",
            module="lazysre.cli.tools.builtin:tool_pack",
            digest_sha256=digest,
            source="test",
        )
    )
    loaded = store.get("builtin_pack")
    assert loaded is not None
    packs = load_tool_packs(pack_specs=["locked:builtin_pack"], lock_file=lock_path)
    assert packs
    names = {tool.spec.name for tool in packs[0].tools}
    assert "kubectl" in names


def test_locked_pack_digest_mismatch_raises(tmp_path: Path) -> None:
    lock_path = tmp_path / "lock.json"
    store = ToolPackLockStore(lock_path)
    store.upsert(
        LockedPack(
            name="builtin_pack",
            version="1.0.0",
            module="lazysre.cli.tools.builtin:tool_pack",
            digest_sha256="deadbeef",
            source="test",
        )
    )
    with pytest.raises(ValueError):
        load_tool_packs(pack_specs=["locked:builtin_pack"], lock_file=lock_path)

