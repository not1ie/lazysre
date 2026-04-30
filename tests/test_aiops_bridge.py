from pathlib import Path

from lazysre.integrations.aiops_bridge import AIOpsBridgeClient, AIOpsBridgeConfig, AIOpsBridgeStore


def test_aiops_bridge_store_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "aiops.json"
    store = AIOpsBridgeStore(path)
    payload = store.save(
        AIOpsBridgeConfig(
            base_url="http://127.0.0.1:9000/",
            api_key_env="MY_AIOPS_KEY",
            timeout_sec=20,
            verify_tls=False,
        )
    )
    assert payload["base_url"] == "http://127.0.0.1:9000"
    loaded = store.load()
    assert loaded.base_url == "http://127.0.0.1:9000"
    assert loaded.api_key_env == "MY_AIOPS_KEY"
    assert loaded.timeout_sec == 20
    assert loaded.verify_tls is False


def test_aiops_bridge_client_headers_from_env(monkeypatch) -> None:
    monkeypatch.setenv("LAZY_AIOPS_API_KEY", "abc123")
    client = AIOpsBridgeClient(AIOpsBridgeConfig(base_url="http://127.0.0.1:9000"))
    headers = client._headers()  # noqa: SLF001 - unit test for header assembly
    assert headers["Authorization"] == "Bearer abc123"
    monkeypatch.delenv("LAZY_AIOPS_API_KEY", raising=False)
    client2 = AIOpsBridgeClient(AIOpsBridgeConfig(base_url="http://127.0.0.1:9000"))
    headers2 = client2._headers()  # noqa: SLF001
    assert "Authorization" not in headers2
