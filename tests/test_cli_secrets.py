from pathlib import Path

from lazysre.cli.secrets import SecretStore


def test_secret_store_set_get_clear(tmp_path: Path) -> None:
    path = tmp_path / "secrets.json"
    store = SecretStore(path)
    assert store.get_openai_api_key() == ""
    store.set_openai_api_key("sk-test-1234567890")
    assert store.get_openai_api_key() == "sk-test-1234567890"
    assert store.masked_openai_api_key().startswith("sk-t")
    removed = store.clear_openai_api_key()
    assert removed is True
    assert store.get_openai_api_key() == ""


def test_secret_store_provider_runtime_config(tmp_path: Path) -> None:
    path = tmp_path / "secrets.json"
    store = SecretStore(path)

    store.set_provider_base_url("compatible", "https://oneapi.example.com/v1")
    store.set_provider_model("compatible", "gpt-4o-mini")

    assert store.get_provider_base_url("compatible") == "https://oneapi.example.com/v1"
    assert store.get_provider_model("compatible") == "gpt-4o-mini"
    assert store.clear_provider_runtime_config("compatible") is True
    assert store.get_provider_base_url("compatible") == ""
    assert store.get_provider_model("compatible") == ""
