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
