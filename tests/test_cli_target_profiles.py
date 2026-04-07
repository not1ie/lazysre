from pathlib import Path

from lazysre.cli.target import TargetEnvironment, TargetEnvStore
from lazysre.cli.target_profiles import ClusterProfileStore


def test_cluster_profile_store_save_activate_remove(tmp_path: Path) -> None:
    profiles_file = tmp_path / "profiles.json"
    runtime_target_file = tmp_path / "target.json"
    store = ClusterProfileStore(profiles_file)

    env = TargetEnvironment(
        prometheus_url="http://127.0.0.1:9090",
        k8s_api_url="https://127.0.0.1:6443",
        k8s_context="dev",
        k8s_namespace="default",
        k8s_bearer_token="",
        k8s_verify_tls=False,
    )
    store.upsert_profile("dev", env, activate=True)
    assert "dev" in store.list_profiles()
    assert store.get_active() == "dev"

    ok = store.activate("dev", target_profile_file=runtime_target_file)
    assert ok is True
    runtime_env = TargetEnvStore(runtime_target_file).load()
    assert runtime_env.k8s_context == "dev"

    removed = store.remove_profile("dev")
    assert removed is True
    assert store.list_profiles() == []
