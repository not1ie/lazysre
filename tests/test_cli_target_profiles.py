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
        ssh_target="root@192.168.10.101",
    )
    store.upsert_profile("dev", env, activate=True)
    assert "dev" in store.list_profiles()
    assert store.get_active() == "dev"

    ok = store.activate("dev", target_profile_file=runtime_target_file)
    assert ok is True
    runtime_env = TargetEnvStore(runtime_target_file).load()
    assert runtime_env.k8s_context == "dev"
    assert runtime_env.ssh_target == "root@192.168.10.101"

    removed = store.remove_profile("dev")
    assert removed is True
    assert store.list_profiles() == []


def test_cluster_profile_store_export_and_import_payload(tmp_path: Path) -> None:
    src_file = tmp_path / "profiles-src.json"
    dst_file = tmp_path / "profiles-dst.json"
    src = ClusterProfileStore(src_file)
    dst = ClusterProfileStore(dst_file)

    env = TargetEnvironment(
        prometheus_url="http://127.0.0.1:9090",
        k8s_api_url="https://127.0.0.1:6443",
        k8s_context="team-dev",
        k8s_namespace="default",
        k8s_bearer_token="",
        k8s_verify_tls=False,
        ssh_target="root@192.168.10.101",
    )
    src.upsert_profile("dev", env, activate=True)

    payload = src.export_payload()
    assert payload["active"] == "dev"
    assert "dev" in payload["profiles"]

    result = dst.import_payload(payload, merge=True)
    assert result["imported"] == 1
    assert result["created"] == 1
    assert result["active"] == "dev"
    assert "dev" in dst.list_profiles()
    imported_env = dst.get_profile("dev")
    assert imported_env is not None
    assert imported_env.ssh_target == "root@192.168.10.101"


def test_cluster_profile_store_import_replace(tmp_path: Path) -> None:
    store = ClusterProfileStore(tmp_path / "profiles.json")
    env_old = TargetEnvironment(
        prometheus_url="http://old:9090",
        k8s_api_url="https://old:6443",
        k8s_context="old",
        k8s_namespace="default",
        k8s_bearer_token="",
        k8s_verify_tls=False,
    )
    store.upsert_profile("old", env_old, activate=True)

    payload = {
        "active": "new",
        "profiles": {
            "new": {
                "prometheus_url": "http://new:9090",
                "k8s_api_url": "https://new:6443",
                "k8s_context": "new",
                "k8s_namespace": "prod",
                "k8s_bearer_token": "",
                "k8s_verify_tls": False,
                "ssh_target": "root@192.168.10.102",
            }
        },
    }
    result = store.import_payload(payload, merge=False)
    assert result["total"] == 1
    assert result["active"] == "new"
    assert store.list_profiles() == ["new"]
    new_env = store.get_profile("new")
    assert new_env is not None
    assert new_env.ssh_target == "root@192.168.10.102"
