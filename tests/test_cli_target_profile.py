from pathlib import Path

from lazysre.cli.executor import SafeExecutor
from lazysre.cli.target import TargetEnvStore
from lazysre.cli.tools.builtin import _get_metrics, _run_kubectl
from lazysre.cli.types import ExecResult
from lazysre.config import settings


class _CaptureExecutor(SafeExecutor):
    def __init__(self) -> None:
        super().__init__(dry_run=True)
        self.commands: list[list[str]] = []

    async def run(self, command: list[str]) -> ExecResult:
        self.commands.append(command)
        return ExecResult(
            ok=True,
            command=command,
            stdout="{}",
            stderr="",
            exit_code=0,
            dry_run=True,
        )


def test_target_store_update_and_mask_token(tmp_path: Path) -> None:
    store = TargetEnvStore(tmp_path / "target.json")
    env = store.update(
        prometheus_url="http://92.168.69.176:9090",
        k8s_api_url="https://192.168.10.1:6443",
        k8s_context="prod-context",
        k8s_namespace="ops",
        k8s_bearer_token="abcdef1234567890",
        k8s_verify_tls=False,
    )
    safe = env.to_safe_dict()
    assert safe["k8s_bearer_token"] != "abcdef1234567890"
    assert safe["k8s_context"] == "prod-context"


async def test_observer_tools_use_target_profile_defaults(tmp_path: Path) -> None:
    old_profile = settings.target_profile_file
    old_prom = settings.target_prometheus_url
    old_k8s_api = settings.target_k8s_api_url
    old_k8s_context = settings.target_k8s_context
    old_k8s_ns = settings.target_k8s_namespace
    old_k8s_token = settings.target_k8s_bearer_token
    old_k8s_tls = settings.target_k8s_verify_tls
    try:
        settings.target_profile_file = str(tmp_path / "target.json")
        store = TargetEnvStore(Path(settings.target_profile_file))
        store.update(
            prometheus_url="http://92.168.69.176:9090",
            k8s_api_url="https://192.168.10.1:6443",
            k8s_context="prod-context",
            k8s_namespace="ops",
            k8s_bearer_token="token-value",
            k8s_verify_tls=False,
        )

        cap1 = _CaptureExecutor()
        metrics_result = await _get_metrics({"query": "up"}, cap1)
        assert metrics_result.ok is True
        assert cap1.commands
        assert cap1.commands[0][0] == "curl"
        assert "92.168.69.176:9090/api/v1/query_range" in cap1.commands[0][-1]

        cap2 = _CaptureExecutor()
        kubectl_result = await _run_kubectl({"command": "get pods"}, cap2)
        assert kubectl_result.ok is True
        assert cap2.commands
        cmd = cap2.commands[0]
        assert "--context" in cmd
        assert "--server" in cmd
        assert "--token" in cmd
    finally:
        settings.target_profile_file = old_profile
        settings.target_prometheus_url = old_prom
        settings.target_k8s_api_url = old_k8s_api
        settings.target_k8s_context = old_k8s_context
        settings.target_k8s_namespace = old_k8s_ns
        settings.target_k8s_bearer_token = old_k8s_token
        settings.target_k8s_verify_tls = old_k8s_tls
