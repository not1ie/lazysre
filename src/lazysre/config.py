from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LAZYSRE_", extra="ignore")

    model_mode: str = "heuristic"
    model_name: str = "gpt-5.4-mini"
    max_reflections: int = 2
    data_dir: str = ".data"
    task_store_file: str = "tasks.json"
    platform_store_file: str = "platform.json"
    target_profile_file: str = ".data/lsre-target.json"
    target_prometheus_url: str = "http://92.168.69.176:9090"
    target_k8s_api_url: str = "https://192.168.10.1:6443"
    target_k8s_context: str = ""
    target_k8s_namespace: str = "default"
    target_k8s_bearer_token: str = ""
    target_k8s_verify_tls: bool = False
    openai_api_key: str = Field(default="", validation_alias="OPENAI_API_KEY")


settings = Settings()
