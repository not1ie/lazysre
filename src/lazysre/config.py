from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LAZYSRE_", extra="ignore")

    model_mode: str = "heuristic"
    model_name: str = "gpt-5.4-mini"
    max_reflections: int = 2
    openai_api_key: str = Field(default="", validation_alias="OPENAI_API_KEY")


settings = Settings()
