from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    label: str
    secret_key: str
    default_model: str
    env_names: tuple[str, ...]


PROVIDER_SPECS: dict[str, ProviderSpec] = {
    "openai": ProviderSpec(
        name="openai",
        label="OpenAI",
        secret_key="openai_api_key",
        default_model="gpt-5.4-mini",
        env_names=("OPENAI_API_KEY",),
    ),
    "anthropic": ProviderSpec(
        name="anthropic",
        label="Anthropic",
        secret_key="anthropic_api_key",
        default_model="claude-sonnet-4-20250514",
        env_names=("ANTHROPIC_API_KEY",),
    ),
    "gemini": ProviderSpec(
        name="gemini",
        label="Gemini",
        secret_key="gemini_api_key",
        default_model="gemini-2.5-flash",
        env_names=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    ),
}

SUPPORTED_PROVIDER_NAMES: tuple[str, ...] = ("mock", *tuple(PROVIDER_SPECS.keys()))
SUPPORTED_PROVIDER_MODES: tuple[str, ...] = ("auto", *SUPPORTED_PROVIDER_NAMES)


def get_provider_spec(name: str) -> ProviderSpec:
    return PROVIDER_SPECS[name.strip().lower()]


def provider_mode_help_text() -> str:
    return "auto|mock|openai|anthropic|gemini"


def provider_mode_error_text() -> str:
    return f"provider must be one of {'/'.join(SUPPORTED_PROVIDER_MODES)}"


def resolve_model_name(provider: str, requested_model: str) -> str:
    normalized = (provider or "").strip().lower()
    model = str(requested_model or "").strip()
    if normalized not in PROVIDER_SPECS:
        return model

    spec = PROVIDER_SPECS[normalized]
    if not model:
        return spec.default_model

    default_openai_model = PROVIDER_SPECS["openai"].default_model
    if normalized != "openai" and model == default_openai_model:
        return spec.default_model
    return model
