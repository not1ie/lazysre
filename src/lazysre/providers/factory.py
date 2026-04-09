from __future__ import annotations

from lazysre.config import settings
from lazysre.providers.anthropic_provider import AnthropicProvider
from lazysre.providers.base import LLMProvider
from lazysre.providers.gemini_provider import GeminiProvider
from lazysre.providers.mock import MockProvider
from lazysre.providers.openai_provider import OpenAIProvider
from lazysre.providers.registry import PROVIDER_SPECS


def resolve_provider_name_from_settings() -> str:
    mode = str(settings.model_mode or "").strip().lower()
    if mode in PROVIDER_SPECS and _settings_api_key_for(mode):
        return mode
    if mode == "mock":
        return "mock"
    for provider in ("openai", "anthropic", "gemini"):
        if _settings_api_key_for(provider):
            return provider
    return "mock"


def build_provider_from_settings() -> LLMProvider:
    provider = resolve_provider_name_from_settings()
    if provider == "openai":
        return OpenAIProvider(settings.openai_api_key)
    if provider == "anthropic":
        return AnthropicProvider(settings.anthropic_api_key)
    if provider == "gemini":
        return GeminiProvider(settings.gemini_api_key)
    return MockProvider()


def _settings_api_key_for(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized == "openai":
        return str(settings.openai_api_key or "").strip()
    if normalized == "anthropic":
        return str(settings.anthropic_api_key or "").strip()
    if normalized == "gemini":
        return str(settings.gemini_api_key or "").strip()
    return ""
