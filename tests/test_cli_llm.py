import httpx

from lazysre.cli.llm import (
    _build_gemini_http_error,
    _build_http_status_error,
    _build_provider_network_error,
)


def test_build_gemini_http_error_masks_secrets_and_adds_hint() -> None:
    request = httpx.Request(
        "POST",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
    )
    response = httpx.Response(
        400,
        request=request,
        json={"error": {"message": "bad request, key=google-api-key-demo-value token=demo-token-value"}},
    )
    exc = httpx.HTTPStatusError("bad request", request=request, response=response)

    message = _build_gemini_http_error(exc)
    assert "Gemini API HTTP 400" in message
    assert "key=***REDACTED***" in message
    assert "token=***REDACTED***" in message
    assert "google-api-key-demo-value" not in message
    assert "hint:" in message


def test_build_gemini_http_error_for_invalid_key_adds_actionable_hint() -> None:
    request = httpx.Request(
        "POST",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
    )
    response = httpx.Response(
        400,
        request=request,
        json={"error": {"message": "API key not valid. Please pass a valid API key."}},
    )
    exc = httpx.HTTPStatusError("bad request", request=request, response=response)

    message = _build_gemini_http_error(exc)
    assert "Gemini API HTTP 400" in message
    assert "API Key 无效或不属于当前项目" in message
    assert "/provider mock" in message


def test_build_http_status_error_masks_secrets_for_compatible_provider() -> None:
    request = httpx.Request(
        "POST",
        "https://api.example.com/v1/chat/completions?key=google-api-key-demo-value",
    )
    response = httpx.Response(
        401,
        request=request,
        json={"error": {"message": "unauthorized token=demo-token-value"}},
    )
    exc = httpx.HTTPStatusError("unauthorized", request=request, response=response)

    message = _build_http_status_error(provider="compatible", exc=exc)
    assert "compatible API HTTP 401" in message
    assert "google-api-key-demo-value" not in message
    assert "demo-token-value" not in message
    assert "token=***REDACTED***" in message
    assert "hint:" in message


def test_build_provider_network_error_masks_bearer_and_adds_socks_hint() -> None:
    err = RuntimeError(
        "Using SOCKS proxy but socksio missing. "
        "Authorization: Bearer super-secret-token-value"
    )
    message = _build_provider_network_error(provider="Gemini", exc=err)
    assert "Gemini network error" in message
    assert "super-secret-token-value" not in message
    assert "Bearer ***REDACTED***" in message
    assert "httpx[socks]" in message
