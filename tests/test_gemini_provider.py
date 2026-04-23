import httpx

from lazysre.providers.gemini_provider import _build_gemini_http_error, _sanitize_secret_text


def test_sanitize_secret_text_masks_api_key_and_query_param() -> None:
    raw = "request failed for https://x.example/v1?key=google-api-key-demo-value"
    masked = _sanitize_secret_text(raw)
    assert "google-api-key-demo-value" not in masked
    assert "key=***REDACTED***" in masked


def test_build_gemini_http_error_surfaces_detail_without_secrets() -> None:
    request = httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent")
    response = httpx.Response(
        400,
        request=request,
        json={"error": {"message": "API key not valid. key=google-api-key-demo-value"}},
    )
    exc = httpx.HTTPStatusError("bad request", request=request, response=response)

    message = _build_gemini_http_error(exc)
    assert "HTTP 400" in message
    assert "API key not valid" in message
    assert "key=***REDACTED***" in message
    assert "google-api-key-demo-value" not in message
    assert "/provider mock" in message


def test_sanitize_secret_text_masks_token_and_bearer() -> None:
    raw = "failed token=demo-secret-token Authorization: Bearer very-secret-token-value"
    masked = _sanitize_secret_text(raw)
    assert "demo-secret-token" not in masked
    assert "very-secret-token-value" not in masked
    assert "token=***REDACTED***" in masked
    assert "Bearer ***REDACTED***" in masked
