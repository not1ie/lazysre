from pathlib import Path


WEB_DIR = Path("src/lazysre/web")


def test_web_console_uses_vue_skill_center() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    app_js = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    assert 'id="app"' in html
    assert 'id="boot-fallback"' in html
    assert "v-for=\"skill in filteredSkills\"" in html
    assert "SKILL CENTER" in html
    assert "createApp" in app_js
    assert "vue-ready" in app_js
    assert "/v1/platform/skills" in app_js


def test_web_console_keeps_dry_run_default() -> None:
    app_js = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    assert "dry_run: true" in app_js
    assert "apply: false" in app_js


def test_web_console_has_local_loading_fallback() -> None:
    css = (WEB_DIR / "styles.css").read_text(encoding="utf-8")
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")

    assert ".vue-ready #boot-fallback" in css
    assert "lazysre web" in html
    assert "PYTHONPATH=src .venv/bin/lazysre web --port 8000" in html
    assert "lazysre skill list" in html
