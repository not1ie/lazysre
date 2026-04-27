from pathlib import Path


WEB_DIR = Path("src/lazysre/web")


def test_web_console_uses_vue_skill_center() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    app_js = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    assert 'id="app"' in html
    assert "v-for=\"skill in filteredSkills\"" in html
    assert "SKILL CENTER" in html
    assert "createApp" in app_js
    assert "/v1/platform/skills" in app_js


def test_web_console_keeps_dry_run_default() -> None:
    app_js = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    assert "dry_run: true" in app_js
    assert "apply: false" in app_js
