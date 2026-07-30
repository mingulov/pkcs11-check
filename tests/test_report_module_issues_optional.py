"""Tests for optional/path-configurable known-issue enrichment in pkcs11_check.report."""

from pkcs11_check.report.__main__ import _resolve_module_issues_text


def test_module_issues_absent_is_empty(monkeypatch):
    monkeypatch.delenv("PKCS11_CHECK_MODULE_ISSUES", raising=False)
    assert _resolve_module_issues_text(explicit=None) == ""


def test_module_issues_explicit_path_wins(tmp_path):
    p = tmp_path / "mi.md"
    p.write_text("# issues\n", encoding="utf-8")
    assert "issues" in _resolve_module_issues_text(explicit=p)


def test_module_issues_env_used(tmp_path, monkeypatch):
    p = tmp_path / "mi.md"
    p.write_text("# env issues\n", encoding="utf-8")
    monkeypatch.setenv("PKCS11_CHECK_MODULE_ISSUES", str(p))
    assert "env issues" in _resolve_module_issues_text(explicit=None)


def test_module_issues_explicit_wins_over_env(tmp_path, monkeypatch):
    explicit_p = tmp_path / "explicit.md"
    explicit_p.write_text("# explicit content\n", encoding="utf-8")
    env_p = tmp_path / "env.md"
    env_p.write_text("# env content\n", encoding="utf-8")
    monkeypatch.setenv("PKCS11_CHECK_MODULE_ISSUES", str(env_p))
    result = _resolve_module_issues_text(explicit=explicit_p)
    assert "explicit content" in result
    assert "env content" not in result
