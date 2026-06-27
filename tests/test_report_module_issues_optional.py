"""Tests for optional/path-configurable module-issues enrichment in tools/report."""

from tools.report.__main__ import _resolve_module_issues_text  # new helper


def test_module_issues_absent_is_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("PKCS11_CHECK_MODULE_ISSUES", raising=False)
    assert _resolve_module_issues_text(explicit=None, repo_root=tmp_path) == ""


def test_module_issues_explicit_path_wins(tmp_path):
    p = tmp_path / "mi.md"
    p.write_text("# issues\n")
    assert "issues" in _resolve_module_issues_text(explicit=p, repo_root=tmp_path)


def test_module_issues_env_used(tmp_path, monkeypatch):
    p = tmp_path / "mi.md"
    p.write_text("# env issues\n")
    monkeypatch.setenv("PKCS11_CHECK_MODULE_ISSUES", str(p))
    assert "env issues" in _resolve_module_issues_text(explicit=None, repo_root=tmp_path)


def test_module_issues_explicit_wins_over_env(tmp_path, monkeypatch):
    explicit_p = tmp_path / "explicit.md"
    explicit_p.write_text("# explicit content\n")
    env_p = tmp_path / "env.md"
    env_p.write_text("# env content\n")
    monkeypatch.setenv("PKCS11_CHECK_MODULE_ISSUES", str(env_p))
    result = _resolve_module_issues_text(explicit=explicit_p, repo_root=tmp_path)
    assert "explicit content" in result
    assert "env content" not in result


def test_module_issues_legacy_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("PKCS11_CHECK_MODULE_ISSUES", raising=False)
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "module-issues.md").write_text("# legacy fallback\n")
    result = _resolve_module_issues_text(explicit=None, repo_root=tmp_path)
    assert "legacy fallback" in result
