"""Parse every Python source file so syntax errors fail fast."""

from __future__ import annotations

from pathlib import Path


def test_all_python_sources_compile() -> None:
    """All committed Python sources should be syntactically valid."""
    root = Path(__file__).resolve().parents[1]
    paths = sorted([*root.joinpath("src").rglob("*.py"), *root.joinpath("tests").rglob("*.py")])

    failures: list[str] = []
    for path in paths:
        try:
            compile(path.read_text(encoding="utf-8"), str(path.relative_to(root)), "exec")
        except SyntaxError as exc:
            failures.append(f"{path.relative_to(root)}:{exc.lineno}: {exc.msg}")

    assert not failures, "Python syntax errors:\n" + "\n".join(failures)
