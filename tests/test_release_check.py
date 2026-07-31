"""Unit tests for the release-state checks, over synthetic repositories."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.release_check import extract_notes, main, verify

CLEAN_CHANGELOG = """# Changelog

## [0.1.9] - 2026-08-01

New things.

### Added

- A thing.

## [0.1.8] - 2026-07-30

Old things.
"""

CLEAN_PYPROJECT = """[project]
name = "pkcs11-check"
dynamic = ["version"]
"""


def _make_repo(
    tmp_path: Path,
    *,
    version: str = "0.1.9",
    changelog: str = CLEAN_CHANGELOG,
    pyproject: str = CLEAN_PYPROJECT,
) -> Path:
    package = tmp_path / "src" / "pkcs11_check"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        f'"""pkcs11-check."""\n\n__version__ = "{version}"\n', encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return tmp_path


def test_clean_repo_reports_no_problems(tmp_path: Path) -> None:
    assert verify(_make_repo(tmp_path), "0.1.9") == []


def test_requested_version_accepts_a_leading_v(tmp_path: Path) -> None:
    assert verify(_make_repo(tmp_path), "v0.1.9") == []


def test_requested_version_mismatch_is_reported(tmp_path: Path) -> None:
    problems = verify(_make_repo(tmp_path), "0.2.0")
    assert [problem.location for problem in problems] == ["input"]
    assert "0.2.0" in problems[0].message


def test_self_consistency_check_needs_no_requested_version(tmp_path: Path) -> None:
    assert verify(_make_repo(tmp_path), None) == []


def test_static_project_version_is_reported(tmp_path: Path) -> None:
    pyproject = '[project]\nname = "pkcs11-check"\nversion = "0.1.9"\ndynamic = ["version"]\n'
    problems = verify(_make_repo(tmp_path, pyproject=pyproject), "0.1.9")
    assert any("[project].version is set" in problem.message for problem in problems)


def test_missing_dynamic_version_is_reported(tmp_path: Path) -> None:
    pyproject = '[project]\nname = "pkcs11-check"\n'
    problems = verify(_make_repo(tmp_path, pyproject=pyproject), "0.1.9")
    assert any("dynamic" in problem.message for problem in problems)


def test_changelog_top_entry_must_match_the_package(tmp_path: Path) -> None:
    changelog = "# Changelog\n\n## [0.1.8] - 2026-07-30\n\nOld.\n"
    problems = verify(_make_repo(tmp_path, changelog=changelog), "0.1.9")
    assert any(problem.location == "CHANGELOG.md" for problem in problems)


def test_changelog_date_must_be_iso(tmp_path: Path) -> None:
    changelog = "# Changelog\n\n## [0.1.9] - 01/08/2026\n\nNew.\n"
    problems = verify(_make_repo(tmp_path, changelog=changelog), "0.1.9")
    assert any("ISO date" in problem.message for problem in problems)


def test_version_must_exceed_the_previous_entry(tmp_path: Path) -> None:
    changelog = (
        "# Changelog\n\n## [0.1.7] - 2026-08-01\n\nNew.\n\n## [0.1.8] - 2026-07-30\n\nOld.\n"
    )
    problems = verify(_make_repo(tmp_path, version="0.1.7", changelog=changelog), "0.1.7")
    assert any("not greater than" in problem.message for problem in problems)


def test_non_numeric_package_version_is_reported(tmp_path: Path) -> None:
    problems = verify(_make_repo(tmp_path, version="0.1.9rc1"), "0.1.9rc1")
    assert any("is not X.Y.Z" in problem.message for problem in problems)


def test_missing_changelog_heading_is_reported(tmp_path: Path) -> None:
    problems = verify(_make_repo(tmp_path, changelog="# Changelog\n\nNothing here.\n"), "0.1.9")
    assert any("no '## [X.Y.Z] - DATE' heading" in problem.message for problem in problems)


def test_dateless_heading_is_reported(tmp_path: Path) -> None:
    changelog = "# Changelog\n\n## [Unreleased]\n\nUpcoming.\n\n## [0.1.9] - 2026-08-01\n\nNew.\n"
    problems = verify(_make_repo(tmp_path, changelog=changelog), "0.1.9")
    assert any("[Unreleased]" in problem.message for problem in problems)


def test_non_numeric_top_version_is_blamed_not_the_previous_entry(tmp_path: Path) -> None:
    changelog = (
        "# Changelog\n\n## [Unreleased] - 2026-08-01\n\nUpcoming.\n\n"
        "## [0.1.8] - 2026-07-30\n\nOld.\n"
    )
    problems = verify(_make_repo(tmp_path, version="0.1.9", changelog=changelog), "0.1.9")
    assert any(
        "entry 'Unreleased' is not a numeric version" in problem.message for problem in problems
    )
    assert not any("previous entry" in problem.message for problem in problems)


def test_extract_notes_returns_the_section_body(tmp_path: Path) -> None:
    notes = extract_notes(_make_repo(tmp_path), "0.1.9")
    assert notes.startswith("New things.")
    assert "- A thing." in notes


def test_extract_notes_stops_at_the_next_heading(tmp_path: Path) -> None:
    notes = extract_notes(_make_repo(tmp_path), "0.1.9")
    assert "Old things." not in notes
    assert "## [0.1.8]" not in notes


def test_extract_notes_reads_an_older_section_too(tmp_path: Path) -> None:
    assert extract_notes(_make_repo(tmp_path), "0.1.8").strip() == "Old things."


def test_extract_notes_raises_when_the_section_is_absent(tmp_path: Path) -> None:
    with pytest.raises(LookupError, match=r"0\.2\.0"):
        extract_notes(_make_repo(tmp_path), "0.2.0")


def test_cli_exits_zero_on_a_clean_repo(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    assert main(["--repo-root", str(repo), "--version", "0.1.9"]) == 0


def test_cli_exits_nonzero_on_a_mismatch(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    assert main(["--repo-root", str(repo), "--version", "0.2.0"]) == 1


def test_cli_writes_the_notes_file(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    notes = tmp_path / "notes.md"
    assert main(["--repo-root", str(repo), "--version", "v0.1.9", "--notes-out", str(notes)]) == 0
    assert "A thing." in notes.read_text(encoding="utf-8")


def test_cli_rejects_notes_without_a_version(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    notes = tmp_path / "notes.md"
    assert main(["--repo-root", str(repo), "--notes-out", str(notes)]) == 1
    assert not notes.exists()
