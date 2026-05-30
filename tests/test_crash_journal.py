"""Crash-journal summary + opt-in per-unit journaling (Phase 4 auto-attach)."""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.core.crash_journal import summarize_crash_journals, unit_journal_slug
from pkcs11_check.core.file_runner import _maybe_set_crash_journal


def test_unit_journal_slug_is_filesystem_safe() -> None:
    slug = unit_journal_slug("src/pkcs11_check/testcases/test_foo.py::TestX::test_y")
    assert "/" not in slug and ":" not in slug
    assert slug == "src_pkcs11_check_testcases_test_foo.py__TestX__test_y"


def test_summarize_reports_only_crashed_journals(tmp_path: Path) -> None:
    # Crashed: i=1 has a 'call' but no 'ret' -> died inside C_DeriveKey.
    (tmp_path / "unitA-111.jsonl").write_text(
        '{"ev": "call", "i": 0, "fn": "C_Sign", "mech": 1}\n'
        '{"ev": "ret", "i": 0, "rv": 0, "rv_name": "CKR_OK"}\n'
        '{"ev": "call", "i": 1, "fn": "C_DeriveKey", "mech": 2, "in_len": 16}\n'
    )
    # Clean: every call matched -> no crash, must be skipped.
    (tmp_path / "unitB-222.jsonl").write_text(
        '{"ev": "call", "i": 0, "fn": "C_GetInfo", "mech": null}\n'
        '{"ev": "ret", "i": 0, "rv": 0, "rv_name": "CKR_OK"}\n'
    )
    (tmp_path / "unitC-333.jsonl").write_text("")  # empty -> skipped

    rows = summarize_crash_journals(tmp_path)

    assert len(rows) == 1
    row = rows[0]
    assert row["journal"] == "unitA-111.jsonl"
    assert (row["fn"], row["i"], row["mech"], row["in_len"]) == ("C_DeriveKey", 1, 2, 16)
    assert row["path"].endswith("unitA-111.jsonl")


def test_summarize_missing_dir_is_empty(tmp_path: Path) -> None:
    assert summarize_crash_journals(tmp_path / "nope") == []


def test_maybe_set_crash_journal_off_by_default() -> None:
    env: dict[str, str] = {}
    _maybe_set_crash_journal(env, "src/pkcs11_check/testcases/test_foo.py")
    assert "PKCS11_CHECK_RV_TRACE_JOURNAL" not in env


def test_maybe_set_crash_journal_on(tmp_path: Path) -> None:
    env = {"PKCS11_CHECK_RV_TRACE_JOURNAL_DIR": str(tmp_path)}
    _maybe_set_crash_journal(env, "src/pkcs11_check/testcases/test_foo.py::TestX::test_y")

    journal = env["PKCS11_CHECK_RV_TRACE_JOURNAL"]
    assert journal.startswith(str(tmp_path))
    assert "{pid}" in journal  # literal -- expanded by the child (raw.api._journal_path)
    assert "test_foo.py" in journal  # the unit slug is embedded
    assert tmp_path.is_dir()  # the dir was created
