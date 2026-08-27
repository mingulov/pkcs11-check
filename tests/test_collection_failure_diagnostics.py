"""A collection failure must say WHY it failed (GH #3).

A user on Windows hit

    Error: pytest metadata collection failed: ERROR: found no collectors for
    C:\\T4\\pkcs11-check\\pkcs11-check\\src\\pkcs11_check\\testcases

and there was nothing else to go on: no indication whether the path existed, was
readable, or held any test files, no exit code, no pytest arguments, and only one of
the two output streams (``stderr or stdout``, so a message on the other one is
dropped). The run could not even start and the tool could not say why.

Both collectors -- the metadata one used by ``test`` and the node-id one used by
``list-tests`` -- carried their own copy of that blind message.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.core.collection_errors import collection_failure_message


def test_reports_both_streams() -> None:
    msg = collection_failure_message(
        returncode=4,
        stdout="ERROR: found no collectors for /x/testcases",
        stderr="some warning on stderr",
        targets=["/x/testcases"],
        pytest_args=["--collect-only", "-qq"],
    )

    assert "found no collectors" in msg, "stdout was dropped when stderr was non-empty"
    assert "some warning on stderr" in msg


def test_reports_exit_code_and_args() -> None:
    msg = collection_failure_message(
        returncode=4,
        stdout="",
        stderr="",
        targets=["/x/testcases"],
        pytest_args=["-k", "rsa", "--collect-only"],
    )

    assert "exit code 4" in msg
    assert "-k" in msg and "rsa" in msg


def test_describes_a_missing_target() -> None:
    msg = collection_failure_message(
        returncode=4,
        stdout="",
        stderr="",
        targets=["/definitely/not/here"],
        pytest_args=[],
    )

    assert "/definitely/not/here" in msg
    assert "does not exist" in msg


def test_describes_an_existing_target_and_counts_test_files(tmp_path: Path) -> None:
    (tmp_path / "test_alpha.py").write_text("def test_a(): pass\n", encoding="utf-8")
    (tmp_path / "test_beta.py").write_text("def test_b(): pass\n", encoding="utf-8")
    (tmp_path / "notatest.py").write_text("x = 1\n", encoding="utf-8")

    msg = collection_failure_message(
        returncode=4, stdout="", stderr="", targets=[str(tmp_path)], pytest_args=[]
    )

    assert "2 test_*.py" in msg, "test-file count is the first thing to check on this failure"


def test_reports_an_empty_directory_as_the_likely_cause(tmp_path: Path) -> None:
    msg = collection_failure_message(
        returncode=4, stdout="", stderr="", targets=[str(tmp_path)], pytest_args=[]
    )

    assert "0 test_*.py" in msg


def test_mentions_the_cache_bypass_switch() -> None:
    """The user's error vanished on its own; a cache bypass is the first thing to try."""
    msg = collection_failure_message(
        returncode=4, stdout="", stderr="", targets=["/x"], pytest_args=[]
    )

    assert "PKCS11_CHECK_NO_COLLECTION_CACHE" in msg


def test_never_returns_the_bare_unknown_error() -> None:
    msg = collection_failure_message(
        returncode=1, stdout="", stderr="", targets=["/x"], pytest_args=[]
    )

    assert msg.strip() != "unknown collection error"
    assert len(msg.splitlines()) > 1, "a diagnosable message needs more than one line"


@pytest.mark.parametrize("module", ["collection", "_unit_discovery"])
def test_both_collectors_use_the_shared_message(module: str) -> None:
    """Neither collector may keep a private copy of the blind message."""
    source = Path("src/pkcs11_check/core") / f"{module}.py"
    text = source.read_text(encoding="utf-8")

    assert "unknown collection error" not in text, f"{module} still has the blind message"
    assert "collection_failure_message" in text
