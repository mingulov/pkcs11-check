"""Guard tests for the NSS slot0 pool-pass scoping (docker/test_pool.py).

The `*-slot0` passes are scoped to the files that have a test node which runs on
slot 0 but skips on slot 1. These tests keep that list honest: every entry must
exist, the digest/KDF anchors must be present, and a missing entry must fall back
to the FULL suite (never silently drop coverage).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_TESTCASES = "src/pkcs11_check/testcases"

_spec = importlib.util.spec_from_file_location("_pool", _REPO / "docker" / "test_pool.py")
assert _spec and _spec.loader
test_pool = importlib.util.module_from_spec(_spec)
sys.modules["_pool"] = test_pool
_spec.loader.exec_module(test_pool)


def test_slot0_unique_files_all_exist() -> None:
    for rel in test_pool.SLOT0_UNIQUE_FILES:
        assert (_REPO / _TESTCASES / rel).is_file(), f"slot0-unique file missing: {rel}"


def test_slot0_anchors_present() -> None:
    anchors = {
        "test_digest.py",
        "test_mech_digest.py",
        "acvp/test_acvp_hash.py",
        "test_sha3.py",
        "test_aes_kdf.py",
        "test_dual_function.py",
    }
    assert anchors <= set(test_pool.SLOT0_UNIQUE_FILES)


def _full(extra: str = "test_zzz_other.py") -> list[str]:
    files = [f"{_TESTCASES}/{rel}" for rel in test_pool.SLOT0_UNIQUE_FILES]
    return [*files, f"{_TESTCASES}/{extra}"]


def test_non_slot0_provider_runs_full_suite() -> None:
    files = _full()
    assert test_pool.files_for_provider("nss", files, _TESTCASES) == files


def test_slot0_provider_is_scoped() -> None:
    files = _full()
    scoped = test_pool.files_for_provider("nss-slot0", files, _TESTCASES)
    assert set(scoped) == {f"{_TESTCASES}/{rel}" for rel in test_pool.SLOT0_UNIQUE_FILES}
    assert f"{_TESTCASES}/test_zzz_other.py" not in scoped


def test_missing_slot0_file_falls_back_to_full(capsys: pytest.CaptureFixture[str]) -> None:
    # No slot0 file present -> must return the full input (never a broken subset).
    incomplete = [f"{_TESTCASES}/test_zzz_other.py"]
    assert test_pool.files_for_provider("nss-slot0", incomplete, _TESTCASES) == incomplete
    assert "falling back to the FULL suite" in capsys.readouterr().err
