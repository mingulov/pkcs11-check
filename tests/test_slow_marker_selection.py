"""Regression tests for the @pytest.mark.slow basic/full profile selection.

Long-running individual cases are marked `slow` so a basic run can skip them
with `--skip-slow` (-m "not slow"); they still run in the full profile or with
`--only-slow`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pkcs11_check.cli.test_cmd import _combine_marker
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE

REPO = Path(__file__).resolve().parents[1]
_KEY_SIZES = "src/pkcs11_check/testcases/test_key_sizes.py"
_CFB128 = "src/pkcs11_check/testcases/acvp/aes/test_cfb128.py"


def _collect(markexpr: str, *targets: str) -> list[str]:
    """Return collected nodeids for a marker expression (addopts cleared for -q)."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-o",
            "addopts=",
            "--co",
            "-q",
            "-p",
            "no:cacheprovider",
            "-m",
            markexpr,
            *targets,
        ],
        capture_output=True,
        text=True,
        cwd=REPO,
        encoding="utf-8",
    )
    return [line for line in proc.stdout.splitlines() if "::" in line]


# -- _combine_marker unit behavior --


def test_combine_skip_slow() -> None:
    assert _combine_marker(None, skip_slow=True, only_slow=False) == "not slow"


def test_combine_only_slow() -> None:
    assert _combine_marker(None, skip_slow=False, only_slow=True) == "slow"


def test_combine_none() -> None:
    assert _combine_marker(None, skip_slow=False, only_slow=False) is None


def test_combine_with_existing_marker() -> None:
    assert _combine_marker("acvp", skip_slow=True, only_slow=False) == "(acvp) and (not slow)"
    assert _combine_marker("acvp", skip_slow=False, only_slow=False) == "acvp"


# -- parametrization-level marking: only RSA-4096 is slow --


def test_rsa_4096_is_slow_but_2048_is_not() -> None:
    slow = _collect("slow", _KEY_SIZES)
    assert any("test_rsa_sign_verify[4096]" in n for n in slow)
    assert not any("test_rsa_sign_verify[2048]" in n for n in slow)


def test_not_slow_keeps_rsa_2048_drops_4096() -> None:
    fast = _collect("not slow", _KEY_SIZES)
    assert any("test_rsa_sign_verify[2048]" in n for n in fast)
    assert not any("test_rsa_sign_verify[4096]" in n for n in fast)


# -- function-level marking: AES multiblock slow, single-block fast --


@pytest.mark.skipif(
    not ACVP_AVAILABLE,
    reason="ACVP vectors not cloned; test_cfb128.py is module-level skipped so the "
    "multiblock cases never collect (run: fetch-data acvp)",
)
def test_aes_multiblock_slow_singleblock_fast() -> None:
    slow = _collect("slow", _CFB128)
    fast = _collect("not slow", _CFB128)
    assert slow, "expected some slow multiblock cases in test_cfb128.py"
    assert all("multiblock" in n for n in slow)
    assert not any("multiblock" in n for n in fast)
    # single-block KAT cases must remain in the fast profile
    assert any("multiblock" not in n for n in fast)
