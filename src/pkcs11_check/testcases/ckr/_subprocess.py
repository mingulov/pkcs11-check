"""Shared helpers for CKR subprocess probes."""

from __future__ import annotations

import pytest

from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

_SETUP_XFAIL_PREFIX = "SETUP_XFAIL:"


def assert_ckr_subprocess_ok(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Classify CKR child-process results without hiding provider crashes."""
    assert_subprocess_completed(rc, stdout, stderr, context=context)
    for line in stdout.splitlines():
        if line.startswith(_SETUP_XFAIL_PREFIX):
            pytest.xfail(line.removeprefix(_SETUP_XFAIL_PREFIX).strip())
    if "OK" not in stdout:
        pytest.fail(
            f"{context}: child subprocess did not emit an OK marker; "
            f"stdout: {stdout[-300:]}; stderr: {stderr[-300:]}"
        )
