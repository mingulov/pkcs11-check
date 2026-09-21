"""H-3: CKR spec tables use real constants, not FUNCTION_FAILED stand-ins."""

from __future__ import annotations

import pathlib

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_AEAD_DECRYPT_FAILED,
    CKR_CANT_LOCK,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_PARALLEL,
    CKR_INFORMATION_SENSITIVE,
    CKR_KEY_CHANGED,
    CKR_NEED_TO_CREATE_THREADS,
    CKR_OPERATION_CANCEL_FAILED,
    CKR_SEED_RANDOM_REQUIRED,
    CKR_TOKEN_RESOURCE_EXCEEDED,
)
from pkcs11_check.testcases.ckr import _ckr_spec as spec
from pkcs11_check.testcases.ckr._ckr_spec import assert_ckr

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TABLES_PATH = REPO_ROOT / "src/pkcs11_check/testcases/ckr/_ckr_spec_tables.py"

_FORMER_PLACEHOLDERS = frozenset(
    {
        int(CKR_AEAD_DECRYPT_FAILED),
        int(CKR_CANT_LOCK),
        int(CKR_FUNCTION_NOT_PARALLEL),
        int(CKR_INFORMATION_SENSITIVE),
        int(CKR_KEY_CHANGED),
        int(CKR_NEED_TO_CREATE_THREADS),
        int(CKR_OPERATION_CANCEL_FAILED),
        int(CKR_SEED_RANDOM_REQUIRED),
        int(CKR_TOKEN_RESOURCE_EXCEEDED),
    }
)


def _all_tables() -> dict[str, dict[str, object]]:
    tables = {
        name: value
        for name, value in vars(spec).items()
        if name.startswith("CKR_") and isinstance(value, dict)
    }
    assert tables, "no CKR_* tables found; the scan would be vacuous"
    return tables


def test_no_not_in_fork_placeholders() -> None:
    """The stale stand-in scaffolding must not come back."""
    text = TABLES_PATH.read_text(encoding="utf-8")
    assert "not in fork" not in text
    assert "spec_ckr_code" not in text


def test_former_placeholders_use_real_constants() -> None:
    """Every formerly missing constant now appears as a row's spec_ckr."""
    seen: set[int] = set()
    for table in _all_tables().values():
        for expectation in table.values():
            codes = expectation.spec_ckr  # type: ignore[attr-defined]
            if isinstance(codes, tuple):
                seen.update(int(code) for code in codes)
            else:
                seen.add(int(codes))
    assert _FORMER_PLACEHOLDERS <= seen


def test_no_function_failed_stand_in_rows() -> None:
    """No row pairs spec_ckr=FUNCTION_FAILED with a code override."""
    offenders = []
    for table_name, table in _all_tables().items():
        for key, expectation in table.items():
            codes = expectation.spec_ckr  # type: ignore[attr-defined]
            code_list = list(codes) if isinstance(codes, tuple) else [codes]
            if int(CKR_FUNCTION_FAILED) in {int(code) for code in code_list}:
                if expectation.spec_ckr_code:  # type: ignore[attr-defined]
                    offenders.append(f"{table_name}[{key}]")
    assert offenders == []


def test_token_resource_exceeded_oracle_direction() -> None:
    """The real code passes; the stale placeholder fails strict, xfails compat."""
    expectation = spec.CKR_SIGN["token_resource_exceeded"]
    assert not isinstance(expectation.spec_ckr, tuple)
    assert int(expectation.spec_ckr) == int(CKR_TOKEN_RESOURCE_EXCEEDED)
    assert int(CKR_FUNCTION_FAILED) in tuple(expectation.compat_tuple)

    assert_ckr(expectation, int(CKR_TOKEN_RESOURCE_EXCEEDED), strict=True)
    assert_ckr(expectation, int(CKR_TOKEN_RESOURCE_EXCEEDED), strict=False)

    with pytest.raises(Failed) as ei:
        assert_ckr(expectation, int(CKR_FUNCTION_FAILED), strict=True)
    assert not isinstance(ei.value, XFailed)

    with pytest.raises(XFailed):
        assert_ckr(expectation, int(CKR_FUNCTION_FAILED), strict=False)
