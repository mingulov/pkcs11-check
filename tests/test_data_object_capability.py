"""Focused CKO_DATA capability-probe classification regressions."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_GENERAL_ERROR,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import conftest as testcase_conftest


@pytest.mark.parametrize("rv", [CKR_ARGUMENTS_BAD, CKR_TEMPLATE_INCONSISTENT])
def test_valid_data_probe_clean_class_refusal_skips(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CkrAssertionError("refused", int(rv))),
    )

    with pytest.raises(pytest.skip.Exception, match="does not support CKO_DATA"):
        testcase_conftest.skip_if_data_objects_unsupported(SimpleNamespace(raw=object(), sh=1))


def test_data_probe_unrelated_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("unexpected", int(CKR_GENERAL_ERROR))
        ),
    )

    with pytest.raises(CkrAssertionError, match="unexpected"):
        testcase_conftest.skip_if_data_objects_unsupported(SimpleNamespace(raw=object(), sh=1))
