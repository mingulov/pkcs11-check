"""Regression tests for validation/trust metadata error routing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_TRUST_SERVER_AUTH,
    CKA_VALIDATION_TYPE,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases import test_trust_objects as trust
from pkcs11_check.testcases import test_validation_objects as validation


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


@pytest.mark.parametrize(
    ("finder", "module"),
    [
        (validation._find_validation_objects, validation),
        (trust._find_trust_objects, trust),
    ],
)
def test_metadata_enumeration_plain_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
    finder: Any,
    module: Any,
) -> None:
    monkeypatch.setattr(
        module,
        "find_objects",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("harness bug")),
    )

    with pytest.raises(AssertionError, match="harness bug"):
        finder(_session().raw, 1)


@pytest.mark.parametrize(
    "finder",
    [validation._find_validation_objects, trust._find_trust_objects],
)
def test_metadata_enumeration_ckr_failure_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
    finder: Any,
) -> None:
    monkeypatch.setattr(
        validation if finder is validation._find_validation_objects else trust,
        "find_objects",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))
        ),
    )

    with pytest.raises(XFailed):
        finder(_session().raw, 1)


def test_validation_enumeration_undefined_ckr_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validation,
        "find_objects",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("undefined CK_RV", 0x12345678)
        ),
    )

    with pytest.raises(Failed, match="undefined CK_RV"):
        validation._find_validation_objects(_session().raw, 1)


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_READ_ONLY, CKR_ACTION_PROHIBITED])
def test_validation_read_only_write_acceptance_and_rejections_are_distinct(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_args: [1])
    monkeypatch.setattr(
        validation,
        "set_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CkrAssertionError("read-only", int(rv))),
    )

    validation.TestValidationObjects().test_validation_objects_are_read_only(_session())


def test_validation_read_only_write_acceptance_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_args: [1])
    monkeypatch.setattr(validation, "set_attributes", lambda *_args, **_kwargs: None)

    with pytest.raises(Failed, match="accepted"):
        validation.TestValidationObjects().test_validation_objects_are_read_only(_session())


def test_validation_unknown_type_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_args: [1])
    monkeypatch.setattr(
        validation,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALIDATION_TYPE: 0x1234},
    )

    with pytest.raises(AssertionError, match="Unknown non-vendor validation type"):
        validation.TestValidationObjects().test_validation_type_is_known(_session())


def test_trust_unknown_value_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust, "_find_trust_objects", lambda *_args: [1])
    monkeypatch.setattr(
        trust,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_TRUST_SERVER_AUTH: 0x1234},
    )

    with pytest.raises(AssertionError, match="Unknown TRUST_SERVER_AUTH"):
        trust.TestTrustObjects().test_trust_server_auth_is_known_value(_session())


def test_trust_read_failure_with_undefined_ckr_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust, "_find_trust_objects", lambda *_args: [1])
    monkeypatch.setattr(
        trust,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("undefined CK_RV", 0x12345678)
        ),
    )

    with pytest.raises(Failed, match="undefined CK_RV"):
        trust.TestTrustObjects().test_trust_server_auth_is_known_value(_session())
