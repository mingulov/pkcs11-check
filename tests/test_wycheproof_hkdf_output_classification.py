"""Regression tests for HKDF derived-value readback classification."""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof_hkdf as hkdf


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    classification.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=7, has_mechanism=lambda _name: True)


def _vector(result: str = "valid") -> dict[str, Any]:
    return {
        "ikm": "01",
        "salt": "",
        "info": "",
        "okm": "02",
        "size": 1,
        "result": result,
        "_sha": "SHA-256",
    }


def _setup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    attrs: dict[int, Any] | None = None,
    derive: Callable[..., int] | None = None,
    read_error: BaseException | None = None,
    import_error: BaseException | None = None,
) -> list[int]:
    destroyed: list[int] = []

    def _import(*_args: Any, **_kwargs: Any) -> int:
        if import_error is not None:
            raise import_error
        return 101

    monkeypatch.setattr(hkdf, "import_secret_key_negotiated", _import)
    monkeypatch.setattr(hkdf, "mech_hkdf", lambda *_a, **_k: object())
    monkeypatch.setattr(hkdf, "derive_key", derive or (lambda *_a, **_k: 202))

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        if read_error is not None:
            raise read_error
        return {} if attrs is None else attrs

    monkeypatch.setattr(hkdf, "read_attributes", _read)
    monkeypatch.setattr(
        hkdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    return destroyed


def test_missing_value_on_valid_vector_is_visible_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _setup(monkeypatch)

    with pytest.raises(pytest.xfail.Exception):
        hkdf.test_hkdf(_session(), "hkdf-tc-valid", _vector())

    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert destroyed == [202, 101]


def test_missing_value_on_invalid_vector_is_accepted_invalid_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _setup(
        monkeypatch,
        read_error=RuntimeError("readback must not decide invalid acceptance"),
    )

    with pytest.raises(Failed):
        hkdf.test_hkdf(_session(), "hkdf-tc-invalid", _vector("invalid"))

    record = classification.get_records()[-1]
    assert record.reason == "accepted_invalid"
    assert record.kind == "crypto"
    assert destroyed == [202, 101]


def test_invalid_vector_rejected_after_derive_is_acceptable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("invalid HKDF vector rejected", int(CKR_KEY_SIZE_RANGE))
        ),
    )

    hkdf.test_hkdf(_session(), "hkdf-tc-rejected", _vector("invalid"))

    assert classification.get_records() == []
    assert destroyed == [101]


@pytest.mark.parametrize("result", ["invalid", "acceptable"])
def test_setup_rejection_is_visible_for_negative_vectors(
    monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    destroyed = _setup(
        monkeypatch,
        import_error=CkrAssertionError(
            "HKDF IKM import rejected", int(CKR_ATTRIBUTE_VALUE_INVALID)
        ),
    )

    with pytest.raises(pytest.xfail.Exception, match="HKDF_DERIVE:key-import"):
        hkdf.test_hkdf(_session(), f"hkdf-tc-{result}", _vector(result))

    assert destroyed == []


def test_setup_vendor_rejection_is_visible_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    _setup(
        monkeypatch,
        import_error=CkrAssertionError("vendor setup refusal", int(CKR_VENDOR_DEFINED) + 1),
    )

    with pytest.raises(pytest.xfail.Exception):
        hkdf.test_hkdf(_session(), "hkdf-tc-valid", _vector())

    assert classification.get_records()[-1].reason == "nonspec_reject"


def test_setup_undefined_ckr_is_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _setup(monkeypatch, import_error=CkrAssertionError("undefined setup result", 0x7FFFFFFF))

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        hkdf.test_hkdf(_session(), "hkdf-tc-valid", _vector())

    assert classification.get_records()[-1].reason == "self_contradiction"


def test_invalid_vector_setup_non_ckr_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, import_error=AssertionError("setup harness bug"))

    with pytest.raises(AssertionError, match="setup harness bug"):
        hkdf.test_hkdf(_session(), "hkdf-tc-invalid", _vector("invalid"))

    assert classification.get_records() == []


@pytest.mark.parametrize("result", ["invalid", "acceptable"])
@pytest.mark.parametrize(
    "rv",
    [int(CKR_DEVICE_ERROR), int(CKR_GENERAL_ERROR), int(CKR_VENDOR_DEFINED) + 1],
)
def test_negative_derive_other_clean_rejections_are_visible_xfails(
    monkeypatch: pytest.MonkeyPatch, rv: int, result: str
) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("negative HKDF vector rejected", rv)
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        hkdf.test_hkdf(_session(), f"hkdf-tc-{result}", _vector(result))

    assert classification.get_records()[-1].reason == "nonspec_reject"
    assert destroyed == [101]


@pytest.mark.parametrize("rv", [int(CKR_DEVICE_ERROR), int(CKR_GENERAL_ERROR)])
def test_valid_derive_clean_refusal_is_visible_not_operational(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("valid HKDF refusal", rv)),
    )

    with pytest.raises(pytest.xfail.Exception):
        hkdf.test_hkdf(_session(), "hkdf-tc-valid", _vector())

    assert classification.get_records()[-1].reason == "not_operational"
    assert destroyed == [101]


def test_valid_derive_vendor_rejection_is_visible_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("valid HKDF vendor refusal", int(CKR_VENDOR_DEFINED) + 1)
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        hkdf.test_hkdf(_session(), "hkdf-tc-valid", _vector())

    assert classification.get_records()[-1].reason == "nonspec_reject"
    assert destroyed == [101]


def test_valid_derive_undefined_ckr_is_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("undefined valid HKDF result", 0x7FFFFFFF)
        ),
    )

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        hkdf.test_hkdf(_session(), "hkdf-tc-valid", _vector())

    assert classification.get_records()[-1].reason == "self_contradiction"
    assert destroyed == [101]


@pytest.mark.parametrize("result", ["invalid", "acceptable"])
def test_negative_derive_undefined_ckr_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("negative HKDF vector rejected", 0x7FFFFFFF)
        ),
    )

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        hkdf.test_hkdf(_session(), f"hkdf-tc-{result}", _vector(result))

    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert destroyed == [101]


def test_acceptable_negative_derive_expected_rejection_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("acceptable HKDF vector rejected", int(CKR_KEY_SIZE_RANGE))
        ),
    )

    hkdf.test_hkdf(_session(), "hkdf-tc-acceptable", _vector("acceptable"))

    assert classification.get_records() == []
    assert destroyed == [101]


@pytest.mark.parametrize(
    "error",
    [AssertionError("local assertion"), TypeError("bad packing")],
)
def test_unexpected_local_derive_errors_propagate(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    destroyed = _setup(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(error),
    )

    with pytest.raises(type(error), match=str(error)):
        hkdf.test_hkdf(_session(), "hkdf-tc-error", _vector())

    assert classification.get_records() == []
    assert destroyed == [101]


def test_acceptable_vector_with_missing_value_is_visible_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _setup(monkeypatch)

    with pytest.raises(pytest.xfail.Exception):
        hkdf.test_hkdf(_session(), "hkdf-tc-acceptable", _vector("acceptable"))

    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert destroyed == [202, 101]


@pytest.mark.parametrize("result", ["valid", "acceptable"])
def test_readable_wrong_value_is_hard_finding_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    destroyed = _setup(monkeypatch, attrs={CKA_VALUE: b"\x03"})

    with pytest.raises(Failed):
        hkdf.test_hkdf(_session(), "hkdf-tc-wrong", _vector(result))

    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert destroyed == [202, 101]


@pytest.mark.parametrize("result", ["valid", "acceptable"])
def test_readable_correct_value_passes_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    destroyed = _setup(monkeypatch, attrs={CKA_VALUE: b"\x02"})

    hkdf.test_hkdf(_session(), "hkdf-tc-correct", _vector(result))

    assert classification.get_records() == []
    assert destroyed == [202, 101]


@pytest.mark.parametrize(
    "error",
    [
        KeyError("unrelated"),
        ValueError("malformed"),
        TypeError("wrong type"),
        AssertionError("unexpected assertion"),
    ],
)
def test_unrelated_readback_errors_propagate_and_still_clean_up(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    destroyed = _setup(monkeypatch, read_error=error)

    with pytest.raises(type(error), match=str(error)):
        hkdf.test_hkdf(_session(), "hkdf-tc-error", _vector())

    assert classification.get_records() == []
    assert destroyed == [202, 101]
