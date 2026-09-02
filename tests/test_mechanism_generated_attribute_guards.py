"""Regression tests for generated-key attribute classification and token fidelity."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import clear, get_records
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_TOKEN,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases import test_mech_attribute, test_mech_keygen


def _rs() -> Any:
    return SimpleNamespace(raw=object(), sh=1)


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    clear()
    yield
    clear()


@pytest.mark.parametrize(
    "rv",
    [CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_SENSITIVE, CKR_TEMPLATE_INCONSISTENT],
)
def test_required_attribute_refusal_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    error = CkrAssertionError("attribute unavailable", int(rv))
    monkeypatch.setattr(
        test_mech_attribute, "read_attributes", lambda *_a, **_k: (_ for _ in ()).throw(error)
    )

    with pytest.raises(XFailed):
        test_mech_attribute._read_attr_safe(_rs(), 1, 2, "CKA_TOKEN")

    record = get_records()[-1]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.actual_ckr == ckr_name(int(rv))


@pytest.mark.parametrize("rv", [CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1])
def test_typed_standard_or_vendor_attribute_error_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    error = CkrAssertionError("attribute read failed", int(rv))
    monkeypatch.setattr(
        test_mech_attribute, "read_attributes", lambda *_a, **_k: (_ for _ in ()).throw(error)
    )

    with pytest.raises(XFailed):
        test_mech_attribute._read_attr_safe(_rs(), 1, 2, "CKA_TOKEN")

    record = get_records()[-1]
    assert record.reason == "not_operational"
    assert record.actual_ckr == ckr_name(int(rv))


def test_undefined_attribute_error_is_a_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = CkrAssertionError("attribute read failed", 0x12345678)
    monkeypatch.setattr(
        test_mech_attribute, "read_attributes", lambda *_a, **_k: (_ for _ in ()).throw(error)
    )

    with pytest.raises(Failed):
        test_mech_attribute._read_attr_safe(_rs(), 1, 2, "CKA_TOKEN")

    record = get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"


def test_plain_attribute_assertion_remains_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = AssertionError("harness bug")
    monkeypatch.setattr(
        test_mech_attribute, "read_attributes", lambda *_a, **_k: (_ for _ in ()).throw(error)
    )

    with pytest.raises(AssertionError) as caught:
        test_mech_attribute._read_attr_safe(_rs(), 1, 2, "CKA_TOKEN")

    assert caught.value is error
    assert get_records() == []


@pytest.mark.parametrize("is_keypair", [False, True])
def test_true_token_readback_is_metadata_failure(
    monkeypatch: pytest.MonkeyPatch, is_keypair: bool
) -> None:
    entry: Any = SimpleNamespace(
        mech_name="AES_KEY_GEN",
        config=SimpleNamespace(
            is_param_gen=False,
            is_keypair=is_keypair,
            key_type=None,
        ),
    )
    rs: Any = SimpleNamespace(raw=object(), sh=1)
    monkeypatch.setattr(test_mech_attribute, "needs_domain_params", lambda _config: False)
    monkeypatch.setattr(test_mech_attribute, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_mech_attribute, "gen_symmetric_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_mech_attribute, "gen_keypair_for_mech", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(
        test_mech_attribute,
        "read_attributes",
        lambda *_a, **_k: {CKA_TOKEN: True},
    )

    with pytest.raises(Failed):
        test_mech_attribute.TestKeyAttributes().test_token_flag_matches_template(rs, entry)

    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.label.endswith("CKA_TOKEN readback")


def test_keygen_local_refusal_is_visible_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    error = CkrAssertionError("local unavailable", int(CKR_ATTRIBUTE_TYPE_INVALID))
    monkeypatch.setattr(
        test_mech_keygen, "read_attributes", lambda *_a, **_k: (_ for _ in ()).throw(error)
    )

    with pytest.raises(XFailed):
        test_mech_keygen._read_local_flag(_rs(), 1, "AES key")

    record = get_records()[-1]
    assert record.reason == "not_operational"
    assert record.actual_ckr == ckr_name(int(CKR_ATTRIBUTE_TYPE_INVALID))
