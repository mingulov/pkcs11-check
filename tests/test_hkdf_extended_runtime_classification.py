"""Regression tests for HKDF extended runtime classification."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKR_ATTRIBUTE_VALUE_INVALID,
)
from pkcs11_check.testcases import test_hkdf_extended


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def test_hkdf_keygen_value_readback_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generated HKDF key value readback rejects should stay visible as xfail evidence."""

    def _read_attributes(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "HKDF_KEY_GEN",
    )
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_hkdf_extended, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_hkdf_extended, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKA_VALUE readback rejected"):
        test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_basic(rs, CKK_HKDF)


def _session(*supported: str) -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: not supported or name in supported,
    )


def test_keygen_missing_metadata_and_value_collects_all_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_a, **_k: 11)
    monkeypatch.setattr(test_hkdf_extended, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_hkdf_extended,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_basic(_session(), CKK_HKDF)

    assert destroyed == [11]
    records = C.get_records()
    assert [record.reason for record in records] == [
        "honest_deviation",
        "honest_deviation",
        "not_operational",
    ]
    assert {record.detail["attribute"]["name"] for record in records if record.detail} == {
        "CKA_KEY_TYPE",
        "CKA_DERIVE",
        "CKA_VALUE",
    }


def test_present_metadata_contradiction_dominates_missing_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_a, **_k: 12)
    monkeypatch.setattr(
        test_hkdf_extended,
        "read_attributes",
        lambda *_a, **_k: {CKA_KEY_TYPE: CKK_HKDF, CKA_DERIVE: False},
    )
    monkeypatch.setattr(
        test_hkdf_extended,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_basic(_session(), CKK_HKDF)

    assert destroyed == [12]
    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "wrong_result",
    ]
    assert C.get_records()[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_keygen_derived_value_missing_is_non_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_a, **_k: 21)
    monkeypatch.setattr(test_hkdf_extended, "_hkdf_derive", lambda *_a, **_k: 22)
    monkeypatch.setattr(test_hkdf_extended, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_hkdf_extended,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_usable_for_derive(
        _session("HKDF_KEY_GEN", "HKDF_DERIVE")
    )

    assert destroyed == [21, 22]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_hkdf_data_missing_value_is_non_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_hkdf_extended, "_create_base_key", lambda *_a, **_k: 31)
    monkeypatch.setattr(test_hkdf_extended, "_hkdf_data_derive", lambda *_a, **_k: 32)
    monkeypatch.setattr(test_hkdf_extended, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_hkdf_extended,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_hkdf_extended.TestHKDFData().test_hkdf_data_derive(_session("HKDF_DATA"))

    assert destroyed == [31, 32]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_deterministic_pair_reads_both_missing_values_before_skipping_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    derives = iter([41, 42])
    monkeypatch.setattr(test_hkdf_extended, "_create_base_key", lambda *_a, **_k: 40)
    monkeypatch.setattr(test_hkdf_extended, "_hkdf_data_derive", lambda *_a, **_k: next(derives))
    monkeypatch.setattr(test_hkdf_extended, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_hkdf_extended,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_hkdf_extended.TestHKDFData().test_hkdf_data_deterministic(_session("HKDF_DATA"))

    assert destroyed == [40, 41, 42]
    assert len(C.get_records()) == 2
    assert all(record.reason == "not_operational" for record in C.get_records())


def test_present_false_like_derive_attribute_is_not_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_a, **_k: 51)
    monkeypatch.setattr(
        test_hkdf_extended,
        "read_attributes",
        lambda *_a, **_k: {CKA_KEY_TYPE: CKK_HKDF, CKA_VALUE: b"x" * 32, CKA_DERIVE: False},
    )
    monkeypatch.setattr(
        test_hkdf_extended,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_basic(_session(), CKK_HKDF)

    assert destroyed == [51]
    assert [record.reason for record in C.get_records()] == ["wrong_result"]


def test_allowed_key_type_deviation_does_not_hide_derive_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_a, **_k: 61)
    monkeypatch.setattr(
        test_hkdf_extended,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_KEY_TYPE: CKK_HKDF,
            CKA_VALUE: b"x" * 32,
            CKA_DERIVE: False,
        },
    )
    monkeypatch.setattr(test_hkdf_extended, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_basic(
            _session(),
            CKK_GENERIC_SECRET,
        )

    assert [record.reason for record in C.get_records()] == [
        "honest_deviation",
        "wrong_result",
    ]


def test_all_present_keygen_contradictions_are_preserved_before_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_hkdf_extended, "_gen_hkdf_key", lambda *_a, **_k: 71)
    monkeypatch.setattr(
        test_hkdf_extended,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: b"",
            CKA_DERIVE: False,
        },
    )
    monkeypatch.setattr(
        test_hkdf_extended,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception, match="CKA_DERIVE"):
        test_hkdf_extended.TestHKDFKeyGen().test_hkdf_key_gen_basic(_session(), CKK_HKDF)

    assert destroyed == [71]
    records = C.get_records()
    assert [record.reason for record in records] == [
        "wrong_result",
        "wrong_result",
        "wrong_result",
    ]
    assert [record.label for record in records] == [
        "CKM_HKDF_KEY_GEN:CKA_KEY_TYPE readback",
        "CKM_HKDF_KEY_GEN:CKA_VALUE length",
        "CKM_HKDF_KEY_GEN:CKA_DERIVE readback",
    ]
