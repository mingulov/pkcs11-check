"""Regression tests for HKDF extended runtime classification."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKK_HKDF,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
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
    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "not_operational",
    ]


def test_hkdf_data_readback_ckr_is_not_reclassified_as_derive_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_hkdf_extended, "_create_base_key", lambda *_a, **_k: 35)
    monkeypatch.setattr(test_hkdf_extended, "_hkdf_data_derive", lambda *_a, **_k: 36)
    monkeypatch.setattr(
        test_hkdf_extended,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected readback refusal", int(CKR_TEMPLATE_INCONSISTENT))
        ),
    )
    monkeypatch.setattr(test_hkdf_extended, "destroy_quietly", lambda *_a: None)

    with pytest.raises(CkrAssertionError, match="unexpected readback refusal"):
        test_hkdf_extended.TestHKDFData().test_hkdf_data_derive(_session("HKDF_DATA"))


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
    assert len(C.get_records()) == 4
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


def test_hkdf_data_template_and_readback_are_mechanism_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_attrs: dict[int, Any] = {}
    read_requests: list[list[int]] = []
    attr_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(test_hkdf_extended, "_create_base_key", lambda *_a, **_k: 81)

    def _derive(*_args: Any, **kwargs: Any) -> int:
        derive_attrs.update(kwargs["attrs"])
        return 82

    monkeypatch.setattr(test_hkdf_extended, "derive_key", _derive)

    def _read(*_args: Any, **kwargs: Any) -> dict[int, Any]:
        read_requests.append(kwargs.get("attrs", _args[-1]))
        return {CKA_CLASS: CKO_DATA, CKA_VALUE: b"x" * 32}

    monkeypatch.setattr(test_hkdf_extended, "read_attributes", _read)
    monkeypatch.setattr(test_hkdf_extended, "destroy_quietly", lambda *_a: None)
    original_attr_or_record = test_hkdf_extended.attr_or_record

    def _attr_or_record(attrs: dict[int, Any], attr: int, **kwargs: Any) -> Any:
        attr_calls.append(kwargs)
        return original_attr_or_record(attrs, attr, **kwargs)

    monkeypatch.setattr(test_hkdf_extended, "attr_or_record", _attr_or_record)
    C.set_mechanism("STALE_MECHANISM", "C_DeriveKey")

    test_hkdf_extended.TestHKDFData().test_hkdf_data_derive(_session("HKDF_DATA"))

    assert derive_attrs[CKA_CLASS] == CKO_DATA
    assert derive_attrs[CKA_VALUE_LEN] == 32
    assert read_requests == [[CKA_CLASS, CKA_VALUE]]
    assert len(attr_calls) == 2
    assert all(call["mechanism"] is None for call in attr_calls)
    assert all(call["inherit_mechanism"] is False for call in attr_calls)


def test_hkdf_data_malformed_class_and_value_are_aggregated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_hkdf_extended, "_create_base_key", lambda *_a, **_k: 91)
    monkeypatch.setattr(test_hkdf_extended, "_hkdf_data_derive", lambda *_a, **_k: 92)
    monkeypatch.setattr(
        test_hkdf_extended,
        "read_attributes",
        lambda *_a, **_k: {CKA_CLASS: CKO_SECRET_KEY, CKA_VALUE: b"short"},
    )
    monkeypatch.setattr(test_hkdf_extended, "destroy_quietly", lambda *_a: None)
    C.set_mechanism("STALE_MECHANISM", "C_DeriveKey")

    with pytest.raises(pytest.fail.Exception):
        test_hkdf_extended.TestHKDFData().test_hkdf_data_derive(_session("HKDF_DATA"))

    records = C.get_records()
    assert [record.detail["attribute"]["name"] for record in records if record.detail] == [
        "CKA_CLASS",
        "CKA_VALUE",
    ]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)
    assert all(record.detail["producer_operation"] == "C_DeriveKey" for record in records)
    assert all(record.detail["consumer_operation"] == "C_GetAttributeValue" for record in records)


def test_hkdf_data_setup_unexpected_ckr_is_not_xfailed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _create(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("unexpected create refusal", int(CKR_MECHANISM_INVALID))

    monkeypatch.setattr(test_hkdf_extended, "_create_base_key", _create)

    with pytest.raises(CkrAssertionError):
        test_hkdf_extended._create_hkdf_data_base_or_xfail(_session("HKDF_DATA"))


def test_hkdf_data_derive_unexpected_ckr_is_not_xfailed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_hkdf_extended, "_hkdf_data_derive", lambda *_a, **_k: 0)

    def _derive(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("unexpected derive refusal", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_hkdf_extended, "_hkdf_data_derive", _derive)

    with pytest.raises(CkrAssertionError):
        test_hkdf_extended._derive_hkdf_data_or_xfail(_session("HKDF_DATA"), 101, b"salt", b"info")


def test_hkdf_data_derive_zero_handle_is_hard_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_hkdf_extended, "_create_base_key", lambda *_a, **_k: 111)
    monkeypatch.setattr(test_hkdf_extended, "_hkdf_data_derive", lambda *_a, **_k: 0)
    monkeypatch.setattr(test_hkdf_extended, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        test_hkdf_extended.TestHKDFData().test_hkdf_data_derive(_session("HKDF_DATA"))

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_HKDF_DATA"
    assert record.spec_ref == "PKCS#11 v3.2 · C_DeriveKey · CKM_HKDF_DATA"
