"""Runtime classification regressions for generic CKM_HKDF_DATA coverage."""

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
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_HKDF_DATA,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_OPERATION_NOT_VALIDATED,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import _capability_claims, test_mech_derive
from pkcs11_check.testcases.mechanism_catalog import MechEntry


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _entry() -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_HKDF_DATA),
        mech_name="CKM_HKDF_DATA",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=object(),
    )


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
    )


def _patch_hkdf_data(
    monkeypatch: pytest.MonkeyPatch,
    *,
    attrs: dict[int, Any],
    derived: int = 22,
) -> dict[str, Any]:
    calls: dict[str, Any] = {}
    monkeypatch.setattr(test_mech_derive, "_create_hkdf_data_base_key", lambda _rs: 11)

    def _derive(*_args: Any, **kwargs: Any) -> int:
        calls["attrs"] = kwargs["attrs"]
        return derived

    monkeypatch.setattr(test_mech_derive, "derive_key", _derive)

    def _read(*args: Any, **_kwargs: Any) -> dict[int, Any]:
        calls["read_attrs"] = args[-1]
        return attrs

    monkeypatch.setattr(
        test_mech_derive,
        "read_attributes",
        _read,
    )
    monkeypatch.setattr(
        test_mech_derive,
        "destroy_quietly",
        lambda *_args, **_kwargs: None,
    )
    return calls


def test_advertised_hkdf_data_is_dispatched_instead_of_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[MechEntry] = []
    monkeypatch.setattr(test_mech_derive, "_derive_hkdf", lambda _rs, entry: called.append(entry))

    test_mech_derive.TestMechDerive().test_derive_produces_key(_session(), _entry())

    assert len(called) == 1
    assert called[0].mech_id == int(CKM_HKDF_DATA)


def test_hkdf_data_base_key_is_generic_secret_and_does_not_need_hkdf_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, Any] = {}

    def _import(*args: Any, **kwargs: Any) -> int:
        calls["args"] = args
        calls["kwargs"] = kwargs
        return 12

    monkeypatch.setattr(test_mech_derive, "import_secret_key_negotiated", _import)

    assert test_mech_derive._create_hkdf_data_base_key(_session()) == 12
    assert calls["args"][1] == CKK_GENERIC_SECRET
    assert calls["args"][2] == bytes(range(32))
    assert calls["kwargs"]["attrs"] == {
        CKA_DERIVE: True,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
    }


def test_hkdf_data_base_key_refusal_is_setup_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("create refused", int(CKR_TEMPLATE_INCONSISTENT))

    monkeypatch.setattr(test_mech_derive, "import_secret_key_negotiated", _import)

    with pytest.raises(pytest.xfail.Exception, match="base-key provisioning"):
        test_mech_derive._create_hkdf_data_base_key(_session())

    record = C.get_records()[-1]
    assert record.operation == "C_CreateObject"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_CreateObject"
    assert record.detail == {
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
        "consumer_operation": "C_DeriveKey",
        "consumer_mechanism": "CKM_HKDF_DATA",
    }


def test_hkdf_data_base_key_zero_is_hard_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_mech_derive, "import_secret_key_negotiated", lambda *_a, **_k: 0)

    with pytest.raises(pytest.fail.Exception):
        test_mech_derive._create_hkdf_data_base_key(_session())

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_CreateObject"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_CreateObject"


def test_hkdf_data_unexpected_setup_ckr_propagates_before_derive_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_mech_derive,
        "_create_hkdf_data_base_key",
        lambda _rs: (_ for _ in ()).throw(
            CkrAssertionError("unexpected create refusal", int(CKR_GENERAL_ERROR))
        ),
    )

    with pytest.raises(CkrAssertionError, match="unexpected create refusal"):
        test_mech_derive._derive_hkdf(_session(), _entry())

    assert C.get_records() == []


def test_hkdf_data_derive_refusal_has_exact_operation_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_mech_derive, "_create_hkdf_data_base_key", lambda _rs: 14)

    def _derive(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("derive refused", int(CKR_MECHANISM_INVALID))

    monkeypatch.setattr(test_mech_derive, "derive_key", _derive)
    monkeypatch.setattr(test_mech_derive, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(pytest.xfail.Exception, match="CKM_HKDF_DATA:derive"):
        test_mech_derive.TestMechDerive().test_derive_produces_key(_session(), _entry())

    record = C.get_records()[-1]
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_HKDF_DATA"
    assert record.spec_ref == "PKCS#11 v3.2 · C_DeriveKey · CKM_HKDF_DATA"
    assert record.detail == {
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
        "consumer_operation": "C_DeriveKey",
        "consumer_mechanism": "CKM_HKDF_DATA",
    }


def test_hkdf_derive_base_key_zero_is_hard_c_generate_key_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = MechEntry(
        mech_id=test_mech_derive._HKDF_DERIVE_ID,
        mech_name="CKM_HKDF_DERIVE",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=object(),
    )
    monkeypatch.setattr(test_mech_derive, "_gen_hkdf_base_key", lambda _rs: 0)

    with pytest.raises(pytest.fail.Exception):
        test_mech_derive._derive_hkdf(_session(), entry)

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_HKDF_KEY_GEN"
    assert record.spec_ref == "PKCS#11 v3.2 · C_GenerateKey · CKM_HKDF_KEY_GEN"
    assert record.detail == {
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_HKDF_KEY_GEN",
        "consumer_operation": "C_DeriveKey",
        "consumer_mechanism": "CKM_HKDF_DERIVE",
    }


def test_hkdf_data_requests_and_validates_cko_data_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"x" * 32
    calls = _patch_hkdf_data(
        monkeypatch,
        attrs={CKA_CLASS: CKO_DATA, CKA_VALUE: expected},
    )

    test_mech_derive._derive_hkdf(_session(), _entry())

    assert calls["attrs"][CKA_CLASS] == CKO_DATA
    assert calls["attrs"][CKA_VALUE_LEN] == len(expected)
    assert calls["read_attrs"] == [CKA_CLASS, CKA_VALUE]


def test_hkdf_data_wrong_class_is_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_hkdf_data(
        monkeypatch,
        attrs={CKA_CLASS: CKO_SECRET_KEY, CKA_VALUE: b"x" * 32},
    )

    with pytest.raises(pytest.fail.Exception):
        test_mech_derive._derive_hkdf(_session(), _entry())

    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["producer_operation"] == "C_DeriveKey"
    assert record.detail["producer_mechanism"] == "CKM_HKDF_DATA"


def test_hkdf_data_wrong_value_length_is_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_hkdf_data(
        monkeypatch,
        attrs={CKA_CLASS: CKO_DATA, CKA_VALUE: b"x" * 31},
    )

    with pytest.raises(pytest.fail.Exception):
        test_mech_derive._derive_hkdf(_session(), _entry())

    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["attribute"]["name"] == "CKA_VALUE"
    assert record.detail["actual"]["length"] == 31


def test_hkdf_data_aggregates_present_malformed_attributes_before_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_hkdf_data(
        monkeypatch,
        attrs={CKA_CLASS: CKO_SECRET_KEY, CKA_VALUE: b"short"},
    )

    with pytest.raises(pytest.fail.Exception):
        test_mech_derive._derive_hkdf(_session(), _entry())

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert [record.detail["attribute"]["name"] for record in records if record.detail] == [
        "CKA_CLASS",
        "CKA_VALUE",
    ]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)


def test_hkdf_data_zero_handle_is_hard_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_hkdf_data(monkeypatch, attrs={}, derived=0)

    with pytest.raises(pytest.fail.Exception):
        test_mech_derive._derive_hkdf(_session(), _entry())

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_HKDF_DATA"


def test_advertised_hkdf_data_clean_derive_refusal_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_mech_derive, "_create_hkdf_data_base_key", lambda _rs: 11)

    def _derive(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("HKDF_DATA refused", int(CKR_MECHANISM_INVALID))

    monkeypatch.setattr(test_mech_derive, "derive_key", _derive)
    monkeypatch.setattr(test_mech_derive, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        test_mech_derive.TestMechDerive().test_derive_produces_key(_session(), _entry())

    record = C.get_records()[-1]
    assert record.reason == "not_operational"


def test_hkdf_data_sanctioned_refusal_stays_in_claim_layer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_mech_derive, "_create_hkdf_data_base_key", lambda _rs: 11)

    def _derive(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("validation policy", int(CKR_OPERATION_NOT_VALIDATED))

    monkeypatch.setattr(test_mech_derive, "derive_key", _derive)
    monkeypatch.setattr(test_mech_derive, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(_capability_claims, "_validation_objects_present", lambda _rs: "False")
    C.set_mechanism("STALE_MECHANISM", "C_DeriveKey")

    test_mech_derive.TestMechDerive().test_derive_produces_key(_session(), _entry())

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "sanctioned_refusal"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_HKDF_DATA"
    assert record.spec_ref == "PKCS#11 v3.2 · C_DeriveKey · CKM_HKDF_DATA"
    assert record.detail == {
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
        "consumer_operation": "C_DeriveKey",
        "consumer_mechanism": "CKM_HKDF_DATA",
    }


def test_hkdf_data_missing_value_stays_advertised_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_hkdf_data(
        monkeypatch,
        attrs={CKA_CLASS: CKO_DATA},
    )
    C.set_mechanism("STALE_MECHANISM", "C_DeriveKey")

    test_mech_derive._derive_hkdf(_session(), _entry())

    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert records[0].detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "producer_operation": "C_DeriveKey",
        "producer_mechanism": "CKM_HKDF_DATA",
        "consumer_operation": "C_GetAttributeValue",
        "consumer_mechanism": None,
    }


def test_hkdf_data_readback_ckr_propagates_without_claim_layer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_mech_derive, "_create_hkdf_data_base_key", lambda _rs: 11)
    monkeypatch.setattr(test_mech_derive, "derive_key", lambda *_a, **_k: 22)
    monkeypatch.setattr(
        test_mech_derive,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected readback refusal", int(CKR_TEMPLATE_INCONSISTENT))
        ),
    )
    monkeypatch.setattr(test_mech_derive, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(CkrAssertionError, match="unexpected readback refusal"):
        test_mech_derive._derive_hkdf(_session(), _entry())

    assert C.get_records() == []
