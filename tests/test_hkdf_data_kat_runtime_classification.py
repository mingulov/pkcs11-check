"""Runtime classification regressions for the strict RFC5869 HKDF_DATA KAT."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_hkdf_data_kat as kat


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session(*, advertised: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: advertised and name == "HKDF_DATA",
    )


def test_rfc5869_sha256_oracle_is_fixed_and_independent() -> None:
    assert kat._rfc5869_sha256_okm() == kat.RFC5869_OKM
    assert len(kat.RFC5869_OKM) == 42


def test_missing_hkdf_data_mechanism_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.skip.Exception, match="HKDF_DATA not supported"):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session(advertised=False))


def test_base_provisioning_refusal_is_xfail_with_consumer_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("base import refused", int(CKR_TEMPLATE_INCONSISTENT))

    monkeypatch.setattr(kat, "import_secret_key_negotiated", _import)

    with pytest.raises(pytest.xfail.Exception, match="base-key provisioning"):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    record = C.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.operation == "C_CreateObject"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["consumer_operation"] == "C_DeriveKey"
    assert record.detail["consumer_mechanism"] == "CKM_HKDF_DATA"


def test_unexpected_base_provisioning_ckr_is_not_xfailed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        kat,
        "import_secret_key_negotiated",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected create refusal", int(CKR_MECHANISM_INVALID))
        ),
    )

    with pytest.raises(CkrAssertionError):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())


def test_base_readback_missing_is_xfail_with_mechanism_free_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 11)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda *_a, **_k: {CKA_CLASS: 4, CKA_KEY_TYPE: CKK_GENERIC_SECRET},
    )
    monkeypatch.setattr(kat, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.xfail.Exception, match="base-key CKA_VALUE readback"):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    assert destroyed == [11]
    record = C.get_records()[-1]
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["producer_operation"] == "C_CreateObject"
    assert record.detail["producer_mechanism"] is None
    assert record.detail["consumer_operation"] == "C_DeriveKey"
    assert record.detail["consumer_mechanism"] == "CKM_HKDF_DATA"


def test_base_readback_ckr_is_not_reclassified_as_derive_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 15)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected readback refusal", int(CKR_TEMPLATE_INCONSISTENT))
        ),
    )
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(CkrAssertionError, match="unexpected readback refusal"):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())


def test_derive_refusal_is_xfail_and_cleans_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 21)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_CLASS: 4,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: kat.RFC5869_IKM,
        },
    )
    monkeypatch.setattr(
        kat,
        "derive_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("derive refused", int(CKR_MECHANISM_INVALID))
        ),
    )
    monkeypatch.setattr(kat, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.xfail.Exception, match="C_DeriveKey"):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    assert destroyed == [21]
    record = C.get_records()[-1]
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_HKDF_DATA"


def test_unexpected_derive_ckr_is_not_xfailed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 25)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_CLASS: 4,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: kat.RFC5869_IKM,
        },
    )
    monkeypatch.setattr(
        kat,
        "derive_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected derive refusal", int(CKR_GENERAL_ERROR))
        ),
    )
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(CkrAssertionError):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())


def test_zero_derived_handle_is_hard_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 31)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_CLASS: 4,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: kat.RFC5869_IKM,
        },
    )
    monkeypatch.setattr(kat, "derive_key", lambda *_a, **_k: 0)
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_HKDF_DATA"


def test_wrong_class_is_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 41)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: (
            {CKA_CLASS: 4, CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: kat.RFC5869_IKM}
            if handle == 41
            else {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_VALUE: kat.RFC5869_OKM,
            }
        ),
    )
    monkeypatch.setattr(kat, "derive_key", lambda *_a, **_k: 42)
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)
    C.set_mechanism("STALE_MECHANISM", "C_DeriveKey")

    with pytest.raises(pytest.fail.Exception):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert record.detail is not None
    assert record.detail["producer_operation"] == "C_DeriveKey"


def test_wrong_value_length_is_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 51)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: (
            {CKA_CLASS: 4, CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: kat.RFC5869_IKM}
            if handle == 51
            else {
                CKA_CLASS: CKO_DATA,
                CKA_VALUE: b"short",
            }
        ),
    )
    monkeypatch.setattr(kat, "derive_key", lambda *_a, **_k: 52)
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None


def test_wrong_exact_value_is_hard_oracle_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 71)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: (
            {CKA_CLASS: 4, CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: kat.RFC5869_IKM}
            if handle == 71
            else {
                CKA_CLASS: CKO_DATA,
                CKA_VALUE: bytes(len(kat.RFC5869_OKM)),
            }
        ),
    )
    monkeypatch.setattr(kat, "derive_key", lambda *_a, **_k: 72)
    monkeypatch.setattr(kat, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    assert destroyed == [72, 71]
    record = C.get_records()[-1]
    assert record.reason == "oracle"
    assert record.kind == "crypto"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["producer_operation"] == "C_DeriveKey"
    assert record.detail["consumer_operation"] == "C_GetAttributeValue"


def test_missing_class_does_not_hide_wrong_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 61)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: (
            {CKA_CLASS: 4, CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: kat.RFC5869_IKM}
            if handle == 61
            else {
                # Omit CKA_CLASS to keep the missing-class signal independent.
                CKA_VALUE: b"short",
            }
        ),
    )
    monkeypatch.setattr(kat, "derive_key", lambda *_a, **_k: 62)
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    records = C.get_records()
    assert any(record.reason == "not_operational" for record in records)
    assert records[-1].reason == "wrong_result"
    assert records[-1].kind == "metadata"


def test_kat_aggregates_all_present_malformed_output_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 81)
    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: (
            {CKA_CLASS: 4, CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: kat.RFC5869_IKM}
            if handle == 81
            else {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_VALUE: b"short",
            }
        ),
    )
    monkeypatch.setattr(kat, "derive_key", lambda *_a, **_k: 82)
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert [record.detail["attribute"]["name"] for record in records if record.detail] == [
        "CKA_CLASS",
        "CKA_VALUE",
    ]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)


def test_kat_readback_never_inherits_stale_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kat, "import_secret_key_negotiated", lambda *_a, **_k: 91)
    read_requests: list[list[int]] = []

    monkeypatch.setattr(
        kat,
        "read_attributes",
        lambda _raw, _sh, handle, attrs: (
            read_requests.append(attrs)
            or (
                {CKA_CLASS: 4, CKA_KEY_TYPE: CKK_GENERIC_SECRET, CKA_VALUE: kat.RFC5869_IKM}
                if handle == 91
                else {
                    CKA_CLASS: CKO_DATA,
                    CKA_VALUE: kat.RFC5869_OKM,
                }
            )
        ),
    )
    monkeypatch.setattr(kat, "derive_key", lambda *_a, **_k: 92)
    monkeypatch.setattr(kat, "destroy_quietly", lambda *_a, **_k: None)
    attr_calls: list[dict[str, Any]] = []
    original_attr_or_record = kat.attr_or_record

    def _attr_or_record(attrs: dict[int, Any], attr: int, **kwargs: Any) -> Any:
        attr_calls.append(kwargs)
        return original_attr_or_record(attrs, attr, **kwargs)

    monkeypatch.setattr(kat, "attr_or_record", _attr_or_record)
    C.set_mechanism("STALE_MECHANISM", "C_DeriveKey")

    kat.TestHKDFDataKAT().test_rfc5869_sha256(_session())

    assert len(attr_calls) == 5
    assert all(call["mechanism"] is None for call in attr_calls)
    assert all(call["inherit_mechanism"] is False for call in attr_calls)
    assert read_requests == [[CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE], [CKA_CLASS, CKA_VALUE]]


def test_kat_marker_and_selector_metadata() -> None:
    marks = kat.pytestmark if isinstance(kat.pytestmark, list) else [kat.pytestmark]
    assert {mark.name for mark in marks} >= {"kat", "keymgmt"}
    assert kat.REQUIRED_MECHANISMS == ["HKDF_DATA"]
