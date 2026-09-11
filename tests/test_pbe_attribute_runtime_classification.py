"""Runtime regressions for PBE provider attribute readback classification."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_KEY_TYPE, CKA_VALUE, CKK_GENERIC_SECRET
from pkcs11_check.testcases import test_pbe as pbe
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_missing_key_type_is_structured_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pbe, "_pbe_gen_key", lambda *_args, **_kwargs: (7, object()))
    monkeypatch.setattr(pbe, "read_attributes", lambda *_args, **_kwargs: {})
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    pbe.TestPBESHA1DES3().test_generate_key(_rs("PBE_SHA1_DES3_EDE_CBC"))

    assert destroyed == [7]
    records = C.get_records()
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_PBE_SHA1_DES3_EDE_CBC" in records[0].label
    assert records[0].detail == {"attribute": {"name": "CKA_KEY_TYPE", "id": int(CKA_KEY_TYPE)}}
    assert all(record.reason != "unclassified" for record in records)
    assert MISSING_ATTRIBUTE is not False


def test_zero_init_vector_is_generate_key_output_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mechanism = SimpleNamespace(buffer_bytes=lambda _name: bytes(8))
    monkeypatch.setattr(pbe, "_pbe_gen_key", lambda *_args, **_kwargs: (7, mechanism))
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        pbe.TestPBESHA1DES3().test_generate_key_writes_init_vector(_rs("PBE_SHA1_DES3_EDE_CBC"))

    assert destroyed == [7]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_PBE_SHA1_DES3_EDE_CBC"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail == {
        "parameter": {
            "name": "pInitVector",
            "expected": "non-zero IV",
            "actual": repr(bytes(8)),
        }
    }


def test_false_like_key_type_is_present_structured_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pbe, "_pbe_gen_key", lambda *_args, **_kwargs: (7, object()))
    monkeypatch.setattr(pbe, "read_attributes", lambda *_args, **_kwargs: {CKA_KEY_TYPE: False})
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        pbe.TestPBESHA1DES3().test_generate_key(_rs("PBE_SHA1_DES3_EDE_CBC"))

    assert destroyed == [7]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(False)
    assert all(item.reason != "unclassified" for item in C.get_records())


def test_honest_generic_pba_key_type_preserves_provider_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pbe, "_pbe_gen_key", lambda *_args, **_kwargs: (7, object()))
    monkeypatch.setattr(
        pbe,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_KEY_TYPE: CKK_GENERIC_SECRET},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.xfail.Exception):
        pbe.TestPBASHA1().test_generate_key(_rs("PBA_SHA1_WITH_SHA1_HMAC"))

    assert destroyed == [7]
    record = C.get_records()[0]
    assert record.reason == "honest_deviation"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(CKK_GENERIC_SECRET)
    assert all(item.reason != "unclassified" for item in C.get_records())


@pytest.mark.parametrize("value", [False, 0, b"", None], ids=["false", "zero", "empty", "none"])
def test_malformed_derived_value_is_structured_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(pbe, "_pbkdf2_gen_key", lambda *_args, **_kwargs: 8)
    monkeypatch.setattr(pbe, "read_attributes", lambda *_args, **_kwargs: {CKA_VALUE: value})
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        pbe.TestPKCS5PBKD2().test_derive_generic_secret_sha256(_rs("PKCS5_PBKD2"))

    assert destroyed == [8]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(value)
    assert all(item.reason != "unclassified" for item in C.get_records())


def test_missing_key_type_does_not_hide_wrong_value_and_crypto_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pbe, "_pbkdf2_gen_key", lambda *_args, **_kwargs: 9)
    monkeypatch.setattr(pbe, "read_attributes", lambda *_args, **_kwargs: {CKA_VALUE: b"short"})
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        pbe.TestPKCS5PBKD2().test_derive_aes_key(_rs("PKCS5_PBKD2"))

    assert destroyed == [9]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[1].kind == "crypto"
    assert records[1].detail is not None
    assert records[1].detail["attribute"]["actual"] == repr(b"short")
    assert all(record.reason != "unclassified" for record in records)


def test_wrong_key_type_and_value_collect_before_cleanup_and_raise_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pbe, "_pbkdf2_gen_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(
        pbe,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_KEY_TYPE: 999, CKA_VALUE: b"short"},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        pbe.TestPKCS5PBKD2().test_derive_aes_key(_rs("PKCS5_PBKD2"))

    assert destroyed == [10]
    records = C.get_records()
    assert [record.kind for record in records] == ["metadata", "crypto"]
    assert records[-1].detail is not None
    assert records[-1].detail["attribute"]["actual"] == repr(b"short")
    assert all(record.reason != "unclassified" for record in records)


def test_deterministic_mismatch_is_crypto_failure_after_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, object()), (12, object())])
    monkeypatch.setattr(pbe, "_pbe_gen_key", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        pbe,
        "read_attributes",
        lambda _raw, _sh, handle, _names: {CKA_VALUE: b"one" if handle == 11 else b"two"},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        pbe.TestPBESHA1DES3().test_generate_key_deterministic(_rs("PBE_SHA1_DES3_EDE_CBC"))

    assert destroyed == [11, 12]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(b"one")
    assert all(item.reason != "unclassified" for item in C.get_records())


def test_second_pbe_generation_failure_cleans_first_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _generate(*_args: Any, **_kwargs: Any) -> tuple[int, object]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("second generation failed")
        return 11, object()

    monkeypatch.setattr(pbe, "_pbe_gen_key", _generate)
    destroyed: list[int] = []
    monkeypatch.setattr(pbe, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="second generation failed"):
        pbe.TestPBESHA1DES3().test_generate_key_deterministic(_rs("PBE_SHA1_DES3_EDE_CBC"))

    assert destroyed == [11]
