"""Regression tests for strict DES CBC derive readback and setup attribution."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_DES_CBC_ENCRYPT_DATA,
    CKO_SECRET_KEY,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_des_kdf as ddk
from pkcs11_check.testcases import test_mech_derive as tmd


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def _attrs(value: Any = ddk._DES_EXPECTED_FULL) -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: len(ddk._DES_EXPECTED_FULL),
        CKA_VALUE: value,
    }


def test_static_oracle_constants_match_independent_cipher_oracle() -> None:
    assert ddk._cbc_oracle(ddk._DES_KEY, ddk._IV, ddk._DATA) == ddk._DES_EXPECTED_FULL
    assert ddk._DES_EXPECTED_FULL[:8] == ddk._DES_EXPECTED_TRUNCATED
    assert ddk._cbc_oracle(ddk._DES3_KEY, ddk._IV, ddk._DATA) == ddk._DES3_EXPECTED_FULL
    assert ddk._DES3_EXPECTED_FULL[:8] == ddk._DES3_EXPECTED_TRUNCATED

    components = [ddk._DES3_KEY[offset : offset + 8] for offset in range(0, 24, 8)]
    assert len(set(components)) == 3
    assert all(all(byte.bit_count() % 2 == 1 for byte in component) for component in components)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_class",
        "wrong_class",
        "malformed_class",
        "missing_key_type",
        "wrong_key_type",
        "malformed_key_type",
        "missing_value_len",
        "wrong_value_len",
        "malformed_value_len",
        "missing_value",
        "malformed_value",
        "wrong_value",
    ],
)
def test_kat_readback_mutations_are_hard_failures(mutation: str) -> None:
    attrs = _attrs()
    if mutation == "missing_class":
        del attrs[CKA_CLASS]
    elif mutation == "wrong_class":
        attrs[CKA_CLASS] = 0
    elif mutation == "malformed_class":
        attrs[CKA_CLASS] = True
    elif mutation == "missing_key_type":
        del attrs[CKA_KEY_TYPE]
    elif mutation == "wrong_key_type":
        attrs[CKA_KEY_TYPE] = 0
    elif mutation == "malformed_key_type":
        attrs[CKA_KEY_TYPE] = "CKK_GENERIC_SECRET"
    elif mutation == "missing_value_len":
        del attrs[CKA_VALUE_LEN]
    elif mutation == "wrong_value_len":
        attrs[CKA_VALUE_LEN] = 8
    elif mutation == "malformed_value_len":
        attrs[CKA_VALUE_LEN] = False
    elif mutation == "missing_value":
        del attrs[CKA_VALUE]
    elif mutation == "malformed_value":
        attrs[CKA_VALUE] = bytearray(ddk._DES_EXPECTED_FULL)
    elif mutation == "wrong_value":
        attrs[CKA_VALUE] = b"wrong-value".ljust(len(ddk._DES_EXPECTED_FULL), b"!")
    else:
        raise AssertionError(mutation)

    with pytest.raises(pytest.fail.Exception):
        ddk._validate_kat_derived_attributes(
            attrs,
            expected_value=ddk._DES_EXPECTED_FULL,
            expected_length=len(ddk._DES_EXPECTED_FULL),
            mechanism_name="CKM_DES_CBC_ENCRYPT_DATA",
        )

    record = C.get_records()[-1]
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.reason in {"wrong_result", "oracle"}


@pytest.mark.parametrize(
    ("actual", "reason"),
    [
        (ddk._DES_EXPECTED_FULL[8:], "oracle"),
        (ddk._DES_EXPECTED_FULL[:8] + b"!" * 8, "wrong_result"),
    ],
)
def test_kat_rejects_trailing_ciphertext_as_truncated_output(actual: bytes, reason: str) -> None:
    attrs = _attrs(actual)
    attrs[CKA_VALUE_LEN] = 8
    with pytest.raises(pytest.fail.Exception):
        ddk._validate_kat_derived_attributes(
            attrs,
            expected_value=ddk._DES_EXPECTED_TRUNCATED,
            expected_length=8,
            mechanism_name="CKM_DES_CBC_ENCRYPT_DATA",
        )
    assert C.get_records()[-1].reason == reason


def _session() -> Any:
    return SimpleNamespace(raw=SimpleNamespace(), sh=1, has_mechanism=lambda _name: True)


def test_generic_cipher_base_keygen_refusal_names_generate_operation() -> None:
    raw = SimpleNamespace(C_GenerateKey=lambda *_args, **_kwargs: int(CKR_MECHANISM_INVALID))
    rs = SimpleNamespace(raw=raw, sh=1)
    case = tmd._CIPHER_ENCRYPT_DATA_DERIVE_CASES[int(CKM_DES_CBC_ENCRYPT_DATA)]

    with pytest.raises(pytest.xfail.Exception):
        tmd._gen_cipher_encrypt_data_base_key(rs, case)

    record = C.get_records()[-1]
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_DES_KEY_GEN"
    assert record.actual_ckr == "CKR_MECHANISM_INVALID"


def test_generic_cipher_zero_base_handle_is_lifecycle_failure() -> None:
    def _generate(*args: Any, **_kwargs: Any) -> int:
        args[-1]._obj.value = 0
        return int(CKR_OK)

    raw = SimpleNamespace(C_GenerateKey=_generate)
    rs = SimpleNamespace(raw=raw, sh=1)
    case = tmd._CIPHER_ENCRYPT_DATA_DERIVE_CASES[int(CKM_DES_CBC_ENCRYPT_DATA)]

    with pytest.raises(pytest.fail.Exception):
        tmd._gen_cipher_encrypt_data_base_key(rs, case)

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_DES_KEY_GEN"


def test_kat_zero_import_handle_is_lifecycle_failure_without_derive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_calls: list[Any] = []
    monkeypatch.setattr(ddk, "import_secret_key_negotiated", lambda *_a, **_k: 0)
    monkeypatch.setattr(ddk, "derive_key", lambda *_a, **_k: derive_calls.append(1))

    with pytest.raises(pytest.fail.Exception):
        ddk.test_des_cbc_encrypt_data_derive_matches_oracle_and_truncates(
            _session(),
            "CKM_DES_CBC_ENCRYPT_DATA",
            CKM_DES_CBC_ENCRYPT_DATA,
            ddk.CKK_DES,
            ddk._DES_KEY,
            ddk._DES_EXPECTED_FULL,
            ddk._DES_EXPECTED_TRUNCATED,
        )

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.operation == "C_CreateObject"
    assert record.mechanism is None
    assert derive_calls == []


def test_kat_provisioning_refusal_is_create_object_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = CkrAssertionError("fixed key rejected", int(CKR_MECHANISM_INVALID))
    monkeypatch.setattr(
        ddk,
        "import_secret_key_negotiated",
        lambda *_a, **_k: (_ for _ in ()).throw(refusal),
    )

    with pytest.raises(pytest.xfail.Exception):
        ddk.test_des_cbc_encrypt_data_derive_matches_oracle_and_truncates(
            _session(),
            "CKM_DES_CBC_ENCRYPT_DATA",
            CKM_DES_CBC_ENCRYPT_DATA,
            ddk.CKK_DES,
            ddk._DES_KEY,
            ddk._DES_EXPECTED_FULL,
            ddk._DES_EXPECTED_TRUNCATED,
        )

    record = C.get_records()[-1]
    assert record.operation == "C_CreateObject"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["consumer_mechanism"] == "CKM_DES_CBC_ENCRYPT_DATA"


def test_kat_derive_failure_still_cleans_up_base_and_prior_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroy_calls: list[int] = []
    derive_calls: list[int] = []

    monkeypatch.setattr(ddk, "import_secret_key_negotiated", lambda *_a, **_k: 9)

    def _derive(*_args: Any, **_kwargs: Any) -> int:
        derive_calls.append(1)
        if len(derive_calls) == 1:
            return 101
        raise CkrAssertionError("truncation probe rejected", int(CKR_MECHANISM_INVALID))

    monkeypatch.setattr(ddk, "derive_key", _derive)
    monkeypatch.setattr(
        ddk, "destroy_quietly", lambda _raw, _sh, handle: destroy_calls.append(handle)
    )
    monkeypatch.setattr(ddk, "read_attributes", lambda *_a, **_k: _attrs())

    with pytest.raises(pytest.xfail.Exception):
        ddk.test_des_cbc_encrypt_data_derive_matches_oracle_and_truncates(
            _session(),
            "CKM_DES_CBC_ENCRYPT_DATA",
            CKM_DES_CBC_ENCRYPT_DATA,
            ddk.CKK_DES,
            ddk._DES_KEY,
            ddk._DES_EXPECTED_FULL,
            ddk._DES_EXPECTED_TRUNCATED,
        )

    assert derive_calls == [1, 1]
    assert destroy_calls == [101, 9]
    record = C.get_records()[-1]
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_DES_CBC_ENCRYPT_DATA"
    assert record.outcome == "xfail"
