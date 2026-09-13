"""Regression tests for the DES weak-key posture probe templates."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_VALUE_LEN,
    CKM_DES3_KEY_GEN,
    CKM_DES_KEY_GEN,
    CKR_FUNCTION_FAILED,
    CKR_KEY_SIZE_RANGE,
    CKR_OK,
)
from pkcs11_check.testcases.security import test_crypto_weakness as weakness


class _GenerateKeyCapture:
    """Minimal raw binding that records a C_GenerateKey template."""

    def __init__(self, key_value: int = 123) -> None:
        self.key_value = key_value
        self.mechanism: int | None = None
        self.attribute_types: list[int] = []

    def C_GenerateKey(  # noqa: N802
        self,
        _session: int,
        mechanism: Any,
        template: Any,
        count: int,
        key: Any,
    ) -> int:
        self.mechanism = int(mechanism._obj.mechanism)
        self.attribute_types = [int(template[index].type) for index in range(count)]
        ctypes.cast(key, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self.key_value
        return CKR_OK


@pytest.mark.parametrize("mechanism", [CKM_DES_KEY_GEN, CKM_DES3_KEY_GEN])
def test_des_weak_key_probe_uses_fixed_size_template_without_value_len(
    mechanism: int,
) -> None:
    """DES key-generation mechanisms must not receive an AES-sized value length."""
    raw = _GenerateKeyCapture()

    key = weakness._generate_fixed_des_key(raw, 7, mechanism)

    assert key == 123
    assert raw.mechanism == int(mechanism)
    assert CKA_VALUE_LEN not in raw.attribute_types


def test_fixed_des_refusal_is_a_structured_not_operational_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid DES keygen refusal remains visible with exact operation metadata."""
    refusal = CkrAssertionError("key generation refused", int(CKR_FUNCTION_FAILED))
    monkeypatch.setattr(
        weakness,
        "_generate_fixed_des_key",
        lambda *_args: (_ for _ in ()).throw(refusal),
    )
    monkeypatch.setattr(weakness, "note", lambda *_args, **_kwargs: pytest.fail("note reached"))
    session = SimpleNamespace(raw=object(), sh=7, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.xfail.Exception):
        weakness.TestWeakKeySizeAcceptance().test_weak_key_size_acceptance(
            session,
            "DES_ECB",
            "DES_KEY_GEN",
            56,
            "DES fixed 8-byte key (56 effective key bits, inherent to DES)",
        )

    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_DES_KEY_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_aes_invalid_size_refusal_remains_a_plain_posture_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES-64's deliberate invalid-size rejection is not a provider xfail."""
    refusal = CkrAssertionError("key size refused", int(CKR_KEY_SIZE_RANGE))
    monkeypatch.setattr(
        weakness,
        "gen_aes_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(refusal),
    )
    session = SimpleNamespace(raw=object(), sh=7, has_mechanism=lambda _name: True)

    weakness.TestWeakKeySizeAcceptance().test_weak_key_size_acceptance(
        session,
        "AES_ECB",
        "AES_KEY_GEN",
        64,
        "AES with 64-bit key",
    )

    assert classification.get_records() == []


def test_zero_des_key_handle_is_a_lifecycle_failure_before_posture_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_OK with no generated handle is a provider self-contradiction."""
    raw = _GenerateKeyCapture(key_value=0)
    monkeypatch.setattr(weakness, "note", lambda *_args, **_kwargs: pytest.fail("note reached"))
    monkeypatch.setattr(weakness, "destroy_quietly", lambda *_args, **_kwargs: None)
    session = SimpleNamespace(raw=raw, sh=7, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.fail.Exception):
        weakness.TestWeakKeySizeAcceptance().test_weak_key_size_acceptance(
            session,
            "DES3_ECB",
            "DES3_KEY_GEN",
            168,
            "3DES fixed 24-byte key (168 keying bits; approximately 112-bit effective strength)",
        )

    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_DES3_KEY_GEN"
    assert record.actual_ckr == "CKR_OK"


@pytest.mark.parametrize(
    ("mech_name", "keygen_name", "bits", "description", "mechanism"),
    [
        (
            "DES_ECB",
            "DES_KEY_GEN",
            56,
            "DES fixed 8-byte key (56 effective key bits, inherent to DES)",
            CKM_DES_KEY_GEN,
        ),
        (
            "DES3_ECB",
            "DES3_KEY_GEN",
            168,
            "3DES fixed 24-byte key (168 keying bits; approximately 112-bit effective strength)",
            CKM_DES3_KEY_GEN,
        ),
    ],
)
def test_des_product_node_does_not_route_through_aes_keygen(
    monkeypatch: pytest.MonkeyPatch,
    mech_name: str,
    keygen_name: str,
    bits: int,
    description: str,
    mechanism: int,
) -> None:
    """The DES product node must exercise its fixed-size generator directly."""
    raw = _GenerateKeyCapture()
    monkeypatch.setattr(
        weakness,
        "gen_aes_key",
        lambda *_args, **_kwargs: pytest.fail("DES probe used the AES key generator"),
    )
    monkeypatch.setattr(weakness, "note", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(weakness, "destroy_quietly", lambda *_args, **_kwargs: None)
    session = SimpleNamespace(raw=raw, sh=7, has_mechanism=lambda _name: True)

    weakness.TestWeakKeySizeAcceptance().test_weak_key_size_acceptance(
        session,
        mech_name,
        keygen_name,
        bits,
        description,
    )

    assert raw.mechanism == int(mechanism)
    assert CKA_VALUE_LEN not in raw.attribute_types
