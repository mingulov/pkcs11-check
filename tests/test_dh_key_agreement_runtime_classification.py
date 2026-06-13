"""Regression tests for classic DH runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_DH_PKCS_DERIVE,
    CKO_SECRET_KEY,
    CKR_DEVICE_ERROR,
    CKR_KEY_SIZE_RANGE,
)
from pkcs11_check.testcases import test_dh_key_agreement as dh


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"DH_PKCS_KEY_PAIR_GEN", "DH_PKCS_DERIVE"},
    )


def test_dh_derive_clean_runtime_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    public_values = {
        11: b"\x02",
        12: b"\x03",
    }

    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_args, **_kwargs: next(keypairs))
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: public_values[handle]},
    )
    monkeypatch.setattr(dh, "derive_key", _derive_reject)
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="DH derive advertised"):
        dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())


def test_dh_rfc3526_group14_exact_vector_constant_matches_modexp() -> None:
    """The embedded DH exact-vector expected value is the rightmost derived secret bytes."""
    prime = int.from_bytes(dh.DH_PRIME_2048, "big")
    generator = int.from_bytes(dh.DH_GEN, "big")
    alice_private = int.from_bytes(dh._DH_RFC3526_GROUP14_ALICE_PRIVATE, "big")
    bob_public = int.from_bytes(dh._DH_RFC3526_GROUP14_BOB_PUBLIC, "big")

    assert pow(generator, alice_private, prime) != bob_public

    full_secret = pow(bob_public, alice_private, prime).to_bytes(len(dh.DH_PRIME_2048), "big")
    assert full_secret[-32:] == dh._DH_RFC3526_GROUP14_EXPECTED_SECRET_32


def test_dh_rfc3526_group14_value_len_truncation_uses_rightmost_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derived_values = {
        501: dh._DH_RFC3526_GROUP14_EXPECTED_SECRET_32,
        502: dh._DH_RFC3526_GROUP14_EXPECTED_SECRET_32[-16:],
    }
    handles_by_len = {32: 501, 16: 502}
    derive_calls: list[dict[str, Any]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        private_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "private_key": private_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        return handles_by_len[attrs[CKA_VALUE_LEN]]

    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_args: 301)
    monkeypatch.setattr(dh, "derive_key", _derive_key)
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: derived_values[handle]},
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)

    dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_value_len_truncation(
        _session()
    )

    assert [call["attrs"][CKA_VALUE_LEN] for call in derive_calls] == [32, 16]
    assert {call["private_key"] for call in derive_calls} == {301}
    assert {call["mechanism"] for call in derive_calls} == {int(CKM_DH_PKCS_DERIVE)}


def test_dh_rfc3526_group14_zero_value_len_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_attrs: list[dict[int, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _private_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_attrs.append(attrs)
        raise CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))

    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_args: 301)
    monkeypatch.setattr(dh, "derive_key", _derive_reject)
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)

    dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len(
        _session()
    )

    assert derive_attrs == [
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE_LEN: 0,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_TOKEN: False,
        }
    ]
