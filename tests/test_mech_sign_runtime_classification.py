"""Regression tests for mechanism sign runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_AES,
    CKK_EC,
    CKM_AES_CMAC_GENERAL,
    CKM_ECDSA_SHA224,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import mechanism_vectors
from pkcs11_check.testcases import test_mech_sign as mech_sign
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe


def _aes_entry() -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_AES_CMAC_GENERAL),
        mech_name="AES_CMAC_GENERAL",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=MechConfig(
            key_type=int(CKK_AES),
            key_sizes=(128,),
            param_required=True,
            param_recipe=ParamRecipe("mac_general", {"mac_len": 8}),
            keygen_recipe=KeygenRecipe("symmetric"),
            vector_file="dummy.json",
        ),
    )


def _ec_entry() -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_ECDSA_SHA224),
        mech_name="ECDSA_SHA224",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(
            key_type=int(CKK_EC),
            is_keypair=True,
            keygen_recipe=KeygenRecipe("ec"),
            param_recipe=ParamRecipe("none"),
            vector_file="dummy.json",
        ),
    )


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def test_roundtrip_sign_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    monkeypatch.setattr(mech_sign, "generate_key_for_sign", lambda *_args: (1, None))
    monkeypatch.setattr(mech_sign, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_sign, "sign_single", _sign_reject)
    monkeypatch.setattr(mech_sign, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        mech_sign.TestMechSignRoundtrip().test_roundtrip(_session(), _aes_entry())


def test_roundtrip_verify_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _verify_reject(*_args: Any, **_kwargs: Any) -> bool:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(mech_sign, "generate_key_for_sign", lambda *_args: (1, None))
    monkeypatch.setattr(mech_sign, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_sign, "sign_single", lambda *_args, **_kwargs: b"sig")
    monkeypatch.setattr(mech_sign, "verify_single", _verify_reject)
    monkeypatch.setattr(mech_sign, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        mech_sign.TestMechSignRoundtrip().test_roundtrip(_session(), _aes_entry())


def test_tampered_verify_non_clean_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _verify_reject(*_args: Any, **_kwargs: Any) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(mech_sign, "generate_key_for_sign", lambda *_args: (1, None))
    monkeypatch.setattr(mech_sign, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_sign, "sign_single", lambda *_args, **_kwargs: b"sig")
    monkeypatch.setattr(mech_sign, "verify_single", _verify_reject)
    monkeypatch.setattr(mech_sign, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="signature verification rejected"):
        mech_sign.TestMechSignRoundtrip().test_tampered_data_fails_verify(
            _session(),
            _aes_entry(),
        )


def test_kat_mac_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    monkeypatch.setattr(
        mechanism_vectors,
        "load_positive_vectors",
        lambda _path: [
            {
                "id": "kat-1",
                "key_hex": "00" * 16,
                "input_hex": "11" * 16,
                "mac_hex": "22" * 8,
            }
        ],
    )
    monkeypatch.setattr(mech_sign, "build_params_from_vector", lambda *_args: None)
    monkeypatch.setattr(mech_sign, "import_secret_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(mech_sign, "sign_single", _sign_reject)
    monkeypatch.setattr(mech_sign, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        mech_sign.TestMechSignKAT().test_kat_vector(_session(), _aes_entry())


def test_kat_ec_private_import_capability_reject_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(
        mechanism_vectors,
        "load_positive_vectors",
        lambda _path: [
            {
                "id": "ec-kat-1",
                "key_type": "asymmetric",
                "ec_params_hex": "06082a8648ce3d030107",
                "ec_private_scalar_hex": "01" * 32,
                "input_hex": "22" * 32,
            }
        ],
    )
    monkeypatch.setattr(mech_sign, "import_ec_private_key", _import_reject)

    with pytest.raises(pytest.skip.Exception, match="cannot import EC private key"):
        mech_sign.TestMechSignKAT().test_kat_vector(_session(), _ec_entry())
