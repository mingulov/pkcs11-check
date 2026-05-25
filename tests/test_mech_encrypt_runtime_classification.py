"""Regression tests for mechanism encrypt runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKK_AES, CKM_AES_CBC, CKR_GENERAL_ERROR
from pkcs11_check.testcases import mechanism_vectors
from pkcs11_check.testcases import test_mech_encrypt as mech_encrypt
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig, ParamRecipe


def _entry() -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_AES_CBC),
        mech_name="AES_CBC",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=MechConfig(
            key_type=int(CKK_AES),
            vector_file="dummy.json",
            param_recipe=ParamRecipe("iv"),
        ),
    )


def test_mechanism_kat_encrypt_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic runtime rejection during advertised mechanism KAT is an xfail finding."""

    def _raise_general_error(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(
        mechanism_vectors,
        "load_positive_vectors",
        lambda _path: [
            {
                "id": "kat-1",
                "key_hex": "00" * 16,
                "plaintext_hex": "11" * 16,
                "ciphertext_hex": "22" * 16,
            }
        ],
    )
    monkeypatch.setattr(mech_encrypt, "build_params_from_vector", lambda *_args: None)
    monkeypatch.setattr(mech_encrypt, "import_secret_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(mech_encrypt, "encrypt_single", _raise_general_error)
    monkeypatch.setattr(mech_encrypt, "destroy_quietly", lambda *_args: None)

    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(
        pytest.xfail.Exception,
        match="advertised but KAT encrypt is not operational",
    ):
        mech_encrypt.TestMechEncryptKAT().test_kat_vector(rs, _entry())
