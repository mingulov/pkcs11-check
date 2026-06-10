"""Regression tests for mechanism encrypt runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_AES,
    CKM_AES_CBC,
    CKM_AES_GCM,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
)
from pkcs11_check.testcases import mechanism_vectors
from pkcs11_check.testcases import test_mech_encrypt as mech_encrypt
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig, ParamRecipe


def _entry(*, auth_tag_included: bool = False) -> MechEntry:
    mech_id = int(CKM_AES_GCM) if auth_tag_included else int(CKM_AES_CBC)
    return MechEntry(
        mech_id=mech_id,
        mech_name="AES_GCM" if auth_tag_included else "AES_CBC",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=MechConfig(
            key_type=int(CKK_AES),
            vector_file="dummy.json",
            param_recipe=ParamRecipe("iv"),
            auth_tag_included=auth_tag_included,
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
        match="advertised but not operational",
    ):
        mech_encrypt.TestMechEncryptKAT().test_kat_vector(rs, _entry())


def test_mechanism_kat_aead_encrypt_uses_tag_overhead_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AEAD KATs use the same NSS-safe output sizing as roundtrip tests."""
    seen_kwargs: dict[str, Any] = {}
    expected = b"\x22" * 16 + b"\x33" * 16

    def _encrypt(*_args: Any, **kwargs: Any) -> bytes:
        seen_kwargs.update(kwargs)
        return expected

    monkeypatch.setattr(
        mechanism_vectors,
        "load_positive_vectors",
        lambda _path: [
            {
                "id": "kat-1",
                "key_hex": "00" * 16,
                "plaintext_hex": "11" * 16,
                "ciphertext_hex": "22" * 16,
                "tag_hex": "33" * 16,
            }
        ],
    )
    monkeypatch.setattr(mech_encrypt, "build_params_from_vector", lambda *_args: None)
    monkeypatch.setattr(mech_encrypt, "import_secret_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(mech_encrypt, "encrypt_single", _encrypt)
    monkeypatch.setattr(mech_encrypt, "destroy_quietly", lambda *_args: None)

    rs = SimpleNamespace(raw=object(), sh=1)

    mech_encrypt.TestMechEncryptKAT().test_kat_vector(
        rs,
        _entry(auth_tag_included=True),
    )

    assert seen_kwargs["output_overhead"] == 16
    assert seen_kwargs["retry_on_buffer_too_small"] is True


def test_mechanism_roundtrip_key_type_inconsistent_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typed-key runtime reject is advertised mechanism capability evidence."""

    def _raise_key_type_inconsistent(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_TYPE_INCONSISTENT",
            int(CKR_KEY_TYPE_INCONSISTENT),
        )

    monkeypatch.setattr(mech_encrypt, "generate_key_for_encrypt", lambda *_args: (1, None))
    monkeypatch.setattr(mech_encrypt, "get_test_plaintext_bytes", lambda: b"0" * 32)
    monkeypatch.setattr(mech_encrypt, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_encrypt, "encrypt_single", _raise_key_type_inconsistent)
    monkeypatch.setattr(mech_encrypt, "destroy_quietly", lambda *_args: None)

    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(
        pytest.xfail.Exception,
        match="advertised but not operational",
    ):
        mech_encrypt.TestMechEncryptRoundtrip().test_roundtrip(rs, _entry())


@pytest.mark.parametrize("rv", [CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_VALUE_INVALID])
def test_mechanism_roundtrip_argument_or_attribute_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    """Provider rejects of advertised valid encrypt paths are visible xfail findings."""

    def _raise_runtime_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV", int(rv))

    monkeypatch.setattr(mech_encrypt, "generate_key_for_encrypt", lambda *_args: (1, None))
    monkeypatch.setattr(mech_encrypt, "get_test_plaintext_bytes", lambda: b"0" * 32)
    monkeypatch.setattr(mech_encrypt, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_encrypt, "encrypt_single", _raise_runtime_reject)
    monkeypatch.setattr(mech_encrypt, "destroy_quietly", lambda *_args: None)

    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(
        pytest.xfail.Exception,
        match="advertised but not operational",
    ):
        mech_encrypt.TestMechEncryptRoundtrip().test_roundtrip(rs, _entry())
