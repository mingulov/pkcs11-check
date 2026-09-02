"""Regression tests for ACVP AES-GCM-SIV decrypt invalid-vector classification."""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_GCM_PARAMS,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKM_AES_GMAC,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.acvp.aes import test_gcm as gcm


class _GcmSivSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "AES_GCM_SIV"


class _GmacSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "AES_GMAC"


@pytest.fixture(autouse=True)
def _fresh_operability_cache() -> None:
    reset_operability_cache()
    classification.clear()


def _wrong_plaintext(*_args: Any, **_kwargs: Any) -> bytes:
    return b"\x00" * 16


def test_gcm_siv_decrypt_invalid_vector_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forged GCM-SIV vector that decrypts must fail (auth break, crypto).

    Phase-2 V1: the decrypt-success path previously had no ``else: fail`` for
    ``test_passed is False``, so a module that returned plaintext for a
    tampered ciphertext/tag was accepted silently.
    """
    vec_id, vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is False
    )

    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(gcm, "decrypt_single", _wrong_plaintext)
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="invalid GCM-SIV"):
        gcm.test_acvp_aes_gcm_siv_decrypt(_GcmSivSession(), vec_id, vec)


def test_gcm_siv_encrypt_wrong_ciphertext_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec_id, vec = gcm._GCM_SIV_ENCRYPT_VECTORS[0]
    wrong_ct = bytearray(vec["ct_expected"])
    wrong_ct[0] ^= 1

    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        gcm,
        "encrypt_single",
        lambda *_a, **_k: bytes(wrong_ct) + vec["tag_expected"],
    )
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        gcm.test_acvp_aes_gcm_siv_encrypt(_GcmSivSession(), vec_id, vec)


def test_gcm_siv_decrypt_valid_wrong_plaintext_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec_id, vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is True
    )
    wrong_pt = bytearray(vec["pt_expected"] or b"\x00")
    if vec["pt_expected"]:
        wrong_pt[0] ^= 1

    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(gcm, "decrypt_single", lambda *_a, **_k: bytes(wrong_pt))
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        gcm.test_acvp_aes_gcm_siv_decrypt(_GcmSivSession(), vec_id, vec)


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_gcm_siv_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    vec_id, vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is True
    )
    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: (_ for _ in ()).throw(exc))
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(type(exc), match=str(exc)):
        gcm.test_acvp_aes_gcm_siv_decrypt(_GcmSivSession(), vec_id, vec)


def test_gcm_siv_invalid_generic_ckr_is_not_accepted_as_auth_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec_id, vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is False
    )
    refusal = CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))
    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(gcm, "decrypt_single", lambda *_a, **_k: (_ for _ in ()).throw(refusal))
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception):
        gcm.test_acvp_aes_gcm_siv_decrypt(_GcmSivSession(), vec_id, vec)


def test_gcm_siv_invalid_reject_requires_valid_canonical_decrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid-vector rejection is a pass only after a valid decrypt runs."""
    invalid_id, invalid_vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is False
    )
    _canonical_id, canonical_vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is True
    )
    calls = 0

    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: 1)

    def _decrypt(*_args: Any, **_kwargs: Any) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise CkrAssertionError("invalid GCM-SIV ciphertext", int(CKR_ENCRYPTED_DATA_INVALID))
        return bytes(canonical_vec["pt_expected"])

    monkeypatch.setattr(gcm, "decrypt_single", _decrypt)
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    gcm.test_acvp_aes_gcm_siv_decrypt(_GcmSivSession(), invalid_id, invalid_vec)
    assert calls == 2


def test_gcm_siv_invalid_reject_is_not_operational_without_canonical_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean reject from both vectors is not evidence that invalid data was checked."""
    vec_id, vec = next(
        (vid, v) for vid, v in gcm._GCM_SIV_DECRYPT_VECTORS if v.get("test_passed") is False
    )
    refusal = CkrAssertionError("invalid GCM-SIV ciphertext", int(CKR_ENCRYPTED_DATA_INVALID))
    monkeypatch.setattr(gcm, "_import_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(gcm, "decrypt_single", lambda *_a, **_k: (_ for _ in ()).throw(refusal))
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception, match="vacuous"):
        gcm.test_acvp_aes_gcm_siv_decrypt(_GcmSivSession(), vec_id, vec)
    assert classification.get_records()[-1].reason == "not_operational"


@pytest.mark.parametrize("interface_version", ["2.40", "3.0", "3.1", "3.2"])
def test_acvp_gmac_uses_sign_and_sign_capability(
    monkeypatch: pytest.MonkeyPatch, interface_version: str
) -> None:
    """GMAC is C_Sign over AAD, with CKA_SIGN rather than CKA_ENCRYPT."""
    vec_id, vec = gcm._GMAC_VECTORS[0]
    seen: dict[str, Any] = {}

    def _import(*_args: Any, **kwargs: Any) -> int:
        seen["attrs"] = kwargs["attrs"]
        return 1

    def _sign(_raw: Any, _sh: int, _key: int, mechanism: Any, data: bytes, **_kwargs: Any) -> bytes:
        seen["mechanism"] = mechanism
        seen["data"] = data
        seen["mech_param"] = _kwargs["mech_param"]
        return bytes(vec["tag_expected"])

    monkeypatch.setattr(gcm, "import_secret_key_negotiated", _import)
    monkeypatch.setattr(gcm, "sign_single", _sign)
    monkeypatch.setattr(
        gcm,
        "encrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("GMAC must not encrypt")),
    )
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    gcm.test_acvp_aes_gmac(_GmacSession(), interface_version, vec_id, vec)

    assert seen["attrs"][CKA_SIGN] is True
    assert CKA_ENCRYPT not in seen["attrs"]
    assert seen["mechanism"] == CKM_AES_GMAC
    assert seen["data"] == (vec.get("aad") or b"")
    packed = seen["mech_param"]
    if interface_version == "2.40":
        assert int(packed.ck.ulParameterLen) == len(vec["iv"])
        assert ctypes.string_at(packed.ck.pParameter, packed.ck.ulParameterLen) == vec["iv"]
    else:
        assert int(packed.ck.ulParameterLen) == ctypes.sizeof(CK_GCM_PARAMS)
        params = ctypes.cast(packed.ck.pParameter, ctypes.POINTER(CK_GCM_PARAMS)).contents
        assert not params.pAAD
        assert int(params.ulAADLen) == 0
        assert ctypes.string_at(params.pIv, params.ulIvLen) == vec["iv"]


def test_acvp_gmac_wrong_tag_is_a_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = gcm._GMAC_VECTORS[0]
    wrong_tag = bytearray(vec["tag_expected"])
    wrong_tag[-1] ^= 1
    monkeypatch.setattr(gcm, "import_secret_key_negotiated", lambda *_a, **_k: 1)
    monkeypatch.setattr(gcm, "sign_single", lambda *_a, **_k: bytes(wrong_tag))
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        gcm.test_acvp_aes_gmac(_GmacSession(), "2.40", vec_id, vec)


def test_acvp_gmac_typed_ckr_remains_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = gcm._GMAC_VECTORS[0]
    refusal = CkrAssertionError("GMAC operation refused", int(CKR_GENERAL_ERROR))
    monkeypatch.setattr(gcm, "import_secret_key_negotiated", lambda *_a, **_k: 1)
    monkeypatch.setattr(gcm, "sign_single", lambda *_a, **_k: (_ for _ in ()).throw(refusal))
    monkeypatch.setattr(gcm, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception):
        gcm.test_acvp_aes_gmac(_GmacSession(), "2.40", vec_id, vec)
    record = classification.get_records()[-1]
    assert record.actual_ckr == "CKR_GENERAL_ERROR"
    assert record.operation == "C_Sign"
