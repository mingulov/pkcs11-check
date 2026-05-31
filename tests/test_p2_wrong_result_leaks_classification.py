"""Phase 6 P2 meta-tests: wrong-result leaks now fail (not skip/xfail).

- test_crossverify_extended AES-GCM: a decrypted plaintext that differs from the
  cryptography-library reference is a crypto break -> fail (was skip). A clean
  reject of the decrypt op stays xfail.
- test_ecdh_extended XEdDSA: a self-produced signature that does not verify with
  its own key is a self-contradiction -> fail (was xfail). A clean reject of the
  verify op stays xfail.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_crossverify_extended as tcv
from pkcs11_check.testcases import test_ecdh_extended as tee


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0

    @staticmethod
    def has_mechanism(_n: str) -> bool:
        return True


# --- crossverify AES-GCM ---------------------------------------------------


def _patch_gcm(monkeypatch: pytest.MonkeyPatch, *, decrypt_result: Any) -> None:
    monkeypatch.setattr(tcv, "_import_aes_key_raw", lambda *_a, **_k: 5)
    monkeypatch.setattr(tcv, "destroy_quietly", lambda *_a, **_k: None)

    def _decrypt(*_a: Any, **_k: Any) -> bytes:
        if isinstance(decrypt_result, BaseException):
            raise decrypt_result
        return decrypt_result

    monkeypatch.setattr(tcv, "decrypt_single", _decrypt)


def test_gcm_wrong_plaintext_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_gcm(monkeypatch, decrypt_result=b"WRONG-plaintext-not-matching")
    # The mismatch surfaces as a hard assertion failure (not skip / not xfail).
    with pytest.raises(AssertionError, match="differs from the cryptography") as ei:
        tcv.TestAESGCMCrossVerify().test_aes_gcm_decrypt_crossverify(_RawSession())
    assert not isinstance(ei.value, (XFailed, Failed))


def test_gcm_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    _patch_gcm(monkeypatch, decrypt_result=exc)
    with pytest.raises(XFailed):
        tcv.TestAESGCMCrossVerify().test_aes_gcm_decrypt_crossverify(_RawSession())


# --- XEdDSA self-roundtrip -------------------------------------------------


def _patch_xeddsa(monkeypatch: pytest.MonkeyPatch, *, verify_result: Any) -> None:
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tee, "sign_single", lambda *_a, **_k: b"sig-bytes")

    def _verify(*_a: Any, **_k: Any) -> bool:
        if isinstance(verify_result, BaseException):
            raise verify_result
        return verify_result

    monkeypatch.setattr(tee, "verify_single", _verify)


def test_xeddsa_self_roundtrip_false_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_xeddsa(monkeypatch, verify_result=False)
    # Self-roundtrip failure surfaces as a hard assertion failure (not xfail).
    with pytest.raises(AssertionError, match="own signature did not verify") as ei:
        tee.TestXEdDSA().test_xeddsa_sign_verify(_RawSession())
    assert not isinstance(ei.value, (XFailed, Failed))


def test_xeddsa_verify_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    _patch_xeddsa(monkeypatch, verify_result=exc)
    with pytest.raises(XFailed):
        tee.TestXEdDSA().test_xeddsa_sign_verify(_RawSession())
