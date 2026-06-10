"""Classification meta-tests for RSA advertised-but-not-operational (FIPS).

FIPS 140-3 restricts RSA PKCS#1 v1.5 key transport, so kryoptic-FIPS advertises
``CKM_RSA_PKCS`` but returns ``CKR_DEVICE_ERROR`` on the private-key decrypt of
an encrypt/decrypt roundtrip. A clean refusal yields no plaintext, so per the
classification model it is an "advertised but not operational" deviation
(xfail), not a hard fail. A completed roundtrip with the WRONG plaintext is
still a real break (fail); a non-CKR error (harness bug) still propagates.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR
from pkcs11_check.testcases import test_encrypt as enc


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _wire(monkeypatch: pytest.MonkeyPatch, *, encrypt: Any, decrypt: Any) -> None:
    monkeypatch.setattr(enc, "gen_rsa_keypair", lambda *a, **k: (1, 2))
    monkeypatch.setattr(enc, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(enc, "encrypt_single", encrypt)
    monkeypatch.setattr(enc, "decrypt_single", decrypt)


def _device_error(*_a: Any, **_k: Any) -> bytes:
    raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))


def test_rsa_pkcs_decrypt_clean_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Encrypt OK but the private-key decrypt refuses (FIPS) -> xfail."""
    _wire(monkeypatch, encrypt=lambda *a, **k: b"ct", decrypt=_device_error)
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        enc.TestRSAEncryption().test_rsa_pkcs_roundtrip(_rs())


def test_rsa_pkcs_roundtrip_ok_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A correct roundtrip passes (no exception)."""
    _wire(
        monkeypatch,
        encrypt=lambda *a, **k: b"ct",
        decrypt=lambda *a, **k: b"RSA roundtrip test",
    )
    enc.TestRSAEncryption().test_rsa_pkcs_roundtrip(_rs())


def test_rsa_pkcs_roundtrip_wrong_plaintext_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A completed roundtrip with the wrong plaintext is a real break (fail)."""
    _wire(monkeypatch, encrypt=lambda *a, **k: b"ct", decrypt=lambda *a, **k: b"WRONG")
    with pytest.raises(AssertionError):
        enc.TestRSAEncryption().test_rsa_pkcs_roundtrip(_rs())


def test_rsa_pkcs_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-CKR AssertionError (harness/ctypes bug) must propagate."""

    def _bug(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("ctypes packing bug")

    _wire(monkeypatch, encrypt=lambda *a, **k: b"ct", decrypt=_bug)
    with pytest.raises(AssertionError, match="packing bug"):
        enc.TestRSAEncryption().test_rsa_pkcs_roundtrip(_rs())
