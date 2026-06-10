"""Classification meta-tests for ECDSA-prehash advertised-but-not-operational.

A module may advertise a prehash mechanism (e.g. ``CKM_ECDSA_SHA1``) yet refuse
the actual sign at runtime -- FIPS 140-3 deprecates SHA-1 for signature
generation, so kryoptic-FIPS lists the mechanism but returns ``CKR_DEVICE_ERROR``
when asked to sign. A clean runtime refusal produces no signature, so per the
classification model it is an "advertised but not operational" deviation
(xfail), not a hard fail. A produced-but-wrong signature (sign OK, verify False)
is still a real break (fail); a non-CKR error (harness bug) still propagates.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKM_ECDSA_SHA1, CKR_DEVICE_ERROR
from pkcs11_check.testcases import test_ecdsa_extended as ext


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _wire(
    monkeypatch: pytest.MonkeyPatch, *, sign: Any, verify: Any = lambda *a, **k: True
) -> None:
    monkeypatch.setattr(ext, "gen_ec_keypair", lambda *a, **k: (1, 2))
    monkeypatch.setattr(ext, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(ext, "sign_single", sign)
    monkeypatch.setattr(ext, "verify_single", verify)


def _device_error(*_a: Any, **_k: Any) -> bytes:
    raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))


def test_prehash_sign_clean_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advertised CKM_ECDSA_SHA1 that refuses to sign (DEVICE_ERROR) -> xfail."""
    _wire(monkeypatch, sign=_device_error)
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        ext.TestECDSAPrehash().test_sign_verify_roundtrip(_rs(), "ECDSA_SHA1", CKM_ECDSA_SHA1)


def test_prehash_sign_ok_verify_ok_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sign + verify both succeed -> the mechanism works (pass, no exception)."""
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: True)
    ext.TestECDSAPrehash().test_sign_verify_roundtrip(_rs(), "ECDSA_SHA1", CKM_ECDSA_SHA1)


def test_prehash_sign_ok_verify_false_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sign produced a signature but verify rejects it -> real break (fail)."""
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: False)
    with pytest.raises(AssertionError):
        ext.TestECDSAPrehash().test_sign_verify_roundtrip(_rs(), "ECDSA_SHA1", CKM_ECDSA_SHA1)


def test_prehash_sign_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-CKR AssertionError (harness/ctypes bug) must NOT be read as
    not-operational -- it propagates."""

    def _bug(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("ctypes packing bug")

    _wire(monkeypatch, sign=_bug)
    with pytest.raises(AssertionError, match="packing bug"):
        ext.TestECDSAPrehash().test_sign_verify_roundtrip(_rs(), "ECDSA_SHA1", CKM_ECDSA_SHA1)


def test_tampered_setup_sign_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """The negative test's setup sign also xfails on a clean runtime refusal."""
    _wire(monkeypatch, sign=_device_error)
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        ext.TestECDSAPrehash().test_tampered_data_fails(_rs(), "ECDSA_SHA1", CKM_ECDSA_SHA1)
