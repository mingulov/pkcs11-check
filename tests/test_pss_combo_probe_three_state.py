"""Meta-tests: RSA-PSS combo self-roundtrip probe is three-state, not bool.

The bool probe collapsed the RSA-2048 keypair-generation staging failure (plain
RSA keygen, no PSS involved) into "not operational", which would let the
vacuous-reject downgrade fire with no PSS-combo evidence. Three-state:
keypair-gen refusal -> INCONCLUSIVE; canonical PSS sign/verify refusal or
verify-False -> NOT_OPERATIONAL; self-roundtrip True -> OPERATIONAL.

Module errors from gen_rsa_keypair / sign_single / verify_single surface as
CkrAssertionError (all go through expect_rv); a plain AssertionError is a
harness bug and must propagate uncached.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR
from pkcs11_check.testcases._operability import Operability, reset_operability_cache
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_pss as mod


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    keygen: Any,
    sign: Any = lambda *a, **k: b"sig",
    verify: Any = lambda *a, **k: True,
) -> None:
    monkeypatch.setattr(mod, "gen_rsa_keypair", keygen)
    monkeypatch.setattr(mod, "sign_single", sign)
    monkeypatch.setattr(mod, "verify_single", verify)
    monkeypatch.setattr(mod, "mech_pss", lambda *a, **k: object())
    monkeypatch.setattr(mod, "destroy_quietly", lambda *a, **k: None)


def _refuse(*_a: Any, **_k: Any) -> Any:
    raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))


def test_keygen_refusal_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    """RSA-2048 keypair generation refusal is staging -> INCONCLUSIVE."""
    _wire(monkeypatch, keygen=_refuse)
    result = mod._pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.INCONCLUSIVE


def test_sign_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), sign=_refuse)
    result = mod._pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.NOT_OPERATIONAL


def test_verify_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), verify=_refuse)
    result = mod._pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.NOT_OPERATIONAL


def test_verify_false_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), verify=lambda *a, **k: False)
    result = mod._pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.NOT_OPERATIONAL


def test_roundtrip_is_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), verify=lambda *a, **k: True)
    result = mod._pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.OPERATIONAL


def test_plain_assertion_error_propagates_uncached(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plain AssertionError (harness bug) from sign must propagate, not be cached."""

    def buggy_sign(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("harness bug: not a CKR error")

    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), sign=buggy_sign)
    with pytest.raises(AssertionError, match="harness bug"):
        mod._pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)

    from pkcs11_check.testcases._operability import _CACHE

    assert not any("RSA_PSS" in k for k in _CACHE)
