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
from pkcs11_check.testcases import _rsa_pss_operability as mod
from pkcs11_check.testcases._operability import Operability, reset_operability_cache
from pkcs11_check.testcases._rsa_pss_operability import pss_combo_operability


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
    result = pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.INCONCLUSIVE


def test_sign_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), sign=_refuse)
    result = pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.NOT_OPERATIONAL


def test_verify_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), verify=_refuse)
    result = pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.NOT_OPERATIONAL


def test_verify_false_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), verify=lambda *a, **k: False)
    result = pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.NOT_OPERATIONAL


def test_roundtrip_is_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), verify=lambda *a, **k: True)
    result = pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)
    assert result.status is Operability.OPERATIONAL


def test_plain_assertion_error_propagates_uncached(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plain AssertionError (harness bug) from sign must propagate, not be cached."""

    def buggy_sign(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("harness bug: not a CKR error")

    _wire(monkeypatch, keygen=lambda *a, **k: (7, 8), sign=buggy_sign)
    with pytest.raises(AssertionError, match="harness bug"):
        pss_combo_operability(_rs(), 0x0D, 0x0220, 0x02, 32)

    from pkcs11_check.testcases._operability import _CACHE

    assert not any("RSA_PSS" in k for k in _CACHE)


def test_different_salt_lengths_produce_distinct_cache_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix 2: salt_len is part of the probe cache key; two calls with the same
    (mech, hash, mgf) but different salt_len must each run the probe once and
    produce independent cache entries.  A dropped ``:{salt_len}`` suffix would
    collapse both calls onto the same key so the probe runs only once and the
    second call returns the first result without re-probing (silent
    cross-contamination of verdicts).
    """
    call_count = 0

    def counting_keygen(*_a: Any, **_k: Any) -> tuple[int, int]:
        nonlocal call_count
        call_count += 1
        return (7, 8)

    _wire(monkeypatch, keygen=counting_keygen, verify=lambda *a, **k: True)

    rs = _rs()
    # First call: sLen=20
    r1 = pss_combo_operability(rs, 0x0D, 0x0220, 0x01, 20)
    # Second call: same mech/hash/mgf, different sLen=32
    r2 = pss_combo_operability(rs, 0x0D, 0x0220, 0x01, 32)

    # Both must be OPERATIONAL (two separate successful probes)
    assert r1.status is Operability.OPERATIONAL
    assert r2.status is Operability.OPERATIONAL
    # The probe (keygen) must have run exactly twice — once per distinct salt
    assert call_count == 2, (
        f"expected 2 probe runs (one per salt_len), got {call_count}; "
        "salt_len is likely missing from the cache key"
    )

    from pkcs11_check.testcases._operability import _CACHE

    # Two distinct keys must be present
    pss_keys = [k for k in _CACHE if "RSA_PSS" in k]
    assert len(pss_keys) == 2, f"expected 2 cache entries, got: {pss_keys}"
