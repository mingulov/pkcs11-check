"""Runtime classification meta-tests for ML-KEM negative tests (Type A + Type B).

Type A -- CKA_VALUE injection (test_decapsulate_with_invalid_attributes_in_template):
injecting CKA_VALUE into a C_DecapsulateKey template lets the caller dictate the
derived key's secret bytes instead of deriving them -- a crypto-correctness
break. Acceptance (CKR_OK) must fail; an expected template reject passes; another
clean reject xfails.

Type B -- CKA_DECAPSULATE=False enforcement (test_decapsulate_missing_permission_flag):
if the module honored CKA_DECAPSULATE=False on the private key (claim) and then
decapsulated anyway (violation) it is a self-contradiction -> fail; if it did not
claim the flag (reads back True/absent) -> xfail; rejection -> pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKA_DECAPSULATE,
    CKR_ARGUMENTS_BAD,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_kem


def _session(decap_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(C_DecapsulateKey=lambda *_a, **_k: int(decap_rv))
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: True)


def _run(monkeypatch: pytest.MonkeyPatch, decap_rv: int) -> None:
    monkeypatch.setattr(test_kem, "_skip_if_no_ml_kem", lambda *_a, **_k: None)
    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(
        test_kem, "_encapsulate_ml_kem_or_xfail", lambda *_a, **_k: (3, b"\x00" * 32)
    )
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_a, **_k: None)
    test_kem.TestMLKEMNegative().test_decapsulate_with_invalid_attributes_in_template(
        _session(decap_rv)
    )


def test_value_injection_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # XFailed subclasses Failed, so assert a *genuine* fail (not an xfail).
    with pytest.raises(Failed) as excinfo:
        _run(monkeypatch, int(CKR_OK))
    assert not isinstance(excinfo.value, XFailed)


def test_value_injection_expected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_TEMPLATE_INCONSISTENT))


def test_value_injection_other_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_ARGUMENTS_BAD))


# ---------------------------------------------------------------------------
# Type B -- CKA_DECAPSULATE=False enforcement
# ---------------------------------------------------------------------------


def _run_perm(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, decap_rv: int) -> None:
    monkeypatch.setattr(test_kem, "_skip_if_no_ml_kem", lambda *_a, **_k: None)
    monkeypatch.setattr(test_kem, "_generate_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(
        test_kem, "_encapsulate_ml_kem_or_xfail", lambda *_a, **_k: (3, b"\x00" * 32)
    )
    monkeypatch.setattr(test_kem, "destroy_quietly", lambda *_a, **_k: None)
    # claim-check reads CKA_DECAPSULATE back: False = claimed, True = not claimed.
    monkeypatch.setattr(
        test_kem,
        "read_attributes",
        lambda *_a, **_k: {CKA_DECAPSULATE: False if claimed else True},
    )
    test_kem.TestMLKEMNegative().test_decapsulate_missing_permission_flag(_session(decap_rv))


def test_perm_claimed_then_violated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as excinfo:
        _run_perm(monkeypatch, claimed=True, decap_rv=int(CKR_OK))
    assert not isinstance(excinfo.value, XFailed)


def test_perm_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_perm(monkeypatch, claimed=False, decap_rv=int(CKR_OK))


def test_perm_claimed_and_rejected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_perm(monkeypatch, claimed=True, decap_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED))
