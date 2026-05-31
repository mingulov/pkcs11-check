"""Runtime classification meta-test for test_stateful_sigs HSS leaf-budget guard (Phase 4 N2).

The 33rd sign on a 32-leaf HSS key must reject (one-time-key reuse is a security
gap). Converted from a local 'fail on unexpected reject CKR' to the shared
reject_or_classify 3-way:

- the over-budget sign succeeds (no raise) -> fail (key reuse),
- the spec-compatible exhaustion code -> pass,
- any other clean reject code -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.testcases import test_stateful_sigs as tss


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)


def _exhaustion_rv() -> int:
    return int(next(iter(tss._EXHAUSTION_OK_RVS)))


def _run(monkeypatch: pytest.MonkeyPatch, *, thirty_third: object) -> None:
    """thirty_third: bytes (success), or an int rv to raise on the 33rd sign."""
    monkeypatch.setattr(tss, "_skip_if_no", lambda *_a, **_k: None)
    monkeypatch.setattr(tss, "_try_keygen", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tss, "_destroy_pair", lambda *_a, **_k: None)

    state = {"calls": 0}

    def _sign(*_a: object, **_k: object) -> bytes:
        state["calls"] += 1
        if state["calls"] <= 32:
            return b"\x01" * 16
        if isinstance(thirty_third, bytes):
            return thirty_third
        raise CkrAssertionError("rv", int(thirty_third))

    monkeypatch.setattr(tss, "sign_single", _sign)
    tss.TestHSSKeyExhaustion().test_hss_sign_past_leaf_budget_returns_key_exhausted(_session())


def test_over_budget_success_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, thirty_third=b"\x02" * 16)
    assert not isinstance(ei.value, XFailed)


def test_spec_exhaustion_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, thirty_third=_exhaustion_rv())


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR

    # CKR_GENERAL_ERROR is a clean reject NOT in the exhaustion-compatible set.
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, thirty_third=int(CKR_GENERAL_ERROR))
