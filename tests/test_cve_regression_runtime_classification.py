"""Runtime classification meta-tests for CVE regression Type-A reclassification.

Drives the invalid-EC-curve-OID import (CVE-2021-3798 pattern) offline with a
fake create_object, asserting the three-way model:

- module ACCEPTS the bogus-OID key (returns a handle) -> fail (crypto-correctness),
- module rejects with an expected curve/param code -> pass,
- module rejects with another clean code -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
)
from pkcs11_check.testcases.security import test_cve_regression


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _run(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, reject_rv: int = 0) -> None:
    if accepted:
        monkeypatch.setattr(test_cve_regression, "create_object", lambda *_a, **_k: 7)
    else:

        def _reject(*_a: object, **_k: object) -> int:
            raise CkrAssertionError(f"rv={reject_rv}", int(reject_rv))

        monkeypatch.setattr(test_cve_regression, "create_object", _reject)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)
    test_cve_regression.TestInvalidECCurve().test_import_ec_key_with_bad_oid(_session())


def test_accepted_bad_oid_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run(monkeypatch, accepted=True)


def test_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, accepted=False, reject_rv=int(CKR_CURVE_NOT_SUPPORTED))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, accepted=False, reject_rv=int(CKR_DEVICE_ERROR))
