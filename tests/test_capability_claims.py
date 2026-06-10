"""Meta-tests: claim-layer verdict for advertised-but-refused (mech, op) roundtrips.

PKCS#11 v3.2 defines CKR_OPERATION_NOT_VALIDATED for validation-policy refusal
of an advertised operation -- the one spec-sanctioned refusal channel that does
not contradict the advertisement. Sanctioned refusal -> the claim test PASSES
with a compliance note; any other clean CKR -> xfail (advertised but not
operational, no CKR allowlist); non-CKR -> harness bug, propagates.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_OPERATION_NOT_VALIDATED
from pkcs11_check.testcases import _capability_claims as cc


@pytest.fixture(autouse=True)
def _fresh_validation_cache() -> None:
    cc.reset_validation_object_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _notes_spy(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ComplianceLevel]]:
    captured: list[tuple[str, ComplianceLevel]] = []

    def fake_note(description: str, level: ComplianceLevel, reference: str = "") -> None:
        captured.append((description, level))

    monkeypatch.setattr(cc.compliance, "note", fake_note)
    return captured


def test_sanctioned_refusal_returns_true_and_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _notes_spy(monkeypatch)
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: True)
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_OPERATION_NOT_VALIDATED", int(CKR_OPERATION_NOT_VALIDATED)
    )
    assert cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign") is True
    assert len(captured) == 1
    description, level = captured[0]
    assert "CKR_OPERATION_NOT_VALIDATED" in description
    assert "CKM_ECDSA_SHA1:sign" in description
    assert level is ComplianceLevel.STANDARD


def test_other_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _notes_spy(monkeypatch)
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign")


def test_non_ckr_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrong-output asserts and harness bugs must never be classified."""
    _notes_spy(monkeypatch)
    exc = AssertionError("verify returned False after valid sign")
    with pytest.raises(AssertionError, match="verify returned False"):
        cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign")


def test_validation_object_probe_failure_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enumeration refusal must not crash the verdict -- presence is just 'None'."""

    def boom(*_a: Any, **_k: Any) -> list[int]:
        raise AssertionError("C_FindObjectsInit failed: CKR_ATTRIBUTE_TYPE_INVALID")

    monkeypatch.setattr(cc, "find_objects", boom)
    assert cc._validation_objects_present(_rs()) is None
