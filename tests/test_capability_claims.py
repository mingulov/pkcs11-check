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
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_OPERATION_NOT_VALIDATED,
)
from pkcs11_check.testcases import _capability_claims as cc


@pytest.fixture(autouse=True)
def _fresh_validation_cache() -> None:
    cc.reset_validation_object_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _notes_spy(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, ComplianceLevel, str]]:
    """Capture (description, level, test_id) tuples from compliance.note calls."""
    captured: list[tuple[str, ComplianceLevel, str]] = []

    def fake_note(
        description: str,
        level: ComplianceLevel,
        reference: str = "",
        *,
        test_id: str = "",
    ) -> None:
        captured.append((description, level, test_id))

    monkeypatch.setattr(cc.compliance, "note", fake_note)
    return captured


def test_sanctioned_refusal_returns_true_and_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _notes_spy(monkeypatch)
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "True")
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_OPERATION_NOT_VALIDATED", int(CKR_OPERATION_NOT_VALIDATED)
    )
    assert cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign") is True
    assert len(captured) == 1
    description, level, test_id = captured[0]
    assert "CKR_OPERATION_NOT_VALIDATED" in description
    assert "CKM_ECDSA_SHA1:sign" in description
    assert level is ComplianceLevel.STANDARD
    # note attribution: test_id must be the calling test's qualname, not claim_refusal_passes
    assert "test_sanctioned_refusal_returns_true_and_notes" in test_id
    assert "claim_refusal_passes" not in test_id


def test_note_attribution_walks_through_nested_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Called from inside a helper, the note attributes to the enclosing test_*."""
    captured = _notes_spy(monkeypatch)
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "True")
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_OPERATION_NOT_VALIDATED", int(CKR_OPERATION_NOT_VALIDATED)
    )

    def _inner_helper() -> bool:
        # A non-test frame sitting between the test and claim_refusal_passes.
        return cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign")

    assert _inner_helper() is True
    assert len(captured) == 1
    _description, _level, test_id = captured[0]
    assert "test_note_attribution_walks_through_nested_helper" in test_id
    assert "_inner_helper" not in test_id


def test_other_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _notes_spy(monkeypatch)
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign")
    # xfail path must NOT emit any note
    assert captured == []


def test_non_ckr_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrong-output asserts and harness bugs must never be classified."""
    _notes_spy(monkeypatch)
    exc = AssertionError("verify returned False after valid sign")
    with pytest.raises(AssertionError, match="verify returned False"):
        cc.claim_refusal_passes(exc, _rs(), probe_key="CKM_ECDSA_SHA1:sign")


# ---------------------------------------------------------------------------
# _validation_objects_present tests
# ---------------------------------------------------------------------------


def test_validation_object_probe_success_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """find_objects returning handles -> presence string 'True'."""
    monkeypatch.setattr(cc, "find_objects", lambda raw, sh, tmpl: [1, 2])
    assert cc._validation_objects_present(_rs()) == "True"


def test_validation_object_probe_success_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """find_objects returning empty list -> presence string 'False'."""
    monkeypatch.setattr(cc, "find_objects", lambda raw, sh, tmpl: [])
    assert cc._validation_objects_present(_rs()) == "False"


def test_validation_object_probe_success_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful probe result is cached -- find_objects called only once."""
    call_count = 0

    def counting_find(*_a: Any, **_k: Any) -> list[int]:
        nonlocal call_count
        call_count += 1
        return [42]

    monkeypatch.setattr(cc, "find_objects", counting_find)
    cc._validation_objects_present(_rs())
    cc._validation_objects_present(_rs())
    assert call_count == 1


def test_validation_object_probe_ckr_failure_not_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CkrAssertionError refusal -> 'unknown (CKR_...)' string, NOT cached (re-probes)."""
    call_count = 0

    def boom(*_a: Any, **_k: Any) -> list[int]:
        nonlocal call_count
        call_count += 1
        raise CkrAssertionError(
            "C_FindObjectsInit failed: CKR_ATTRIBUTE_TYPE_INVALID",
            int(CKR_ATTRIBUTE_TYPE_INVALID),
        )

    monkeypatch.setattr(cc, "find_objects", boom)
    result1 = cc._validation_objects_present(_rs())
    result2 = cc._validation_objects_present(_rs())
    # Both calls return the "unknown" description
    assert result1 is not None
    assert "unknown" in result1
    assert "CKR_ATTRIBUTE_TYPE_INVALID" in result1
    assert result2 is not None
    assert "unknown" in result2
    # Nothing was cached -- both calls hit find_objects
    assert call_count == 2


def test_validation_object_probe_non_ckr_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plain AssertionError (harness bug) must propagate, never be swallowed."""

    def boom(*_a: Any, **_k: Any) -> list[int]:
        raise AssertionError("harness bug: unexpected None session handle")

    monkeypatch.setattr(cc, "find_objects", boom)
    with pytest.raises(AssertionError, match="harness bug"):
        cc._validation_objects_present(_rs())
