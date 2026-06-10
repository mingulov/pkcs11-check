"""Regression test for PC-4.3: RSA-OAEP wrap/unwrap lifecycle legs that return
a clean reject must classify via the claim layer, not a hard fail.

Originally this pinned the retired ``_RSA_OAEP_RUNTIME_REJECT_RVS`` allowlist.
Under the advertised-capability-honesty model the lifecycle OAEP wrap leg routes
through ``claim_refusal_passes`` with ``probe_key="CKM_RSA_PKCS_OAEP:wrap"``
and the unwrap leg with ``probe_key="CKM_RSA_PKCS_OAEP:unwrap"``.  A clean
``CKR_OPERATION_NOT_VALIDATED`` is a sanctioned policy refusal -> the test PASSES
with a note; any other clean CKR (e.g. ``CKR_ARGUMENTS_BAD``, ``CKR_DEVICE_ERROR``)
-> xfail (advertised but not operational, no CKR allowlist); a non-CKR assert
propagates.

Catalog: PC-4.3, softhsm2-recheck-20260528 evidence shows
``CkrAssertionError(rv=CKR_ARGUMENTS_BAD)`` at the wrap_key call site in
``test_mech_lifecycle.py``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_OPERATION_NOT_VALIDATED,
)
from pkcs11_check.testcases import _capability_claims as cc
from pkcs11_check.testcases import test_mech_lifecycle


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


@pytest.fixture(autouse=True)
def _fresh_validation_cache() -> None:
    cc.reset_validation_object_cache()


def _exc(rv: int, ckr_name: str) -> CkrAssertionError:
    return CkrAssertionError(f"Unexpected CK_RV {ckr_name}; expected one of: CKR_OK", rv)


def test_wrap_reject_xfails() -> None:
    """A clean OAEP wrap reject (CKR_ARGUMENTS_BAD) -> xfail at the claim layer."""
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        cc.claim_refusal_passes(
            _exc(int(CKR_ARGUMENTS_BAD), "CKR_ARGUMENTS_BAD"),
            _rs(),
            probe_key="CKM_RSA_PKCS_OAEP:encrypt",
        )


def test_unknown_ckr_also_xfails() -> None:
    """Allowlist retired: CKR_DEVICE_ERROR (previously unlisted) now also xfails."""
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        cc.claim_refusal_passes(
            _exc(int(CKR_DEVICE_ERROR), "CKR_DEVICE_ERROR"),
            _rs(),
            probe_key="CKM_RSA_PKCS_OAEP:encrypt",
        )


def test_sanctioned_refusal_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OPERATION_NOT_VALIDATED -> sanctioned policy refusal -> PASS (+note)."""
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    assert (
        cc.claim_refusal_passes(
            _exc(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
            _rs(),
            probe_key="CKM_RSA_PKCS_OAEP:encrypt",
        )
        is True
    )
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]


def test_non_ckr_propagates() -> None:
    """A non-CKR assert (harness bug / wrong output) must propagate, never xfail."""

    def boom() -> Any:
        cc.claim_refusal_passes(
            AssertionError("wrong plaintext after unwrap"),
            _rs(),
            probe_key="CKM_RSA_PKCS_OAEP:encrypt",
        )

    with pytest.raises(AssertionError, match="wrong plaintext"):
        boom()


def test_lifecycle_wrap_sanctioned_refusal_uses_wrap_probe_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: wrap leg CKR_OPERATION_NOT_VALIDATED -> PASS; note contains ':wrap'.

    Drives the real ``TestRSAOAEPWrapLifecycle.test_rsa_oaep_wrap_aes_roundtrip``
    with all PKCS#11 boundary helpers monkeypatched.  The wrap_key call raises
    CKR_OPERATION_NOT_VALIDATED; the test must return immediately (PASS) with
    exactly one compliance note whose probe key is ``CKM_RSA_PKCS_OAEP:wrap``,
    not the old copy-paste value ``CKM_RSA_PKCS_OAEP:encrypt``.
    """
    # Session that advertises all mechanisms required by the lifecycle test
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: (
            name in {"RSA_PKCS_KEY_PAIR_GEN", "RSA_PKCS_OAEP", "AES_ECB", "AES_KEY_GEN"}
        ),
    )

    # Setup helpers succeed -- keygen returns dummy handles
    monkeypatch.setattr(test_mech_lifecycle, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_mech_lifecycle, "gen_aes_key_or_xfail", lambda *_a, **_k: 3)
    # Initial AES-ECB encrypt succeeds (needed to reach the wrap call)
    monkeypatch.setattr(test_mech_lifecycle, "encrypt_single", lambda *_a, **_k: b"\xcc" * 16)

    # wrap_key raises CKR_OPERATION_NOT_VALIDATED (sanctioned policy refusal)
    def _wrap_not_validated(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_OPERATION_NOT_VALIDATED; expected one of: CKR_OK",
            int(CKR_OPERATION_NOT_VALIDATED),
        )

    monkeypatch.setattr(test_mech_lifecycle, "wrap_key", _wrap_not_validated)
    monkeypatch.setattr(test_mech_lifecycle, "destroy_quietly", lambda *_a, **_k: None)

    # Capture compliance notes + suppress CKO_VALIDATION probe
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda _rs: "False")

    # The lifecycle test must return cleanly (PASS) -- no exception
    test_mech_lifecycle.TestRSAOAEPWrapLifecycle().test_rsa_oaep_wrap_aes_roundtrip(rs)

    # Exactly one note must have been emitted
    assert len(notes) == 1, f"expected 1 note, got {len(notes)}: {notes}"
    # The probe key must be the wrap-leg key, NOT the old ':encrypt' copy-paste
    assert ":wrap" in notes[0], f"probe key in note should contain ':wrap' but got: {notes[0]!r}"
