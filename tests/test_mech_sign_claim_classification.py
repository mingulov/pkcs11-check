"""Meta-tests: test_mech_sign roundtrip routes refusals through the claim layer.

Sanctioned policy refusal -> PASS (+note); any other clean CKR -> xfail
(allowlist retired: previously-unlisted clean codes now xfail too); wrong
output and non-CKR errors still fail/propagate.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_OPERATION_NOT_VALIDATED,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import _capability_claims as cc
from pkcs11_check.testcases import test_mech_sign as tms


@pytest.fixture(autouse=True)
def _fresh_validation_cache() -> None:
    cc.reset_validation_object_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _entry() -> SimpleNamespace:
    return SimpleNamespace(
        mech_id=0x1,
        mech_name="CKM_TEST_SIGN",
        config=SimpleNamespace(input_constraint=None, param_recipe=None),
    )


def _wire(
    monkeypatch: pytest.MonkeyPatch, *, sign: Any, verify: Any = lambda *a, **k: True
) -> None:
    monkeypatch.setattr(tms, "generate_key_for_sign", lambda *a, **k: (1, 2))
    monkeypatch.setattr(tms, "make_mech_param_or_skip", lambda entry: None)
    monkeypatch.setattr(tms, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(tms, "sign_single", sign)
    monkeypatch.setattr(tms, "verify_single", verify)


def _raise(rv: int, name: str) -> Any:
    def _f(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(f"Unexpected CK_RV {name}", int(rv))

    return _f


def test_sanctioned_sign_refusal_passes_with_note(monkeypatch: pytest.MonkeyPatch) -> None:
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    _wire(
        monkeypatch,
        sign=_raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    tms.TestMechSignRoundtrip().test_roundtrip(_rs(), _entry())  # no exception = PASS
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]


def test_unlisted_clean_ckr_now_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allowlist retirement pinned: SESSION_HANDLE_INVALID was NOT in
    _SIGN_RUNTIME_REJECT_RVS and used to hard-fail; the model's positive-op
    row says any clean refusal is an honest deviation -> xfail."""
    _wire(
        monkeypatch,
        sign=_raise(int(CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID"),
    )
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        tms.TestMechSignRoundtrip().test_roundtrip(_rs(), _entry())


def test_verify_false_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, sign=lambda *a, **k: b"sig", verify=lambda *a, **k: False)
    with pytest.raises(AssertionError, match="verify failed"):
        tms.TestMechSignRoundtrip().test_roundtrip(_rs(), _entry())


# ---------------------------------------------------------------------------
# KAT loop single-note pinning (Step 3c)
# ---------------------------------------------------------------------------


def _kat_entry() -> SimpleNamespace:
    return SimpleNamespace(
        mech_id=0x2,
        mech_name="CKM_TEST_SIGN",
        config=SimpleNamespace(
            input_constraint=None,
            param_recipe=SimpleNamespace(style="none"),
            key_type=None,
            vector_file="fake_vectors.json",
        ),
    )


def test_kat_sanctioned_refusal_emits_exactly_one_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanctioned refusal on a KAT asymmetric sign -> test passes with exactly ONE note.

    Before the _run_asymmetric_sign_kat -> bool change, the calling loop continued
    to re-probe and append an identical note per remaining vector (report noise).
    """
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")

    # Two asymmetric vectors -- only the first should produce a note; the loop must exit.
    two_vectors = [
        {"key_type": "asymmetric", "n_hex": "aa" * 256, "input_hex": "bb" * 32},
        {"key_type": "asymmetric", "n_hex": "cc" * 256, "input_hex": "dd" * 32},
    ]

    # test_kat_vector does a local `from ...mechanism_vectors import load_positive_vectors`,
    # so the patch must land on the mechanism_vectors module, not on tms.
    import pkcs11_check.testcases.mechanism_vectors as mv

    monkeypatch.setattr(mv, "load_positive_vectors", lambda _f: two_vectors)

    # _run_asymmetric_sign_kat is called for each asymmetric vector; make it return True
    # (sanctioned refusal) on the first call to verify the loop terminates.
    call_count = {"n": 0}

    def fake_run_asymmetric(
        rs: Any, entry: Any, config: Any, vec: Any, p11_config: Any = None
    ) -> bool:
        call_count["n"] += 1
        # Simulate sanctioned refusal: emit note directly
        cc.compliance.note(
            f"{entry.mech_name}:kat-sign: refused via sanctioned CKR_OPERATION_NOT_VALIDATED "
            "(validation-policy refusal; CKO_VALIDATION objects present: False)",
            cc.ComplianceLevel.STANDARD,
            reference="PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED / Sec. 4.15",
        )
        return True  # sanctioned refusal seen

    monkeypatch.setattr(tms, "_run_asymmetric_sign_kat", fake_run_asymmetric)

    entry = _kat_entry()
    tms.TestMechSignKAT().test_kat_vector(_rs(), entry, None)

    # Only ONE call to _run_asymmetric_sign_kat (loop exited after first sanctioned refusal)
    assert call_count["n"] == 1, f"expected 1 call, got {call_count['n']}"
    # Exactly ONE note (no duplicate from second vector)
    assert len(notes) == 1, f"expected exactly 1 note, got {len(notes)}: {notes}"
    assert "CKR_OPERATION_NOT_VALIDATED" in notes[0]


def test_run_asymmetric_sign_kat_sanctioned_refusal_real_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real _run_asymmetric_sign_kat path: a sanctioned sign refusal returns True + one note.

    Drives the RSA deterministic (verify_only=False) branch: import the private
    key, then sign_single refuses with CKR_OPERATION_NOT_VALIDATED. The function
    must classify it via the claim layer (True) and emit exactly one note.
    """
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    monkeypatch.setattr(tms, "provision_rsa_private_key", lambda *a, **k: 7)
    monkeypatch.setattr(tms, "destroy_quietly", lambda *a, **k: None)
    # _run_asymmetric_sign_kat does a local import of build_params_from_vector,
    # so patch it on the source module.
    import pkcs11_check.testcases.mechanism_helpers as mh

    monkeypatch.setattr(mh, "build_params_from_vector", lambda *a, **k: None)
    monkeypatch.setattr(
        tms,
        "sign_single",
        _raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )

    # Minimal RSA vector with the hex fields _run_asymmetric_sign_kat reads
    # (verify_only absent -> deterministic sign-and-compare branch).
    vec = {
        "n_hex": "aa" * 256,
        "e_hex": "010001",
        "d_hex": "bb" * 256,
        "p_hex": "cc" * 128,
        "q_hex": "dd" * 128,
        "dmp1_hex": "ee" * 128,
        "dmq1_hex": "ff" * 128,
        "iqmp_hex": "11" * 128,
        "input_hex": "22" * 32,
        "signature_hex": "33" * 256,
    }
    entry = _kat_entry()
    result = tms._run_asymmetric_sign_kat(_rs(), entry, entry.config, vec, None)

    assert result is True
    assert len(notes) == 1, f"expected exactly 1 note, got {len(notes)}: {notes}"
    assert "CKR_OPERATION_NOT_VALIDATED" in notes[0]
