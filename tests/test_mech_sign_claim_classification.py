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
