"""Meta-tests: remaining test_mech_* suites route refusals through the claim layer.

Covers the two most distinct flows -- test_mech_derive (op-refusal in the test
method's outer except) and test_mech_wrap (op-refusal at the wrap/unwrap op
sites, with setup-stage keygen refusals left on their legacy helper). Sanctioned
policy refusal (CKR_OPERATION_NOT_VALIDATED) -> PASS (+note); any other clean
CKR -> xfail (per-suite allowlist retired).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_AES,
    CKM_AES_KEY_WRAP,
    CKM_SHA256_KEY_DERIVATION,
    CKR_OPERATION_NOT_VALIDATED,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import _capability_claims as cc
from pkcs11_check.testcases import test_mech_derive as tmder
from pkcs11_check.testcases import test_mech_wrap as tmw


@pytest.fixture(autouse=True)
def _fresh_validation_cache() -> None:
    cc.reset_validation_object_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _notes_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    return notes


def _raise(rv: int, name: str) -> Any:
    def _f(*_a: Any, **_k: Any) -> Any:
        raise CkrAssertionError(f"Unexpected CK_RV {name}", int(rv))

    return _f


# ---------------------------------------------------------------------------
# test_mech_derive
# ---------------------------------------------------------------------------


def _derive_entry() -> SimpleNamespace:
    return SimpleNamespace(
        mech_id=int(CKM_SHA256_KEY_DERIVATION),
        mech_name="CKM_SHA256_KEY_DERIVATION",
        config=SimpleNamespace(),
    )


def _wire_derive(monkeypatch: pytest.MonkeyPatch, *, derive: Any) -> None:
    monkeypatch.setattr(tmder, "gen_generic_secret", lambda *a, **k: 1)
    monkeypatch.setattr(tmder, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(tmder, "derive_key", derive)


def test_derive_sanctioned_refusal_passes_with_note(monkeypatch: pytest.MonkeyPatch) -> None:
    notes = _notes_spy(monkeypatch)
    _wire_derive(
        monkeypatch,
        derive=_raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    tmder.TestMechDerive().test_derive_produces_key(_rs(), _derive_entry())  # no exc = PASS
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]
    assert "CKM_SHA256_KEY_DERIVATION:derive" in notes[0]


def test_derive_unlisted_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_derive(
        monkeypatch,
        derive=_raise(int(CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID"),
    )
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        tmder.TestMechDerive().test_derive_produces_key(_rs(), _derive_entry())


# ---------------------------------------------------------------------------
# test_mech_wrap
# ---------------------------------------------------------------------------


def _wrap_entry() -> SimpleNamespace:
    return SimpleNamespace(
        mech_id=int(CKM_AES_KEY_WRAP),
        mech_name="CKM_AES_KEY_WRAP",
        config=SimpleNamespace(
            key_type=int(CKK_AES),
            key_sizes=None,
            param_recipe=SimpleNamespace(style="none"),
            param_required=False,
            input_constraint=None,
        ),
    )


def _wire_wrap(monkeypatch: pytest.MonkeyPatch, *, wrap: Any) -> None:
    monkeypatch.setattr(tmw, "gen_aes_key", lambda *a, **k: 1)
    monkeypatch.setattr(tmw, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(tmw, "read_attributes", lambda *a, **k: {})
    monkeypatch.setattr(tmw, "encrypt_single", lambda *a, **k: b"\x00" * 16)
    monkeypatch.setattr(tmw, "wrap_key", wrap)


def test_wrap_sanctioned_refusal_passes_with_note(monkeypatch: pytest.MonkeyPatch) -> None:
    notes = _notes_spy(monkeypatch)
    _wire_wrap(
        monkeypatch,
        wrap=_raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    tmw.TestMechWrapRoundtrip().test_wrap_unwrap_aes_key(
        _rs(), SimpleNamespace(), _wrap_entry()
    )  # no exc = PASS
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]
    assert "CKM_AES_KEY_WRAP:wrap" in notes[0]


def test_wrap_unlisted_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_wrap(
        monkeypatch,
        wrap=_raise(int(CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID"),
    )
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        tmw.TestMechWrapRoundtrip().test_wrap_unwrap_aes_key(
            _rs(), SimpleNamespace(), _wrap_entry()
        )
