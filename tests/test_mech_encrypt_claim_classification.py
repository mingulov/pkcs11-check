"""Meta-tests: test_mech_encrypt and test_mech_digest route refusals through the claim layer.

Sanctioned policy refusal (CKR_OPERATION_NOT_VALIDATED) -> PASS (+note); any
other clean CKR -> xfail (allowlist retired); wrong-output asserts still fail.
For digest: sanctioned refusal causes _digest_or_xfail to return None and the
calling test returns early (no digest comparison runs).
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
from pkcs11_check.testcases import test_mech_digest as tmd
from pkcs11_check.testcases import test_mech_encrypt as tme

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_validation_cache() -> None:
    cc.reset_validation_object_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _encrypt_entry() -> SimpleNamespace:
    return SimpleNamespace(
        mech_id=0x1082,
        mech_name="CKM_AES_CBC",
        config=SimpleNamespace(
            input_constraint=None,
            param_recipe=None,
            auth_tag_included=False,
            key_type=None,
            vector_file=None,
        ),
    )


def _digest_entry() -> SimpleNamespace:
    return SimpleNamespace(
        mech_id=0x220,  # CKM_SHA256
        mech_name="SHA256",
        config=SimpleNamespace(
            input_constraint=None,
            param_recipe=SimpleNamespace(style="none"),
            param_required=False,
            vector_file=None,
        ),
    )


def _wire_encrypt(
    monkeypatch: pytest.MonkeyPatch,
    *,
    encrypt: Any,
    decrypt: Any = lambda *a, **k: b"\x00" * 32,
) -> None:
    monkeypatch.setattr(tme, "generate_key_for_encrypt", lambda *a, **k: (1, None))
    monkeypatch.setattr(tme, "make_mech_param_or_skip", lambda entry: None)
    monkeypatch.setattr(tme, "get_test_plaintext_bytes", lambda: b"\x00" * 32)
    monkeypatch.setattr(tme, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(tme, "encrypt_single", encrypt)
    monkeypatch.setattr(tme, "decrypt_single", decrypt)


def _raise(rv: int, name: str) -> Any:
    def _f(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(f"Unexpected CK_RV {name}", int(rv))

    return _f


# ---------------------------------------------------------------------------
# test_mech_encrypt claim-layer tests
# ---------------------------------------------------------------------------


def test_encrypt_sanctioned_refusal_passes_with_note(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OPERATION_NOT_VALIDATED on encrypt -> test PASSES + compliance note."""
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    _wire_encrypt(
        monkeypatch,
        encrypt=_raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    tme.TestMechEncryptRoundtrip().test_roundtrip(_rs(), _encrypt_entry())  # no exception = PASS
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]
    assert "CKM_AES_CBC:encrypt" in notes[0]


def test_encrypt_unlisted_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any non-sanctioned clean CKR on encrypt -> xfail 'advertised but not operational'."""
    _wire_encrypt(
        monkeypatch,
        encrypt=_raise(int(CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID"),
    )
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        tme.TestMechEncryptRoundtrip().test_roundtrip(_rs(), _encrypt_entry())


def test_decrypt_sanctioned_refusal_passes_with_note(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OPERATION_NOT_VALIDATED on decrypt -> test PASSES + compliance note."""
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    _wire_encrypt(
        monkeypatch,
        encrypt=lambda *a, **k: b"\x00" * 32,
        decrypt=_raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    tme.TestMechEncryptRoundtrip().test_roundtrip(_rs(), _encrypt_entry())  # no exception = PASS
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]
    assert "CKM_AES_CBC:decrypt" in notes[0]


def test_decrypt_unlisted_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any non-sanctioned clean CKR on decrypt -> xfail 'advertised but not operational'."""
    _wire_encrypt(
        monkeypatch,
        encrypt=lambda *a, **k: b"\x00" * 32,
        decrypt=_raise(int(CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID"),
    )
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        tme.TestMechEncryptRoundtrip().test_roundtrip(_rs(), _encrypt_entry())


def test_encrypt_wrong_output_assert_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrong-output AssertionError propagates (harness bug path)."""

    def bad_encrypt(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("wrong output after encrypt")

    _wire_encrypt(monkeypatch, encrypt=bad_encrypt)
    with pytest.raises(AssertionError, match="wrong output"):
        tme.TestMechEncryptRoundtrip().test_roundtrip(_rs(), _encrypt_entry())


# ---------------------------------------------------------------------------
# test_mech_digest claim-layer tests
# ---------------------------------------------------------------------------


def test_digest_sanctioned_refusal_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OPERATION_NOT_VALIDATED on digest -> _digest_or_xfail returns None."""
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    monkeypatch.setattr(
        tmd,
        "digest_single",
        _raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    result = tmd._digest_or_xfail(_rs(), _digest_entry(), b"test")  # type: ignore[arg-type]
    assert result is None
    assert notes and "CKR_OPERATION_NOT_VALIDATED" in notes[0]


def test_digest_unlisted_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any non-sanctioned clean CKR -> xfail 'advertised but not operational'."""
    monkeypatch.setattr(
        tmd,
        "digest_single",
        _raise(int(CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID"),
    )
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        tmd._digest_or_xfail(_rs(), _digest_entry(), b"test")  # type: ignore[arg-type]


def test_digest_sanctioned_refusal_stops_test_early(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanctioned refusal in _digest_or_xfail -> test_known_empty returns before
    comparing digests (the compliance note is the finding, no comparison runs)."""
    notes: list[str] = []
    monkeypatch.setattr(
        cc.compliance,
        "note",
        lambda d, level, reference="", *, test_id="": notes.append(d),
    )
    monkeypatch.setattr(cc, "_validation_objects_present", lambda rs: "False")
    monkeypatch.setattr(
        tmd,
        "digest_single",
        _raise(int(CKR_OPERATION_NOT_VALIDATED), "CKR_OPERATION_NOT_VALIDATED"),
    )
    # If the early-return is missing, the test would fail with "digest output is zero bytes"
    # (None has no len()). The fact it returns cleanly proves early-return is in place.
    tmd.TestMechDigest().test_known_empty(_rs(), _digest_entry())  # type: ignore[arg-type]
    assert notes, "expected a compliance note to be recorded"
