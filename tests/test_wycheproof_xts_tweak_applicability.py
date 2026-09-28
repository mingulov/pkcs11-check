"""Pins for Wycheproof XTS tweak applicability.

PKCS#11 fixes the CKM_AES_XTS tweak at 16 bytes, so a corpus-positive
vector with any other tweak length is inapplicable -- it must skip with a
precise reason, not xfail as provider non-operability. Short-tweak
rejection itself is covered by a dedicated malformed-parameter negative.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_MECHANISM_PARAM_INVALID
from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as xts


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def _vec(tweak_len: int, result: str = "valid") -> dict[str, Any]:
    return {
        "key": "ee" * 64,
        "iv": "ab" * tweak_len,
        "msg": "cc" * 16,
        "ct": "dd" * 16,
        "result": result,
    }


@pytest.mark.parametrize("tweak_len", [1, 8, 15, 17])
def test_valid_short_tweak_vector_skips_as_inapplicable(tweak_len: int) -> None:
    """Corpus-positive vectors with non-16-byte tweaks skip -- they cannot
    establish provider non-operability."""
    with pytest.raises(pytest.skip.Exception, match="inexpressible in PKCS#11"):
        xts.test_aes_xts(_rs(), f"tc-short-{tweak_len}", _vec(tweak_len))
    assert C.get_records() == []


def test_valid_16_byte_tweak_vector_still_runs_kat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 16-byte-tweak positive vector still runs the output comparison."""
    monkeypatch.setattr(xts, "import_secret_key_negotiated", lambda *_a, **_k: 11)
    monkeypatch.setattr(xts, "encrypt_single", lambda *_a, **_k: bytes.fromhex("dd" * 16))
    monkeypatch.setattr(xts, "destroy_quietly", lambda *_a, **_k: None)

    xts.test_aes_xts(_rs(), "tc-16", _vec(16))

    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []


def test_invalid_short_tweak_vector_is_not_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid-labeled short-tweak vectors still exercise the rejection
    path instead of skipping."""
    monkeypatch.setattr(xts, "import_secret_key_negotiated", lambda *_a, **_k: 11)

    def _reject(*args: Any, **kwargs: Any) -> bytes:
        raise CkrAssertionError("rejected", int(CKR_MECHANISM_PARAM_INVALID))

    monkeypatch.setattr(xts, "encrypt_single", _reject)
    monkeypatch.setattr(xts, "destroy_quietly", lambda *_a, **_k: None)
    reached: list[str] = []
    monkeypatch.setattr(
        xts,
        "xfail_vacuous_reject",
        lambda _op, label: reached.append(label),
    )
    monkeypatch.setattr(xts, "xts_encrypt_operability", lambda _rs: True)

    xts.test_aes_xts(_rs(), "tc-invalid-short", _vec(15, result="invalid"))

    assert len(reached) == 1


def test_short_tweak_negative_passes_on_clean_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dedicated short-tweak negative passes on a clean rejection and
    sends the exact short tweak bytes."""

    def _reject(*args: Any, **kwargs: Any) -> bytes:
        mech_param = kwargs.get("mech_param")
        assert mech_param is not None
        import ctypes

        assert int(mech_param.ck.ulParameterLen) == 15
        assert bytes(ctypes.string_at(mech_param.ck.pParameter, 15)) == b"\x05" * 15
        raise CkrAssertionError("rejected", int(CKR_MECHANISM_PARAM_INVALID))

    monkeypatch.setattr(xts, "import_secret_key_negotiated", lambda *_a, **_k: 11)
    monkeypatch.setattr(xts, "encrypt_single", _reject)
    monkeypatch.setattr(xts, "destroy_quietly", lambda *_a, **_k: None)

    xts.test_aes_xts_short_tweak_rejected(_rs())

    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []


def test_short_tweak_negative_fails_on_accept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module accepting a short tweak fails accepted_invalid."""

    def _accept(*args: Any, **kwargs: Any) -> bytes:
        return b"\x00" * 16

    monkeypatch.setattr(xts, "import_secret_key_negotiated", lambda *_a, **_k: 11)
    monkeypatch.setattr(xts, "encrypt_single", _accept)
    monkeypatch.setattr(xts, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        xts.test_aes_xts_short_tweak_rejected(_rs())

    (rec,) = C.get_records()
    assert rec.reason == "accepted_invalid"
    assert rec.outcome == "fail"
    assert rec.expected_ckr == ["CKR_MECHANISM_PARAM_INVALID"]
    assert rec.actual_ckr == "CKR_OK"
