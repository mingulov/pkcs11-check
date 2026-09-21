"""H-2 remainder: CKR_ENCRYPT empty-input oracles are inverted (live false pass).

Empty ECB plaintext, 15-byte CBC_PAD input, and empty GCM plaintext with AAD
are all VALID inputs (CKR_OK is spec-correct), but the CKR_ENCRYPT table
blessed rejection with CKR_DATA_LEN_RANGE as the spec-preferred outcome --
and the live tests passed such rejections through assert_ckr. The inverted
entries are removed; the live tests are positive tests now (mirroring
testcases/test_errors.py::_xfail_on_empty_input_reject): CKR_OK with the
correct output length passes, a clean reject xfails as a noted deviation,
and wrong output fails.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKR_DATA_LEN_RANGE,
    CKR_OK,
)
from pkcs11_check.testcases.ckr import test_ckr_encrypt as enc
from pkcs11_check.testcases.ckr._ckr_spec import CKR_ENCRYPT

_UNDEFINED_RV = 0x7FFFFFFF


@pytest.mark.parametrize("key", ["data_empty", "data_invalid_cbc_padding", "data_gcm_aad_only"])
def test_inverted_empty_input_oracle_removed(key: str) -> None:
    """An entry blessing rejection of valid input must not exist to consult."""
    assert key not in CKR_ENCRYPT


def _session_with_raw(raw: Any) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: True)


def _scripted_encrypt(script: list[tuple[int, int]]) -> Any:
    """Fake C_Encrypt: pop ``(rv, out_len)`` per call, writing out_len."""

    calls = list(script)

    def _call(*args: Any) -> int:
        rv, length = calls.pop(0)
        ctypes.cast(args[-1], ctypes.POINTER(CK_ULONG)).contents.value = length
        return int(rv)

    return _call


def _stub_key_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enc, "gen_aes_key_or_xfail", lambda *_a, **_k: 7)
    monkeypatch.setattr(enc, "destroy_quietly", lambda *_a, **_k: None)


def _raw(reject_rv: int | None, out_len: int) -> SimpleNamespace:
    script = [(int(CKR_OK), out_len)] if reject_rv is None else [(int(reject_rv), out_len)]
    return SimpleNamespace(
        C_EncryptInit=lambda *_a: int(CKR_OK),
        C_Encrypt=_scripted_encrypt(script),
    )


def test_empty_data_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rejecting valid empty ECB input is a deviation, not a spec-correct pass."""
    _stub_key_setup(monkeypatch)
    rs = _session_with_raw(_raw(int(CKR_DATA_LEN_RANGE), 0))

    with pytest.raises(XFailed):
        enc.TestEncryptDataErrors().test_empty_data(rs, False)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "C_Encrypt of empty data under AES-ECB"
    assert record.mechanism == "AES_ECB"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_DATA_LEN_RANGE"
    assert record.summary == (
        "C_Encrypt of empty data under AES-ECB: rejected well-defined "
        "empty input with CKR_DATA_LEN_RANGE, expected CKR_OK"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_Encrypt · AES_ECB"
    assert record.detail is None


def test_empty_data_happy_path_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty ECB plaintext yielding empty ciphertext is the correct outcome."""
    _stub_key_setup(monkeypatch)
    rs = _session_with_raw(_raw(None, 0))

    enc.TestEncryptDataErrors().test_empty_data(rs, False)

    assert C.get_records() == []


def test_empty_data_wrong_length_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """ECB CKR_OK with nonzero output for empty input is wrong output (fail)."""
    _stub_key_setup(monkeypatch)
    rs = _session_with_raw(_raw(None, 16))

    with pytest.raises(Failed) as ei:
        enc.TestEncryptDataErrors().test_empty_data(rs, False)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.severity == "CRITICAL"
    assert record.kind == "crypto"
    assert record.label == "C_Encrypt of empty data under AES-ECB"
    assert record.mechanism == "AES_ECB"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr is None
    assert record.actual_ckr == "16 bytes"


def test_empty_data_undefined_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """An undefined CK_RV answering valid input violates the RV contract."""
    _stub_key_setup(monkeypatch)
    rs = _session_with_raw(_raw(_UNDEFINED_RV, 0))

    with pytest.raises(Failed) as ei:
        enc.TestEncryptDataErrors().test_empty_data(rs, False)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].outcome == "fail"


def test_cbc_pad_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rejecting valid 15-byte CBC_PAD input is a deviation, not a pass."""
    _stub_key_setup(monkeypatch)
    rs = _session_with_raw(_raw(int(CKR_DATA_LEN_RANGE), 0))

    with pytest.raises(XFailed):
        enc.TestEncryptDataErrors().test_cbc_pad_non_aligned(rs, False)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "C_Encrypt of 15-byte data under AES-CBC-PAD"
    assert record.mechanism == "AES_CBC_PAD"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_DATA_LEN_RANGE"
    assert record.summary == (
        "C_Encrypt of 15-byte data under AES-CBC-PAD: rejected well-defined "
        "15-byte input with CKR_DATA_LEN_RANGE, expected CKR_OK"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_Encrypt · AES_CBC_PAD"
    assert record.detail is None


def test_cbc_pad_happy_path_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """15-byte CBC_PAD input yielding one 16-byte block is correct."""
    _stub_key_setup(monkeypatch)
    rs = _session_with_raw(_raw(None, 16))

    enc.TestEncryptDataErrors().test_cbc_pad_non_aligned(rs, False)

    assert C.get_records() == []


def test_cbc_pad_wrong_length_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """CBC_PAD CKR_OK with anything but one block is wrong output (fail)."""
    _stub_key_setup(monkeypatch)
    rs = _session_with_raw(_raw(None, 32))

    with pytest.raises(Failed) as ei:
        enc.TestEncryptDataErrors().test_cbc_pad_non_aligned(rs, False)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.severity == "CRITICAL"
    assert record.kind == "crypto"
    assert record.label == "C_Encrypt of 15-byte data under AES-CBC-PAD"
    assert record.mechanism == "AES_CBC_PAD"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr is None
    assert record.actual_ckr == "32 bytes"
