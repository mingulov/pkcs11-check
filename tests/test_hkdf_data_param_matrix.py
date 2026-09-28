"""Pins for the HKDF-DATA salt/info/prf parameter matrix.

Each matrix row must reach C_DeriveKey with the exact CK_HKDF_PARAMS shape
(salt source, info presence, prf mechanism), derive twice for determinism,
match the RFC 5869 oracle output, and the HMAC-as-prf negative must reject
cleanly. These tests drive the real product nodes with stubbed
derive/readback and decode the captured mechanism params.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable, Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKF_HKDF_SALT_DATA,
    CKF_HKDF_SALT_KEY,
    CKF_HKDF_SALT_NULL,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKM_SHA512,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_hkdf_extended as hkdf

_OUTPUT = b"\xab" * 32

# Nominal salt-key CKA_VALUE the readback stub returns: the default 32-byte
# IKM the matrix provisions for salt keys. Must equal hkdf._hkdf_base_ikm().
_NOMINAL_SALT_KEY_VALUE = bytes(range(32))


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def _decode_hkdf(mech_param: Any) -> dict[str, Any]:
    """Decode captured CK_HKDF_PARAMS to plain values."""
    params = mech_param.params
    salt = bytes(ctypes.string_at(params.pSalt, params.ulSaltLen)) if params.pSalt else None
    info = bytes(ctypes.string_at(params.pInfo, params.ulInfoLen)) if params.pInfo else None
    return {
        "prf": int(params.prfHashMechanism),
        "salt_type": int(params.ulSaltType),
        "salt_key": int(params.hSaltKey),
        "salt_ptr": params.pSalt is not None,
        "salt_len": int(params.ulSaltLen),
        "salt": salt,
        "info_ptr": params.pInfo is not None,
        "info_len": int(params.ulInfoLen),
        "info": info,
    }


def _stub_harness(
    monkeypatch: pytest.MonkeyPatch,
    derive: Callable[..., int],
    *,
    output: bytes = _OUTPUT,
    salt_value: Any = _NOMINAL_SALT_KEY_VALUE,
    salt_readable: bool = True,
) -> list[dict[str, Any]]:
    """Stub base-key/readback/destroy plus the given derive impl; return the
    decoded per-call param shapes."""
    captured: list[dict[str, Any]] = []

    def _derive(*args: Any, **kwargs: Any) -> int:
        captured.append(_decode_hkdf(kwargs["mech_param"]))
        return derive(*args, **kwargs)

    base_handles = iter([7, 21])

    def _fake_base(_rs: Any, **kwargs: Any) -> tuple[int, bytes]:
        return (
            next(base_handles),
            hkdf._hkdf_base_ikm(kwargs.get("key_len", hkdf._HKDF_BASE_KEY_LEN)),
        )

    monkeypatch.setattr(hkdf, "_create_hkdf_data_base_or_xfail", _fake_base)
    monkeypatch.setattr(hkdf, "derive_key", _derive)
    monkeypatch.setattr(hkdf, "_read_hkdf_data_output", lambda *_a, **_k: output)
    if salt_readable:
        salt_attrs: dict[Any, Any] = {CKA_VALUE: salt_value}
    else:
        # Faithful nonextractable-key shape: absent value plus the observed
        # conformant CKR_ATTRIBUTE_SENSITIVE refusal on the channel.
        unreadable = AttrReadResult()
        unreadable.refusals[CKA_VALUE] = AttrRefusal(ckr=int(CKR_ATTRIBUTE_SENSITIVE))
        salt_attrs = unreadable
    monkeypatch.setattr(hkdf, "read_attributes", lambda _raw, _sh, _h, _attrs: salt_attrs)
    monkeypatch.setattr(hkdf, "destroy_quietly", lambda *_a, **_k: None)
    return captured


class _DeriveOk:
    """Counting derive stub returning a distinct handle per call."""

    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, *args: Any, **kwargs: Any) -> int:
        self.counter += 1
        return 30 + self.counter


_derive_ok = _DeriveOk()


def _expected_output(case_id: str) -> bytes:
    """Oracle output for a matrix row under nominal provisioning."""
    case = hkdf._HKDF_DATA_MATRIX[case_id]
    hash_mech = case.get("hash_mech")
    ikm = hkdf._hkdf_base_ikm(hkdf._hkdf_matrix_base_key_len(hash_mech))
    salt = case["salt"]
    if case.get("needs_salt_key"):
        salt = _NOMINAL_SALT_KEY_VALUE
    return hkdf._hkdf_oracle(
        hash_mech=hash_mech,
        ikm=ikm,
        salt=salt,
        info=case["info"],
        length=hkdf._HKDF_DATA_OUTPUT_LEN,
    )


def _run_matrix_row(monkeypatch: pytest.MonkeyPatch, case_id: str) -> list[dict[str, Any]]:
    _derive_ok.counter = 0
    case = dict(hkdf._HKDF_DATA_MATRIX[case_id])
    captured = _stub_harness(monkeypatch, _derive_ok, output=_expected_output(case_id))
    hkdf.TestHKDFData().test_hkdf_data_param_matrix(_rs(), case)
    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    assert len(captured) == 2  # derived twice for determinism
    assert captured[0] == captured[1]
    return captured


def test_matrix_salt_null(monkeypatch: pytest.MonkeyPatch) -> None:
    shape = _run_matrix_row(monkeypatch, "salt-null")[0]
    assert shape["salt_type"] == int(CKF_HKDF_SALT_NULL)
    assert shape["salt_ptr"] is False
    assert shape["prf"] == int(CKM_SHA256)
    assert shape["info"] == b"info-value"


def test_matrix_salt_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    shape = _run_matrix_row(monkeypatch, "salt-empty")[0]
    assert shape["salt_type"] == int(CKF_HKDF_SALT_DATA)
    assert shape["salt_ptr"] is True
    assert shape["salt_len"] == 0
    assert shape["salt"] == b""


def test_matrix_salt_key(monkeypatch: pytest.MonkeyPatch) -> None:
    shape = _run_matrix_row(monkeypatch, "salt-key")[0]
    assert shape["salt_type"] == int(CKF_HKDF_SALT_KEY)
    assert shape["salt_key"] == 21
    assert shape["salt_ptr"] is False


def test_matrix_info_null(monkeypatch: pytest.MonkeyPatch) -> None:
    shape = _run_matrix_row(monkeypatch, "info-null")[0]
    assert shape["info_ptr"] is False
    assert shape["salt"] == b"salt-value"


def test_matrix_info_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    shape = _run_matrix_row(monkeypatch, "info-empty")[0]
    assert shape["info_ptr"] is True
    assert shape["info_len"] == 0
    assert shape["info"] == b""


def test_matrix_prf_sha512(monkeypatch: pytest.MonkeyPatch) -> None:
    shape = _run_matrix_row(monkeypatch, "prf-sha512")[0]
    assert shape["prf"] == int(CKM_SHA512)
    assert shape["salt"] == b"salt-value"
    assert shape["info"] == b"info-value"


def test_hmac_prf_rejected_on_clean_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """An HMAC prf mechanism must be cleanly rejected (pass)."""

    def _refuse(*args: Any, **kwargs: Any) -> int:
        raise CkrAssertionError("rejected", int(CKR_MECHANISM_PARAM_INVALID))

    captured = _stub_harness(monkeypatch, _refuse)
    hkdf.TestHKDFData().test_hkdf_data_hmac_prf_rejected(_rs())

    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    assert len(captured) == 1
    assert captured[0]["prf"] != int(CKM_SHA256)
    assert captured[0]["prf"] != int(CKM_SHA512)


def test_hmac_prf_acceptance_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that accepts an HMAC prf fails accepted_invalid."""

    def _accept(*args: Any, **kwargs: Any) -> int:
        return 33

    _stub_harness(monkeypatch, _accept)
    with pytest.raises(pytest.fail.Exception):
        hkdf.TestHKDFData().test_hkdf_data_hmac_prf_rejected(_rs())

    (rec,) = C.get_records()
    assert rec.reason == "accepted_invalid"
    assert rec.outcome == "fail"


def test_sha512_row_provisions_hash_sized_base_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The prf-sha512 row provisions a 64-byte GENERIC_SECRET base key."""
    output = _expected_output("prf-sha512")
    captured: list[tuple[int, bytes]] = []
    handles = iter([7])

    def _fake_import(_rs: Any, key_type: int, value: bytes, **kwargs: Any) -> int:
        captured.append((int(key_type), bytes(value)))
        return next(handles)

    derive_calls: list[dict[str, Any]] = []

    def _derive(*args: Any, **kwargs: Any) -> int:
        derive_calls.append(_decode_hkdf(kwargs["mech_param"]))
        _derive_ok.counter += 1
        return 30 + _derive_ok.counter

    _derive_ok.counter = 0
    monkeypatch.setattr(hkdf, "import_secret_key_negotiated", _fake_import)
    monkeypatch.setattr(hkdf, "derive_key", _derive)
    monkeypatch.setattr(hkdf, "_read_hkdf_data_output", lambda *_a, **_k: output)
    monkeypatch.setattr(hkdf, "destroy_quietly", lambda *_a, **_k: None)
    hkdf.TestHKDFData().test_hkdf_data_param_matrix(
        _rs(), dict(hkdf._HKDF_DATA_MATRIX["prf-sha512"])
    )
    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    assert len(derive_calls) == 2
    assert [(key_type, len(value)) for key_type, value in captured] == [
        (int(CKK_GENERIC_SECRET), 64)
    ]


def test_null_for_data_salt_substitution_caught_by_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output derived as if a DATA salt were NULL must fail the oracle check."""
    case = dict(hkdf._HKDF_DATA_MATRIX["info-null"])
    hash_mech = case.get("hash_mech")
    ikm = hkdf._hkdf_base_ikm(hkdf._hkdf_matrix_base_key_len(hash_mech))
    wrong = hkdf._hkdf_oracle(
        hash_mech=hash_mech,
        ikm=ikm,
        salt=None,
        info=case["info"],
        length=hkdf._HKDF_DATA_OUTPUT_LEN,
    )
    assert wrong != _expected_output("info-null")
    _derive_ok.counter = 0
    _stub_harness(monkeypatch, _derive_ok, output=wrong)
    with pytest.raises(pytest.fail.Exception):
        hkdf.TestHKDFData().test_hkdf_data_param_matrix(_rs(), case)
    (rec,) = C.get_records()
    assert rec.reason == "wrong_result"
    assert rec.outcome == "fail"


@pytest.mark.parametrize("hash_mech", [None, CKM_SHA512], ids=["sha256", "sha512"])
def test_null_and_empty_salt_oracle_values_match(hash_mech: Any) -> None:
    """NULL salt (HashLen zeros) and empty salt (empty HMAC key) are equivalent.

    HMAC zero-pads short keys to the block size, so the RFC 5869 section 2.2
    NULL-salt default and a zero-length DATA salt necessarily derive the same
    output; the oracle must not distinguish them.
    """
    ikm = hkdf._hkdf_base_ikm(hkdf._hkdf_matrix_base_key_len(hash_mech))
    kwargs: dict[str, Any] = {
        "hash_mech": hash_mech,
        "ikm": ikm,
        "info": b"info-value",
        "length": hkdf._HKDF_DATA_OUTPUT_LEN,
    }
    assert hkdf._hkdf_oracle(salt=None, **kwargs) == hkdf._hkdf_oracle(salt=b"", **kwargs)


def test_null_and_empty_info_oracle_values_match() -> None:
    """NULL and empty info are both empty info (NULL pInfo carries no bytes)."""
    ikm = hkdf._hkdf_base_ikm()
    kwargs: dict[str, Any] = {
        "hash_mech": None,
        "ikm": ikm,
        "salt": b"salt-value",
        "length": hkdf._HKDF_DATA_OUTPUT_LEN,
    }
    assert hkdf._hkdf_oracle(info=None, **kwargs) == hkdf._hkdf_oracle(info=b"", **kwargs)


def test_oracle_matches_rfc5869_test_case_1() -> None:
    """Pin the oracle against RFC 5869 Appendix A Test Case 1 (SHA-256)."""
    okm = hkdf._hkdf_oracle(
        hash_mech=None,
        ikm=b"\x0b" * 22,
        salt=bytes(range(13)),
        info=bytes(range(0xF0, 0xFA)),
        length=42,
    )
    expected = (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert okm.hex() == expected


def test_malformed_salt_key_readback_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-bytes salt-key CKA_VALUE is a hard metadata finding."""
    _derive_ok.counter = 0
    _stub_harness(
        monkeypatch, _derive_ok, output=_expected_output("salt-key"), salt_value="not-bytes"
    )
    with pytest.raises(pytest.fail.Exception):
        hkdf.TestHKDFData().test_hkdf_data_param_matrix(
            _rs(), dict(hkdf._HKDF_DATA_MATRIX["salt-key"])
        )
    (rec,) = C.get_records()
    assert rec.reason == "wrong_result"
    assert rec.kind == "metadata"
    assert rec.outcome == "fail"


def test_salt_key_nonextractable_correct_output_passes_without_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lawfully nonextractable salt key must not gate the oracle.

    The oracle feeds on the known imported bytes, so correct output passes
    with no not_operational record even when CKA_VALUE is unreadable.
    """
    _derive_ok.counter = 0
    _stub_harness(monkeypatch, _derive_ok, output=_expected_output("salt-key"), salt_readable=False)
    hkdf.TestHKDFData().test_hkdf_data_param_matrix(_rs(), dict(hkdf._HKDF_DATA_MATRIX["salt-key"]))
    assert [rec for rec in C.get_records() if rec.reason == "not_operational"] == []
    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    (observed,) = [rec for rec in C.get_records() if rec.reason == "sanctioned_refusal"]
    assert observed.outcome == "pass"


def test_salt_key_nonextractable_wrong_output_still_fails_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With an unreadable salt key the oracle still runs: wrong output fails."""
    expected = _expected_output("salt-key")
    wrong = bytes([expected[0] ^ 0x01]) + expected[1:]
    assert wrong != expected
    _derive_ok.counter = 0
    _stub_harness(monkeypatch, _derive_ok, output=wrong, salt_readable=False)
    with pytest.raises(pytest.fail.Exception):
        hkdf.TestHKDFData().test_hkdf_data_param_matrix(
            _rs(), dict(hkdf._HKDF_DATA_MATRIX["salt-key"])
        )
    records = C.get_records()
    assert [rec for rec in records if rec.reason == "not_operational"] == []
    (failed,) = [rec for rec in records if rec.outcome == "fail"]
    assert failed.reason == "wrong_result"
    (observed,) = [rec for rec in records if rec.reason == "sanctioned_refusal"]
    assert observed.outcome == "pass"


def test_salt_key_mismatched_readback_caught_by_consistency_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An extractable salt key whose CKA_VALUE differs from the imported bytes
    fails the separate consistency check (mechanism-free metadata)."""
    mismatched = bytes(32)
    assert mismatched != _NOMINAL_SALT_KEY_VALUE
    _derive_ok.counter = 0
    _stub_harness(
        monkeypatch,
        _derive_ok,
        output=_expected_output("salt-key"),
        salt_value=mismatched,
    )
    with pytest.raises(pytest.fail.Exception):
        hkdf.TestHKDFData().test_hkdf_data_param_matrix(
            _rs(), dict(hkdf._HKDF_DATA_MATRIX["salt-key"])
        )
    (rec,) = C.get_records()
    assert rec.reason == "wrong_result"
    assert rec.kind == "metadata"
    assert rec.outcome == "fail"
    assert rec.label == "CKM_HKDF_DATA matrix salt-key readback"
    assert rec.mechanism is None
