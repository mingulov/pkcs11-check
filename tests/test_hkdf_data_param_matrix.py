"""Pins for the HKDF-DATA salt/info/prf parameter matrix.

Each matrix row must reach C_DeriveKey with the exact CK_HKDF_PARAMS shape
(salt source, info presence, prf mechanism), derive twice for determinism,
and the HMAC-as-prf negative must reject cleanly. These tests drive the
real product nodes with stubbed derive/readback and decode the captured
mechanism params.
"""

from __future__ import annotations

import ctypes
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_HKDF_SALT_DATA,
    CKF_HKDF_SALT_KEY,
    CKF_HKDF_SALT_NULL,
    CKM_SHA256,
    CKM_SHA512,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_hkdf_extended as hkdf

_OUTPUT = b"\xab" * 32


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


def _stub_harness(monkeypatch: pytest.MonkeyPatch, derive: Any) -> list[dict[str, Any]]:
    """Stub base-key/readback/destroy plus the given derive impl; return the
    decoded per-call param shapes."""
    captured: list[dict[str, Any]] = []

    def _derive(*args: Any, **kwargs: Any) -> int:
        captured.append(_decode_hkdf(kwargs["mech_param"]))
        return derive(*args, **kwargs)

    base_handles = iter([7, 21])
    monkeypatch.setattr(hkdf, "_create_hkdf_data_base_or_xfail", lambda _rs: next(base_handles))
    monkeypatch.setattr(hkdf, "derive_key", _derive)
    monkeypatch.setattr(hkdf, "_read_hkdf_data_output", lambda *_a, **_k: _OUTPUT)
    monkeypatch.setattr(hkdf, "destroy_quietly", lambda *_a, **_k: None)
    return captured


def _derive_ok(*args: Any, **kwargs: Any) -> int:
    _derive_ok.counter += 1
    return 30 + _derive_ok.counter


_derive_ok.counter = 0


def _run_matrix_row(monkeypatch: pytest.MonkeyPatch, case_id: str) -> list[dict[str, Any]]:
    _derive_ok.counter = 0
    case = dict(hkdf._HKDF_DATA_MATRIX[case_id])
    captured = _stub_harness(monkeypatch, _derive_ok)
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
