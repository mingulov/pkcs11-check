"""F8 shape-contract regressions for raw DSS signatures (P11C-0198-002, P11C-0198-014).

A token-produced ECDSA/DSA signature must be validated as strict raw ``r || s``
before any scalar analysis: exactly ``2 * half_len`` bytes with
``0 < r,s < order``. A well-formed DER signature where PKCS#11 requires raw
encoding is an encoding/interoperability deviation (``honest_deviation``
XFAIL); wrong length, malformed encoding, or out-of-range scalars are
``wrong_result`` FAIL. No shape record may claim nonce reuse or key recovery.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.der import ecdsa_sig_to_der
from pkcs11_check.testcases._ec_export import SECP256R1_ORDER, parse_raw_dss_or_classify

_HALF = 32
_LABEL = "CKM_ECDSA:sign P-256 raw shape"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    classification.clear()
    yield
    classification.clear()


def _raw(r: int, s: int, half: int = _HALF) -> bytes:
    return r.to_bytes(half, "big") + s.to_bytes(half, "big")


def _parse(sig: bytes, *, half: int = _HALF, order: int = SECP256R1_ORDER) -> tuple[int, int]:
    return parse_raw_dss_or_classify(
        sig,
        half_len=half,
        order=order,
        label=_LABEL,
        operation="C_Sign",
        mechanism="CKM_ECDSA",
    )


def _last_record() -> classification.Classification:
    records = classification.get_records()
    assert len(records) == 1
    return records[0]


def test_p256_order_matches_fips1865() -> None:
    assert SECP256R1_ORDER == (0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)


def test_valid_raw_returns_scalars() -> None:
    r, s = SECP256R1_ORDER // 3, SECP256R1_ORDER // 2
    assert _parse(_raw(r, s)) == (r, s)
    assert classification.get_records() == []


def test_boundary_scalars_accepted() -> None:
    assert _parse(_raw(1, SECP256R1_ORDER - 1)) == (1, SECP256R1_ORDER - 1)
    assert classification.get_records() == []


@pytest.mark.parametrize("length", [0, 1, 63, 65, 128])
def test_wrong_length_is_wrong_result_fail(length: int) -> None:
    sig = b"\x01" * length
    with pytest.raises(Failed) as exc_info:
        _parse(sig)
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_ECDSA"
    assert record.detail is not None
    assert record.detail["expected_length"] == 64
    assert record.detail["actual_length"] == length
    assert str(length) in record.summary
    assert "64" in record.summary
    assert "nonce" not in record.summary.lower()
    assert "recover" not in record.summary.lower()


def test_zero_r_is_wrong_result_fail() -> None:
    with pytest.raises(Failed) as exc_info:
        _parse(_raw(0, 5))
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.detail is not None
    assert record.detail["r_in_range"] is False
    assert record.detail["s_in_range"] is True
    assert "out-of-range" in record.summary


def test_zero_s_is_wrong_result_fail() -> None:
    with pytest.raises(Failed):
        _parse(_raw(7, 0))
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.detail is not None
    assert record.detail["r_in_range"] is True
    assert record.detail["s_in_range"] is False


@pytest.mark.parametrize("r_s", ["r", "s"])
def test_scalar_at_order_is_wrong_result_fail(r_s: str) -> None:
    if r_s == "r":
        sig = _raw(SECP256R1_ORDER, 5)
    else:
        sig = _raw(5, SECP256R1_ORDER)
    with pytest.raises(Failed) as exc_info:
        _parse(sig)
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert "out-of-range" in record.summary


def test_scalar_above_order_is_wrong_result_fail() -> None:
    with pytest.raises(Failed):
        _parse(_raw(SECP256R1_ORDER + 5, 5))
    assert _last_record().reason == "wrong_result"


def test_der_shaped_output_is_honest_deviation_xfail() -> None:
    r, s = SECP256R1_ORDER // 3, SECP256R1_ORDER // 2
    der = ecdsa_sig_to_der(r, s)
    assert len(der) != 64
    with pytest.raises(XFailed):
        _parse(der)
    record = _last_record()
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_ECDSA"
    assert "DER" in record.summary
    assert "raw" in record.summary
    assert record.detail is not None
    assert record.detail["encoding"] == "der"
    assert record.detail["actual_length"] == len(der)


def test_short_der_is_still_encoding_deviation_not_length_fail() -> None:
    with pytest.raises(XFailed):
        _parse(ecdsa_sig_to_der(1, 2))
    assert _last_record().reason == "honest_deviation"


def test_der_with_out_of_range_scalar_is_wrong_result_fail() -> None:
    with pytest.raises(Failed) as exc_info:
        _parse(ecdsa_sig_to_der(0, 5))
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert "out-of-range" in record.summary


def test_truncated_der_is_malformed_fail() -> None:
    der = ecdsa_sig_to_der(SECP256R1_ORDER // 3, 5)
    with pytest.raises(Failed) as exc_info:
        _parse(der[:-1])
    assert not isinstance(exc_info.value, XFailed)
    assert _last_record().reason == "wrong_result"


def test_width_comes_from_half_len_not_fixed_slicing() -> None:
    q = int.from_bytes(b"\x11" * 28, "big")
    assert _parse(_raw(1000, 2000, half=28), half=28, order=q) == (1000, 2000)
    assert classification.get_records() == []
    with pytest.raises(Failed):
        _parse(_raw(1000, 2000), half=28, order=q)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.detail is not None
    assert record.detail["expected_length"] == 56
    assert record.detail["actual_length"] == 64
