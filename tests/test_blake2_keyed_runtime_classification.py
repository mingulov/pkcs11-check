"""Regression tests for keyed BLAKE2b coverage and classification."""

from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_blake2


def test_blake2b_keyed_cases_cover_all_output_sizes() -> None:
    assert {case.bits for case in test_blake2._BLAKE2B_KEYED_CASES} == {160, 256, 384, 512}


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_blake2b_hmac_reference_matches_python_hmac() -> None:
    key = b"blake2 hmac key"
    data = b"blake2 hmac data"
    digest_size = 32

    def _digest(payload: bytes = b"") -> Any:
        return hashlib.blake2b(payload, digest_size=digest_size)

    expected = hmac.new(key, data, _digest).digest()

    assert test_blake2._blake2b_hmac_reference(key, data, digest_size) == expected


def test_blake2b_hmac_general_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reject)

    with pytest.raises(pytest.xfail.Exception, match="BLAKE2B_256_HMAC_GENERAL advertised"):
        test_blake2.TestBlake2bKeyed()._hmac_general_truncates(
            rs,
            test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256],
        )


@pytest.mark.parametrize("mac_len", (1, 32))
def test_blake2b_hmac_general_boundary_lengths_match_reference(
    monkeypatch: pytest.MonkeyPatch,
    mac_len: int,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    expected = test_blake2._blake2b_hmac_reference(
        test_blake2._BLAKE2B_TEST_KEY,
        test_blake2._BLAKE2B_TEST_DATA,
        case.digest_len,
    )[:mac_len]
    signed: list[bytes] = []

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        signed.append(expected)
        return expected

    def _verify_reference(*_args: Any, **_kwargs: Any) -> bool:
        return True

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_reference)

    test_blake2.TestBlake2bKeyed()._hmac_general_matches_reference(
        rs,
        case,
        mac_len=mac_len,
    )

    assert signed == [expected]


def test_blake2b_hmac_general_invalid_length_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_accepts_invalid_length(*_args: Any, **_kwargs: Any) -> bytes:
        return b"invalid"

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_accepts_invalid_length)

    with pytest.raises(AssertionError, match="accepted invalid BLAKE2B_256_HMAC_GENERAL"):
        test_blake2.TestBlake2bKeyed()._hmac_general_invalid_length_rejected(
            rs,
            test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256],
            bad_len=0,
        )


def test_blake2b_hmac_general_wrong_length_mac_variants_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    mac = b"\x5a" * 12
    verified: list[bytes] = []

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        return mac

    def _verify_rejects(
        _raw: Any,
        _sh: int,
        _key: int,
        _mech: Any,
        _data: bytes,
        sig: bytes,
        **_kwargs: Any,
    ) -> bool:
        verified.append(sig)
        return False

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_rejects)

    test_blake2.TestBlake2bKeyed()._hmac_general_rejects_wrong_length_mac(
        rs,
        case,
        mac_len=12,
    )

    assert verified == [mac + b"\x00", mac[:-1]]


def test_blake2b_hmac_general_wrong_length_mac_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]

    def _sign_reference(*_args: Any, **_kwargs: Any) -> bytes:
        return b"\xa5" * 12

    def _verify_accepts(*_args: Any, **_kwargs: Any) -> bool:
        return True

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reference)
    monkeypatch.setattr(test_blake2, "verify_single", _verify_accepts)

    with pytest.raises(AssertionError, match="accepted wrong-length BLAKE2B_256_HMAC_GENERAL"):
        test_blake2.TestBlake2bKeyed()._hmac_general_rejects_wrong_length_mac(
            rs,
            case,
            mac_len=12,
        )


def test_blake2b_key_derive_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)

    with pytest.raises(pytest.xfail.Exception, match="BLAKE2B_256_KEY_DERIVE advertised"):
        test_blake2.TestBlake2bKeyed()._key_derive_value(
            rs,
            test_blake2._BLAKE2B_KEYED_CASE_BY_BITS[256],
        )
