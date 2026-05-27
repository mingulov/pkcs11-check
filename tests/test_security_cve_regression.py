"""Regression tests for security CVE testcase behavior."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_NOT_WRAPPABLE,
)
from pkcs11_check.testcases.security import test_cve_regression


class _EncryptStateRaw:
    def __init__(self) -> None:
        self.active = False
        self.abort_count = 0

    def C_EncryptFinal(self, *_args: Any) -> int:  # noqa: N802 - raw PKCS#11 API shape
        self.active = False
        self.abort_count += 1
        return 0


class _KeygenRejectRaw(_EncryptStateRaw):
    def C_GenerateKey(self, *_args: Any) -> int:  # noqa: N802 - raw PKCS#11 API shape
        return int(CKR_FUNCTION_NOT_SUPPORTED)


def _session(raw: Any, *mechanisms: str) -> SimpleNamespace:
    supported = set(mechanisms) or {
        "AES_ECB",
        "AES_KEY_GEN",
        "RSA_PKCS_KEY_PAIR_GEN",
        "SHA256_RSA_PKCS",
    }
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: name in supported)


def _raise_function_not_supported(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )


def _run_tookan_sensitive_unwrap_until_wrap(
    monkeypatch: pytest.MonkeyPatch,
    wrap_exc: CkrAssertionError,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_cve_regression,
        "wrap_key_recipe",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(wrap_exc),
    )

    test_cve_regression.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(
        _session(_EncryptStateRaw(), "AES_KEY_WRAP", "AES_KEY_GEN")
    )


def test_aes_ecb_boundary_lengths_aborts_after_rejected_invalid_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _encrypt_single(_raw: Any, _sh: int, _key: int, _mech: int, data: bytes) -> bytes:
        if raw.active:
            raise AssertionError("Unexpected CK_RV CKR_OPERATION_ACTIVE")
        if len(data) % 16 != 0 or len(data) == 0:
            raw.active = True
            raise AssertionError("Unexpected CK_RV CKR_DATA_LEN_RANGE")
        return data

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "encrypt_single", _encrypt_single)
    monkeypatch.setattr(test_cve_regression, "decrypt_single", lambda *_args: _args[4])
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)

    test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(_session(raw))

    assert raw.abort_count >= 4


def test_aes_ecb_boundary_lengths_fails_when_nonaligned_input_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _encrypt_single(_raw: Any, _sh: int, _key: int, _mech: int, data: bytes) -> bytes:
        if len(data) % 16 == 0 and len(data) > 0:
            return data
        if len(data) == 1:
            return b"accepted"
        raise AssertionError("Unexpected CK_RV CKR_DATA_LEN_RANGE")

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "encrypt_single", _encrypt_single)
    monkeypatch.setattr(test_cve_regression, "decrypt_single", lambda *_args: _args[4])
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="accepted non-block-aligned"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(_session(raw))


def test_aes_ecb_boundary_lengths_skips_without_aes_ecb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES setup should not run without AES_ECB")

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", _unexpected_keygen)

    with pytest.raises(pytest.skip.Exception, match="AES_ECB not supported"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(
            _session(raw, "AES_KEY_GEN")
        )


def test_aes_ecb_boundary_lengths_xfails_when_advertised_keygen_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", _raise_function_not_supported)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(
            _session(_EncryptStateRaw(), "AES_ECB", "AES_KEY_GEN")
        )


def test_tookan_sensitive_unwrap_skips_explicit_key_not_wrappable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(pytest.skip.Exception, match="cannot wrap SENSITIVE=True"):
        _run_tookan_sensitive_unwrap_until_wrap(
            monkeypatch,
            CkrAssertionError(
                "Unexpected CK_RV CKR_KEY_NOT_WRAPPABLE",
                int(CKR_KEY_NOT_WRAPPABLE),
            ),
        )


def test_tookan_sensitive_unwrap_xfails_generic_wrap_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_cve_regression.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="sensitive-key wrap rejected"):
        _run_tookan_sensitive_unwrap_until_wrap(
            monkeypatch,
            CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR)),
        )


def test_rapid_sign_skips_without_sha256_rsa_pkcs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("RSA setup should not run without SHA256_RSA_PKCS")

    monkeypatch.setattr(test_cve_regression, "gen_rsa_keypair", _unexpected_keypair)

    with pytest.raises(pytest.skip.Exception, match="SHA256_RSA_PKCS not supported"):
        test_cve_regression.TestTPM2Issue44().test_rapid_sign_no_deadlock(
            _session(_EncryptStateRaw(), "RSA_PKCS_KEY_PAIR_GEN")
        )


def test_rapid_sign_xfails_when_advertised_rsa_keygen_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_rsa_keypair", _raise_function_not_supported)

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_cve_regression.TestTPM2Issue44().test_rapid_sign_no_deadlock(
            _session(_EncryptStateRaw(), "RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")
        )


def test_session_objects_after_logout_xfails_when_advertised_aes_keygen_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cve_regression, "get_pin_bytes", lambda _config: b"1234")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(_KeygenRejectRaw(), "AES_KEY_GEN"),
            SimpleNamespace(pin="1234"),
        )
