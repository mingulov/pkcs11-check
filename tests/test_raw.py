"""Tests for the pkcs11_check.raw package and helpers."""

from __future__ import annotations

import ctypes

import pytest


def test_raw_package_exports_core_symbols() -> None:
    from pkcs11_check.raw import CK_ATTRIBUTE, CK_MECHANISM, RawPKCS11
    from pkcs11_check.raw.api import RawPKCS11 as ApiRawPKCS11
    from pkcs11_check.raw.types_std import CKR_OK

    assert RawPKCS11 is not None
    assert RawPKCS11 is ApiRawPKCS11
    assert CK_MECHANISM is not None
    assert CK_ATTRIBUTE is not None
    assert CKR_OK == 0


def test_cktemplate_builds_array_and_keeps_native_lengths() -> None:
    from pkcs11_check.raw import CK_ATTRIBUTE
    from pkcs11_check.raw.pack import TemplateArg, attr_bool, attr_bytes, attr_ulong

    template = TemplateArg(
        attr_ulong(0x0000, 4),
        attr_bool(0x0104, True),
        attr_bytes(0x0011, b"abc"),
    )

    assert template.count == 3
    assert isinstance(template.array[0], CK_ATTRIBUTE)
    assert template.array[0].type == 0x0000
    assert template.array[0].ulValueLen == ctypes.sizeof(ctypes.c_ulong)
    assert template.array[1].ulValueLen == ctypes.sizeof(ctypes.c_ubyte)
    assert template.array[2].ulValueLen == 3
    assert template.ptr is not None


def test_mech_simple_sets_null_parameter() -> None:
    from pkcs11_check.raw import CK_MECHANISM
    from pkcs11_check.raw.pack import mech_simple

    mech = mech_simple(0x1080)

    assert isinstance(mech.ck, CK_MECHANISM)
    assert mech.ck.mechanism == 0x1080
    assert mech.ck.pParameter is None
    assert mech.ck.ulParameterLen == 0


def test_expect_rv_allows_expected_values() -> None:
    from pkcs11_check.raw.rv import expect_rv

    assert expect_rv(0x00000000, 0x00000000) == 0x00000000
    assert expect_rv(0x00000007, 0x00000000, 0x00000007) == 0x00000007


def test_expect_rv_raises_for_unexpected_value() -> None:
    from pkcs11_check.raw.rv import expect_rv

    with pytest.raises(AssertionError, match="CKR_ARGUMENTS_BAD"):
        expect_rv(0x00000007, 0x00000000)


def test_expect_rv_attaches_rv_to_exception() -> None:
    """CkrAssertionError carries the offending CKR int so callers can match by value."""
    from pkcs11_check.raw.rv import CkrAssertionError, expect_rv

    with pytest.raises(CkrAssertionError) as exc_info:
        expect_rv(0x00000007, 0x00000000)
    assert exc_info.value.rv == 0x00000007


def test_is_known_error_uses_exact_rv_match_when_available() -> None:
    """``CKR_MECHANISM_INVALID`` must not falsely match against
    ``CKR_MECHANISM_PARAM_INVALID``: with exact-rv matching, the prefix
    collision is gone.
    """
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID
    from pkcs11_check.testcases.conftest import is_known_error

    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK",
        int(CKR_MECHANISM_PARAM_INVALID),
    )
    assert is_known_error(exc, {int(CKR_MECHANISM_PARAM_INVALID)}) is True
    assert is_known_error(exc, {int(CKR_MECHANISM_INVALID)}) is False


# ---------------------------------------------------------------------------
# L2 — single-shot recipes cancel a dangling *Init when the op call errors
# ---------------------------------------------------------------------------


class _FakeRaw:
    """Minimal RawPKCS11 stand-in that records calls and lets a chosen
    operation function fail, so we can verify operation-state cleanup."""

    def __init__(self, fail_on: str) -> None:
        self._fail_on = fail_on
        self.calls: list[str] = []

    # Telemetry hooks accessed by recipes / coverage; harmless no-ops here.
    call_log: dict[str, int] = {}
    mechanism_counts: dict[int, int] = {}

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        if not name.startswith("C_"):
            raise AttributeError(name)

        def _fn(*_args: object) -> int:
            self.calls.append(name)
            if name == self._fail_on:
                # Non-OK return drives expect_rv() to raise inside the recipe.
                from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR

                return int(CKR_DEVICE_ERROR)
            from pkcs11_check.raw.types_std import CKR_OK

            return int(CKR_OK)

        return _fn


def test_encrypt_single_cancels_on_terminal_error() -> None:
    """If the C_Encrypt size-probe errors, the dangling C_EncryptInit must be
    cancelled (via C_SessionCancel) before the error propagates."""
    from pkcs11_check.raw.recipes import encrypt_single
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKM_AES_ECB

    raw = _FakeRaw(fail_on="C_Encrypt")
    with pytest.raises(CkrAssertionError):
        encrypt_single(raw, 1, 2, CKM_AES_ECB, b"plaintext")  # type: ignore[arg-type]

    assert "C_EncryptInit" in raw.calls
    assert "C_SessionCancel" in raw.calls, "operation left active -- no cancel issued"


def test_sign_single_cancels_on_terminal_error() -> None:
    from pkcs11_check.raw.recipes import sign_single
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKM_SHA256_RSA_PKCS

    raw = _FakeRaw(fail_on="C_Sign")
    with pytest.raises(CkrAssertionError):
        sign_single(raw, 1, 2, CKM_SHA256_RSA_PKCS, b"data")  # type: ignore[arg-type]

    assert "C_SignInit" in raw.calls
    assert "C_SessionCancel" in raw.calls


def test_decrypt_single_cancels_on_terminal_error() -> None:
    from pkcs11_check.raw.recipes import decrypt_single
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKM_AES_ECB

    raw = _FakeRaw(fail_on="C_Decrypt")
    with pytest.raises(CkrAssertionError):
        decrypt_single(raw, 1, 2, CKM_AES_ECB, b"ciphertext")  # type: ignore[arg-type]

    assert "C_DecryptInit" in raw.calls
    assert "C_SessionCancel" in raw.calls


def test_find_objects_finalizes_on_error() -> None:
    """If C_FindObjects errors after C_FindObjectsInit, C_FindObjectsFinal must
    still be issued to release the search operation."""
    from pkcs11_check.raw.recipes import find_objects
    from pkcs11_check.raw.rv import CkrAssertionError

    raw = _FakeRaw(fail_on="C_FindObjects")
    with pytest.raises(CkrAssertionError):
        find_objects(raw, 1)  # type: ignore[arg-type]

    assert "C_FindObjectsInit" in raw.calls
    assert "C_FindObjectsFinal" in raw.calls


def test_encrypt_single_no_cancel_on_success() -> None:
    """On the happy path no spurious cancel is issued."""
    from pkcs11_check.raw.recipes import encrypt_single
    from pkcs11_check.raw.types_std import CKM_AES_ECB

    raw = _FakeRaw(fail_on="")  # nothing fails
    encrypt_single(raw, 1, 2, CKM_AES_ECB, b"plaintext")  # type: ignore[arg-type]
    assert "C_SessionCancel" not in raw.calls
