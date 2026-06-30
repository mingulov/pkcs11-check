"""NULL pointer + non-zero length probes for PKCS#11 data operations.

All tests run in subprocess for crash safety. Each test passes a NULL pointer
where a data buffer is expected with a non-zero length claim, verifying the
module rejects the mismatch cleanly (CKR error) rather than crashing (SIGSEGV).

A NULL data pointer paired with a non-zero length is a classic FFI hazard
(CWE-476): the module must validate the (pointer, length) pair before forming
a slice/buffer from it, returning a clean CK_RV instead of dereferencing NULL.

Covers:
- NULL data pointer in multi-part Update operations
- NULL output buffer in Final operations (standard length-query path)
- NULL buffer in C_SeedRandom / C_GenerateRandom
- NULL PIN in C_InitPIN / C_SetPIN
- NULL state buffer in C_SetOperationState
- NULL wrapped key in C_UnwrapKey
- HMAC-General with NULL mechanism parameter
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKA_UNWRAP
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import (
    destroy_returned_handles,
    gen_aes_key_or_xfail,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]


def _preflight_aes_key(
    rs: Any,
    *,
    purpose: str,
    attrs: dict[Any, Any] | None = None,
) -> None:
    """Check setup key generation before entering a crash-isolated child."""
    setup_key = gen_aes_key_or_xfail(rs, 256, attrs=attrs, purpose=purpose)
    destroy_returned_handles(rs, setup_key)


# ---------------------------------------------------------------------------
# NULL data pointer in multi-part Update operations
# ---------------------------------------------------------------------------

# (operation, init_func, update_func, mechanism_check)
_UPDATE_CASES = [
    pytest.param(
        "encrypt",
        "C_EncryptInit",
        "C_EncryptUpdate",
        "AES_CBC",
        id="C_EncryptUpdate",
    ),
    pytest.param(
        "decrypt",
        "C_DecryptInit",
        "C_DecryptUpdate",
        "AES_CBC",
        id="C_DecryptUpdate",
    ),
    pytest.param(
        "sign",
        "C_SignInit",
        "C_SignUpdate",
        "SHA256_HMAC",
        id="C_SignUpdate",
    ),
    pytest.param(
        "verify",
        "C_VerifyInit",
        "C_VerifyUpdate",
        "SHA256_HMAC",
        id="C_VerifyUpdate",
    ),
    pytest.param(
        "digest",
        "C_DigestInit",
        "C_DigestUpdate",
        "SHA256",
        id="C_DigestUpdate",
    ),
]


class TestNullDataUpdate:
    """NULL data pointer with non-zero length in multi-part Update ops.

    PKCS#11 Update functions accept (session, data_ptr, data_len).
    Passing NULL data_ptr with non-zero data_len is a mismatch that can
    crash modules without proper NULL-pointer validation.
    """

    @pytest.mark.parametrize(
        "operation,init_func,update_func,mech_check",
        _UPDATE_CASES,
    )
    def test_null_data_update(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        init_func: str,
        update_func: str,
        mech_check: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")

        if operation in ("encrypt", "decrypt"):
            _preflight_aes_key(
                rs,
                purpose=f"{update_func} NULL-data crash probe setup",
            )

        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": f"update_{operation}",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{update_func}(data=NULL, data_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL output buffer in Final operations (standard length-query path)
# ---------------------------------------------------------------------------

_FINAL_CASES = [
    pytest.param(
        "encrypt",
        "C_EncryptFinal",
        "AES_CBC",
        id="C_EncryptFinal",
    ),
    pytest.param(
        "decrypt",
        "C_DecryptFinal",
        "AES_CBC",
        id="C_DecryptFinal",
    ),
    pytest.param(
        "sign",
        "C_SignFinal",
        "SHA256_HMAC",
        id="C_SignFinal",
    ),
    pytest.param(
        "digest",
        "C_DigestFinal",
        "SHA256",
        id="C_DigestFinal",
    ),
]


class TestNullOutputFinal:
    """NULL output buffer in Final operations.

    In PKCS#11, passing NULL as the output buffer is the standard
    length-query mechanism. A correct module returns CKR_OK with the
    required buffer length. These tests verify the module handles this
    correctly and does not crash.
    """

    @pytest.mark.parametrize(
        "operation,final_func,mech_check",
        _FINAL_CASES,
    )
    def test_null_output_final(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        final_func: str,
        mech_check: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")

        if operation in ("encrypt", "decrypt"):
            _preflight_aes_key(
                rs,
                purpose=f"{final_func} NULL-output crash probe setup",
            )

        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": f"final_{operation}",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{final_func}(output=NULL, length_query)",
        )


# ---------------------------------------------------------------------------
# NULL buffer in C_SeedRandom / C_GenerateRandom
# ---------------------------------------------------------------------------


class TestNullRandomBuffer:
    """NULL buffer with non-zero length in random operations.

    C_SeedRandom and C_GenerateRandom have no length-query mode, so
    NULL pointer with non-zero length is always a crash vector.
    """

    def test_seed_random_null_buffer(self, p11_config: Any) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "seed_random",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_SeedRandom(data=NULL, data_len=32)",
        )

    def test_generate_random_null_buffer(
        self,
        p11_config: Any,
    ) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "generate_random",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_GenerateRandom(buf=NULL, buf_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL PIN in C_InitPIN / C_SetPIN
# ---------------------------------------------------------------------------


@pytest.mark.destructive
class TestNullPinBuffer:
    """NULL PIN pointer with non-zero length in PIN management ops.

    These tests don't auto-login so we can test the raw PIN functions
    without interference from the session login state.

    Destructive: ``test_set_pin_null_new_pin`` calls ``C_SetPIN`` with the
    real current user PIN as the old PIN, so a module that accepts it can
    change/corrupt the live token PIN. On modules that enforce a PIN retry
    lockout this then locks the shared token and every later login fails with
    ``CKR_PIN_LOCKED``. Must run only under ``--p11-destructive`` against a
    throwaway/reprovisioned token.
    """

    def test_init_pin_null_with_length(
        self,
        p11_config: Any,
    ) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "init_pin_null",
            },
            pin=None,
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_InitPIN(pin=NULL, pin_len=8)",
        )

    def test_set_pin_null_old_pin(self, p11_config: Any) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "set_pin_null_old_pin",
            },
            pin=None,
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_SetPIN(old_pin=NULL, old_pin_len=8)",
        )

    def test_set_pin_null_new_pin(self, p11_config: Any) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "set_pin_null_new_pin",
            },
            pin=None,
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_SetPIN(new_pin=NULL, new_pin_len=8)",
        )


# ---------------------------------------------------------------------------
# NULL state buffer in C_SetOperationState
# ---------------------------------------------------------------------------


class TestNullOperationState:
    """NULL state buffer with non-zero length in C_SetOperationState.

    C_SetOperationState has no length-query mode for the input state
    buffer, so NULL pointer + non-zero length is a crash vector.
    """

    def test_set_operation_state_null_buffer(
        self,
        p11_config: Any,
    ) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "set_operation_state_null",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_SetOperationState(state=NULL, state_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL wrapped key data in C_UnwrapKey
# ---------------------------------------------------------------------------


class TestNullWrapUnwrap:
    """NULL wrapped-key data with non-zero length in C_UnwrapKey.

    Passing NULL as the wrapped key buffer with a non-zero length can
    crash modules that dereference the pointer without validation.
    """

    def test_unwrap_key_null_wrapped_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        _preflight_aes_key(
            rs,
            purpose="C_UnwrapKey NULL wrapped-data crash probe setup",
            attrs={CKA_UNWRAP: True},
        )
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "unwrap_key_null_data",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_UnwrapKey(wrapped=NULL, wrapped_len=32)",
        )


# ---------------------------------------------------------------------------
# HMAC-General with NULL mechanism parameter
# ---------------------------------------------------------------------------


class TestHmacGeneralNullParam:
    """CKM_SHA256_HMAC_GENERAL with NULL pParameter but non-zero length.

    CKM_SHA256_HMAC_GENERAL requires a CK_MAC_GENERAL_PARAMS (CK_ULONG)
    specifying the output MAC length. Passing NULL pParameter with
    ulParameterLen = sizeof(CK_ULONG) can crash modules that dereference
    the parameter pointer without checking for NULL.
    """

    def test_hmac_general_null_parameter(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC_GENERAL"):
            pytest.skip("CKM_SHA256_HMAC_GENERAL not supported")
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "hmac_general_null_param",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=("C_SignInit(CKM_SHA256_HMAC_GENERAL, pParameter=NULL, ulParameterLen=8)"),
        )


# ---------------------------------------------------------------------------
# NULL data pointer in one-shot operations
# ---------------------------------------------------------------------------

_ONESHOT_CASES = [
    pytest.param(
        "encrypt",
        "C_Encrypt",
        "AES_ECB",
        id="C_Encrypt",
    ),
    pytest.param(
        "decrypt",
        "C_Decrypt",
        "AES_ECB",
        id="C_Decrypt",
    ),
    pytest.param(
        "sign",
        "C_Sign",
        "SHA256_HMAC",
        id="C_Sign",
    ),
    pytest.param(
        "verify",
        "C_Verify",
        "SHA256_HMAC",
        id="C_Verify",
    ),
    pytest.param(
        "digest",
        "C_Digest",
        "SHA256",
        id="C_Digest",
    ),
]


class TestNullDataOneShot:
    """NULL data pointer with non-zero length in one-shot operations.

    One-shot C_Encrypt, C_Decrypt, C_Sign, C_Verify, and C_Digest hit
    different code paths from the multi-part Update functions. Passing
    NULL data with non-zero length can crash modules without proper
    NULL-pointer validation.
    """

    @pytest.mark.parametrize(
        "operation,func_name,mech_check",
        _ONESHOT_CASES,
    )
    def test_null_data_oneshot(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        func_name: str,
        mech_check: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")

        if operation in ("encrypt", "decrypt"):
            _preflight_aes_key(
                rs,
                purpose=f"{func_name} NULL-data crash probe setup",
            )

        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": f"oneshot_{operation}",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{func_name}(data=NULL, data_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL data pointers in v3.0 Message-based encryption/decryption
# ---------------------------------------------------------------------------


class TestNullMessageApi:
    """NULL data pointers in v3.0 Message-based encrypt/decrypt.

    The v3.0 Message API (C_EncryptMessage, C_DecryptMessage) has
    separate pointers for associated data and plaintext/ciphertext.
    Passing NULL for these with non-zero length can crash modules
    without proper NULL-pointer validation.

    Tests gracefully skip when the module does not support the v3.0
    Message API.
    """

    def test_encrypt_message_null_plaintext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        _preflight_aes_key(
            rs,
            purpose="C_EncryptMessage NULL plaintext crash probe setup",
        )
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "encrypt_message_null_plaintext",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        if "not_supported" in result.stdout:
            pytest.skip("C_MessageEncryptInit not available")
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_EncryptMessage(plaintext=NULL, plaintext_len=32)",
        )

    def test_decrypt_message_null_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        _preflight_aes_key(
            rs,
            purpose="C_DecryptMessage NULL ciphertext crash probe setup",
        )
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "decrypt_message_null_ciphertext",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        if "not_supported" in result.stdout:
            pytest.skip("C_MessageDecryptInit not available")
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_DecryptMessage(ciphertext=NULL, ciphertext_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL ciphertext in v3.2 C_DecapsulateKey
# ---------------------------------------------------------------------------


class TestNullKemApi:
    """NULL ciphertext pointer in v3.2 C_DecapsulateKey.

    C_DecapsulateKey accepts a ciphertext buffer pointer and length.
    Passing NULL ciphertext with non-zero length can crash modules
    that dereference the pointer without validation.

    Gracefully skips when the module does not support v3.2 KEM functions.
    """

    def test_decapsulate_key_null_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported (needed for key gen)")
        _preflight_aes_key(
            rs,
            purpose="C_DecapsulateKey NULL ciphertext crash probe setup",
        )
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "decapsulate_key_null_ciphertext",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        if "not_supported" in result.stdout:
            pytest.skip("C_DecapsulateKey not available")
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_DecapsulateKey(ciphertext=NULL, ciphertext_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL PIN / NULL label in C_InitToken
# ---------------------------------------------------------------------------


@pytest.mark.destructive
class TestNullInitToken:
    """NULL PIN or NULL label in C_InitToken.

    C_InitToken(slot_id, pPin, ulPinLen, pLabel) is a sensitive
    operation. Passing NULL pPin with non-zero length or NULL pLabel
    can crash modules that dereference without validation.

    Destructive: C_InitToken reinitializes the token (wiping objects and
    PIN), so it must run only under ``--p11-destructive`` against a
    throwaway/reprovisioned token, never the shared session token.

    Since our preamble opens a session, C_InitToken will likely fail
    with CKR_SESSION_EXISTS or similar -- but the module must check
    that BEFORE dereferencing NULL pointers.
    """

    def test_init_token_null_pin(self, p11_config: Any) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "init_token_null_pin",
            },
            pin=None,
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_InitToken(pin=NULL, pin_len=8, label=valid)",
        )

    def test_init_token_null_label(self, p11_config: Any) -> None:
        result = run_probe(
            "ffi_null_pointer",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "init_token_null_label",
            },
            pin=None,
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_InitToken(pin=valid, pin_len=4, label=NULL)",
        )
