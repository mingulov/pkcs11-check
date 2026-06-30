"""API boundary tests -- crash-safe probes for invalid handles, NULL pointers, and edge-case inputs.

All tests run in subprocess for crash safety. Each test launches a probe via
run_probe() and checks that the module did not crash (negative returncode = killed by signal).

Covers:
- Session handle boundary values (0, ULONG_MAX)
- Object handle boundary values (0, ULONG_MAX)
- NULL mechanism pointer to *Init functions
- Mechanism with pParameter=NULL but ulParameterLen>0
- NULL template pointer with non-zero count
- Zero-length data to encrypt/decrypt/sign
- NULL PIN with non-zero length to C_Login
- Extreme and zero RSA/AES key sizes
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import (
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# CK_ULONG max for the host ABI (2^64-1 on LP64, 2^32-1 on Win64 LLP64). Used as a
# literal in subprocess script strings, so it must fit the child's CK_ULONG width.
_CK_ULONG_MAX = ctypes.c_ulong(-1).value


# ---------------------------------------------------------------------------
# Session handle boundary values
# ---------------------------------------------------------------------------


class TestSessionHandleBoundary:
    """Probe C_* session functions with boundary session handles (0, MAX).

    PKCS#11 v3.2: functions taking CK_SESSION_HANDLE must return
    CKR_SESSION_HANDLE_INVALID for unknown handles -- never crash.
    """

    _SESSION_FUNCTIONS = ["C_GetSessionInfo", "C_CloseSession", "C_GetOperationState"]
    _BOUNDARY_HANDLES = [
        pytest.param(0, id="zero"),
        pytest.param(_CK_ULONG_MAX, id="max"),
    ]

    @pytest.mark.parametrize("func_name", _SESSION_FUNCTIONS)
    @pytest.mark.parametrize("handle", _BOUNDARY_HANDLES)
    def test_session_handle_boundary(
        self,
        p11_config: Any,
        func_name: str,
        handle: int,
    ) -> None:
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "session_handle",
                "func_name": func_name,
                "handle": handle,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{func_name}(handle={handle:#x})",
        )


# ---------------------------------------------------------------------------
# Object handle boundary values
# ---------------------------------------------------------------------------


class TestObjectHandleBoundary:
    """Probe C_* object functions with boundary object handles (0, MAX).

    PKCS#11 v3.2: functions taking CK_OBJECT_HANDLE must return
    CKR_OBJECT_HANDLE_INVALID for unknown handles -- never crash.
    """

    _OBJECT_FUNCTIONS = [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
        "C_DestroyObject",
        "C_CopyObject",
    ]
    _BOUNDARY_HANDLES = [
        pytest.param(0, id="zero"),
        pytest.param(_CK_ULONG_MAX, id="max"),
    ]

    @pytest.mark.parametrize("func_name", _OBJECT_FUNCTIONS)
    @pytest.mark.parametrize("handle", _BOUNDARY_HANDLES)
    def test_object_handle_boundary(
        self,
        p11_config: Any,
        func_name: str,
        handle: int,
    ) -> None:
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "object_handle",
                "func_name": func_name,
                "handle": handle,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{func_name}(object_handle={handle:#x})",
        )


# ---------------------------------------------------------------------------
# NULL mechanism pointer to *Init functions
# ---------------------------------------------------------------------------


class TestNullMechanismInit:
    """Probe C_*Init functions with NULL mechanism pointer.

    PKCS#11 v3.2: CK_MECHANISM_PTR must not be NULL. The module should
    return CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID -- never crash.
    """

    _INIT_FUNCTIONS = [
        "C_EncryptInit",
        "C_DecryptInit",
        "C_SignInit",
        "C_VerifyInit",
        "C_DigestInit",
    ]

    @pytest.mark.parametrize("func_name", _INIT_FUNCTIONS)
    def test_null_mechanism_init(
        self,
        p11_config: Any,
        func_name: str,
    ) -> None:
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "null_mechanism_init",
                "func_name": func_name,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{func_name}(mechanism=NULL)",
        )


# ---------------------------------------------------------------------------
# Mechanism with pParameter=NULL but ulParameterLen>0
# ---------------------------------------------------------------------------


class TestMechanismParamNullWithLength:
    """Probe *Init with a mechanism whose pParameter is NULL but ulParameterLen > 0.

    This NULL-pointer + non-zero-length mismatch can cause crashes in modules
    that dereference pParameter without checking ulParameterLen first.
    """

    _INIT_FUNCTIONS = [
        "C_EncryptInit",
        "C_DecryptInit",
        "C_SignInit",
        "C_VerifyInit",
    ]

    @pytest.mark.parametrize("func_name", _INIT_FUNCTIONS)
    def test_mechanism_param_null_with_length(
        self,
        p11_config: Any,
        func_name: str,
    ) -> None:
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "mechanism_param_null",
                "func_name": func_name,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{func_name}(pParameter=NULL, ulParameterLen=16)",
        )


# ---------------------------------------------------------------------------
# NULL template pointer with non-zero count
# ---------------------------------------------------------------------------


class TestNullTemplateNonzeroCount:
    """Probe functions with NULL template pointer but count > 0.

    The NULL-pointer + non-zero-count mismatch can cause crashes in modules
    that iterate the template array without checking the pointer first.
    """

    _TEMPLATE_FUNCTIONS = [
        "C_CreateObject",
        "C_FindObjectsInit",
        "C_GenerateKey",
        "C_SetAttributeValue",
    ]

    @pytest.mark.parametrize("func_name", _TEMPLATE_FUNCTIONS)
    def test_null_template_nonzero_count(
        self,
        p11_config: Any,
        func_name: str,
    ) -> None:
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "null_template",
                "func_name": func_name,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{func_name}(template=NULL, count=5)",
        )


# ---------------------------------------------------------------------------
# Zero-length data to encrypt/decrypt/sign
# ---------------------------------------------------------------------------

_ZERO_LENGTH_CASES = [
    pytest.param("encrypt", "AES_ECB", "CKM_AES_ECB", id="encrypt-AES_ECB"),
    pytest.param("encrypt", "AES_CBC", "CKM_AES_CBC", id="encrypt-AES_CBC"),
    pytest.param("decrypt", "AES_ECB", "CKM_AES_ECB", id="decrypt-AES_ECB"),
    pytest.param("decrypt", "AES_CBC", "CKM_AES_CBC", id="decrypt-AES_CBC"),
    pytest.param("sign", "RSA_PKCS", "CKM_SHA256_RSA_PKCS", id="sign-RSA_PKCS"),
    pytest.param("sign", "ECDSA", "CKM_ECDSA_SHA256", id="sign-ECDSA"),
]


class TestZeroLengthData:
    """Probe encrypt/decrypt/sign with zero-length data.

    Passing a zero-length buffer can cause edge-case failures in modules
    that don't validate data length before processing. The module should
    return an appropriate error code -- never crash.
    """

    @pytest.mark.parametrize("operation,mech_check,mech_name", _ZERO_LENGTH_CASES)
    def test_zero_length_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        mech_check: str,
        mech_name: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")

        if operation in ("encrypt", "decrypt") and "AES" in mech_name:
            setup_key = gen_aes_key_or_xfail(
                rs,
                256,
                purpose=f"{operation} zero-length {mech_name} crash probe setup",
            )
            destroy_returned_handles(rs, setup_key)
            result = run_probe(
                "api_boundary",
                {
                    "module_path": str(p11_config.module),
                    "slot_id": p11_config.slot,
                    "which": "zero_length_aes",
                    "operation": operation,
                    "mech_name": mech_name,
                },
                pin=pin_from_config(p11_config),
                timeout=15,
            )
        elif operation == "sign" and "RSA" in mech_name:
            pub, priv = gen_rsa_keypair_or_xfail(
                rs,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
            destroy_returned_handles(rs, pub, priv)
            result = run_probe(
                "api_boundary",
                {
                    "module_path": str(p11_config.module),
                    "slot_id": p11_config.slot,
                    "which": "zero_length_rsa",
                },
                pin=pin_from_config(p11_config),
                timeout=15,
            )
        elif operation == "sign" and "ECDSA" in mech_name:
            curve_oid = encode_named_curve_parameters("secp256r1")
            pub, priv = gen_ec_keypair_or_xfail(
                rs,
                curve_oid,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            )
            destroy_returned_handles(rs, pub, priv)
            result = run_probe(
                "api_boundary",
                {
                    "module_path": str(p11_config.module),
                    "slot_id": p11_config.slot,
                    "which": "zero_length_ecdsa",
                },
                pin=pin_from_config(p11_config),
                timeout=15,
            )
        else:
            raise ValueError(f"Unhandled: operation={operation}, mech_name={mech_name}")

        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"{operation}(mechanism={mech_name}, data_len=0)",
        )


# ---------------------------------------------------------------------------
# Standalone boundary tests
# ---------------------------------------------------------------------------


class TestLoginNullPin:
    """Probe C_Login with NULL PIN pointer but non-zero length.

    This mismatch (NULL pointer + non-zero length) can cause crashes in
    modules that memcpy the PIN without checking the pointer first.
    """

    def test_login_null_pin_nonzero_length(self, p11_config: Any) -> None:
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "login_null_pin",
            },
            pin=None,  # Don't auto-login -- we're testing C_Login directly
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_Login(pin=NULL, pin_len=8)",
        )


class TestGenerateRsaExtremeKeySize:
    """Probe RSA keygen with extreme modulus size (0xFFFFFFFF bits).

    A module that doesn't validate CKA_MODULUS_BITS before allocating
    memory could hang or exhaust resources. Enforced with a 5-second timeout.
    """

    def test_generate_rsa_extreme_key_size(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "generate_rsa_extreme",
            },
            pin=pin_from_config(p11_config),
            timeout=5,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_GenerateKeyPair(CKA_MODULUS_BITS=0xFFFFFFFF)",
        )


class TestGenerateRsaZeroKeySize:
    """Probe RSA keygen with CKA_MODULUS_BITS = 0.

    A zero modulus size is invalid; the module should reject it cleanly.
    """

    def test_generate_rsa_zero_key_size(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "generate_rsa_zero",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_GenerateKeyPair(CKA_MODULUS_BITS=0)",
        )


class TestGenerateAesExtremeKeySize:
    """Probe AES keygen with CKA_VALUE_LEN = ULONG_MAX.

    A module that doesn't validate CKA_VALUE_LEN before allocating memory
    could crash or exhaust resources.
    """

    def test_generate_aes_extreme_key_size(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES keygen not supported")
        result = run_probe(
            "api_boundary",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "generate_aes_extreme",
            },
            pin=pin_from_config(p11_config),
            timeout=5,
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKey(CKA_VALUE_LEN={_CK_ULONG_MAX:#x})",
        )
