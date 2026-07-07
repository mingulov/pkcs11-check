"""Crash-safe probes for oversized secret-key ``CKA_VALUE_LEN`` templates.

These tests cover entry points not exercised by the existing key-generation
overflow probes. The target bug class is storing a caller-supplied secret-key
length before validating it, then reusing that stored length during cleanup,
digest, derive, unwrap, copy, or zeroization.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    _CK_ULONG_MAX,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

_ULONG_MAX = int(_CK_ULONG_MAX)
_HKDF_SHA256_MAX_OUTPUT = 255 * 32
_VALUE_LEN_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
)


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


class TestCreateObjectSecretKeyValueLen:
    """``C_CreateObject`` secret-key templates with oversized ``CKA_VALUE_LEN``."""

    @pytest.mark.parametrize(
        ("key_type_name", "include_value"),
        (
            pytest.param("CKK_GENERIC_SECRET", True, id="generic_secret_with_value"),
            pytest.param("CKK_GENERIC_SECRET", False, id="generic_secret_without_value"),
            pytest.param("CKK_AES", True, id="aes_with_value"),
        ),
    )
    def test_create_secret_key_with_oversized_value_len_does_not_crash(
        self,
        p11_config: Any,
        key_type_name: str,
        include_value: bool,
    ) -> None:
        """A bad secret-key import template must reject cleanly or tear down cleanly."""
        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "create_object",
                "key_type_name": key_type_name,
                "include_value": include_value,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=(
                f"C_CreateObject({key_type_name}, "
                f"CKA_VALUE_LEN={_ULONG_MAX:#x}, include_value={include_value})"
            ),
        )


class TestExistingSecretKeyValueLen:
    """Existing secret-key paths with oversized ``CKA_VALUE_LEN`` templates."""

    def test_copy_secret_key_with_oversized_value_len_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """``C_CopyObject`` must reject a bad output template or tear down cleanly."""
        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "copy_secret_key",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_CopyObject(secret key, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )

    def test_set_secret_key_oversized_value_len_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """``C_SetAttributeValue`` must not persist a toxic secret length."""
        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "set_secret_key_attr",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_SetAttributeValue(secret key, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


class TestDigestKeySecretKeyValueLen:
    """``C_DigestKey`` must not consume a toxic stored secret length."""

    def test_digest_key_after_oversized_value_len_import_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Digesting an accepted bad-length secret key must be clean and correct."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "digest_key",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=(f"C_DigestKey(secret key imported with CKA_VALUE_LEN={_ULONG_MAX:#x})"),
        )


class TestUnwrapSecretKeyValueLen:
    """``C_UnwrapKey`` output templates with oversized ``CKA_VALUE_LEN``."""

    def test_aes_ecb_unwrap_oversized_value_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """A valid wrapped key with a toxic output template must not corrupt state."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "aes_ecb_unwrap",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_UnwrapKey(AES_ECB, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


class TestGenerateKeySecretKeyValueLen:
    """``C_GenerateKey`` output templates with oversized ``CKA_VALUE_LEN``."""

    def test_generic_secret_generate_key_oversized_value_len_rejects_cleanly(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Variable-length generic-secret generation must reject impossible sizes."""
        rs = p11_raw_session
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "generate_generic_secret",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKey(GENERIC_SECRET, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _VALUE_LEN_REJECT_RVS,
            label=f"C_GenerateKey(GENERIC_SECRET, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )

    def test_pbkdf2_generate_key_oversized_value_len_rejects_cleanly(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """PBKDF2 output length must reject ``CK_ULONG_MAX`` without crashing."""
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "generate_pbkdf2",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKey(PBKDF2, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _VALUE_LEN_REJECT_RVS,
            label=f"C_GenerateKey(PBKDF2, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


class TestDeriveKeySecretKeyValueLen:
    """``C_DeriveKey`` output templates with oversized ``CKA_VALUE_LEN``."""

    @pytest.mark.parametrize(
        "output_value_len",
        (
            pytest.param(_HKDF_SHA256_MAX_OUTPUT, id="hkdf_sha256_max_output"),
            pytest.param(_ULONG_MAX, id="ulong_max"),
        ),
    )
    def test_hkdf_derive_max_output_value_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        output_value_len: int,
    ) -> None:
        """HKDF output lengths must not corrupt object creation or teardown."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")

        result = run_probe(
            "secret_key_value_len",
            {
                "module_path": str(p11_config.module),
                "which": "hkdf_derive",
                "output_value_len": output_value_len,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=(f"C_DeriveKey(HKDF_SHA256, CKA_VALUE_LEN={output_value_len:#x})"),
        )
