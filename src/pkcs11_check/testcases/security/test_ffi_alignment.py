"""FFI pointer-alignment hardening probes.

These tests exercise caller buffers whose bytes encode valid PKCS#11 structs or
scalar values but whose pointers are intentionally unaligned. This is a
crash-safety boundary for modules reached through foreign-function bindings:
providers may accept the call or reject it cleanly, but they must not crash.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]


class TestMisalignedAttributeValues:
    """CK_ATTRIBUTE.pValue points to unaligned scalar storage."""

    def test_generate_key_with_misaligned_scalar_attribute_values(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKey must not crash on unaligned scalar pValue pointers."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        result = run_probe(
            "ffi_alignment",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "misaligned_scalar_attrs",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_GenerateKey with misaligned CK_ATTRIBUTE.pValue scalars",
        )


class TestMisalignedMechanismPointer:
    """CK_MECHANISM_PTR itself points to unaligned struct storage."""

    def test_encrypt_init_with_misaligned_mechanism_pointer(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_EncryptInit must not crash on an unaligned CK_MECHANISM_PTR."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        result = run_probe(
            "ffi_alignment",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "misaligned_mechanism_ptr",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit with misaligned CK_MECHANISM_PTR",
        )
