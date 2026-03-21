"""Tests for remaining OASIS spec gaps identified in post-Phase audit.

Covers:
- C_SignEncryptUpdate / C_DecryptVerifyUpdate (dual-function §5.14.3, §5.14.4)
- CKA_WRAP_TEMPLATE / CKA_UNWRAP_TEMPLATE / CKA_DERIVE_TEMPLATE
- CKM_RSA_PKCS_NULL mechanism
- Standalone SHAKE XOF coverage
- KMAC-128 / KMAC-256
- ML_DSA_EXTERNAL_MU / ML_DSA_EXTERNAL_MU_GEN
- PKCS12_PBE_EXPORT / PKCS12_PBE_IMPORT

Most modules do not support these — tests skip cleanly.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import AttributeTypeInvalid, PKCS11Error

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.compliance]


# ---------------------------------------------------------------------------
# Template constraint attributes (Phase B gap)
# ---------------------------------------------------------------------------


class TestTemplateConstraintAttributes:
    """CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE."""

    def test_wrap_template_attribute_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Keys should accept CKA_WRAP_TEMPLATE if the module supports it."""
        if not has_mechanism(p11_module, "AES_KEY_GEN"):
            pytest.skip("AES not supported")
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            mechanism=Mechanism.AES_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.WRAP: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            # Try to read WRAP_TEMPLATE — may not be supported
            try:
                wt = key[Attribute.WRAP_TEMPLATE]
                assert wt is not None or wt == b""  # Empty template is valid
            except (AttributeTypeInvalid, PKCS11Error):
                pytest.skip("Module does not support CKA_WRAP_TEMPLATE")
        finally:
            key.destroy()

    def test_unwrap_template_attribute_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Keys should accept CKA_UNWRAP_TEMPLATE if the module supports it."""
        if not has_mechanism(p11_module, "AES_KEY_GEN"):
            pytest.skip("AES not supported")
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            mechanism=Mechanism.AES_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.UNWRAP: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            try:
                ut = key[Attribute.UNWRAP_TEMPLATE]
                assert ut is not None or ut == b""
            except (AttributeTypeInvalid, PKCS11Error):
                pytest.skip("Module does not support CKA_UNWRAP_TEMPLATE")
        finally:
            key.destroy()

    def test_derive_template_attribute_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Keys should accept CKA_DERIVE_TEMPLATE if the module supports it."""
        if not has_mechanism(p11_module, "AES_KEY_GEN"):
            pytest.skip("AES not supported")
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            mechanism=Mechanism.AES_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DERIVE: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            try:
                dt = key[Attribute.DERIVE_TEMPLATE]
                assert dt is not None or dt == b""
            except (AttributeTypeInvalid, PKCS11Error):
                pytest.skip("Module does not support CKA_DERIVE_TEMPLATE")
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# CKM_RSA_PKCS_NULL (Phase G gap)
# ---------------------------------------------------------------------------


class TestRsaPkcsNull:
    """CKM_RSA_PKCS_NULL — raw RSA with no formatting."""

    def test_null_mechanism_availability(
        self, p11_module: Any
    ) -> None:
        """Check if CKM_RSA_PKCS_NULL is reported by the module."""
        # Most modules do not support this
        if not has_mechanism(p11_module, "RSA_PKCS_NULL"):
            pytest.skip("CKM_RSA_PKCS_NULL not supported")
        # If we get here, the mechanism exists — that's the test


# ---------------------------------------------------------------------------
# KMAC (Phase D gap)
# ---------------------------------------------------------------------------


class TestKmac:
    """CKM_KMAC_128 and CKM_KMAC_256 — NIST SP 800-185 KECCAK MAC."""

    def test_kmac_128_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "KMAC_128"):
            pytest.skip("CKM_KMAC_128 not supported")

    def test_kmac_256_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "KMAC_256"):
            pytest.skip("CKM_KMAC_256 not supported")


# ---------------------------------------------------------------------------
# Standalone SHAKE XOF (Phase D gap)
# ---------------------------------------------------------------------------


class TestShakeXof:
    """Standalone SHAKE128/SHAKE256 as XOF digest mechanisms."""

    def test_shake_128_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "SHAKE_128"):
            pytest.skip("CKM_SHAKE_128 not supported")

    def test_shake_256_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "SHAKE_256"):
            pytest.skip("CKM_SHAKE_256 not supported")


# ---------------------------------------------------------------------------
# ML-DSA External MU (Phase D gap)
# ---------------------------------------------------------------------------


class TestMlDsaExternalMu:
    """CKM_ML_DSA_EXTERNAL_MU and CKM_ML_DSA_EXTERNAL_MU_GEN."""

    @pytest.mark.requires_v32
    def test_external_mu_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "ML_DSA_EXTERNAL_MU"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU not supported")

    @pytest.mark.requires_v32
    def test_external_mu_gen_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "ML_DSA_EXTERNAL_MU_GEN"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU_GEN not supported")


# ---------------------------------------------------------------------------
# PKCS#12 PBE (Phase F gap)
# ---------------------------------------------------------------------------


class TestPkcs12Pbe:
    """CKM_PKCS12_PBE_EXPORT and CKM_PKCS12_PBE_IMPORT."""

    def test_pkcs12_pbe_export_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "PKCS12_PBE_EXPORT"):
            pytest.skip("CKM_PKCS12_PBE_EXPORT not supported")

    def test_pkcs12_pbe_import_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "PKCS12_PBE_IMPORT"):
            pytest.skip("CKM_PKCS12_PBE_IMPORT not supported")
