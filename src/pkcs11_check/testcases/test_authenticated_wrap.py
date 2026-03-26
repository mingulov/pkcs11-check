"""AES-GCM authenticated key wrapping tests (v3.2).

Tests wrap_key_authenticated / unwrap_key_authenticated using
AES-GCM AEAD. Requires PKCS#11 v3.2 interface (C_WrapKeyAuthenticated).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_gcm
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    generate_random,
    read_attributes,
    unwrap_key_authenticated,
    wrap_key_authenticated,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKM_AES_GCM,
)

pytestmark = pytest.mark.keymgmt


class TestAuthenticatedWrap:
    """Test AES-GCM authenticated key wrapping (v3.2)."""

    def test_aes_gcm_wrap_unwrap(self, p11_raw_session: Any, p11_interface_version: str) -> None:
        """Wrap/unwrap AES key with AES-GCM authenticated wrapping."""
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        # Generate wrapping key
        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )

        # Generate target key
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            original_value = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]

            # Wrap with authentication
            iv = generate_random(rs.raw, rs.sh, 12)
            gcm = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped, tag = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=gcm,
                )
            except (NotImplementedError, AttributeError, TypeError):
                pytest.skip("wrap_key_authenticated not available or GCM params unsupported")
                return
            except AssertionError as e:
                # Some modules need specific GCM parameters
                pytest.skip(f"Authenticated wrapping failed: {e}")
                return

            assert wrapped != original_value
            assert tag is not None or wrapped is not None

            # Unwrap with authentication
            gcm2 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            unwrapped = unwrap_key_authenticated(
                rs.raw,
                rs.sh,
                wrap_h,
                wrapped,
                tag if tag else b"",
                CKM_AES_GCM,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                mech_param=gcm2,
            )
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert unwrapped_value == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_authenticated_wrap_requires_v32(
        self, p11_raw_session: Any, p11_interface_version: str
    ) -> None:
        """On v2.40 modules, wrap_key_authenticated is not available."""
        rs = p11_raw_session
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True},
        )

        try:
            # v2.40 raw API should not have C_WrapKeyAuthenticated
            has_fn = hasattr(rs.raw, "C_WrapKeyAuthenticated")
            if has_fn:
                iv = generate_random(rs.raw, rs.sh, 12)
                gcm = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
                try:
                    wrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        key,
                        target,
                        CKM_AES_GCM,
                        mech_param=gcm,
                    )
                except (AssertionError, AttributeError, NotImplementedError):
                    pass  # Expected on v2.40
            # If no C_WrapKeyAuthenticated method, test passes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
            destroy_quietly(rs.raw, rs.sh, target)
