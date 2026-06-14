"""CKR return code coverage tests.

Verifies that common PKCS#11 error codes are properly reported.
Each test intentionally triggers a specific error condition and
verifies the module returns the expected CKR code (or a close one).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_ULONG,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKM_SHA256,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_SESSION_HANDLE_INVALID,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
)

pytestmark = pytest.mark.security


class TestCKRPinErrors:
    """Test PIN-related CKR codes."""

    def test_ckr_pin_incorrect(self, p11_raw_session: Any) -> None:
        """Wrong PIN triggers CKR_PIN_INCORRECT."""
        rs = p11_raw_session
        # Open a new session for this test
        from pkcs11_check.raw.bootstrap import close_session_quietly, open_session

        sh = open_session(rs.raw, rs.slot_id, (CKF_SERIAL_SESSION | CKF_RW_SESSION))
        try:
            wrong_pin = b"WRONG_PIN_XYZ_999"
            pin_buf = (ctypes.c_ubyte * len(wrong_pin))(*wrong_pin)
            rv = rs.raw.C_Login(sh, CKU_USER, pin_buf, len(wrong_pin))
            # May get PIN_INCORRECT or USER_ALREADY_LOGGED_IN (if token-level login)
            if rv == CKR_USER_ALREADY_LOGGED_IN or rv == CKR_USER_TYPE_INVALID:
                pytest.skip("Token-level login prevents testing wrong PIN")
            assert rv == CKR_PIN_INCORRECT, f"Expected CKR_PIN_INCORRECT, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, sh)


class TestCKRMechanismErrors:
    """Test mechanism-related CKR codes."""

    def test_ckr_mechanism_invalid(self, p11_raw_session: Any) -> None:
        """Using a non-existent mechanism triggers CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        try:
            # Use SHA256 (digest mech) for encrypt - should fail
            mech = mech_simple(CKM_SHA256)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, "Using SHA256 as encryption mechanism should fail"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestCKRDataErrors:
    """Test data-related CKR codes."""

    def test_ckr_data_len_range_ecb(self, p11_raw_session: Any) -> None:
        """Non-block-aligned data in AES-ECB triggers CKR_DATA_LEN_RANGE."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"C_EncryptInit failed: {ckr_name(rv)}")
            data = (ctypes.c_ubyte * 15)(*([0] * 15))
            out_len = CK_ULONG(32)
            out_buf = (ctypes.c_ubyte * 32)()
            rv = rs.raw.C_Encrypt(rs.sh, data, 15, out_buf, byref(out_len))
            assert rv != CKR_OK, "15-byte AES-ECB encrypt should fail"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestCKRAttributeErrors:
    """Test attribute-related CKR codes."""

    def test_ckr_attribute_sensitive(self, p11_raw_session: Any) -> None:
        """Reading CKA_VALUE on sensitive key triggers CKR_ATTRIBUTE_SENSITIVE.

        PKCS#11 v3.2: CKA_VALUE on a CKA_SENSITIVE=True key MUST return
        CKR_ATTRIBUTE_SENSITIVE.
        """
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, attrs={CKA_SENSITIVE: True})
        try:
            # Type-B claim/effect-check: claimed = the key reports
            # CKA_SENSITIVE=True back; violated = the protected CKA_VALUE is
            # actually readable (read_attributes omits unavailable attributes).
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            claimed = sens_attrs.get(CKA_SENSITIVE) is True
            val_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            violated = CKA_VALUE in val_attrs
            classify_policy_enforcement(
                claimed=claimed,
                violated=violated,
                label="read CKA_VALUE on a CKA_SENSITIVE=True key "
                "(PKCS#11 v3.2 requires CKR_ATTRIBUTE_SENSITIVE)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_ckr_attribute_type_invalid(self, p11_raw_session: Any) -> None:
        """Reading a nonsense attribute ID triggers CKR_ATTRIBUTE_TYPE_INVALID or similar."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        try:
            tmpl = (CK_ATTRIBUTE * 1)()
            tmpl[0].type = 0xFFFFFFFF
            tmpl[0].pValue = None
            tmpl[0].ulValueLen = 0
            rv = rs.raw.C_GetAttributeValue(rs.sh, key, tmpl, 1)
            # Module should reject nonsense attribute type
            assert rv != CKR_OK or tmpl[0].ulValueLen == 0xFFFFFFFF
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestCKRSessionErrors:
    """Test session-related CKR codes."""

    def test_ckr_user_already_logged_in(self, p11_raw_session: Any) -> None:
        """Double login triggers CKR_USER_ALREADY_LOGGED_IN.

        Per PKCS#11 v3.2: C_Login when already logged in MUST return
        CKR_USER_ALREADY_LOGGED_IN. NSS returns CKR_PIN_INCORRECT because it
        re-validates the PIN on every C_Login call even when already authenticated.
        CKR_USER_TYPE_INVALID is accepted for NSS slots that require no login.
        """
        rs = p11_raw_session
        # Already logged in via fixture; try to login again
        pin = b"1234"  # default test PIN
        pin_buf = (ctypes.c_ubyte * len(pin))(*pin)
        rv = rs.raw.C_Login(rs.sh, CKU_USER, pin_buf, len(pin))
        assert rv in (
            CKR_USER_ALREADY_LOGGED_IN,
            CKR_USER_TYPE_INVALID,  # NSS: slot requires no login
            CKR_PIN_INCORRECT,  # NSS: re-validates PIN on duplicate login
        ), f"Expected CKR_USER_ALREADY_LOGGED_IN, got {ckr_name(rv)}"


class TestCKRObjectErrors:
    """Test object-related CKR codes."""

    def test_ckr_object_handle_invalid_after_destroy(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Using a destroyed object's handle -> CKR_OBJECT_HANDLE_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        rs.raw.C_DestroyObject(rs.sh, key)
        # Negative op on a destroyed handle. Issue C_GetAttributeValue *directly*
        # (not via read_attributes, which would re-raise the correct
        # CKR_OBJECT_HANDLE_INVALID rejection as a setup error). Sizing call only.
        tmpl = (CK_ATTRIBUTE * 1)()
        tmpl[0].type = CKA_LABEL
        tmpl[0].pValue = None
        tmpl[0].ulValueLen = 0
        rv = rs.raw.C_GetAttributeValue(rs.sh, key, tmpl, 1)
        # CKR_OK -> the read succeeded on a destroyed handle (use-after-destroy)
        # -> fail. A handle-invalid rejection is spec-correct -> pass. Any other
        # clean reject code -> xfail (honest non-spec deviation).
        classify_negative_rv(
            rv,
            (CKR_OBJECT_HANDLE_INVALID, CKR_SESSION_HANDLE_INVALID),
            label="C_GetAttributeValue via a destroyed object handle (use-after-destroy)",
        )
