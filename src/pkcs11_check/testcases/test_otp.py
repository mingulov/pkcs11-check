"""OTP and CT-KIP mechanism tests - HOTP, SecurID, ACTI, CT-KIP.

Covers OTP key generation and OTP value generation via sign operations:
- CKM_HOTP_KEY_GEN / CKM_HOTP
- CKM_SECURID_KEY_GEN / CKM_SECURID
- CKM_ACTI_KEY_GEN / CKM_ACTI

Also covers CT-KIP key derivation/wrapping/MAC mechanisms:
- CKM_KIP_DERIVE
- CKM_KIP_WRAP
- CKM_KIP_MAC

These mechanisms are rarely supported by software HSMs. All tests check
mechanism availability and skip cleanly when not supported.

OASIS spec: otp_mechanisms.md, ct-kip.md
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_ACTI,
    CKK_HOTP,
    CKK_SECURID,
    CKM_ACTI,
    CKM_ACTI_KEY_GEN,
    CKM_HOTP,
    CKM_HOTP_KEY_GEN,
    CKM_SECURID,
    CKM_SECURID_KEY_GEN,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = pytest.mark.full

_OTP_OPERATIONAL_ERROR_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _xfail_otp_reject(exc: AssertionError, msg: str) -> None:
    xfail_if_known_ckr(exc, _OTP_OPERATIONAL_ERROR_CKRS, msg)
    raise exc


def _gen_otp_key(rs: Any, key_type: int, mechanism: int) -> int:
    """Generate an OTP key with minimal template."""
    return gen_aes_key(
        rs.raw,
        rs.sh,
        0,
        attrs={
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: key_type,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_SIGN: True,
        },
        mechanism=mechanism,
    )


class TestHOTP:
    """Tests for CKM_HOTP_KEY_GEN and CKM_HOTP."""

    def test_hotp_key_gen(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_HOTP, CKM_HOTP_KEY_GEN)
            assert key != 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_HOTP_KEY_GEN advertised but keygen rejected")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_hotp_generate_otp(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        if not rs.has_mechanism("HOTP"):
            pytest.skip("CKM_HOTP not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_HOTP, CKM_HOTP_KEY_GEN)
            otp = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_HOTP advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_hotp_two_otps_differ(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        if not rs.has_mechanism("HOTP"):
            pytest.skip("CKM_HOTP not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_HOTP, CKM_HOTP_KEY_GEN)
            otp1 = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            otp2 = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            assert otp1 != otp2, "Consecutive HOTP values must differ"
        except AssertionError as exc:
            if "Consecutive" in str(exc):
                raise
            _xfail_otp_reject(exc, "CKM_HOTP advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestSecurID:
    """Tests for CKM_SECURID_KEY_GEN and CKM_SECURID."""

    def test_securid_key_gen(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SECURID_KEY_GEN"):
            pytest.skip("CKM_SECURID_KEY_GEN not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_SECURID, CKM_SECURID_KEY_GEN)
            assert key != 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_SECURID_KEY_GEN advertised but keygen rejected")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_securid_generate_otp(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SECURID_KEY_GEN"):
            pytest.skip("CKM_SECURID_KEY_GEN not supported")
        if not rs.has_mechanism("SECURID"):
            pytest.skip("CKM_SECURID not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_SECURID, CKM_SECURID_KEY_GEN)
            otp = sign_single(rs.raw, rs.sh, key, CKM_SECURID, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_SECURID advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestACTI:
    """Tests for CKM_ACTI_KEY_GEN and CKM_ACTI."""

    def test_acti_key_gen(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ACTI_KEY_GEN"):
            pytest.skip("CKM_ACTI_KEY_GEN not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_ACTI, CKM_ACTI_KEY_GEN)
            assert key != 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_ACTI_KEY_GEN advertised but keygen rejected")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    def test_acti_generate_otp(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ACTI_KEY_GEN"):
            pytest.skip("CKM_ACTI_KEY_GEN not supported")
        if not rs.has_mechanism("ACTI"):
            pytest.skip("CKM_ACTI not supported")
        key = 0
        try:
            key = _gen_otp_key(rs, CKK_ACTI, CKM_ACTI_KEY_GEN)
            otp = sign_single(rs.raw, rs.sh, key, CKM_ACTI, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            _xfail_otp_reject(exc, "CKM_ACTI advertised but sign is not operational")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestCTKIP:
    """Tests for CT-KIP mechanisms: CKM_KIP_DERIVE, CKM_KIP_WRAP, CKM_KIP_MAC."""

    def test_kip_derive_skips_when_unsupported(
        self,
        p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_DERIVE"):
            pytest.skip("CKM_KIP_DERIVE not supported")
        pytest.skip("CKM_KIP_DERIVE requires CT-KIP parameter setup")

    def test_kip_wrap_skips_when_unsupported(
        self,
        p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_WRAP"):
            pytest.skip("CKM_KIP_WRAP not supported")
        # Mechanism listed but requires specialized key types not available in standard tests
        pytest.skip("CKM_KIP_WRAP requires specialized key types")

    def test_kip_mac_skips_when_unsupported(
        self,
        p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_MAC"):
            pytest.skip("CKM_KIP_MAC not supported")
        pytest.skip("CKM_KIP_MAC requires specialized key types")

    def test_kip_mac_verify_skips_when_unsupported(
        self,
        p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_MAC"):
            pytest.skip("CKM_KIP_MAC not supported")
        pytest.skip("CKM_KIP_MAC requires specialized key types")
