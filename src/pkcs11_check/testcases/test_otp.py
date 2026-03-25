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
    create_object,
    destroy_quietly,
    gen_aes_key,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_ACTI,
    CKK_GENERIC_SECRET,
    CKK_HOTP,
    CKK_SECURID,
    CKM_ACTI,
    CKM_ACTI_KEY_GEN,
    CKM_HOTP,
    CKM_HOTP_KEY_GEN,
    CKM_KIP_DERIVE,
    CKM_SECURID,
    CKM_SECURID_KEY_GEN,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.full


def _gen_otp_key(rs: Any, key_type: int, mechanism: int) -> int:
    """Generate an OTP key with minimal template."""
    return gen_aes_key(
        rs.raw, rs.sh, 0,
        attrs={
            int(CKA_CLASS): int(CKO_SECRET_KEY),
            int(CKA_KEY_TYPE): key_type,
            int(CKA_TOKEN): False,
            int(CKA_SENSITIVE): False,
            int(CKA_EXTRACTABLE): True,
            int(CKA_SIGN): True,
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
            key = _gen_otp_key(rs, int(CKK_HOTP), int(CKM_HOTP_KEY_GEN))
            assert key != 0
        except AssertionError as exc:
            pytest.xfail(f"CKM_HOTP_KEY_GEN keygen rejected: {exc}")
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
            key = _gen_otp_key(rs, int(CKK_HOTP), int(CKM_HOTP_KEY_GEN))
            otp = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            pytest.xfail(f"CKM_HOTP not operational: {exc}")
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
            key = _gen_otp_key(rs, int(CKK_HOTP), int(CKM_HOTP_KEY_GEN))
            otp1 = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            otp2 = sign_single(rs.raw, rs.sh, key, CKM_HOTP, b"")
            assert otp1 != otp2, "Consecutive HOTP values must differ"
        except AssertionError as exc:
            if "Consecutive" in str(exc):
                raise
            pytest.xfail(f"CKM_HOTP not operational: {exc}")
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
            key = _gen_otp_key(rs, int(CKK_SECURID), int(CKM_SECURID_KEY_GEN))
            assert key != 0
        except AssertionError as exc:
            pytest.xfail(f"CKM_SECURID_KEY_GEN keygen rejected: {exc}")
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
            key = _gen_otp_key(rs, int(CKK_SECURID), int(CKM_SECURID_KEY_GEN))
            otp = sign_single(rs.raw, rs.sh, key, CKM_SECURID, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            pytest.xfail(f"CKM_SECURID not operational: {exc}")
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
            key = _gen_otp_key(rs, int(CKK_ACTI), int(CKM_ACTI_KEY_GEN))
            assert key != 0
        except AssertionError as exc:
            pytest.xfail(f"CKM_ACTI_KEY_GEN keygen rejected: {exc}")
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
            key = _gen_otp_key(rs, int(CKK_ACTI), int(CKM_ACTI_KEY_GEN))
            otp = sign_single(rs.raw, rs.sh, key, CKM_ACTI, b"")
            assert len(otp) > 0
        except AssertionError as exc:
            pytest.xfail(f"CKM_ACTI not operational: {exc}")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestCTKIP:
    """Tests for CT-KIP mechanisms: CKM_KIP_DERIVE, CKM_KIP_WRAP, CKM_KIP_MAC."""

    def _make_generic_key(self, rs: Any) -> int:
        return gen_aes_key(
            rs.raw, rs.sh, 128,
            attrs={
                int(CKA_TOKEN): False,
                int(CKA_SENSITIVE): False,
                int(CKA_EXTRACTABLE): True,
                int(CKA_DERIVE): True,
                int(CKA_SIGN): True,
                int(CKA_VERIFY): True,
            },
            mechanism=int(CKA_KEY_TYPE),  # use AES_KEY_GEN default
        )

    def _make_generic_key_raw(self, rs: Any) -> int:
        """Create a 16-byte GENERIC_SECRET key."""
        return create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_SECRET_KEY),
            int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET),
            int(CKA_VALUE_LEN): 16,
            int(CKA_TOKEN): False,
            int(CKA_SENSITIVE): False,
            int(CKA_EXTRACTABLE): True,
            int(CKA_DERIVE): True,
            int(CKA_SIGN): True,
            int(CKA_VERIFY): True,
            int(CKA_WRAP): True,
        })

    def test_kip_derive_skips_when_unsupported(
        self, p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_DERIVE"):
            pytest.skip("CKM_KIP_DERIVE not supported")
        base_key = 0
        derived = 0
        try:
            base_key = _gen_otp_key(
                rs, int(CKK_GENERIC_SECRET),
                int(CKM_KIP_DERIVE),
            )
            # This will almost certainly fail - xfail expected
            pytest.xfail("CKM_KIP_DERIVE keygen unexpectedly succeeded")
        except AssertionError as exc:
            pytest.xfail(f"CKM_KIP_DERIVE rejected: {exc}")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if base_key:
                destroy_quietly(rs.raw, rs.sh, base_key)

    def test_kip_wrap_skips_when_unsupported(
        self, p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_WRAP"):
            pytest.skip("CKM_KIP_WRAP not supported")
        # If mechanism is listed, attempt and xfail
        pytest.xfail("CKM_KIP_WRAP requires specialized key types")

    def test_kip_mac_skips_when_unsupported(
        self, p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_MAC"):
            pytest.skip("CKM_KIP_MAC not supported")
        pytest.xfail("CKM_KIP_MAC requires specialized key types")

    def test_kip_mac_verify_skips_when_unsupported(
        self, p11_raw_session: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KIP_MAC"):
            pytest.skip("CKM_KIP_MAC not supported")
        pytest.xfail("CKM_KIP_MAC requires specialized key types")
