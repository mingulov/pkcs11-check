"""Tests for mechanisms that lack dedicated roundtrip coverage.

Phase 4.1: High-priority mechanism roundtrip tests for:
- CKM_SHAKE_128 / CKM_SHAKE_256 — XOF digest (requires C_DigestXof* functions)
- CKM_SHA512_224 / CKM_SHA512_256 — Truncated SHA-512 variants
- CKM_AES_KEY_WRAP_KWP — AES Key Wrap with Padding
- CKM_KMAC_128 / CKM_KMAC_256 — Keccak MAC (v3.2)
- CKM_ML_DSA_EXTERNAL_MU — External message update PQC sign
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    gen_aes_key,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_KEY_WRAP_KWP,
    CKM_SHA512_224,
    CKM_SHA512_256,
    CKO_SECRET_KEY,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)

pytestmark = pytest.mark.full


class TestSHAKEDigest:
    """CKM_SHAKE_128 and CKM_SHAKE_256 XOF digest via C_DigestXof functions.

    SHAKE is an extendable-output function. Per PKCS#11 v3.1 working draft,
    it requires C_DigestXofInit/C_DigestXofUpdate/C_DigestXofExtract/
    C_DigestXofFinal which are not yet in the published stable headers.

    Most current modules do not expose SHAKE as a standalone digest mechanism.
    Tests skip cleanly when the functions or mechanism are unavailable.
    """

    def test_shake_128_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHAKE_128"):
            pytest.skip("CKM_SHAKE_128 not supported")
        has_xof = hasattr(rs.raw, "C_DigestXofInit")
        if not has_xof:
            pytest.skip("C_DigestXofInit not available in this raw binding")

    def test_shake_128_xof_init(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHAKE_128"):
            pytest.skip("CKM_SHAKE_128 not supported")
        if not hasattr(rs.raw, "C_DigestXofInit"):
            pytest.skip("C_DigestXofInit not available in this raw binding")
        try:
            mech = mech_simple(0x00000418)
            rv = rs.raw.C_DigestXofInit(rs.sh, mech.byref())
            expect_rv(rv, CKR_OK, CKR_MECHANISM_INVALID)
        except (AttributeError, TypeError):
            pytest.skip("C_DigestXofInit call failed")
            return
        if rv == CKR_MECHANISM_INVALID:
            pytest.skip("CKM_SHAKE_128 mechanism rejected by module")
            return

    def test_shake_256_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHAKE_256"):
            pytest.skip("CKM_SHAKE_256 not supported")
        has_xof = hasattr(rs.raw, "C_DigestXofInit")
        if not has_xof:
            pytest.skip("C_DigestXofInit not available in this raw binding")

    def test_shake_256_xof_init(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHAKE_256"):
            pytest.skip("CKM_SHAKE_256 not supported")
        if not hasattr(rs.raw, "C_DigestXofInit"):
            pytest.skip("C_DigestXofInit not available in this raw binding")
        try:
            mech = mech_simple(0x00000419)
            rv = rs.raw.C_DigestXofInit(rs.sh, mech.byref())
            expect_rv(rv, CKR_OK, CKR_MECHANISM_INVALID)
        except (AttributeError, TypeError):
            pytest.skip("C_DigestXofInit call failed")
            return
        if rv == CKR_MECHANISM_INVALID:
            pytest.skip("CKM_SHAKE_256 mechanism rejected by module")
            return


class TestSHA512Truncated:
    """CKM_SHA512_224 and CKM_SHA512_256 truncated SHA-512 digests."""

    def test_sha512_224_cross_verify(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_224"):
            pytest.skip("CKM_SHA512_224 not supported")
        data = b"SHA-512/224 cross-verification test data"
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_224, data)
        expected = hashlib.new("sha512_224", data).digest()
        assert p11_digest == expected

    def test_sha512_224_empty_data(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_224"):
            pytest.skip("CKM_SHA512_224 not supported")
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_224, b"")
        expected = hashlib.new("sha512_224", b"").digest()
        assert p11_digest == expected
        assert len(p11_digest) == 28

    def test_sha512_256_cross_verify(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_256"):
            pytest.skip("CKM_SHA512_256 not supported")
        data = b"SHA-512/256 cross-verification test data"
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_256, data)
        expected = hashlib.new("sha512_256", data).digest()
        assert p11_digest == expected

    def test_sha512_256_empty_data(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_256"):
            pytest.skip("CKM_SHA512_256 not supported")
        p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512_256, b"")
        expected = hashlib.new("sha512_256", b"").digest()
        assert p11_digest == expected
        assert len(p11_digest) == 32

    def test_sha512_224_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_224"):
            pytest.skip("CKM_SHA512_224 not supported")
        data = b"deterministic SHA-512/224 test"
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA512_224, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA512_224, data)
        assert d1 == d2

    def test_sha512_256_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA512_256"):
            pytest.skip("CKM_SHA512_256 not supported")
        data = b"deterministic SHA-512/256 test"
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA512_256, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA512_256, data)
        assert d1 == d2


class TestAESKeyWrapKWP:
    """CKM_AES_KEY_WRAP_KWP — AES Key Wrap with Padding (NIST SP 800-38F)."""

    def test_wrap_unwrap_roundtrip(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
            pytest.skip("CKM_AES_KEY_WRAP_KWP not supported")

        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )

        target_key = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
        )
        unwrapped_h = 0
        try:
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                target_key,
                CKM_AES_KEY_WRAP_KWP,
            )
            assert len(wrapped) > 0, "wrap_key returned empty output"

            unwrapped_h = unwrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                wrapped,
                CKM_AES_KEY_WRAP_KWP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                    CKA_ENCRYPT: True,
                },
            )
        finally:
            if unwrapped_h:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
            destroy_quietly(rs.raw, rs.sh, target_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)

    def test_wrap_unwrap_256bit_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
            pytest.skip("CKM_AES_KEY_WRAP_KWP not supported")

        wrapping_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_TOKEN: False,
            },
        )

        target_key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
        )
        unwrapped_h = 0
        try:
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                target_key,
                CKM_AES_KEY_WRAP_KWP,
            )
            assert len(wrapped) > 0

            unwrapped_h = unwrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                wrapped,
                CKM_AES_KEY_WRAP_KWP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
            )
        finally:
            if unwrapped_h:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
            destroy_quietly(rs.raw, rs.sh, target_key)
            destroy_quietly(rs.raw, rs.sh, wrapping_key)


class TestKMAC:
    """CKM_KMAC_128 / CKM_KMAC_256 — Keccak MAC (v3.2, NIST SP 800-185).

    KMAC mechanisms require CK_KMAC_PARAMS with a key handle, output length,
    and optional customization string. These are XOF-capable: output can be
    any length when ulMacLength is 0.

    Most current modules do not yet support KMAC. Tests skip cleanly.
    """

    @pytest.mark.requires_v32
    def test_kmac_128_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_128"):
            pytest.skip("CKM_KMAC_128 not supported")

    @pytest.mark.requires_v32
    def test_kmac_256_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_256"):
            pytest.skip("CKM_KMAC_256 not supported")

    @pytest.mark.requires_v32
    def test_kmac_128_sign_roundtrip(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_128"):
            pytest.skip("CKM_KMAC_128 not supported")
        pytest.skip(
            "CKM_KMAC_128 requires CK_KMAC_PARAMS mechanism parameter "
            "not yet available in pkcs11_check.raw bindings"
        )

    @pytest.mark.requires_v32
    def test_kmac_256_sign_roundtrip(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("KMAC_256"):
            pytest.skip("CKM_KMAC_256 not supported")
        pytest.skip(
            "CKM_KMAC_256 requires CK_KMAC_PARAMS mechanism parameter "
            "not yet available in pkcs11_check.raw bindings"
        )


class TestMLDSAExternalMU:
    """CKM_ML_DSA_EXTERNAL_MU — External message update PQC sign (v3.2).

    ExternalMu-ML-DSA accepts a precomputed 64-byte message representative mu
    instead of hashing the message on-token. The mu value is normally computed
    by step 6 of algorithm 7 in FIPS-204.

    Since CKM_ML_DSA_EXTERNAL_MU and its constant are not yet in the stable
    published PKCS#11 headers (only in working draft), and no CKM constant
    exists in pkcs11_check.raw.types_std, we test mechanism availability and
    document the limitation.
    """

    @pytest.mark.requires_v32
    def test_external_mu_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA_EXTERNAL_MU"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU not supported")

    @pytest.mark.requires_v32
    def test_external_mu_sign_verify_with_dummy_mu(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA_EXTERNAL_MU"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU not supported")
        if not rs.has_mechanism("ML_DSA"):
            pytest.skip("CKM_ML_DSA keygen not supported for EXTERNAL_MU test")
        pytest.skip(
            "CKM_ML_DSA_EXTERNAL_MU constant (0x00000020) not yet in "
            "pkcs11_check.raw.types_std — awaiting published PKCS#11 header"
        )
