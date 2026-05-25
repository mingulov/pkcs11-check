"""Security probes for weak or invalid mechanism parameters.

Tests that modules correctly reject insecure parameter choices:
- GCM with weak tag sizes, weak/empty IVs, IV reuse, NULL AAD pointer
- PSS with zero or excessive salt length
- XTS with identical key halves
- RSA with weak public exponents
- EC with invalid points (off-curve, infinity, truncated)
- OAEP with SHA-1 MGF, PSS with MD5 hash
- CBC with all-zero IV
- ECB pattern leakage confirmation
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.pack_mechanisms import mech_ecdh, mech_gcm, mech_oaep, mech_pss
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    import_secret_key,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKD_NULL,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_GCM,
    CKM_AES_XTS,
    CKM_ECDH1_DERIVE,
    CKM_MD5,
    CKM_RSA_PKCS_OAEP,
    CKM_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases._subprocess_preamble import (
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess_per_test]

# ---------------------------------------------------------------------------
# GCM tag size validation
# ---------------------------------------------------------------------------

_WEAK_GCM_TAG_BITS = [
    pytest.param(0, id="tag-0-bits"),
    pytest.param(8, id="tag-8-bits"),
    pytest.param(32, id="tag-32-bits"),
    pytest.param(64, id="tag-64-bits"),
]


class TestGcmTagSize:
    """Probe whether the module accepts weak GCM authentication tag sizes.

    NIST SP 800-38D requires tag lengths of 96, 104, 112, 120, or 128 bits.
    Tag lengths below 96 bits weaken authentication guarantees significantly.
    """

    @pytest.mark.parametrize("tag_bits", _WEAK_GCM_TAG_BITS)
    def test_gcm_weak_tag_size(self, p11_raw_session: Any, tag_bits: int) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            iv = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
            pt = b"A" * 32
            mech = mech_gcm(CKM_AES_GCM, iv, tag_bits=tag_bits)
            overhead = tag_bits // 8 if tag_bits > 0 else 0
            try:
                encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    pt,
                    mech_param=mech,
                    output_overhead=overhead,
                )
                # Module accepted a weak tag -- report finding
                note(
                    f"AES-GCM accepts {tag_bits}-bit tag -- below NIST minimum of 96 bits",
                    ComplianceLevel.VENDOR,
                    reference="NIST SP 800-38D Section 5.2.1.2: tag lengths < 96 bits "
                    "are not recommended",
                )
            except (AssertionError, OSError):
                pass  # Module rejected weak tag -- correct behavior
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# GCM IV weakness
# ---------------------------------------------------------------------------

_WEAK_GCM_IVS = [
    pytest.param(b"", id="empty-iv"),
    pytest.param(b"\x00", id="single-zero-byte-iv"),
    pytest.param(b"\x00" * 4, id="4-zero-bytes-iv"),
]


class TestGcmIvWeakness:
    """Probe whether the module accepts weak/short GCM IVs.

    NIST SP 800-38D strongly recommends 96-bit (12-byte) IVs.
    Shorter or empty IVs are insecure.
    """

    @pytest.mark.parametrize("iv", _WEAK_GCM_IVS)
    def test_gcm_weak_iv(self, p11_raw_session: Any, iv: bytes) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            pt = b"B" * 32
            mech = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    pt,
                    mech_param=mech,
                    output_overhead=16,
                )
                note(
                    f"AES-GCM accepts {len(iv)}-byte IV -- NIST recommends 96-bit (12-byte)",
                    ComplianceLevel.VENDOR,
                    reference="NIST SP 800-38D Section 8.2.1: "
                    "IVs should be 96 bits for interoperability and security",
                )
            except (AssertionError, OSError):
                pass  # Module rejected weak IV -- correct behavior
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# GCM IV reuse
# ---------------------------------------------------------------------------


class TestGcmIvReuse:
    """Probe whether the module prevents IV reuse with the same key.

    Reusing an IV with the same key in GCM completely breaks confidentiality
    and authenticity. NIST SP 800-38D requires IV uniqueness per key.
    """

    def test_gcm_iv_reuse_same_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            iv = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
            pt1 = b"A" * 32
            pt2 = b"B" * 32
            mech1 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                pt1,
                mech_param=mech1,
                output_overhead=16,
            )
            # Second encrypt with SAME key + SAME IV
            mech2 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                ct2 = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    pt2,
                    mech_param=mech2,
                    output_overhead=16,
                )
                # Both succeeded -- IV reuse not prevented
                _ = ct1, ct2  # suppress unused warnings
                note(
                    "AES-GCM allows IV reuse with same key -- NIST SP 800-38D violation",
                    ComplianceLevel.CRITICAL,
                    reference="NIST SP 800-38D: IVs must be unique per key",
                )
            except (AssertionError, OSError):
                pass  # Module rejected reuse -- good
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# GCM NULL AAD pointer with non-zero length (subprocess -- crash risk)
# ---------------------------------------------------------------------------


class TestGcmAadNullWithLength:
    """Test GCM with NULL AAD pointer but non-zero AAD length.

    This NULL-pointer + non-zero-length mismatch can cause crashes in
    modules that dereference pAAD without checking ulAADLen first.
    """

    def test_gcm_null_aad_pointer_nonzero_length(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        preamble = subprocess_session_preamble(
            str(p11_config.module),
            pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
        )
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import CK_AES_GCM_PARAMS, CKM_AES_GCM, CK_MECHANISM
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    params = CK_AES_GCM_PARAMS()
    params.pIv = (ctypes.c_ubyte * 12)(*range(12))
    params.ulIvLen = 12
    params.ulIvBits = 96
    params.pAAD = None  # NULL pointer
    params.ulAADLen = 16  # Non-zero length -- mismatch!
    params.ulTagBits = 128
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_GCM)
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="GCM NULL AAD pointer with nonzero ulAADLen",
        )


# ---------------------------------------------------------------------------
# PSS salt length validation
# ---------------------------------------------------------------------------

_PSS_SALT_LENGTHS = [
    pytest.param(0, id="sLen-0-deterministic"),
]


class TestPssSaltLength:
    """Probe RSA-PSS salt length edge cases.

    sLen=0 makes PSS deterministic (same message always produces same signature),
    weakening the scheme. sLen > (modLen/8 - hashLen - 2) is invalid per RFC 8017.
    """

    @pytest.mark.parametrize("salt_len", _PSS_SALT_LENGTHS)
    def test_pss_zero_salt_length(self, p11_raw_session: Any, salt_len: int) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("SHA256_RSA_PKCS_PSS not supported")
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            pss = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
                salt_len=salt_len,
            )
            data = b"PSS salt length test"
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_SHA256_RSA_PKCS_PSS,
                    data,
                    mech_param=pss,
                )
                note(
                    f"RSA-PSS accepts sLen={salt_len} -- deterministic signatures "
                    f"(produced {len(sig)}-byte signature)",
                    ComplianceLevel.VENDOR,
                    reference="RFC 8017 Section 9.1: sLen=0 makes PSS deterministic, "
                    "reducing security margin",
                )
            except (AssertionError, OSError):
                pass  # Module rejected zero salt -- acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_pss_excessive_salt_length(self, p11_raw_session: Any) -> None:
        """PSS with salt exceeding maximum: sLen > (modLen/8 - hashLen - 2).

        For 2048-bit RSA with SHA-256 (32-byte hash):
        max sLen = 256 - 32 - 2 = 222 bytes.
        We use sLen = 255 which exceeds the limit.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("SHA256_RSA_PKCS_PSS not supported")
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            # max sLen = 256 - 32 - 2 = 222 for 2048-bit RSA / SHA-256
            pss = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
                salt_len=255,
            )
            data = b"PSS excessive salt test"
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_SHA256_RSA_PKCS_PSS,
                    data,
                    mech_param=pss,
                )
                note(
                    f"RSA-PSS accepts sLen=255 exceeding maximum of 222 "
                    f"(produced {len(sig)}-byte signature)",
                    ComplianceLevel.VENDOR,
                    reference="RFC 8017 Section 9.1: sLen must not exceed emLen - hLen - 2",
                )
            except (AssertionError, OSError):
                pass  # Module rejected excessive salt -- correct
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# XTS identical key halves
# ---------------------------------------------------------------------------


class TestXtsKeyValidation:
    """Probe whether the module rejects XTS keys with identical halves.

    AES-XTS uses two independent 128-bit keys. If both halves are identical,
    the tweak encryption degenerates, weakening the construction to ECB-like
    behavior. NIST SP 800-38E forbids this.
    """

    def test_xts_identical_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_XTS"):
            pytest.skip("AES_XTS not supported")
        # 256-bit key = 128-bit data key + 128-bit tweak key (identical)
        half = b"\xaa" * 16
        key_material = half + half  # Both halves identical
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                key_material,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                },
            )
        except (AssertionError, OSError):
            return  # Module rejected identical halves at import -- good
        # Key was imported; try to use it
        try:
            mech = mech_simple(CKM_AES_XTS)
            pt = b"C" * 32  # At least two blocks
            try:
                encrypt_single(rs.raw, rs.sh, key, CKM_AES_XTS, pt, mech_param=mech)
                note(
                    "AES-XTS accepts key with identical halves -- NIST SP 800-38E violation",
                    ComplianceLevel.VENDOR,
                    reference="NIST SP 800-38E: the two AES keys in XTS must differ",
                )
            except (AssertionError, OSError):
                pass  # Module rejected at encrypt time -- acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# RSA weak public exponent
# ---------------------------------------------------------------------------

_WEAK_RSA_EXPONENTS = [
    pytest.param(0, id="e=0"),
    pytest.param(1, id="e=1"),
    pytest.param(2, id="e=2"),
    pytest.param(3, id="e=3-low"),
    pytest.param(4, id="e=4"),
]


class TestRsaExponent:
    """Probe whether the module rejects weak RSA public exponents.

    e=0 is invalid, e=1 produces identity encryption (m^1 mod n = m), e=2/e=4
    are even, and e=3 is a historically common but weak low public exponent.
    All should be rejected.
    """

    @pytest.mark.parametrize("exponent", _WEAK_RSA_EXPONENTS)
    def test_rsa_weak_public_exponent(self, p11_raw_session: Any, exponent: int) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        # Encode exponent as big-endian bytes
        byte_len = max(1, (exponent.bit_length() + 7) // 8)
        exp_bytes = exponent.to_bytes(byte_len, "big")
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                public_attrs={CKA_PUBLIC_EXPONENT: exp_bytes},
            )
        except (AssertionError, OSError):
            return  # Module rejected weak exponent -- correct behavior
        try:
            note(
                f"Module accepts RSA keygen with public exponent e={exponent}",
                ComplianceLevel.VENDOR,
                reference="FIPS 186-5: public exponent must be odd and >= 65537 for key generation",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# EC point validation for ECDH
# ---------------------------------------------------------------------------

_INVALID_EC_POINTS = [
    pytest.param("off_curve", id="off-curve-point"),
    pytest.param("infinity", id="point-at-infinity"),
    pytest.param("truncated", id="truncated-point"),
]


class TestEcPointValidation:
    """Probe whether the module validates EC public keys in ECDH derive.

    Invalid points (off-curve, infinity, truncated) used in ECDH can leak
    the private key through invalid-curve attacks. Modules must validate
    incoming public keys per NIST SP 800-56A.
    """

    @pytest.mark.parametrize("point_type", _INVALID_EC_POINTS)
    def test_ecdh_invalid_point(self, p11_raw_session: Any, point_type: str) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("ECDH1_DERIVE not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(
            rs.raw,
            rs.sh,
            curve_oid,
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
        try:
            # Read the valid EC point to use as a base for crafting invalid ones
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])
            ec_point_val = attrs[CKA_EC_POINT]
            assert isinstance(ec_point_val, bytes)
            raw_point = decode_ec_point(ec_point_val)

            invalid_point = self._craft_invalid_point(raw_point, point_type)

            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_ECDH1_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                        CKA_VALUE_LEN: 32,
                    },
                    mech_param=mech_ecdh(
                        CKM_ECDH1_DERIVE,
                        kdf=CKD_NULL,
                        public_data=invalid_point,
                    ),
                )
            except (AssertionError, OSError):
                return  # Module rejected invalid point -- correct behavior

            try:
                note(
                    f"ECDH derive accepts {point_type} point -- invalid curve attack risk",
                    ComplianceLevel.CRITICAL,
                    reference="NIST SP 800-56A Section 5.6.2.3.3: "
                    "full public key validation required",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @staticmethod
    def _craft_invalid_point(valid_point: bytes, point_type: str) -> bytes:
        """Craft an invalid EC point from a valid uncompressed point.

        Args:
            valid_point: Uncompressed point (0x04 || x || y) for P-256 (65 bytes).
            point_type: Type of invalidity to introduce.

        Returns:
            Invalid point bytes.
        """
        if point_type == "off_curve":
            # Flip the last byte of Y coordinate to move point off curve
            modified = bytearray(valid_point)
            modified[-1] ^= 0x01
            return bytes(modified)
        elif point_type == "infinity":
            # Point at infinity encoded as a single 0x00 byte
            return b"\x00"
        elif point_type == "truncated":
            # Cut the point short -- missing half of Y coordinate
            return valid_point[: len(valid_point) // 2]
        else:
            raise ValueError(f"Unknown point type: {point_type}")


# ---------------------------------------------------------------------------
# Standalone weakness probes
# ---------------------------------------------------------------------------


class TestRsaOaepSha1Mgf:
    """Probe whether RSA-OAEP with SHA-1 MGF is accepted."""

    def test_rsa_oaep_sha1_mgf(self, p11_raw_session: Any) -> None:
        """RSA-OAEP with SHA-1 as MGF hash -- weakness report.

        SHA-1 is deprecated for collision resistance (SHAttered, 2017).
        While OAEP does not directly rely on collision resistance,
        using SHA-1 in MGF is a cryptographic hygiene concern.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("RSA_PKCS_OAEP not supported")
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            pt = b"OAEP SHA-1 MGF test"
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP,
                    pt,
                    mech_param=oaep,
                )
                _ = ct
                note(
                    "RSA-OAEP accepts SHA-1 as MGF hash function",
                    ComplianceLevel.VENDOR,
                    reference="SHA-1 deprecated per NIST SP 800-131A Rev.2; "
                    "prefer SHA-256 or stronger for new applications",
                )
            except (AssertionError, OSError):
                pass  # Module rejected SHA-1 MGF -- acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestRsaPssMd5Hash:
    """Probe whether RSA-PSS with MD5 hash is accepted."""

    def test_rsa_pss_md5_hash(self, p11_raw_session: Any) -> None:
        """RSA-PSS with MD5 as hash -- weakness report.

        MD5 has been broken for collision resistance since 2004.
        Using MD5 in PSS signatures enables forgery attacks.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("RSA_PKCS_PSS"):
            pytest.skip("RSA_PKCS_PSS not supported")
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        )
        try:
            # MD5 hash with SHA-256 MGF -- intentionally mismatched
            # to specifically test whether MD5 hash is accepted
            pss = mech_pss(
                CKM_RSA_PKCS_PSS,
                hash_mech=CKM_MD5,
                mgf=CKG_MGF1_SHA256,
                salt_len=16,  # MD5 digest length
            )
            data = b"PSS MD5 hash test"
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_RSA_PKCS_PSS,
                    data,
                    mech_param=pss,
                )
                _ = sig
                note(
                    "RSA-PSS accepts MD5 as hash algorithm",
                    ComplianceLevel.VENDOR,
                    reference="MD5 collision attacks are practical since 2004; "
                    "NIST SP 800-131A Rev.2 disallows MD5 for digital signatures",
                )
            except (AssertionError, OSError):
                pass  # Module rejected MD5 -- correct behavior
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestCbcIvAllZeros:
    """Probe whether AES-CBC accepts an all-zero IV."""

    def test_cbc_iv_all_zeros(self, p11_raw_session: Any) -> None:
        """AES-CBC with all-zero IV -- weakness report.

        An all-zero IV makes the first block encryption equivalent to ECB
        for the first block. While not always a vulnerability, it indicates
        weak IV generation practices.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("AES_CBC not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            zero_iv = b"\x00" * 16  # 128-bit all-zero IV
            pt = b"D" * 16  # Single AES block
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC,
                    pt,
                    mech_param=mech_bytes(CKM_AES_CBC, zero_iv),
                )
                _ = ct
                note(
                    "AES-CBC accepts all-zero IV -- weak IV generation indicator",
                    ComplianceLevel.VENDOR,
                    reference="CWE-329: not using a random IV for CBC makes "
                    "the first block equivalent to ECB",
                )
            except (AssertionError, OSError):
                pass  # Module rejected all-zero IV -- unusual but acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestEcbPatternLeakage:
    """Confirm ECB mode leaks plaintext patterns.

    ECB encrypts each block independently, so identical plaintext blocks
    produce identical ciphertext blocks. This is inherent to ECB and is
    a compliance note confirming expected behavior.
    """

    def test_ecb_pattern_leakage(self, p11_raw_session: Any) -> None:
        """Encrypt two identical blocks and verify identical ciphertext."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("AES_ECB not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            # Two identical 16-byte blocks
            block = b"E" * 16
            pt = block + block  # 32 bytes = 2 identical blocks
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            ct_block1 = ct[:16]
            ct_block2 = ct[16:32]
            if ct_block1 == ct_block2:
                note(
                    "AES-ECB produces identical ciphertext for identical plaintext blocks "
                    "-- expected pattern leakage confirmed",
                    ComplianceLevel.VENDOR,
                    reference="NIST SP 800-38A: ECB mode does not provide "
                    "semantic security; avoid for multi-block data",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
