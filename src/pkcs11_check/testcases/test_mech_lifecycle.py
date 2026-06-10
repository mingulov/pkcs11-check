"""Composite lifecycle tests -- multi-step operation patterns.

Each test exercises a realistic end-to-end sequence that crosses multiple
mechanism categories.  These tests are NOT parametrized by mechanism entry;
they use hard-coded mechanism selections to keep complexity manageable.

Patterns covered:
  1. AES key generate -> encrypt -> wrap -> destroy -> unwrap -> decrypt
  2. ECDH derive -> use derived key for AES-CBC encrypt
  3. HKDF expand -> AES-256 key -> AES-ECB encrypt roundtrip
  4. RSA-OAEP wrap AES key -> unwrap -> encrypt/decrypt verify
  5. HMAC-SHA256 sign -> copy key -> verify with copy
  6. Digest then encrypt: hash plaintext, encrypt result
  7. Export then re-import: gen AES -> extract value -> import -> encrypt roundtrip
  8. RSA keygen -> sign -> verify (SHA256-RSA-PKCS roundtrip)
  9. EC keygen -> ECDSA sign -> verify
 10. Generate multiple AES keys -> batch encrypt -> destroy all
 11. AES-GCM encrypt -> AES-GCM decrypt (AEAD full cycle)
"""

from __future__ import annotations

import os
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
from pkcs11_check.raw.pack_mechanisms import mech_ecdh, mech_gcm, mech_hkdf, mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    derive_key,
    destroy_quietly,
    digest_single,
    encrypt_single,
    import_secret_key,
    pack_attrs,
    read_attributes,
    sign_single,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKD_NULL,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_HKDF,
    CKM_AES_ECB,
    CKM_SHA256,
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
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._capability_claims import claim_refusal_passes
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.lifecycle]

_HKDF_KEYGEN_REJECT_CKRS = (
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


class TestAESWrapUnwrapUse:
    """Generate AES -> encrypt -> wrap -> destroy -> unwrap -> decrypt."""

    def test_aes_wrap_roundtrip(self, p11_module_session: RawSession) -> None:
        """Full AES key lifecycle: generate, use, wrap, destroy, unwrap, use again."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        try:
            from pkcs11_check.raw.types_std import CKM_AES_KEY_WRAP
        except ImportError:
            pytest.skip("CKM_AES_KEY_WRAP not in types_std")

        # Generate wrapping key and target key.
        # CKA_UNWRAP is required in addition to CKA_WRAP so the same key can be
        # used for both wrap and unwrap operations.
        wrap_key_handle = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_TOKEN: False},
            purpose="AES lifecycle wrap setup",
        )
        target = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_TOKEN: False,
            },
            purpose="AES lifecycle target setup",
        )
        unwrapped_key: int = 0

        try:
            plaintext = b"\xde\xad\xbe\xef" * 4  # 16 bytes
            ciphertext = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, plaintext)

            # Wrap the target key
            wrapped = wrap_key(rs.raw, rs.sh, wrap_key_handle, target, CKM_AES_KEY_WRAP)
            assert len(wrapped) > 0, "wrap produced empty blob"

            # Destroy original -- only the wrapped copy remains
            destroy_quietly(rs.raw, rs.sh, target)
            target = 0

            # Unwrap and decrypt to verify key material was preserved.
            # CKA_CLASS is required by PKCS#11 spec for C_UnwrapKey -- Kryoptic
            # returns CKR_TEMPLATE_INCONSISTENT when it is absent.
            unwrapped_key = unwrap_key(
                rs.raw,
                rs.sh,
                wrap_key_handle,
                wrapped,
                CKM_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_DECRYPT: True,
                    CKA_ENCRYPT: True,
                    CKA_TOKEN: False,
                },
            )
            assert unwrapped_key != 0, "unwrap returned handle 0"

            recovered = decrypt_single(rs.raw, rs.sh, unwrapped_key, CKM_AES_ECB, ciphertext)
            assert recovered == plaintext, (
                f"wrap/unwrap key mismatch: expected {plaintext.hex()!r}, got {recovered.hex()!r}"
            )
        finally:
            if target != 0:
                destroy_quietly(rs.raw, rs.sh, target)
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            destroy_quietly(rs.raw, rs.sh, wrap_key_handle)


class TestECDHDerivedKeyUse:
    """ECDH1 derive -> use derived key for AES-CBC encryption."""

    def test_ecdh_derive_and_use(self, p11_module_session: RawSession) -> None:
        """ECDH derive a shared secret, use it as AES-128 key to encrypt/decrypt."""
        rs = p11_module_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")

        try:
            from pkcs11_check.raw.ec import encode_named_curve_parameters
            from pkcs11_check.raw.types_std import CKM_AES_CBC, CKM_ECDH1_DERIVE
        except ImportError:
            pytest.skip("Required types not available")

        p256_oid = encode_named_curve_parameters("secp256r1")
        pub_a, priv_a = 0, 0
        pub_b, priv_b = 0, 0
        derived: int = 0

        try:
            pub_a, priv_a = gen_ec_keypair_or_xfail(
                rs,
                p256_oid,
                private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
            )
            pub_b, priv_b = gen_ec_keypair_or_xfail(rs, p256_oid)

            peer_attrs = read_attributes(rs.raw, rs.sh, pub_b, [CKA_EC_POINT])
            peer_point = peer_attrs.get(CKA_EC_POINT)
            if not peer_point or not isinstance(peer_point, bytes):
                pytest.skip("Cannot read CKA_EC_POINT from peer public key")

            ecdh_param = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=peer_point)

            # CKA_CLASS is required by PKCS#11 spec for C_DeriveKey -- Kryoptic
            # returns CKR_TEMPLATE_INCONSISTENT when it is absent.
            derived = derive_key(
                rs.raw,
                rs.sh,
                priv_a,
                CKM_ECDH1_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE_LEN: 16,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
                mech_param=ecdh_param,
            )
            assert derived != 0, "ECDH derive returned handle 0"

            # Use derived key for AES-CBC encrypt/decrypt roundtrip
            from pkcs11_check.raw.pack import mech_bytes

            iv = os.urandom(16)

            cbc_param = mech_bytes(CKM_AES_CBC, iv)
            plaintext = b"ecdh lifecycle test padded 32byt"
            ct = encrypt_single(
                rs.raw, rs.sh, derived, CKM_AES_CBC, plaintext, mech_param=cbc_param
            )
            pt = decrypt_single(rs.raw, rs.sh, derived, CKM_AES_CBC, ct, mech_param=cbc_param)
            assert pt == plaintext, (
                f"ECDH-derived key encrypt/decrypt mismatch: "
                f"expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            for h in (pub_a, priv_a, pub_b, priv_b, derived):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestHKDFDerivedKeyUse:
    """HKDF expand -> AES-256 key -> AES-ECB encrypt roundtrip."""

    def test_hkdf_to_aes_encrypt(self, p11_module_session: RawSession) -> None:
        """HKDF-derive an AES key and use it for encryption."""
        rs = p11_module_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")
        if not rs.has_mechanism("HKDF_KEY_GEN"):
            pytest.skip("CKM_HKDF_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        try:
            from pkcs11_check.raw.types_std import CKM_HKDF_DERIVE
        except ImportError:
            pytest.skip("CKM_HKDF_DERIVE not in types_std")

        base_key: int = 0
        derived: int = 0

        try:
            from pkcs11_check.raw.types_std import CKM_HKDF_KEY_GEN

            # Generate HKDF base key using CKM_HKDF_KEY_GEN + CKK_HKDF.
            # Using CKM_GENERIC_SECRET_KEY_GEN with CKK_HKDF fails on Kryoptic
            # with CKR_TEMPLATE_INCONSISTENT -- the HKDF keygen mechanism is
            # required for this key type.
            hkdf_attrs: dict[int, Any] = {
                CKA_KEY_TYPE: CKK_HKDF,
                CKA_DERIVE: True,
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            }
            packed = [attr_ulong(CKA_VALUE_LEN, 32)]
            packed.extend(pack_attrs(hkdf_attrs, skip={CKA_VALUE_LEN}))
            tmpl = template(*packed)
            gen_mech = mech_simple(CKM_HKDF_KEY_GEN)
            handle = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(rs.sh, gen_mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
            try:
                expect_rv(rv, CKR_OK, context="HKDF lifecycle C_GenerateKey")
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _HKDF_KEYGEN_REJECT_CKRS,
                    "HKDF base key generation rejected on advertised lifecycle path",
                )
                raise  # unreachable
            base_key = handle.value

            hkdf_param = mech_hkdf(
                CKM_HKDF_DERIVE,
                hash_mech=CKM_SHA256,
                extract=True,
                expand=True,
                salt=os.urandom(16),
                info=b"pkcs11-check lifecycle test",
            )

            # CKA_CLASS is required by PKCS#11 spec for C_DeriveKey -- Kryoptic
            # returns CKR_TEMPLATE_INCONSISTENT when it is absent.
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_HKDF_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE_LEN: 32,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
                mech_param=hkdf_param,
            )
            assert derived != 0, "HKDF derive returned handle 0"

            # Encrypt/decrypt roundtrip with the derived AES-256 key
            plaintext = b"\xaa\xbb\xcc\xdd" * 8  # 32 bytes
            ct = encrypt_single(rs.raw, rs.sh, derived, CKM_AES_ECB, plaintext)
            pt = decrypt_single(rs.raw, rs.sh, derived, CKM_AES_ECB, ct)
            assert pt == plaintext, (
                f"HKDF-derived key encrypt/decrypt mismatch: "
                f"expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            for h in (base_key, derived):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestRSAOAEPWrapLifecycle:
    """RSA-OAEP wrap AES key -> unwrap -> encrypt/decrypt verify."""

    def test_rsa_oaep_wrap_aes_roundtrip(self, p11_module_session: RawSession) -> None:
        """Wrap an AES key under RSA-OAEP, unwrap, and verify enc/dec works."""
        rs = p11_module_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        try:
            from pkcs11_check.raw.types_std import CKM_RSA_PKCS_OAEP
        except ImportError:
            pytest.skip("CKM_RSA_PKCS_OAEP not in types_std")

        rsa_pub, rsa_priv = 0, 0
        target: int = 0
        unwrapped_key: int = 0

        try:
            rsa_pub, rsa_priv = gen_rsa_keypair_or_xfail(
                rs,
                2048,
                public_attrs={CKA_WRAP: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
                private_attrs={CKA_UNWRAP: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            )
            target = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
                purpose="RSA-OAEP lifecycle AES target setup",
            )

            # Encrypt a block to verify key identity later
            plaintext = b"\x11\x22\x33\x44" * 4
            ciphertext = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, plaintext)

            # OAEP param
            oaep_param = mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA256)

            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    rsa_pub,
                    target,
                    CKM_RSA_PKCS_OAEP,
                    mech_param=oaep_param,
                )
            except AssertionError as exc:
                if claim_refusal_passes(exc, rs, probe_key="CKM_RSA_PKCS_OAEP:encrypt"):
                    return
            assert len(wrapped) > 0

            destroy_quietly(rs.raw, rs.sh, target)
            target = 0

            # CKA_CLASS is required by PKCS#11 spec for C_UnwrapKey -- Kryoptic
            # returns CKR_TEMPLATE_INCONSISTENT when it is absent.
            try:
                unwrapped_key = unwrap_key(
                    rs.raw,
                    rs.sh,
                    rsa_priv,
                    wrapped,
                    CKM_RSA_PKCS_OAEP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_DECRYPT: True,
                        CKA_ENCRYPT: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=oaep_param,
                )
            except AssertionError as exc:
                if claim_refusal_passes(exc, rs, probe_key="CKM_RSA_PKCS_OAEP:encrypt"):
                    return
            assert unwrapped_key != 0

            recovered = decrypt_single(rs.raw, rs.sh, unwrapped_key, CKM_AES_ECB, ciphertext)
            assert recovered == plaintext, (
                f"RSA-OAEP wrapped/unwrapped key mismatch: "
                f"expected {plaintext.hex()!r}, got {recovered.hex()!r}"
            )
        finally:
            for h in (rsa_pub, rsa_priv, target, unwrapped_key):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestDigestThenEncrypt:
    """Hash plaintext, then encrypt the digest."""

    def test_sha256_digest_then_aes_ecb_encrypt(self, p11_module_session: RawSession) -> None:
        """Compute SHA-256 digest, encrypt it with AES-ECB, decrypt and compare."""
        rs = p11_module_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        from pkcs11_check.raw.types_std import CKM_SHA256

        key: int = 0
        try:
            plaintext = b"lifecycle test input for digest"
            digest = digest_single(rs.raw, rs.sh, CKM_SHA256, plaintext)
            assert len(digest) == 32, f"SHA-256 digest length {len(digest)} != 32"

            key = gen_aes_key_or_xfail(
                rs,
                256,
                purpose="digest-then-encrypt lifecycle setup",
            )
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, digest)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == digest, (
                f"encrypt(SHA256(data)) roundtrip failed: "
                f"expected {digest.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestExportReimportAES:
    """Export AES key value, re-import, verify encrypt compatibility."""

    def test_export_reimport_aes_roundtrip(self, p11_module_session: RawSession) -> None:
        """Generate extractable AES key, export raw bytes, re-import, verify enc/dec."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        key1: int = 0
        key2: int = 0
        try:
            key1 = gen_aes_key_or_xfail(
                rs,
                256,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
                purpose="export/reimport lifecycle setup",
            )

            # Read the raw key value
            attrs = read_attributes(rs.raw, rs.sh, key1, [CKA_VALUE])
            key_bytes = attrs.get(CKA_VALUE)
            if not key_bytes or not isinstance(key_bytes, bytes):
                pytest.skip(
                    "Module does not allow CKA_VALUE export (CKA_EXTRACTABLE may be ignored)"
                )

            # Encrypt with original key
            plaintext = b"\xfe\xed\xfa\xce" * 8
            ct = encrypt_single(rs.raw, rs.sh, key1, CKM_AES_ECB, plaintext)

            # Re-import the raw bytes
            key2 = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                key_bytes,
                attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            )
            assert key2 != 0

            # Decrypt with re-imported key -- must recover original plaintext
            pt = decrypt_single(rs.raw, rs.sh, key2, CKM_AES_ECB, ct)
            assert pt == plaintext, (
                f"export/reimport key mismatch: expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            for h in (key1, key2):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestRSASignVerifyLifecycle:
    """RSA keygen -> SHA256-RSA-PKCS sign -> verify."""

    def test_rsa_sign_verify_roundtrip(self, p11_module_session: RawSession) -> None:
        """Full RSA sign/verify lifecycle with SHA256-RSA-PKCS."""
        rs = p11_module_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        try:
            from pkcs11_check.raw.types_std import CKM_SHA256_RSA_PKCS
        except ImportError:
            pytest.skip("CKM_SHA256_RSA_PKCS not in types_std")

        pub, priv = 0, 0
        try:
            pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
            data = b"rsa lifecycle test message" * 4
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            ok = verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
            assert ok, "RSA SHA256-RSA-PKCS verify failed after sign"
        finally:
            for h in (pub, priv):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestECSignVerifyLifecycle:
    """EC keygen -> ECDSA sign -> verify."""

    def test_ecdsa_sign_verify_roundtrip(self, p11_module_session: RawSession) -> None:
        """Full ECDSA sign/verify lifecycle on P-256."""
        rs = p11_module_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDSA_SHA256"):
            pytest.skip("CKM_ECDSA_SHA256 not supported")

        try:
            from pkcs11_check.raw.ec import encode_named_curve_parameters
            from pkcs11_check.raw.types_std import CKM_ECDSA_SHA256
        except ImportError:
            pytest.skip("Required types not available")

        p256_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = 0, 0
        try:
            pub, priv = gen_ec_keypair_or_xfail(rs, p256_oid)
            data = b"ecdsa lifecycle test" * 3
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA_SHA256, data)
            ok = verify_single(rs.raw, rs.sh, pub, CKM_ECDSA_SHA256, data, sig)
            assert ok, "ECDSA SHA256 verify failed after sign"
        finally:
            for h in (pub, priv):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestAESGCMFullCycle:
    """AES-GCM AEAD encrypt -> decrypt (full cycle with auth tag)."""

    def test_aes_gcm_encrypt_decrypt(self, p11_module_session: RawSession) -> None:
        """AES-GCM encrypt, then decrypt with same IV -- auth tag verified."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        try:
            from pkcs11_check.raw.types_std import CKM_AES_GCM
        except ImportError:
            pytest.skip("CKM_AES_GCM not in types_std")

        key: int = 0
        try:
            key = gen_aes_key_or_xfail(rs, 256, purpose="AES-GCM lifecycle setup")
            plaintext = b"aes-gcm lifecycle test data!!!!!"  # 32 bytes
            iv = os.urandom(12)
            gcm_param = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)

            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                plaintext,
                mech_param=gcm_param,
                output_overhead=16,
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                ct,
                mech_param=gcm_param,
            )
            assert pt == plaintext, (
                f"AES-GCM decrypt mismatch: expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


class TestBatchAESKeys:
    """Generate multiple AES keys, batch encrypt, destroy all."""

    def test_batch_keygen_encrypt_destroy(self, p11_module_session: RawSession) -> None:
        """Generate 5 AES keys, encrypt with each, then clean up all."""
        rs = p11_module_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        keys: list[int] = []
        try:
            for i in range(5):
                k = gen_aes_key_or_xfail(
                    rs,
                    128 + 64 * (i % 3),
                    purpose="batch AES lifecycle setup",
                )
                assert k != 0, f"Key {i}: handle is 0"
                keys.append(k)

            plaintext = b"\xca\xfe\xba\xbe" * 4  # 16 bytes
            for i, k in enumerate(keys):
                ct = encrypt_single(rs.raw, rs.sh, k, CKM_AES_ECB, plaintext)
                pt = decrypt_single(rs.raw, rs.sh, k, CKM_AES_ECB, ct)
                assert pt == plaintext, f"Key {i}: decrypt mismatch"
        finally:
            for k in keys:
                destroy_quietly(rs.raw, rs.sh, k)
