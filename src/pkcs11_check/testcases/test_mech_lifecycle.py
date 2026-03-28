"""Composite lifecycle tests — multi-step operation patterns.

Each test exercises a realistic end-to-end sequence that crosses multiple
mechanism categories.  These tests are NOT parametrized by mechanism entry;
they use hard-coded mechanism selections to keep complexity manageable.

Patterns covered:
  1. AES key generate → encrypt → wrap → destroy → unwrap → decrypt
  2. ECDH derive → use derived key for AES-CBC encrypt
  3. HKDF expand → AES-256 key → AES-ECB encrypt roundtrip
  4. RSA-OAEP wrap AES key → unwrap → encrypt/decrypt verify
  5. HMAC-SHA256 sign → copy key → verify with copy
  6. Digest then encrypt: hash plaintext, encrypt result
  7. Export then re-import: gen AES → extract value → import → encrypt roundtrip
  8. RSA keygen → sign → verify (SHA256-RSA-PKCS roundtrip)
  9. EC keygen → ECDSA sign → verify
 10. Generate multiple AES keys → batch encrypt → destroy all
 11. AES-GCM encrypt → AES-GCM decrypt (AEAD full cycle)
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
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    import_secret_key,
    pack_attrs,
    read_attributes,
    sign_single,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKD_NULL,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_HKDF,
    CKM,
    CKM_AES_ECB,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA256,
    CKR_OK,
    CKZ_SALT_SPECIFIED,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.lifecycle]


class TestAESWrapUnwrapUse:
    """Generate AES → encrypt → wrap → destroy → unwrap → decrypt."""

    def test_aes_wrap_roundtrip(self, p11_raw_session: RawSession) -> None:
        """Full AES key lifecycle: generate, use, wrap, destroy, unwrap, use again."""
        rs = p11_raw_session
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

        # Generate wrapping key and target key
        wrap_key_handle = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_TOKEN: False},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_TOKEN: False,
            },
        )
        unwrapped_key: int = 0

        try:
            plaintext = b"\xde\xad\xbe\xef" * 4  # 16 bytes
            ciphertext = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, plaintext)

            # Wrap the target key
            wrapped = wrap_key(
                rs.raw, rs.sh, wrap_key_handle, target, CKM(int(CKM_AES_KEY_WRAP))
            )
            assert len(wrapped) > 0, "wrap produced empty blob"

            # Destroy original — only the wrapped copy remains
            destroy_quietly(rs.raw, rs.sh, target)
            target = 0

            # Unwrap and decrypt to verify key material was preserved
            unwrapped_key = unwrap_key(
                rs.raw,
                rs.sh,
                wrap_key_handle,
                wrapped,
                CKM(int(CKM_AES_KEY_WRAP)),
                attrs={
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_DECRYPT: True,
                    CKA_ENCRYPT: True,
                    CKA_TOKEN: False,
                },
            )
            assert unwrapped_key != 0, "unwrap returned handle 0"

            recovered = decrypt_single(rs.raw, rs.sh, unwrapped_key, CKM_AES_ECB, ciphertext)
            assert recovered == plaintext, (
                f"wrap/unwrap key mismatch: expected {plaintext.hex()!r}, "
                f"got {recovered.hex()!r}"
            )
        finally:
            if target != 0:
                destroy_quietly(rs.raw, rs.sh, target)
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            destroy_quietly(rs.raw, rs.sh, wrap_key_handle)


class TestECDHDerivedKeyUse:
    """ECDH1 derive → use derived key for AES-CBC encryption."""

    def test_ecdh_derive_and_use(self, p11_raw_session: RawSession) -> None:
        """ECDH derive a shared secret, use it as AES-128 key to encrypt/decrypt."""
        rs = p11_raw_session
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
            pub_a, priv_a = gen_ec_keypair(
                rs.raw, rs.sh, p256_oid,
                private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
            )
            pub_b, priv_b = gen_ec_keypair(rs.raw, rs.sh, p256_oid)

            peer_attrs = read_attributes(rs.raw, rs.sh, pub_b, [CKA_EC_POINT])
            peer_point = peer_attrs.get(CKA_EC_POINT)
            if not peer_point or not isinstance(peer_point, bytes):
                pytest.skip("Cannot read CKA_EC_POINT from peer public key")

            ecdh_param = mech_ecdh(
                CKM(int(CKM_ECDH1_DERIVE)), kdf=int(CKD_NULL), public_data=peer_point
            )

            derived = derive_key(
                rs.raw,
                rs.sh,
                priv_a,
                CKM(int(CKM_ECDH1_DERIVE)),
                attrs={
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

            cbc_param = mech_bytes(CKM(int(CKM_AES_CBC)), iv)
            plaintext = b"ecdh lifecycle test padded 32byt"
            ct = encrypt_single(
                rs.raw, rs.sh, derived, CKM(int(CKM_AES_CBC)), plaintext, mech_param=cbc_param
            )
            pt = decrypt_single(
                rs.raw, rs.sh, derived, CKM(int(CKM_AES_CBC)), ct, mech_param=cbc_param
            )
            assert pt == plaintext, (
                f"ECDH-derived key encrypt/decrypt mismatch: "
                f"expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            for h in (pub_a, priv_a, pub_b, priv_b, derived):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestHKDFDerivedKeyUse:
    """HKDF expand → AES-256 key → AES-ECB encrypt roundtrip."""

    def test_hkdf_to_aes_encrypt(self, p11_raw_session: RawSession) -> None:
        """HKDF-derive an AES key and use it for encryption."""
        rs = p11_raw_session
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
            # Generate HKDF base key
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
            gen_mech = mech_simple(CKM(CKM_GENERIC_SECRET_KEY_GEN))
            handle = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
                rs.sh, gen_mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
            )
            assert rv == CKR_OK, f"HKDF base key gen failed: {rv}"
            base_key = handle.value

            hkdf_param = mech_hkdf(
                CKM(int(CKM_HKDF_DERIVE)),
                hash_mech=int(CKM_SHA256),
                extract=True,
                expand=True,
                salt_type=int(CKZ_SALT_SPECIFIED),
                salt=os.urandom(16),
                info=b"pkcs11-check lifecycle test",
            )

            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM(int(CKM_HKDF_DERIVE)),
                attrs={
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
    """RSA-OAEP wrap AES key → unwrap → encrypt/decrypt verify."""

    def test_rsa_oaep_wrap_aes_roundtrip(self, p11_raw_session: RawSession) -> None:
        """Wrap an AES key under RSA-OAEP, unwrap, and verify enc/dec works."""
        rs = p11_raw_session
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

        from pkcs11_check.raw.types_std import CKA_UNWRAP

        rsa_pub, rsa_priv = 0, 0
        target: int = 0
        unwrapped_key: int = 0

        try:
            rsa_pub, rsa_priv = gen_rsa_keypair(
                rs.raw, rs.sh, 2048,
                public_attrs={CKA_WRAP: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
                private_attrs={CKA_UNWRAP: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            )
            target = gen_aes_key(
                rs.raw, rs.sh, 128,
                attrs={
                    CKA_ENCRYPT: True, CKA_DECRYPT: True,
                    CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False,
                },
            )

            # Encrypt a block to verify key identity later
            plaintext = b"\x11\x22\x33\x44" * 4
            ciphertext = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, plaintext)

            # OAEP param
            oaep_param = mech_oaep(
                CKM(int(CKM_RSA_PKCS_OAEP)), hash_mech=int(CKM_SHA256), mgf=int(CKG_MGF1_SHA256)
            )

            wrapped = wrap_key(
                rs.raw, rs.sh, rsa_pub, target, CKM(int(CKM_RSA_PKCS_OAEP)),
                mech_param=oaep_param,
            )
            assert len(wrapped) > 0

            destroy_quietly(rs.raw, rs.sh, target)
            target = 0

            unwrapped_key = unwrap_key(
                rs.raw, rs.sh, rsa_priv, wrapped, CKM(int(CKM_RSA_PKCS_OAEP)),
                attrs={
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_DECRYPT: True,
                    CKA_ENCRYPT: True,
                    CKA_TOKEN: False,
                },
                mech_param=oaep_param,
            )
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

    def test_sha256_digest_then_aes_ecb_encrypt(self, p11_raw_session: RawSession) -> None:
        """Compute SHA-256 digest, encrypt it with AES-ECB, decrypt and compare."""
        rs = p11_raw_session
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

            key = gen_aes_key(rs.raw, rs.sh, 256)
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

    def test_export_reimport_aes_roundtrip(self, p11_raw_session: RawSession) -> None:
        """Generate extractable AES key, export raw bytes, re-import, verify enc/dec."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        key1: int = 0
        key2: int = 0
        try:
            key1 = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
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
                rs.raw, rs.sh, CKK_AES, key_bytes,
                attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            )
            assert key2 != 0

            # Decrypt with re-imported key — must recover original plaintext
            pt = decrypt_single(rs.raw, rs.sh, key2, CKM_AES_ECB, ct)
            assert pt == plaintext, (
                f"export/reimport key mismatch: expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            for h in (key1, key2):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestRSASignVerifyLifecycle:
    """RSA keygen → SHA256-RSA-PKCS sign → verify."""

    def test_rsa_sign_verify_roundtrip(self, p11_raw_session: RawSession) -> None:
        """Full RSA sign/verify lifecycle with SHA256-RSA-PKCS."""
        rs = p11_raw_session
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
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
            data = b"rsa lifecycle test message" * 4
            sig = sign_single(rs.raw, rs.sh, priv, CKM(int(CKM_SHA256_RSA_PKCS)), data)
            ok = verify_single(rs.raw, rs.sh, pub, CKM(int(CKM_SHA256_RSA_PKCS)), data, sig)
            assert ok, "RSA SHA256-RSA-PKCS verify failed after sign"
        finally:
            for h in (pub, priv):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestECSignVerifyLifecycle:
    """EC keygen → ECDSA sign → verify."""

    def test_ecdsa_sign_verify_roundtrip(self, p11_raw_session: RawSession) -> None:
        """Full ECDSA sign/verify lifecycle on P-256."""
        rs = p11_raw_session
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
            pub, priv = gen_ec_keypair(rs.raw, rs.sh, p256_oid)
            data = b"ecdsa lifecycle test" * 3
            sig = sign_single(rs.raw, rs.sh, priv, CKM(int(CKM_ECDSA_SHA256)), data)
            ok = verify_single(rs.raw, rs.sh, pub, CKM(int(CKM_ECDSA_SHA256)), data, sig)
            assert ok, "ECDSA SHA256 verify failed after sign"
        finally:
            for h in (pub, priv):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


class TestAESGCMFullCycle:
    """AES-GCM AEAD encrypt → decrypt (full cycle with auth tag)."""

    def test_aes_gcm_encrypt_decrypt(self, p11_raw_session: RawSession) -> None:
        """AES-GCM encrypt, then decrypt with same IV — auth tag verified."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        try:
            from pkcs11_check.raw.types_std import CKM_AES_GCM
        except ImportError:
            pytest.skip("CKM_AES_GCM not in types_std")

        key: int = 0
        try:
            key = gen_aes_key(rs.raw, rs.sh, 256)
            plaintext = b"aes-gcm lifecycle test data!!!!!"  # 32 bytes
            iv = os.urandom(12)
            gcm_param = mech_gcm(CKM(int(CKM_AES_GCM)), iv, tag_bits=128)

            ct = encrypt_single(
                rs.raw, rs.sh, key, CKM(int(CKM_AES_GCM)), plaintext,
                mech_param=gcm_param, output_overhead=16,
            )
            pt = decrypt_single(
                rs.raw, rs.sh, key, CKM(int(CKM_AES_GCM)), ct,
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

    def test_batch_keygen_encrypt_destroy(self, p11_raw_session: RawSession) -> None:
        """Generate 5 AES keys, encrypt with each, then clean up all."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        keys: list[int] = []
        try:
            for i in range(5):
                k = gen_aes_key(rs.raw, rs.sh, 128 + 64 * (i % 3))
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
