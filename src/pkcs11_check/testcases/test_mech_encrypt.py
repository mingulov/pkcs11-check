"""Mechanism-driven encrypt/decrypt tests.

Parametrized by mech_encrypt_entry — tests every encrypt mechanism advertised
by the module that also has a registry config.

Key types covered:
- AES block modes (ECB, CBC, CBC-PAD, OFB, CFB*, CTS): 32-byte plaintext, block-aligned where needed
- AES stream modes (CTR): any-length plaintext, CK_AES_CTR_PARAMS
- AES-AEAD (GCM, CCM): 32-byte plaintext, random IV, auth tag included in ciphertext
- AES-XTS: 32-byte plaintext, IV param required
- RSA-PKCS / RSA-OAEP: small plaintext (< modulus), asymmetric keypair
- DES/DES3/SEED/Camellia/ARIA/etc.: follow AES block/stream patterns via registry config

Mechanisms not yet parameterised (complex wraps, SSL3/TLS key-mat, etc.) are
skipped with a clear message.
"""
from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import decrypt_single, destroy_quietly, encrypt_single, pack_attrs
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_AES_XTS,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_RSA,
    CKK_SEED,
    CKM,
    CKM_AES_KEY_GEN,
    CKM_AES_XTS_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_X9_31_KEY_PAIR_GEN,
    CKR_OK,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig
from pkcs11_check.testcases.test_mech_keygen import (
    _needs_domain_params,
    _pick_key_size,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.encrypt]

# RSA keygen mechanisms (same CKK_RSA key works for encrypt/decrypt)
_RSA_KEYGEN_MECHS: set[int] = {int(CKM_RSA_PKCS_KEY_PAIR_GEN), int(CKM_RSA_X9_31_KEY_PAIR_GEN)}

# Fixed-length key types: must not set CKA_VALUE_LEN
_FIXED_LENGTH_KEY_TYPES: set[int] = {
    int(CKK_DES), int(CKK_DES2), int(CKK_DES3), int(CKK_SEED)
}


def _test_plaintext(config: MechConfig) -> bytes:
    """Return appropriate plaintext for the given mechanism config.

    - Block-aligned modes: 32 bytes (2 AES blocks)
    - CBC-PAD and any-length modes: 32 bytes (works for both)
    - RSA: 32 bytes (safely below 2048-bit modulus limit)
    """
    return b"\xab\xcd\xef\x01" * 8  # 32 bytes


def _make_mech_param(
    entry: MechEntry,
    config: MechConfig,
) -> Any:
    """Create mechanism parameter for the operation, or None for no-param mechanisms.

    Returns None for mechanisms that take no parameters (e.g., AES-ECB).
    Skips with a clear message for mechanisms whose param builder cannot produce
    test params generically.
    """
    from pkcs11_check.testcases.mechanism_helpers import build_test_params

    if not config.param_required:
        return None

    result = build_test_params(entry.mech_id, config.param_recipe)
    if result == "SKIP":
        pytest.skip(
            f"{entry.mech_name}: param recipe '{config.param_recipe.style}' needs runtime data"
        )
    return result


def _generate_key_for_encrypt(
    rs: RawSession,
    entry: MechEntry,
    config: MechConfig,
) -> tuple[int, int | None]:
    """Generate a key suitable for encrypt+decrypt operations.

    Returns (encrypt_key_or_pub, decrypt_key_or_priv).
    For symmetric: both are the same handle, second value is None.
    For asymmetric: (pub_handle, priv_handle).
    """
    if config.key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    kt = int(config.key_type)

    if config.is_keypair:
        if _needs_domain_params(config):
            pytest.skip(
                f"{entry.mech_name}: requires external domain parameters (DSA/DH/KEA/GOSTR)"
            )

        # For RSA, create an encrypt/decrypt keypair
        if kt == int(CKK_RSA):
            from pkcs11_check.raw.recipes import gen_keypair

            keygen = config.keygen_mech
            if keygen is None or keygen not in _RSA_KEYGEN_MECHS:
                keygen = int(CKM_RSA_PKCS_KEY_PAIR_GEN)
            key_size = _pick_key_size(entry, config) or 2048
            pub, priv = gen_keypair(
                rs.raw,
                rs.sh,
                keygen,
                pub_base=[
                    attr_ulong(CKA_MODULUS_BITS, key_size),
                    attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
                ],
                priv_base=[],
                public_attrs={CKA_VERIFY: True, CKA_ENCRYPT: True, CKA_TOKEN: False},
                private_attrs={CKA_SIGN: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            )
            return pub, priv

        # Other asymmetric key types don't typically support encrypt — skip
        pytest.skip(
            f"{entry.mech_name}: keypair mechanism with key type {config.key_type!r} "
            "not supported for encrypt/decrypt test"
        )

    # Symmetric: AES-XTS needs special double-length key
    if kt == int(CKK_AES_XTS):
        keygen = config.keygen_mech or int(CKM_AES_XTS_KEY_GEN)
        xts_key_size = _pick_key_size(entry, config)
        if xts_key_size is None:
            pytest.skip(f"{entry.mech_name}: no usable key size")
        assert xts_key_size is not None  # guarded by pytest.skip above
        attrs: dict[int, Any] = {
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
            CKA_KEY_TYPE: CKK_AES_XTS,
        }
        packed = [attr_ulong(CKA_VALUE_LEN, xts_key_size // 8)]
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
        tmpl = template(*packed)
        mech = mech_simple(CKM(keygen))
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
            rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
        )
        assert rv == CKR_OK, f"AES-XTS keygen failed: {rv}"
        return handle.value, None

    # Standard symmetric keygen — build key with explicit encrypt/decrypt attributes.
    keygen_mech = config.keygen_mech
    if keygen_mech is None:
        keygen_mech = int(CKM_AES_KEY_GEN) if kt == int(CKK_AES) else None
    if keygen_mech is None:
        pytest.skip(f"{entry.mech_name}: no keygen_mech in registry config")

    is_fixed = kt in _FIXED_LENGTH_KEY_TYPES

    attrs2: dict[int, Any] = {
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
        CKA_TOKEN: False,
        CKA_KEY_TYPE: config.key_type,
    }
    packed2 = []
    if not is_fixed:
        sym_key_size = _pick_key_size(entry, config)
        if sym_key_size is None:
            pytest.skip(f"{entry.mech_name}: no usable key size in registry")
        assert sym_key_size is not None  # guarded by pytest.skip above
        packed2.append(attr_ulong(CKA_VALUE_LEN, sym_key_size // 8))
        packed2.extend(pack_attrs(attrs2, skip={CKA_VALUE_LEN}))
    else:
        packed2.extend(pack_attrs(attrs2))

    tmpl2 = template(*packed2)
    mech2 = mech_simple(CKM(keygen_mech))
    handle2 = CK_OBJECT_HANDLE(0)
    rv2 = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
        rs.sh, mech2.byref(), tmpl2.ptr, tmpl2.count, byref(handle2)
    )
    assert rv2 == CKR_OK, f"C_GenerateKey failed: {rv2} for {entry.mech_name}"
    return handle2.value, None


class TestMechEncryptRoundtrip:
    """Encrypt then decrypt roundtrip for every advertised encrypt mechanism."""

    def test_roundtrip(self, p11_raw_session: RawSession, mech_encrypt_entry: MechEntry) -> None:
        """Encrypt then decrypt, verify recovered plaintext matches original."""
        rs = p11_raw_session
        entry = mech_encrypt_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        # Key-wrap only mechanisms — not testing data encrypt here
        if config.input_constraint == "none":
            pytest.skip(f"{entry.mech_name}: wrap-only mechanism, no data encrypt test")

        enc_key, dec_key = _generate_key_for_encrypt(rs, entry, config)
        dec_key_handle = dec_key if dec_key is not None else enc_key

        try:
            plaintext = _test_plaintext(config)
            mech_param = _make_mech_param(entry, config)

            overhead = 16 if config.auth_tag_included else 0
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                enc_key,
                CKM(entry.mech_id),
                plaintext,
                mech_param=mech_param,
                output_overhead=overhead,
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                dec_key_handle,
                CKM(entry.mech_id),
                ct,
                mech_param=mech_param,
            )
            assert pt == plaintext, (
                f"Decrypt mismatch for {entry.mech_name}: "
                f"expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, enc_key)
            if dec_key is not None:
                destroy_quietly(rs.raw, rs.sh, dec_key)
