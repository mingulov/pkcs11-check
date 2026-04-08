"""Mechanism-driven wrap/unwrap tests.

Parametrized by mech_wrap_entry -- tests every wrap mechanism advertised
by the module that also has a registry config.

Key types covered:
- AES key-wrap mechanisms (AES_KEY_WRAP, AES_KEY_WRAP_KWP, AES_KEY_WRAP_PAD,
  AES_KEY_WRAP_PKCS7): wrapping key is AES, target is AES-128
- AES block/stream encrypt mechanisms with CKF_WRAP (AES_ECB, AES_CBC, etc.):
  wrapping key is AES, target is AES-128
- RSA mechanisms (RSA_PKCS, RSA_PKCS_OAEP): wrapping key is RSA

Mechanisms not covered here (skipped with clear message):
- ECDH-AES hybrid wraps (ECDH_AES_KEY_WRAP, ECDH_COF_AES_KEY_WRAP) -- need
  ECDH parameter construction
- AES-CTR: requires CK_AES_CTR_PARAMS (complex, skip here)
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.api import ckm_name
from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKG_MGF1_SHA1,
    CKK_AES,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_RSA,
    CKM,
    CKM_AES_ECB,
    CKM_SHA_1,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig

# Integer value for CKK_AES -- used for dispatch in the wrapping-key builder.
_AES_KEY_TYPE: int = int(CKK_AES)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.wrap]

# Hybrid wrap mechanisms that need ECDH parameter construction -- skipped here
_HYBRID_WRAP_MECH_IDS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import (
        CKM_ECDH_AES_KEY_WRAP,
        CKM_ECDH_COF_AES_KEY_WRAP,
        CKM_ECDH_X_AES_KEY_WRAP,
    )

    _HYBRID_WRAP_MECH_IDS = {
        int(CKM_ECDH_AES_KEY_WRAP),
        int(CKM_ECDH_COF_AES_KEY_WRAP),
        int(CKM_ECDH_X_AES_KEY_WRAP),
    }
except ImportError:
    pass

# RSA mechanisms that use RSA key pair for wrap/unwrap
_RSA_KEY_WRAP_MECHS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP

    _RSA_KEY_WRAP_MECHS = {int(CKM_RSA_PKCS), int(CKM_RSA_PKCS_OAEP)}
except ImportError:
    pass

# RSA_AES hybrid -- needs CK_RSA_AES_KEY_WRAP_PARAMS which is beyond this test's scope
_RSA_AES_KEY_WRAP_MECH_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_RSA_AES_KEY_WRAP

    _RSA_AES_KEY_WRAP_MECH_ID = int(CKM_RSA_AES_KEY_WRAP)
except ImportError:
    pass

# DES/3DES key types -- these mechanisms need a DES key, not an AES key, as the wrapping key
_DES_KEY_TYPES: set[int] = {int(CKK_DES), int(CKK_DES2), int(CKK_DES3)}

# Block cipher mechanisms (AES, Camellia, ARIA, SEED) that have CKF_WRAP and
# require a 16-byte IV passed as raw bytes to mech_bytes().
_IV16_WRAP_MECHS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import (
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_CFB1,
        CKM_AES_CFB8,
        CKM_AES_CFB64,
        CKM_AES_CFB128,
        CKM_AES_OFB,
    )

    _IV16_WRAP_MECHS = {
        int(CKM_AES_CBC),
        int(CKM_AES_CBC_PAD),
        int(CKM_AES_OFB),
        int(CKM_AES_CFB8),
        int(CKM_AES_CFB64),
        int(CKM_AES_CFB128),
        int(CKM_AES_CFB1),
    }
except ImportError:
    pass

try:
    from pkcs11_check.raw.types_std import (
        CKM_CAMELLIA_CBC,
        CKM_CAMELLIA_CBC_PAD,
    )

    _IV16_WRAP_MECHS |= {int(CKM_CAMELLIA_CBC), int(CKM_CAMELLIA_CBC_PAD)}
except ImportError:
    pass

try:
    from pkcs11_check.raw.types_std import (
        CKM_ARIA_CBC,
        CKM_ARIA_CBC_PAD,
    )

    _IV16_WRAP_MECHS |= {int(CKM_ARIA_CBC), int(CKM_ARIA_CBC_PAD)}
except ImportError:
    pass

try:
    from pkcs11_check.raw.types_std import CKM_AES_CTS, CKM_AES_XTS

    _IV16_WRAP_MECHS |= {int(CKM_AES_XTS), int(CKM_AES_CTS)}
except ImportError:
    pass

try:
    from pkcs11_check.raw.types_std import (
        CKM_SEED_CBC,
        CKM_SEED_CBC_PAD,
    )

    _IV16_WRAP_MECHS |= {int(CKM_SEED_CBC), int(CKM_SEED_CBC_PAD)}
except ImportError:
    pass

# Keep the old name as an alias so _make_wrap_mech_param() still works
_AES_IV_WRAP_MECHS = _IV16_WRAP_MECHS

# DES/3DES/CDMF block cipher mechanisms that have CKF_WRAP and require an 8-byte IV param.
_DES_IV_WRAP_MECHS: set[int] = set()
try:
    from pkcs11_check.raw.types_std import (
        CKM_DES3_CBC,
        CKM_DES3_CBC_PAD,
        CKM_DES_CBC,
        CKM_DES_CBC_PAD,
    )

    _DES_IV_WRAP_MECHS = {
        int(CKM_DES_CBC),
        int(CKM_DES_CBC_PAD),
        int(CKM_DES3_CBC),
        int(CKM_DES3_CBC_PAD),
    }
except ImportError:
    pass

try:
    from pkcs11_check.raw.types_std import (
        CKM_CDMF_CBC,
        CKM_CDMF_CBC_PAD,
    )

    _DES_IV_WRAP_MECHS |= {int(CKM_CDMF_CBC), int(CKM_CDMF_CBC_PAD)}
except ImportError:
    pass

# AES CTR -- needs CK_AES_CTR_PARAMS struct, skip here
_AES_CTR_MECH_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_AES_CTR

    _AES_CTR_MECH_ID = int(CKM_AES_CTR)
except ImportError:
    pass


def _make_wrap_mech_param(entry: MechEntry) -> Any:
    """Return a mechanism parameter for the wrap mechanism, or None if not needed.

    Returns None for no-param mechanisms (e.g. AES_ECB, AES_KEY_WRAP).
    Skips for mechanisms whose param construction is not yet implemented here.
    """
    mech_id = entry.mech_id

    # RSA_AES hybrid requires CK_RSA_AES_KEY_WRAP_PARAMS -- not covered here
    if _RSA_AES_KEY_WRAP_MECH_ID and mech_id == _RSA_AES_KEY_WRAP_MECH_ID:
        pytest.skip(f"{entry.mech_name}: RSA_AES hybrid wrap needs CK_RSA_AES_KEY_WRAP_PARAMS")

    if mech_id in _AES_IV_WRAP_MECHS:
        iv = os.urandom(16)
        return mech_bytes(CKM(mech_id), iv)

    if mech_id in _DES_IV_WRAP_MECHS:
        iv = os.urandom(8)
        return mech_bytes(CKM(mech_id), iv)

    if _AES_CTR_MECH_ID and mech_id == _AES_CTR_MECH_ID:
        pytest.skip(f"{entry.mech_name}: CTR wrap needs CK_AES_CTR_PARAMS -- skipped here")

    # RSA OAEP
    try:
        from pkcs11_check.raw.types_std import CKM_RSA_PKCS_OAEP

        if mech_id == int(CKM_RSA_PKCS_OAEP):
            from pkcs11_check.raw.pack_mechanisms import mech_oaep

            return mech_oaep(CKM(mech_id), hash_mech=int(CKM_SHA_1), mgf=int(CKG_MGF1_SHA1))
    except ImportError:
        pass

    # GCM / CCM / AEAD variants -- complex, skip
    config = entry.config
    if config is not None and config.param_recipe.style in ("gcm", "ccm"):
        pytest.skip(f"{entry.mech_name}: AEAD wrap not covered here")

    return None


def _build_rsa_wrap_pair(rs: RawSession) -> tuple[int, int]:
    """Build an RSA-2048 wrap/unwrap keypair. Returns (pub_handle, priv_handle)."""
    return gen_rsa_keypair(
        rs.raw,
        rs.sh,
        2048,
        public_attrs={
            CKA_WRAP: True,
            CKA_ENCRYPT: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_UNWRAP: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
        },
    )


def _build_aes_wrap_key(rs: RawSession, entry: MechEntry, config: MechConfig) -> int:
    """Generate an AES wrap/unwrap key sized for the mechanism."""
    from pkcs11_check.testcases.mechanism_helpers import pick_key_size

    key_size = pick_key_size(entry, config) or 256
    return gen_aes_key(
        rs.raw,
        rs.sh,
        key_size,
        attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_DECRYPT: True},
    )


def _build_des_wrap_key(rs: RawSession, config: MechConfig) -> int:
    """Generate a DES/3DES wrap/unwrap key matching the mechanism's key type.

    DES mechanisms require a DES key as the wrapping key, not AES.
    Uses fixed-length keygen (no CKA_VALUE_LEN needed).
    """
    from ctypes import byref

    from pkcs11_check.raw.pack import mech_simple, template
    from pkcs11_check.raw.recipes import pack_attrs
    from pkcs11_check.raw.rv import expect_rv
    from pkcs11_check.raw.types_std import (
        CK_OBJECT_HANDLE,
        CKM_DES2_KEY_GEN,
        CKM_DES3_KEY_GEN,
        CKM_DES_KEY_GEN,
        CKR_OK,
    )

    key_type = config.key_type
    kt = int(key_type) if key_type is not None else int(CKK_DES3)

    if kt == int(CKK_DES):
        keygen_id = int(CKM_DES_KEY_GEN)
    elif kt == int(CKK_DES2):
        keygen_id = int(CKM_DES2_KEY_GEN)
    else:
        keygen_id = int(CKM_DES3_KEY_GEN)

    attrs: dict[int, Any] = {
        CKA_KEY_TYPE: key_type,
        CKA_WRAP: True,
        CKA_UNWRAP: True,
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
        CKA_TOKEN: False,
    }
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    mech = mech_simple(CKM(keygen_id))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)
    return handle.value


def _build_generic_cipher_wrap_key(
    rs: RawSession, entry: MechEntry, config: MechConfig
) -> int:
    """Generate a wrapping key for non-AES, non-DES, non-RSA cipher mechanisms.

    Uses config.keygen_mech and config.key_type from the registry to produce the
    correct key type (e.g. CKK_CAMELLIA, CKK_ARIA, CKK_SEED, CKK_CDMF).
    Handles both variable-length (symmetric: Camellia, ARIA) and fixed-length
    (fixed_length: SEED, CDMF) key types.
    """
    from ctypes import byref

    from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
    from pkcs11_check.raw.recipes import pack_attrs
    from pkcs11_check.raw.rv import expect_rv
    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK
    from pkcs11_check.testcases.mechanism_helpers import (
        FIXED_LENGTH_KEY_TYPES,
        pick_key_size,
    )

    keygen_mech = config.keygen_mech
    if keygen_mech is None:
        pytest.skip(f"{entry.mech_name}: no keygen_mech in registry config for wrapping key")

    key_type = config.key_type
    kt = int(key_type) if key_type is not None else 0
    is_fixed = kt in FIXED_LENGTH_KEY_TYPES

    attrs: dict[int, Any] = {
        CKA_KEY_TYPE: key_type,
        CKA_WRAP: True,
        CKA_UNWRAP: True,
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
        CKA_TOKEN: False,
    }

    packed: list[Any] = []
    if not is_fixed:
        key_size = pick_key_size(entry, config) or 128
        packed.append(attr_ulong(CKA_VALUE_LEN, key_size // 8))
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    else:
        packed.extend(pack_attrs(attrs))

    tmpl = template(*packed)
    mech = mech_simple(CKM(int(keygen_mech)))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)
    return handle.value


def _build_target_aes_key(rs: RawSession) -> int:
    """Generate an extractable AES-128 target key for wrapping."""
    return gen_aes_key(
        rs.raw,
        rs.sh,
        128,
        attrs={
            CKA_EXTRACTABLE: True,
            CKA_SENSITIVE: False,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
        },
    )


def _target_unwrap_attrs(entry: MechEntry) -> dict[int, Any]:
    """Build the unwrap template for the AES-128 target key.

    CKM_RSA_X_509 wraps only the raw key bytes. The application must supply the
    key length separately when unwrapping, so include CKA_VALUE_LEN for that
    case.
    """
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_DECRYPT: True,
        CKA_ENCRYPT: True,
        CKA_TOKEN: False,
    }
    config = entry.config
    if config is not None and config.input_constraint == "raw_block":
        attrs[CKA_VALUE_LEN] = 16
    return attrs


def _raw_rsa_unwrap_hint(
    original_value: bytes,
    decrypted_block: bytes,
    unwrapped_value: bytes | None,
) -> str:
    """Diagnose modules that unwrap CKM_RSA_X_509 from the wrong end of the block."""
    key_len = len(original_value)
    if key_len == 0 or len(decrypted_block) < key_len:
        return ""

    trailing = decrypted_block[-key_len:]
    if trailing != original_value:
        return ""

    leading = decrypted_block[:key_len]
    if unwrapped_value is None:
        return (
            " Raw RSA unwrap hint: the decrypted RSA block ends with the original key "
            "bytes. CKM_RSA_X_509 requires deriving the key from the trailing bytes."
        )

    if unwrapped_value == leading and unwrapped_value != trailing:
        return (
            " Raw RSA unwrap hint: the module appears to derive the unwrapped key from "
            "the leading bytes of the decrypted RSA block, but CKM_RSA_X_509 requires "
            "the trailing bytes."
        )

    return ""


class TestMechWrapRoundtrip:
    """Wrap/unwrap roundtrip for every advertised wrap mechanism with a registry config."""

    def test_wrap_unwrap_aes_key(
        self, p11_raw_session: RawSession, mech_wrap_entry: MechEntry
    ) -> None:
        """Wrap an AES key, unwrap it, verify it works for encryption.

        Steps:
        1. Generate wrapping key (AES or RSA depending on mechanism)
        2. Generate target AES-128 key with CKA_EXTRACTABLE=True
        3. Encrypt some data with target key
        4. Wrap target key
        5. Destroy target key
        6. Unwrap to get new key
        7. Decrypt data with unwrapped key
        8. Verify plaintext matches
        """
        rs = p11_raw_session
        entry = mech_wrap_entry
        config = entry.config
        mech_id = entry.mech_id

        assert config is not None

        # Skip hybrid wraps (ECDH-AES) -- need ECDH parameter construction
        if mech_id in _HYBRID_WRAP_MECH_IDS:
            pytest.skip(f"{entry.mech_name}: hybrid ECDH-AES wrap not covered here")

        # Check that the module actually supports this mechanism
        mech_short = ckm_name(mech_id).removeprefix("CKM_")
        if not rs.has_mechanism(mech_short):
            pytest.skip(f"{entry.mech_name}: mechanism not available")

        mech_param = _make_wrap_mech_param(entry)

        # Build the wrapping key(s)
        is_rsa = config.key_type is not None and int(config.key_type) == int(CKK_RSA)
        is_des = config.key_type is not None and int(config.key_type) in _DES_KEY_TYPES

        is_aes = config.key_type is not None and int(config.key_type) == _AES_KEY_TYPE

        if is_rsa:
            wrap_pub, wrap_priv = _build_rsa_wrap_pair(rs)
            wrap_handle = wrap_pub
            unwrap_handle = wrap_priv
        elif is_des:
            # DES/3DES mechanisms need a DES key as the wrapping key, not AES
            wrap_handle = _build_des_wrap_key(rs, config)
            unwrap_handle = wrap_handle
            wrap_priv = None
        elif is_aes or config.key_type is None:
            # AES wrapping key (or unknown key type -- fall back to AES)
            wrap_handle = _build_aes_wrap_key(rs, entry, config)
            unwrap_handle = wrap_handle
            wrap_priv = None
        else:
            # Generic cipher wrapping key: Camellia, ARIA, SEED, CDMF, etc.
            # Use config.keygen_mech and config.key_type to generate the correct type.
            wrap_handle = _build_generic_cipher_wrap_key(rs, entry, config)
            unwrap_handle = wrap_handle
            wrap_priv = None

        target_key = _build_target_aes_key(rs)
        unwrapped_key: int = 0
        original_value: bytes | None = None

        try:
            # Encrypt some data with the target key
            plaintext = b"\x5a\xa5\x5a\xa5" * 4  # 16 bytes, one AES block
            original_attrs = read_attributes(rs.raw, rs.sh, target_key, [CKA_VALUE])
            original_candidate = original_attrs.get(CKA_VALUE)
            if isinstance(original_candidate, bytes):
                original_value = original_candidate
            ciphertext = encrypt_single(
                rs.raw,
                rs.sh,
                target_key,
                CKM_AES_ECB,
                plaintext,
            )

            # Wrap the target key
            wrapped_blob = wrap_key(
                rs.raw,
                rs.sh,
                wrap_handle,
                target_key,
                CKM(mech_id),
                mech_param=mech_param,
            )
            assert len(wrapped_blob) > 0, f"{entry.mech_name}: wrap produced empty blob"

            # Destroy the original target key -- unwrapped copy must still work
            destroy_quietly(rs.raw, rs.sh, target_key)
            target_key = 0

            # Unwrap to get a new key handle.
            # Raw RSA unwrap needs the key length supplied in the template
            # because CKM_RSA_X_509 wraps only the raw key value bytes.
            unwrapped_key = unwrap_key(
                rs.raw,
                rs.sh,
                unwrap_handle,
                wrapped_blob,
                CKM(mech_id),
                attrs=_target_unwrap_attrs(entry),
                mech_param=mech_param,
            )
            assert unwrapped_key != 0, f"{entry.mech_name}: unwrap returned handle 0"

            # Decrypt with the unwrapped key -- must recover original plaintext
            recovered = decrypt_single(
                rs.raw,
                rs.sh,
                unwrapped_key,
                CKM_AES_ECB,
                ciphertext,
            )
            diagnostic = ""
            if (
                recovered != plaintext
                and config.input_constraint == "raw_block"
                and original_value is not None
            ):
                decrypted_block = decrypt_single(
                    rs.raw,
                    rs.sh,
                    unwrap_handle,
                    CKM(mech_id),
                    wrapped_blob,
                    mech_param=mech_param,
                )
                unwrapped_attrs = read_attributes(rs.raw, rs.sh, unwrapped_key, [CKA_VALUE])
                unwrapped_candidate = unwrapped_attrs.get(CKA_VALUE)
                unwrapped_value = (
                    unwrapped_candidate if isinstance(unwrapped_candidate, bytes) else None
                )
                diagnostic = _raw_rsa_unwrap_hint(original_value, decrypted_block, unwrapped_value)
            assert recovered == plaintext, (
                f"{entry.mech_name}: decrypt mismatch after unwrap -- "
                f"expected {plaintext.hex()!r}, got {recovered.hex()!r}{diagnostic}"
            )

        finally:
            if target_key != 0:
                destroy_quietly(rs.raw, rs.sh, target_key)
            if unwrapped_key != 0:
                destroy_quietly(rs.raw, rs.sh, unwrapped_key)
            if is_rsa:
                destroy_quietly(rs.raw, rs.sh, wrap_pub)
                if wrap_priv is not None:
                    destroy_quietly(rs.raw, rs.sh, wrap_priv)
            else:
                destroy_quietly(rs.raw, rs.sh, wrap_handle)
