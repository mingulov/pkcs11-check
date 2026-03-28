"""Mechanism-driven wrap/unwrap tests.

Parametrized by mech_wrap_entry — tests every wrap mechanism advertised
by the module that also has a registry config.

Key types covered:
- AES key-wrap mechanisms (AES_KEY_WRAP, AES_KEY_WRAP_KWP, AES_KEY_WRAP_PAD,
  AES_KEY_WRAP_PKCS7): wrapping key is AES, target is AES-128
- AES block/stream encrypt mechanisms with CKF_WRAP (AES_ECB, AES_CBC, etc.):
  wrapping key is AES, target is AES-128
- RSA mechanisms (RSA_PKCS, RSA_PKCS_OAEP): wrapping key is RSA

Mechanisms not covered here (skipped with clear message):
- ECDH-AES hybrid wraps (ECDH_AES_KEY_WRAP, ECDH_COF_AES_KEY_WRAP) — need
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
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_WRAP,
    CKK_AES,
    CKK_RSA,
    CKM,
    CKM_AES_ECB,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.wrap]

# Hybrid wrap mechanisms that need ECDH parameter construction — skipped here
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

# AES block/stream encrypt mechanisms that also have CKF_WRAP and require an IV param.
# These need a 16-byte IV passed as raw bytes to mech_bytes().
_AES_IV_WRAP_MECHS: set[int] = set()
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

    _AES_IV_WRAP_MECHS = {
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

# AES CTR — needs CK_AES_CTR_PARAMS struct, skip here
_AES_CTR_MECH_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKM_AES_CTR

    _AES_CTR_MECH_ID = int(CKM_AES_CTR)
except ImportError:
    pass

# OAEP defaults
_CKM_SHA1 = 0x00000220
_CKG_MGF1_SHA1 = 0x00000001


def _make_wrap_mech_param(entry: MechEntry) -> Any:
    """Return a mechanism parameter for the wrap mechanism, or None if not needed.

    Returns None for no-param mechanisms (e.g. AES_ECB, AES_KEY_WRAP).
    Skips for mechanisms whose param construction is not yet implemented here.
    """
    mech_id = entry.mech_id

    if mech_id in _AES_IV_WRAP_MECHS:
        iv = os.urandom(16)
        return mech_bytes(CKM(mech_id), iv)

    if _AES_CTR_MECH_ID and mech_id == _AES_CTR_MECH_ID:
        pytest.skip(f"{entry.mech_name}: CTR wrap needs CK_AES_CTR_PARAMS — skipped here")

    # RSA OAEP
    try:
        from pkcs11_check.raw.types_std import CKM_RSA_PKCS_OAEP

        if mech_id == int(CKM_RSA_PKCS_OAEP):
            from pkcs11_check.raw.pack_mechanisms import mech_oaep

            return mech_oaep(CKM(mech_id), hash_mech=_CKM_SHA1, mgf=_CKG_MGF1_SHA1)
    except ImportError:
        pass

    # GCM / CCM / AEAD variants — complex, skip
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
    from pkcs11_check.testcases.test_mech_keygen import _pick_key_size

    key_size = _pick_key_size(entry, config) or 256
    return gen_aes_key(
        rs.raw,
        rs.sh,
        key_size,
        attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_DECRYPT: True},
    )


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

        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        # Skip hybrid wraps (ECDH-AES) — need ECDH parameter construction
        if mech_id in _HYBRID_WRAP_MECH_IDS:
            pytest.skip(f"{entry.mech_name}: hybrid ECDH-AES wrap not covered here")

        # Check that the module actually supports this mechanism
        mech_short = ckm_name(mech_id).removeprefix("CKM_")
        if not rs.has_mechanism(mech_short):
            pytest.skip(f"{entry.mech_name}: mechanism not available")

        mech_param = _make_wrap_mech_param(entry)

        # Build the wrapping key(s)
        is_rsa = config.key_type is not None and int(config.key_type) == int(CKK_RSA)

        if is_rsa:
            wrap_pub, wrap_priv = _build_rsa_wrap_pair(rs)
            wrap_handle = wrap_pub
            unwrap_handle = wrap_priv
        else:
            # Default to AES wrapping key
            wrap_handle = _build_aes_wrap_key(rs, entry, config)
            unwrap_handle = wrap_handle
            wrap_priv = None

        target_key = _build_target_aes_key(rs)
        unwrapped_key: int = 0

        try:
            # Encrypt some data with the target key
            plaintext = b"\x5a\xa5\x5a\xa5" * 4  # 16 bytes, one AES block
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

            # Destroy the original target key — unwrapped copy must still work
            destroy_quietly(rs.raw, rs.sh, target_key)
            target_key = 0

            # Unwrap to get a new key handle
            unwrapped_key = unwrap_key(
                rs.raw,
                rs.sh,
                unwrap_handle,
                wrapped_blob,
                CKM(mech_id),
                attrs={
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_DECRYPT: True,
                    CKA_ENCRYPT: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech_param,
            )
            assert unwrapped_key != 0, f"{entry.mech_name}: unwrap returned handle 0"

            # Decrypt with the unwrapped key — must recover original plaintext
            recovered = decrypt_single(
                rs.raw,
                rs.sh,
                unwrapped_key,
                CKM_AES_ECB,
                ciphertext,
            )
            assert recovered == plaintext, (
                f"{entry.mech_name}: decrypt mismatch after unwrap — "
                f"expected {plaintext.hex()!r}, got {recovered.hex()!r}"
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
