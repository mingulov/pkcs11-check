"""Mechanism-specific parameter packers for PKCS#11 operations.

Callers should import mechanism packers from ``pkcs11_check.raw.pack``
(which re-exports all names), not directly from this module.
"""

from __future__ import annotations

import ctypes
from typing import Any, Literal

from .pack import (
    KeyMatMechanism,
    PackedMechanism,
    _mech_struct,
    _pack_bytes,
    mech_bytes,
)
from .types_std import (
    CK_AES_CCM_PARAMS,
    CK_AES_CTR_PARAMS,
    CK_AES_GCM_PARAMS,
    CK_BBOOL,
    CK_BYTE,
    CK_CCM_MESSAGE_PARAMS,
    CK_CCM_WRAP_PARAMS,
    CK_CHACHA20_PARAMS,
    CK_ECDH1_DERIVE_PARAMS,
    CK_ECDH_AES_KEY_WRAP_PARAMS,
    CK_EDDSA_PARAMS,
    CK_GCM_MESSAGE_PARAMS,
    CK_GCM_WRAP_PARAMS,
    CK_HASH_SIGN_ADDITIONAL_CONTEXT,
    CK_HKDF_PARAMS,
    CK_IKE2_PRF_PLUS_DERIVE_PARAMS,
    CK_IKE_PRF_DERIVE_PARAMS,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_PBE_PARAMS,
    CK_PKCS5_PBKD2_PARAMS2,
    CK_RC2_CBC_PARAMS,
    CK_RC2_MAC_GENERAL_PARAMS,
    CK_RC5_CBC_PARAMS,
    CK_RC5_MAC_GENERAL_PARAMS,
    CK_RC5_PARAMS,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_RSA_PKCS_PSS_PARAMS,
    CK_SALSA20_CHACHA20_POLY1305_PARAMS,
    CK_SALSA20_PARAMS,
    CK_SIGN_ADDITIONAL_CONTEXT,
    CK_SSL3_KEY_MAT_OUT,
    CK_SSL3_KEY_MAT_PARAMS,
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS12_KEY_MAT_PARAMS,
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS_KDF_PARAMS,
    CK_TLS_MAC_PARAMS,
    CK_TLS_PRF_PARAMS,
    CK_ULONG,
    CK_VERSION,
    CK_VOID_PTR,
    CK_WTLS_KEY_MAT_OUT,
    CK_WTLS_KEY_MAT_PARAMS,
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
    CK_WTLS_PRF_PARAMS,
    CKD,
    CKG,
    CKG_GENERATE_RANDOM,
    CKH,
    CKH_HEDGE_PREFERRED,
    CKM,
    CKZ_DATA_SPECIFIED,
    CKZ_SALT_SPECIFIED,
)


def _alloc_writable_pointer(
    params: ctypes.Structure,
    ptr_field: str,
    length: int,
) -> ctypes.Array[Any]:
    """Allocate a writable ``CK_BYTE * length`` buffer and aim ``params.<ptr_field>`` at it.

    Returns the buffer so the caller can keep it alive (e.g. via
    ``result.add_buffer(name, buf, length)``).  Centralises the
    ``buf = (CK_BYTE * n)(); params.X = ctypes.cast(buf, CK_VOID_PTR)``
    idiom that every generated-output packer repeats.
    """
    buf = (CK_BYTE * length)()
    setattr(params, ptr_field, ctypes.cast(buf, CK_VOID_PTR))
    return buf


def mech_gcm(
    mechanism_type: CKM | int,
    iv: bytes,
    *,
    aad: bytes | None = None,
    aad_len: int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_AES_GCM_PARAMS.

    Pass ``aad`` for actual AAD data; ``aad_len`` is a legacy shortcut that
    sets ulAADLen without a pointer (only valid when the module ignores pAAD).
    When ``aad`` is provided its length overrides ``aad_len``.
    """
    ka: list[Any] = []
    params = CK_AES_GCM_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvBits = params.ulIvLen * 8
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = aad_len
    params.ulTagBits = tag_bits
    return _mech_struct(
        mechanism_type, params, "mech_gcm", ka, sub_mechanisms={"tagBits": tag_bits}
    )


def mech_gcm_generated_iv(
    mechanism_type: CKM | int,
    *,
    iv_len: int = 12,
    iv_bits: int | None = None,
    aad: bytes | None = None,
    aad_len: int = 0,
    tag_bits: int = 128,
    convention: Literal["strict", "aws"] = "strict",
) -> PackedMechanism:
    """Pack CK_AES_GCM_PARAMS for provider-generated IV writeback.

    ``strict`` uses the convention observed by pkcs11-proxy (`ulIvLen=0`,
    `ulIvBits=N`) while keeping a writable pIv buffer of N bits. ``aws``
    models AWS CloudHSM callers (`ulIvLen=N`, `ulIvBits=0`) with a zeroized
    writable pIv buffer that the provider may overwrite.
    """
    if iv_len < 0:
        raise ValueError("iv_len must be non-negative")
    resolved_iv_bits = iv_len * 8 if iv_bits is None else iv_bits
    if resolved_iv_bits < 0:
        raise ValueError("iv_bits must be non-negative")
    if convention not in ("strict", "aws"):
        raise ValueError("convention must be 'strict' or 'aws'")

    bit_capacity = (resolved_iv_bits + 7) // 8
    iv_buf_len = max(iv_len, bit_capacity)
    if iv_buf_len == 0:
        raise ValueError("generated GCM IV buffer must be non-empty")

    ka: list[Any] = []
    params = CK_AES_GCM_PARAMS()
    iv_buf = _alloc_writable_pointer(params, "pIv", iv_buf_len)
    if convention == "strict":
        params.ulIvLen = 0
        params.ulIvBits = resolved_iv_bits
    else:
        params.ulIvLen = iv_len
        params.ulIvBits = 0
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = aad_len
    params.ulTagBits = tag_bits

    result = _mech_struct(
        mechanism_type,
        params,
        "mech_gcm_generated_iv",
        ka,
        sub_mechanisms={"tagBits": tag_bits, "generatedIvBytes": iv_buf_len},
    )
    result.add_buffer("iv", iv_buf, iv_buf_len)
    return result


def mech_gcm_message(
    mechanism_type: CKM | int,
    iv: bytes,
    *,
    iv_fixed_bits: int = 0,
    iv_generator: CKG | int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_GCM_MESSAGE_PARAMS for v3.0 message-based AEAD.

    The ``pTag`` field is a pre-allocated output buffer (ceil(tag_bits / 8) bytes)
    that the token writes the authentication tag to.
    """
    ka: list[Any] = []
    params = CK_GCM_MESSAGE_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvFixedBits = iv_fixed_bits
    params.ivGenerator = iv_generator
    if tag_bits < 0:
        raise ValueError("tag_bits must be non-negative")
    tag_len = (tag_bits + 7) // 8
    tag_buf = _alloc_writable_pointer(params, "pTag", tag_len)
    params.ulTagBits = tag_bits
    result = _mech_struct(mechanism_type, params, "mech_gcm_message", ka)
    result.add_buffer("tag", tag_buf, tag_len)
    return result


def mech_gcm_message_inherit_tag(
    mechanism_type: CKM | int,
    iv: bytes,
    *,
    source: PackedMechanism,
    iv_fixed_bits: int = 0,
    iv_generator: CKG | int = 0,
) -> PackedMechanism:
    """Pack CK_GCM_MESSAGE_PARAMS that shares its pTag with ``source``.

    Used to wire an AEAD unwrap mechanism to the tag buffer the matching
    wrap call wrote, without callers reaching into ``source.params.pTag``
    directly (which orphans the unwrap-side buffer from the new mech's
    ``buffer_bytes("tag")``).

    The shared tag buffer is registered under the name ``"tag"`` on the
    returned mechanism, so ``mech.buffer_bytes("tag")`` returns the same
    bytes ``source.buffer_bytes("tag")`` does.  ``source`` is kept alive
    via the new mechanism's keepalive list.
    """
    tag_storage, tag_len = source.buffer_storage("tag")
    ka: list[Any] = [source]
    params = CK_GCM_MESSAGE_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvFixedBits = iv_fixed_bits
    params.ivGenerator = iv_generator
    params.pTag = source.params.pTag
    params.ulTagBits = source.params.ulTagBits
    result = _mech_struct(mechanism_type, params, "mech_gcm_message_inherit_tag", ka)
    result.add_buffer("tag", tag_storage, tag_len)
    return result


def mech_gcm_message_generated_iv(
    mechanism_type: CKM | int,
    *,
    iv_len: int = 12,
    iv_fixed_bits: int = 0,
    iv_generator: CKG | int = CKG_GENERATE_RANDOM,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_GCM_MESSAGE_PARAMS with writable IV and tag buffers."""
    if iv_len <= 0:
        raise ValueError("iv_len must be positive")
    if tag_bits < 0:
        raise ValueError("tag_bits must be non-negative")

    params = CK_GCM_MESSAGE_PARAMS()
    iv_buf = _alloc_writable_pointer(params, "pIv", iv_len)
    params.ulIvLen = iv_len
    params.ulIvFixedBits = iv_fixed_bits
    params.ivGenerator = iv_generator

    tag_len = (tag_bits + 7) // 8
    tag_buf = _alloc_writable_pointer(params, "pTag", tag_len)
    params.ulTagBits = tag_bits

    result = _mech_struct(
        mechanism_type,
        params,
        "mech_gcm_message_generated_iv",
        sub_mechanisms={"tagBits": tag_bits, "generatedIvBytes": iv_len},
    )
    result.add_buffer("iv", iv_buf, iv_len)
    result.add_buffer("tag", tag_buf, tag_len)
    return result


def mech_gcm_wrap(
    mechanism_type: CKM | int,
    iv: bytes,
    *,
    iv_fixed_bits: int = 0,
    aad: bytes | None = None,
    aad_len: int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_GCM_WRAP_PARAMS with caller-supplied IV bytes."""
    ka: list[Any] = []
    params = CK_GCM_WRAP_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvFixedBits = iv_fixed_bits
    params.ivGenerator = 0
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = aad_len
    params.ulTagBits = tag_bits
    return _mech_struct(
        mechanism_type,
        params,
        "mech_gcm_wrap",
        ka,
        sub_mechanisms={"tagBits": tag_bits},
    )


def mech_gcm_wrap_generated_iv(
    mechanism_type: CKM | int,
    *,
    iv_len: int = 12,
    iv_fixed_bits: int = 0,
    iv_generator: CKG | int = CKG_GENERATE_RANDOM,
    aad: bytes | None = None,
    aad_len: int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_GCM_WRAP_PARAMS with a writable generated-IV buffer."""
    if iv_len <= 0:
        raise ValueError("iv_len must be positive")
    ka: list[Any] = []
    params = CK_GCM_WRAP_PARAMS()
    iv_buf = _alloc_writable_pointer(params, "pIv", iv_len)
    params.ulIvLen = iv_len
    params.ulIvFixedBits = iv_fixed_bits
    params.ivGenerator = iv_generator
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = aad_len
    params.ulTagBits = tag_bits

    result = _mech_struct(
        mechanism_type,
        params,
        "mech_gcm_wrap_generated_iv",
        ka,
        sub_mechanisms={"tagBits": tag_bits, "generatedIvBytes": iv_len},
    )
    result.add_buffer("iv", iv_buf, iv_len)
    return result


def mech_ccm_message_generated_nonce(
    mechanism_type: CKM | int,
    *,
    data_len: int,
    nonce_len: int = 12,
    nonce_fixed_bits: int = 0,
    nonce_generator: CKG | int = CKG_GENERATE_RANDOM,
    mac_len: int = 16,
) -> PackedMechanism:
    """Pack CK_CCM_MESSAGE_PARAMS with writable nonce and MAC buffers."""
    if data_len < 0:
        raise ValueError("data_len must be non-negative")
    if nonce_len <= 0:
        raise ValueError("nonce_len must be positive")
    if mac_len < 0:
        raise ValueError("mac_len must be non-negative")

    params = CK_CCM_MESSAGE_PARAMS()
    params.ulDataLen = data_len
    nonce_buf = _alloc_writable_pointer(params, "pNonce", nonce_len)
    params.ulNonceLen = nonce_len
    params.ulNonceFixedBits = nonce_fixed_bits
    params.nonceGenerator = nonce_generator
    mac_buf = _alloc_writable_pointer(params, "pMAC", mac_len)
    params.ulMACLen = mac_len

    result = _mech_struct(
        mechanism_type,
        params,
        "mech_ccm_message_generated_nonce",
        sub_mechanisms={"macLen": mac_len, "generatedNonceBytes": nonce_len},
    )
    result.add_buffer("nonce", nonce_buf, nonce_len)
    result.add_buffer("mac", mac_buf, mac_len)
    return result


def mech_ccm_wrap(
    mechanism_type: CKM | int,
    nonce: bytes,
    *,
    data_len: int,
    nonce_fixed_bits: int = 0,
    aad: bytes | None = None,
    aad_len: int = 0,
    mac_len: int = 16,
) -> PackedMechanism:
    """Pack CK_CCM_WRAP_PARAMS with caller-supplied nonce bytes."""
    if data_len < 0:
        raise ValueError("data_len must be non-negative")
    ka: list[Any] = []
    params = CK_CCM_WRAP_PARAMS()
    params.ulDataLen = data_len
    params.pNonce, params.ulNonceLen = _pack_bytes(nonce, ka)
    params.ulNonceFixedBits = nonce_fixed_bits
    params.nonceGenerator = 0
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = aad_len
    params.ulMACLen = mac_len
    return _mech_struct(
        mechanism_type,
        params,
        "mech_ccm_wrap",
        ka,
        sub_mechanisms={"macLen": mac_len},
    )


def mech_ccm_wrap_generated_nonce(
    mechanism_type: CKM | int,
    *,
    data_len: int,
    nonce_len: int = 12,
    nonce_fixed_bits: int = 0,
    nonce_generator: CKG | int = CKG_GENERATE_RANDOM,
    aad: bytes | None = None,
    aad_len: int = 0,
    mac_len: int = 16,
) -> PackedMechanism:
    """Pack CK_CCM_WRAP_PARAMS with a writable generated-nonce buffer."""
    if data_len < 0:
        raise ValueError("data_len must be non-negative")
    if nonce_len <= 0:
        raise ValueError("nonce_len must be positive")
    ka: list[Any] = []
    params = CK_CCM_WRAP_PARAMS()
    params.ulDataLen = data_len
    nonce_buf = _alloc_writable_pointer(params, "pNonce", nonce_len)
    params.ulNonceLen = nonce_len
    params.ulNonceFixedBits = nonce_fixed_bits
    params.nonceGenerator = nonce_generator
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = aad_len
    params.ulMACLen = mac_len

    result = _mech_struct(
        mechanism_type,
        params,
        "mech_ccm_wrap_generated_nonce",
        ka,
        sub_mechanisms={"macLen": mac_len, "generatedNonceBytes": nonce_len},
    )
    result.add_buffer("nonce", nonce_buf, nonce_len)
    return result


def mech_ccm(
    mechanism_type: CKM | int,
    nonce: bytes,
    *,
    data_len: int = 0,
    aad: bytes | None = None,
    mac_len: int = 16,
) -> PackedMechanism:
    """Pack CK_AES_CCM_PARAMS."""
    ka: list[Any] = []
    params = CK_AES_CCM_PARAMS()
    params.ulDataLen = data_len
    params.pNonce, params.ulNonceLen = _pack_bytes(nonce, ka)
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = 0
    params.ulMACLen = mac_len
    return _mech_struct(
        mechanism_type,
        params,
        "mech_ccm",
        ka,
        sub_mechanisms={"macLen": mac_len, "nonceLen": len(nonce)},
    )


def mech_pss(
    mechanism_type: CKM | int,
    *,
    hash_mech: CKM | int,
    mgf: CKG | int,
    salt_len: int,
) -> PackedMechanism:
    """Pack CK_RSA_PKCS_PSS_PARAMS."""
    params = CK_RSA_PKCS_PSS_PARAMS()
    params.hashAlg = hash_mech
    params.mgf = mgf
    params.sLen = salt_len
    return _mech_struct(
        mechanism_type,
        params,
        "mech_pss",
        sub_mechanisms={"hashAlg": hash_mech, "mgf": mgf},
    )


def mech_oaep(
    mechanism_type: CKM | int,
    *,
    hash_mech: CKM | int,
    mgf: CKG | int,
    source_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_RSA_PKCS_OAEP_PARAMS."""
    ka: list[Any] = []
    params = CK_RSA_PKCS_OAEP_PARAMS()
    params.hashAlg = hash_mech
    params.mgf = mgf
    params.source = CKZ_DATA_SPECIFIED
    params.pSourceData, params.ulSourceDataLen = _pack_bytes(source_data, ka)
    return _mech_struct(
        mechanism_type,
        params,
        "mech_oaep",
        ka,
        sub_mechanisms={"hashAlg": hash_mech, "mgf": mgf},
    )


def mech_ecdh(
    mechanism_type: CKM | int,
    *,
    kdf: CKD | int,
    public_data: bytes,
    shared_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_ECDH1_DERIVE_PARAMS."""
    ka: list[Any] = []
    params = CK_ECDH1_DERIVE_PARAMS()
    params.kdf = kdf
    params.pPublicData, params.ulPublicDataLen = _pack_bytes(public_data, ka)
    params.pSharedData, params.ulSharedDataLen = _pack_bytes(shared_data, ka)
    return _mech_struct(
        mechanism_type,
        params,
        "mech_ecdh",
        ka,
        sub_mechanisms={"kdf": kdf},
    )


def mech_ecdh_aes_kw(
    mechanism_type: CKM | int,
    *,
    aes_key_bits: int,
    kdf: CKD | int,
    shared_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_ECDH_AES_KEY_WRAP_PARAMS for CKM_ECDH_AES_KEY_WRAP family.

    Used for hybrid wrap mechanisms that derive an ephemeral AES key via
    ECDH and then wrap the target with AES-KW. See PKCS#11 v3.1
    Sec.6.3.13.4.

    Args:
        mechanism_type: CKM_ECDH_AES_KEY_WRAP, CKM_ECDH_COF_AES_KEY_WRAP,
            or CKM_ECDH_X_AES_KEY_WRAP.
        aes_key_bits: 128 / 192 / 256.
        kdf: a CKD_* constant (e.g. CKD_SHA256_KDF).
        shared_data: optional info string mixed into the KDF.
    """
    ka: list[Any] = []
    params = CK_ECDH_AES_KEY_WRAP_PARAMS()
    params.ulAESKeyBits = aes_key_bits
    params.kdf = kdf
    params.pSharedData, params.ulSharedDataLen = _pack_bytes(shared_data, ka)
    return _mech_struct(
        mechanism_type,
        params,
        "mech_ecdh_aes_kw",
        ka,
        sub_mechanisms={"aes_key_bits": aes_key_bits, "kdf": kdf},
    )


def mech_hkdf(
    mechanism_type: CKM | int,
    *,
    hash_mech: CKM | int,
    extract: bool = True,
    expand: bool = True,
    salt_type: int | None = None,
    salt: bytes | None = None,
    salt_key: int = 0,
    info: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_HKDF_PARAMS.

    ``salt_type`` defaults to CKF_HKDF_SALT_DATA (2) when ``salt`` is provided
    and CKF_HKDF_SALT_NULL (1) when it is not.  Pass an explicit value to
    override (e.g. CKF_HKDF_SALT_KEY = 3).
    """
    # CKF_HKDF_SALT_NULL = 1, CKF_HKDF_SALT_DATA = 2, CKF_HKDF_SALT_KEY = 3
    if salt_type is None:
        salt_type = 2 if salt is not None else 1
    ka: list[Any] = []
    params = CK_HKDF_PARAMS()
    params.bExtract = 1 if extract else 0
    params.bExpand = 1 if expand else 0
    params.prfHashMechanism = hash_mech
    params.ulSaltType = salt_type
    params.hSaltKey = salt_key
    params.pSalt, params.ulSaltLen = _pack_bytes(salt, ka)
    params.pInfo, params.ulInfoLen = _pack_bytes(info, ka)
    return _mech_struct(
        mechanism_type,
        params,
        "mech_hkdf",
        ka,
        sub_mechanisms={"prfHashMechanism": hash_mech},
    )


def mech_cbc_pad(mechanism_type: CKM | int, iv: bytes) -> PackedMechanism:
    """Pack 16-byte IV for AES-CBC / AES-CBC-PAD (raw bytes parameter)."""
    return mech_bytes(mechanism_type, iv)


def mech_ctr(mechanism_type: CKM | int, bits: int = 128) -> PackedMechanism:
    """Pack CK_AES_CTR_PARAMS with ulCounterBits=bits and zeroed counter block."""
    params = CK_AES_CTR_PARAMS()
    params.ulCounterBits = bits
    for i in range(16):
        params.cb[i] = 0
    return _mech_struct(mechanism_type, params, "mech_ctr", sub_mechanisms={"counterBits": bits})


def mech_chacha20(
    mechanism_type: CKM | int,
    nonce: bytes,
    counter: int = 0,
) -> PackedMechanism:
    """Pack CK_CHACHA20_PARAMS with a counter and nonce."""
    ka: list[Any] = []
    params = CK_CHACHA20_PARAMS()
    counter_bytes = counter.to_bytes(4, "little")
    params.pBlockCounter, _ = _pack_bytes(counter_bytes, ka)
    params.blockCounterBits = 32
    params.pNonce, _ = _pack_bytes(nonce, ka)
    params.ulNonceBits = len(nonce) * 8
    return _mech_struct(mechanism_type, params, "mech_chacha20", ka)


def mech_salsa20(
    mechanism_type: CKM | int,
    nonce: bytes,
    counter: int = 0,
) -> PackedMechanism:
    """Pack CK_SALSA20_PARAMS with a 64-bit counter and nonce."""
    if counter < 0 or counter >= 2**64:
        raise ValueError("counter must fit in 64 bits")
    ka: list[Any] = []
    params = CK_SALSA20_PARAMS()
    counter_bytes = counter.to_bytes(8, "little")
    params.pBlockCounter, _ = _pack_bytes(counter_bytes, ka)
    params.pNonce, _ = _pack_bytes(nonce, ka)
    params.ulNonceBits = len(nonce) * 8
    return _mech_struct(mechanism_type, params, "mech_salsa20", ka)


def mech_chacha20_poly1305(
    mechanism_type: CKM | int,
    nonce: bytes,
    aad: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_SALSA20_CHACHA20_POLY1305_PARAMS with nonce and optional AAD."""
    ka: list[Any] = []
    params = CK_SALSA20_CHACHA20_POLY1305_PARAMS()
    params.pNonce, params.ulNonceLen = _pack_bytes(nonce, ka)
    params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    return _mech_struct(mechanism_type, params, "mech_chacha20_poly1305", ka)


def mech_salsa20_poly1305(
    mechanism_type: CKM | int,
    nonce: bytes,
    aad: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_SALSA20_CHACHA20_POLY1305_PARAMS for Salsa20-Poly1305."""
    ka: list[Any] = []
    params = CK_SALSA20_CHACHA20_POLY1305_PARAMS()
    params.pNonce, params.ulNonceLen = _pack_bytes(nonce, ka)
    params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    return _mech_struct(mechanism_type, params, "mech_salsa20_poly1305", ka)


def mech_rc2(
    mechanism_type: CKM | int,
    effective_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_RC2_PARAMS (a single CK_ULONG: ulEffectiveBits)."""
    value = CK_ULONG(effective_bits)
    return mech_bytes(
        mechanism_type,
        bytes(value),
    )


def mech_rc2_cbc(
    mechanism_type: CKM | int,
    effective_bits: int = 128,
    iv: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_RC2_CBC_PARAMS (ulEffectiveBits + 8-byte IV)."""
    params = CK_RC2_CBC_PARAMS()
    params.ulEffectiveBits = effective_bits
    if iv is None:
        iv = bytes(8)
    for i in range(8):
        params.iv[i] = CK_BYTE(iv[i])
    return _mech_struct(mechanism_type, params, "mech_rc2_cbc")


def mech_rc2_mac_general(
    mechanism_type: CKM | int,
    *,
    effective_bits: int = 128,
    mac_len: int = 8,
) -> PackedMechanism:
    """Pack CK_RC2_MAC_GENERAL_PARAMS (effective bits + MAC length)."""
    if effective_bits <= 0:
        raise ValueError("effective_bits must be positive")
    if mac_len <= 0:
        raise ValueError("mac_len must be positive")
    params = CK_RC2_MAC_GENERAL_PARAMS()
    params.ulEffectiveBits = effective_bits
    params.ulMacLength = mac_len
    return _mech_struct(mechanism_type, params, "mech_rc2_mac_general")


def mech_rc5(
    mechanism_type: CKM | int,
    *,
    word_bits: int = 32,
    rounds: int = 12,
) -> PackedMechanism:
    """Pack CK_RC5_PARAMS (word size in bits + rounds)."""
    if word_bits <= 0:
        raise ValueError("word_bits must be positive")
    if rounds < 0:
        raise ValueError("rounds must be non-negative")
    params = CK_RC5_PARAMS()
    params.ulWordsize = word_bits
    params.ulRounds = rounds
    return _mech_struct(mechanism_type, params, "mech_rc5")


def mech_rc5_cbc(
    mechanism_type: CKM | int,
    *,
    word_bits: int = 32,
    rounds: int = 12,
    iv: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_RC5_CBC_PARAMS (word size, rounds, variable-length IV)."""
    if word_bits <= 0:
        raise ValueError("word_bits must be positive")
    if rounds < 0:
        raise ValueError("rounds must be non-negative")
    if iv is None:
        iv = bytes((word_bits * 2 + 7) // 8)
    if len(iv) == 0:
        raise ValueError("iv must be non-empty")
    ka: list[Any] = []
    params = CK_RC5_CBC_PARAMS()
    params.ulWordsize = word_bits
    params.ulRounds = rounds
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    return _mech_struct(mechanism_type, params, "mech_rc5_cbc", ka)


def mech_rc5_mac_general(
    mechanism_type: CKM | int,
    *,
    word_bits: int = 32,
    rounds: int = 12,
    mac_len: int = 8,
) -> PackedMechanism:
    """Pack CK_RC5_MAC_GENERAL_PARAMS (word size, rounds, MAC length)."""
    if word_bits <= 0:
        raise ValueError("word_bits must be positive")
    if rounds < 0:
        raise ValueError("rounds must be non-negative")
    if mac_len <= 0:
        raise ValueError("mac_len must be positive")
    params = CK_RC5_MAC_GENERAL_PARAMS()
    params.ulWordsize = word_bits
    params.ulRounds = rounds
    params.ulMacLength = mac_len
    return _mech_struct(mechanism_type, params, "mech_rc5_mac_general")


def mech_eddsa(
    mechanism_type: CKM | int,
    *,
    context_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_EDDSA_PARAMS; sets phFlag=1 when context_data is provided."""
    ka: list[Any] = []
    params = CK_EDDSA_PARAMS()
    params.phFlag = CK_BBOOL(1 if context_data is not None else 0)
    params.pContextData, params.ulContextDataLen = _pack_bytes(context_data, ka)
    return _mech_struct(
        mechanism_type, params, "mech_eddsa", ka, sub_mechanisms={"phFlag": int(params.phFlag)}
    )


def mech_pbkdf2(
    mechanism_type: CKM | int,
    *,
    salt: bytes,
    iterations: int,
    prf: int,
    password: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_PKCS5_PBKD2_PARAMS2 (saltSource=CKZ_SALT_SPECIFIED=1)."""
    ka: list[Any] = []
    params = CK_PKCS5_PBKD2_PARAMS2()
    params.saltSource = CKZ_SALT_SPECIFIED
    params.pSaltSourceData, params.ulSaltSourceDataLen = _pack_bytes(salt, ka)
    params.iterations = iterations
    params.prf = prf
    params.pPrfData = None
    params.ulPrfDataLen = 0
    params.pPassword, params.ulPasswordLen = _pack_bytes(password, ka)
    return _mech_struct(
        mechanism_type,
        params,
        "mech_pbkdf2",
        ka,
        sub_mechanisms={"prf": prf},
    )


def mech_pbe(
    mechanism_type: CKM | int,
    *,
    password: bytes,
    salt: bytes,
    iteration: int,
    iv_len: int | None = 8,
    init_vector: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_PBE_PARAMS for password-based encryption/key derivation.

    By default, pInitVector points at a caller-owned 8-byte output buffer.
    Pass iv_len=None only for deliberate legacy/provider-specific NULL shapes.
    """
    if iv_len is None and init_vector is not None:
        raise ValueError("init_vector requires iv_len")
    if iv_len is not None and iv_len <= 0:
        raise ValueError("iv_len must be positive or None")
    if init_vector is not None and iv_len is not None and len(init_vector) != iv_len:
        raise ValueError("init_vector length must match iv_len")

    ka: list[Any] = []
    params = CK_PBE_PARAMS()
    iv_buf: Any | None = None
    if iv_len is None:
        params.pInitVector = None
    else:
        iv_buf = (ctypes.c_ubyte * iv_len)()
        if init_vector is not None:
            ctypes.memmove(iv_buf, init_vector, iv_len)
        params.pInitVector = ctypes.cast(iv_buf, CK_VOID_PTR)
        ka.append(iv_buf)
    params.pPassword, params.ulPasswordLen = _pack_bytes(password, ka)
    params.pSalt, params.ulSaltLen = _pack_bytes(salt, ka)
    params.ulIteration = iteration
    result = _mech_struct(mechanism_type, params, "mech_pbe", ka)
    if iv_buf is not None and iv_len is not None:
        result.add_buffer("init_vector", iv_buf, iv_len)
    return result


def mech_string_data(mechanism_type: CKM | int, data: bytes) -> PackedMechanism:
    """Pack CK_KEY_DERIVATION_STRING_DATA for concatenation-style derivation."""
    ka: list[Any] = []
    params = CK_KEY_DERIVATION_STRING_DATA()
    params.pData, params.ulLen = _pack_bytes(data, ka)
    return _mech_struct(mechanism_type, params, "mech_string_data", ka)


# ---------------------------------------------------------------------------
# SSL3 / TLS / WTLS mechanism packers
# ---------------------------------------------------------------------------


def mech_ike_prf_derive(
    mechanism_type: CKM | int,
    *,
    prf_mechanism: CKM | int,
    initiator_nonce: bytes,
    responder_nonce: bytes,
    data_as_key: bool = False,
    rekey: bool = False,
    new_key_handle: int = 0,
) -> PackedMechanism:
    """Pack CK_IKE_PRF_DERIVE_PARAMS for CKM_IKE_PRF_DERIVE."""
    ka: list[Any] = []
    params = CK_IKE_PRF_DERIVE_PARAMS()
    params.prfMechanism = prf_mechanism
    params.bDataAsKey = CK_BBOOL(1 if data_as_key else 0)
    params.bRekey = CK_BBOOL(1 if rekey else 0)
    params.pNi, params.ulNiLen = _pack_bytes(initiator_nonce, ka)
    params.pNr, params.ulNrLen = _pack_bytes(responder_nonce, ka)
    params.hNewKey = new_key_handle
    return _mech_struct(
        mechanism_type,
        params,
        "mech_ike_prf_derive",
        ka,
        sub_mechanisms={"prfMechanism": int(prf_mechanism)},
    )


def mech_ike2_prf_plus_derive(
    mechanism_type: CKM | int,
    *,
    prf_mechanism: CKM | int,
    seed_data: bytes | None = None,
    seed_key_handle: int = 0,
) -> PackedMechanism:
    """Pack CK_IKE2_PRF_PLUS_DERIVE_PARAMS for CKM_IKE2_PRF_PLUS_DERIVE."""
    ka: list[Any] = []
    params = CK_IKE2_PRF_PLUS_DERIVE_PARAMS()
    params.prfMechanism = prf_mechanism
    params.bHasSeedKey = CK_BBOOL(1 if seed_key_handle else 0)
    params.hSeedKey = seed_key_handle
    if seed_data is None:
        params.pSeedData = None
        params.ulSeedDataLen = 0
    else:
        params.pSeedData, params.ulSeedDataLen = _pack_bytes(seed_data, ka)
    return _mech_struct(
        mechanism_type,
        params,
        "mech_ike2_prf_plus_derive",
        ka,
        sub_mechanisms={"prfMechanism": int(prf_mechanism)},
    )


def _fill_random_data(
    random_info: Any,
    client_random: bytes,
    server_random: bytes,
    keepalive: list[Any],
) -> None:
    """Fill pClientRandom/pServerRandom on SSL3 or WTLS random structs."""
    cr_ptr, cr_len = _pack_bytes(client_random, keepalive)
    sr_ptr, sr_len = _pack_bytes(server_random, keepalive)
    random_info.pClientRandom = cr_ptr
    random_info.ulClientRandomLen = cr_len
    random_info.pServerRandom = sr_ptr
    random_info.ulServerRandomLen = sr_len


def mech_ssl3_master_key_derive(
    mechanism_type: CKM | int,
    client_random: bytes,
    server_random: bytes,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_SSL3_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_SSL3_MASTER_KEY_DERIVE, CKM_SSL3_MASTER_KEY_DERIVE_DH,
    CKM_TLS_MASTER_KEY_DERIVE, and CKM_TLS_MASTER_KEY_DERIVE_DH.

    When *with_version* is True (default), pVersion points to a CK_VERSION
    struct that the module will fill in.  Set False for DH variants where
    the version field is unused (pVersion=NULL).
    """
    ka: list[Any] = []
    params = CK_SSL3_MASTER_KEY_DERIVE_PARAMS()
    _fill_random_data(params.RandomInfo, client_random, server_random, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    return _mech_struct(mechanism_type, params, "mech_ssl3_master_key_derive", ka)


def mech_ssl3_key_mat(
    mechanism_type: CKM | int,
    client_random: bytes,
    server_random: bytes,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 128,
    is_export: bool = False,
) -> KeyMatMechanism:
    """Pack CK_SSL3_KEY_MAT_PARAMS.

    Used for CKM_SSL3_KEY_AND_MAC_DERIVE and CKM_TLS_KEY_AND_MAC_DERIVE.
    Returns a KeyMatMechanism whose .params.pReturnedKeyMaterial points to a
    CK_SSL3_KEY_MAT_OUT struct (accessible as ``mech.key_mat_out``).
    """
    ka: list[Any] = []
    params = CK_SSL3_KEY_MAT_PARAMS()
    params.ulMacSizeInBits = mac_size_bits
    params.ulKeySizeInBits = key_size_bits
    params.ulIVSizeInBits = iv_size_bits
    params.bIsExport = CK_BBOOL(1 if is_export else 0)
    _fill_random_data(params.RandomInfo, client_random, server_random, ka)

    # Allocate output struct
    key_mat_out = CK_SSL3_KEY_MAT_OUT()
    iv_bytes = iv_size_bits // 8 if iv_size_bits else 0
    if iv_bytes:
        iv_client = (ctypes.c_ubyte * iv_bytes)()
        iv_server = (ctypes.c_ubyte * iv_bytes)()
        key_mat_out.pIVClient = ctypes.cast(iv_client, CK_VOID_PTR)
        key_mat_out.pIVServer = ctypes.cast(iv_server, CK_VOID_PTR)
        ka.extend([iv_client, iv_server])
    ka.append(key_mat_out)
    params.pReturnedKeyMaterial = ctypes.cast(
        ctypes.pointer(key_mat_out),
        CK_VOID_PTR,
    )
    result = _mech_struct(mechanism_type, params, "mech_ssl3_key_mat", ka, cls=KeyMatMechanism)
    if iv_bytes:
        result.add_buffer("iv_client", iv_client, iv_bytes)
        result.add_buffer("iv_server", iv_server, iv_bytes)
    assert isinstance(result, KeyMatMechanism)
    result.key_mat_out = key_mat_out
    return result


def mech_tls12_master_key_derive(
    mechanism_type: CKM | int,
    client_random: bytes,
    server_random: bytes,
    hash_mech: CKM | int,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_TLS12_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_TLS12_MASTER_KEY_DERIVE and CKM_TLS12_MASTER_KEY_DERIVE_DH.
    *hash_mech* is the PRF hash mechanism (e.g. CKM_SHA256).
    """
    ka: list[Any] = []
    params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS()
    _fill_random_data(params.RandomInfo, client_random, server_random, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    params.prfHashMechanism = hash_mech
    return _mech_struct(
        mechanism_type,
        params,
        "mech_tls12_master_key_derive",
        ka,
        sub_mechanisms={"prfHashMechanism": hash_mech},
    )


def mech_tls12_key_mat(
    mechanism_type: CKM | int,
    client_random: bytes,
    server_random: bytes,
    hash_mech: CKM | int,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 128,
    is_export: bool = False,
) -> KeyMatMechanism:
    """Pack CK_TLS12_KEY_MAT_PARAMS.

    Used for CKM_TLS12_KEY_AND_MAC_DERIVE and CKM_TLS12_KEY_SAFE_DERIVE.
    """
    ka: list[Any] = []
    params = CK_TLS12_KEY_MAT_PARAMS()
    params.ulMacSizeInBits = mac_size_bits
    params.ulKeySizeInBits = key_size_bits
    params.ulIVSizeInBits = iv_size_bits
    params.bIsExport = CK_BBOOL(1 if is_export else 0)
    _fill_random_data(params.RandomInfo, client_random, server_random, ka)

    key_mat_out = CK_SSL3_KEY_MAT_OUT()
    iv_bytes = iv_size_bits // 8 if iv_size_bits else 0
    if iv_bytes:
        iv_client = (ctypes.c_ubyte * iv_bytes)()
        iv_server = (ctypes.c_ubyte * iv_bytes)()
        key_mat_out.pIVClient = ctypes.cast(iv_client, CK_VOID_PTR)
        key_mat_out.pIVServer = ctypes.cast(iv_server, CK_VOID_PTR)
        ka.extend([iv_client, iv_server])
    ka.append(key_mat_out)
    params.pReturnedKeyMaterial = ctypes.cast(
        ctypes.pointer(key_mat_out),
        CK_VOID_PTR,
    )
    params.prfHashMechanism = hash_mech
    result = _mech_struct(
        mechanism_type,
        params,
        "mech_tls12_key_mat",
        ka,
        sub_mechanisms={"prfHashMechanism": hash_mech},
        cls=KeyMatMechanism,
    )
    if iv_bytes:
        result.add_buffer("iv_client", iv_client, iv_bytes)
        result.add_buffer("iv_server", iv_server, iv_bytes)
    assert isinstance(result, KeyMatMechanism)
    result.key_mat_out = key_mat_out
    return result


def mech_tls12_extended_master_key_derive(
    mechanism_type: CKM | int,
    hash_mech: CKM | int,
    session_hash: bytes,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE and the DH variant.
    """
    ka: list[Any] = []
    params = CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS()
    params.prfHashMechanism = hash_mech
    params.pSessionHash, params.ulSessionHashLen = _pack_bytes(session_hash, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    return _mech_struct(
        mechanism_type,
        params,
        "mech_tls12_extended_master_key_derive",
        ka,
        sub_mechanisms={"prfHashMechanism": hash_mech},
    )


def mech_tls_prf(
    mechanism_type: CKM | int,
    seed: bytes,
    label: bytes,
    output_len: int,
) -> PackedMechanism:
    """Pack CK_TLS_PRF_PARAMS.

    Used for CKM_TLS_PRF. Allocates an output buffer of *output_len* bytes
    and a CK_ULONG for pulOutputLen.
    """
    ka: list[Any] = []
    params = CK_TLS_PRF_PARAMS()
    params.pSeed, params.ulSeedLen = _pack_bytes(seed, ka)
    params.pLabel, params.ulLabelLen = _pack_bytes(label, ka)
    out_buf = (ctypes.c_ubyte * output_len)()
    ka.append(out_buf)
    params.pOutput = ctypes.cast(out_buf, CK_VOID_PTR)
    out_len = CK_ULONG(output_len)
    ka.append(out_len)
    params.pulOutputLen = ctypes.cast(ctypes.pointer(out_len), CK_VOID_PTR)
    result = _mech_struct(mechanism_type, params, "mech_tls_prf", ka)
    result.add_buffer("output", out_buf, output_len)
    result._output_buf = out_buf  # type: ignore[attr-defined]
    result._output_len = out_len  # type: ignore[attr-defined]
    return result


def mech_tls_kdf(
    mechanism_type: CKM | int,
    prf_mechanism: int,
    label: bytes,
    client_random: bytes,
    server_random: bytes,
    *,
    context_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_TLS_KDF_PARAMS.

    Used for CKM_TLS12_KDF and CKM_TLS_KDF.
    """
    ka: list[Any] = []
    params = CK_TLS_KDF_PARAMS()
    params.prfMechanism = prf_mechanism
    params.pLabel, params.ulLabelLength = _pack_bytes(label, ka)
    _fill_random_data(params.RandomInfo, client_random, server_random, ka)
    params.pContextData, params.ulContextDataLength = _pack_bytes(context_data, ka)
    return _mech_struct(
        mechanism_type,
        params,
        "mech_tls_kdf",
        ka,
        sub_mechanisms={"prfMechanism": prf_mechanism},
    )


def mech_tls_mac(
    mechanism_type: CKM | int,
    prf_hash_mechanism: int,
    mac_length: int,
    server_or_client: int,
) -> PackedMechanism:
    """Pack CK_TLS_MAC_PARAMS.

    Used for CKM_TLS12_MAC and CKM_TLS_MAC.
    *server_or_client*: 1=server, 2=client.
    """
    params = CK_TLS_MAC_PARAMS()
    params.prfHashMechanism = prf_hash_mechanism
    params.ulMacLength = mac_length
    params.ulServerOrClient = server_or_client
    return _mech_struct(
        mechanism_type,
        params,
        "mech_tls_mac",
        sub_mechanisms={"prfHashMechanism": prf_hash_mechanism},
    )


def mech_wtls_master_key_derive(
    mechanism_type: CKM | int,
    digest_mechanism: int,
    client_random: bytes,
    server_random: bytes,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_WTLS_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_WTLS_MASTER_KEY_DERIVE and CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC.
    """
    ka: list[Any] = []
    params = CK_WTLS_MASTER_KEY_DERIVE_PARAMS()
    params.DigestMechanism = digest_mechanism
    _fill_random_data(params.RandomInfo, client_random, server_random, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    return _mech_struct(
        mechanism_type,
        params,
        "mech_wtls_master_key_derive",
        ka,
        sub_mechanisms={"DigestMechanism": digest_mechanism},
    )


def mech_wtls_key_mat(
    mechanism_type: CKM | int,
    digest_mechanism: int,
    client_random: bytes,
    server_random: bytes,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 0,
    sequence_number: int = 0,
    is_export: bool = False,
) -> KeyMatMechanism:
    """Pack CK_WTLS_KEY_MAT_PARAMS.

    Used for CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE and
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE.
    """
    ka: list[Any] = []
    params = CK_WTLS_KEY_MAT_PARAMS()
    params.DigestMechanism = digest_mechanism
    params.ulMacSizeInBits = mac_size_bits
    params.ulKeySizeInBits = key_size_bits
    params.ulIVSizeInBits = iv_size_bits
    params.ulSequenceNumber = sequence_number
    params.bIsExport = CK_BBOOL(1 if is_export else 0)
    _fill_random_data(params.RandomInfo, client_random, server_random, ka)

    key_mat_out = CK_WTLS_KEY_MAT_OUT()
    iv_bytes = iv_size_bits // 8 if iv_size_bits else 0
    if iv_bytes:
        iv_buf = (ctypes.c_ubyte * iv_bytes)()
        key_mat_out.pIV = ctypes.cast(iv_buf, CK_VOID_PTR)
        ka.append(iv_buf)
    ka.append(key_mat_out)
    params.pReturnedKeyMaterial = ctypes.cast(
        ctypes.pointer(key_mat_out),
        CK_VOID_PTR,
    )
    result = _mech_struct(
        mechanism_type,
        params,
        "mech_wtls_key_mat",
        ka,
        sub_mechanisms={"DigestMechanism": digest_mechanism},
        cls=KeyMatMechanism,
    )
    if iv_bytes:
        result.add_buffer("iv", iv_buf, iv_bytes)
    assert isinstance(result, KeyMatMechanism)
    result.key_mat_out = key_mat_out
    return result


def mech_wtls_prf(
    mechanism_type: CKM | int,
    digest_mechanism: int,
    seed: bytes,
    label: bytes,
    output_len: int,
) -> PackedMechanism:
    """Pack CK_WTLS_PRF_PARAMS.

    Used for CKM_WTLS_PRF.
    """
    ka: list[Any] = []
    params = CK_WTLS_PRF_PARAMS()
    params.DigestMechanism = digest_mechanism
    params.pSeed, params.ulSeedLen = _pack_bytes(seed, ka)
    params.pLabel, params.ulLabelLen = _pack_bytes(label, ka)
    out_buf = (ctypes.c_ubyte * output_len)()
    ka.append(out_buf)
    params.pOutput = ctypes.cast(out_buf, CK_VOID_PTR)
    out_len = CK_ULONG(output_len)
    ka.append(out_len)
    params.pulOutputLen = ctypes.cast(ctypes.pointer(out_len), CK_VOID_PTR)
    result = _mech_struct(
        mechanism_type,
        params,
        "mech_wtls_prf",
        ka,
        sub_mechanisms={"DigestMechanism": digest_mechanism},
    )
    result.add_buffer("output", out_buf, output_len)
    result._output_buf = out_buf  # type: ignore[attr-defined]
    result._output_len = out_len  # type: ignore[attr-defined]
    return result


def mech_hash_sign_context(
    mechanism_type: CKM | int,
    hash_mech: CKM | int,
    *,
    hedge: CKH | int | None = None,
    context: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_HASH_SIGN_ADDITIONAL_CONTEXT for CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA.

    The ``hash`` field specifies which hash to use (mandatory for the generic
    CKM_HASH_ML_DSA and CKM_HASH_SLH_DSA mechanisms).
    ``hedge`` defaults to CKH_HEDGE_PREFERRED.
    """
    ka: list[Any] = []
    params = CK_HASH_SIGN_ADDITIONAL_CONTEXT()
    params.hedgeVariant = CKH_HEDGE_PREFERRED if hedge is None else hedge
    if context is not None:
        params.pContext, params.ulContextLen = _pack_bytes(context, ka)
    else:
        params.pContext = None
        params.ulContextLen = 0
    params.hash = hash_mech
    return _mech_struct(mechanism_type, params, "mech_hash_sign_context", ka)


def mech_sign_context(
    mechanism_type: CKM | int,
    *,
    hedge: CKH | int | None = None,
    context: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_SIGN_ADDITIONAL_CONTEXT for CKM_ML_DSA / CKM_SLH_DSA (pure).

    For hash-and-sign variants (CKM_HASH_ML_DSA, CKM_HASH_SLH_DSA), use
    ``mech_hash_sign_context`` instead -- it has a ``hash`` field.
    ``hedge`` defaults to CKH_HEDGE_PREFERRED.
    """
    ka: list[Any] = []
    params = CK_SIGN_ADDITIONAL_CONTEXT()
    params.hedgeVariant = CKH_HEDGE_PREFERRED if hedge is None else hedge
    if context is not None:
        params.pContext, params.ulContextLen = _pack_bytes(context, ka)
    else:
        params.pContext = None
        params.ulContextLen = 0
    return _mech_struct(mechanism_type, params, "mech_sign_context", ka)


__all__ = [
    "mech_cbc_pad",
    "mech_ccm",
    "mech_ccm_message_generated_nonce",
    "mech_ccm_wrap",
    "mech_ccm_wrap_generated_nonce",
    "mech_chacha20",
    "mech_chacha20_poly1305",
    "mech_ctr",
    "mech_ecdh",
    "mech_eddsa",
    "mech_gcm",
    "mech_gcm_generated_iv",
    "mech_gcm_message",
    "mech_gcm_message_generated_iv",
    "mech_gcm_message_inherit_tag",
    "mech_gcm_wrap",
    "mech_gcm_wrap_generated_iv",
    "mech_hash_sign_context",
    "mech_hkdf",
    "mech_ike2_prf_plus_derive",
    "mech_ike_prf_derive",
    "mech_oaep",
    "mech_pbe",
    "mech_pbkdf2",
    "mech_pss",
    "mech_rc2",
    "mech_rc2_cbc",
    "mech_rc2_mac_general",
    "mech_rc5",
    "mech_rc5_cbc",
    "mech_rc5_mac_general",
    "mech_salsa20",
    "mech_salsa20_poly1305",
    "mech_sign_context",
    "mech_ssl3_key_mat",
    "mech_ssl3_master_key_derive",
    "mech_string_data",
    "mech_tls12_extended_master_key_derive",
    "mech_tls12_key_mat",
    "mech_tls12_master_key_derive",
    "mech_tls_kdf",
    "mech_tls_mac",
    "mech_tls_prf",
    "mech_wtls_key_mat",
    "mech_wtls_master_key_derive",
    "mech_wtls_prf",
]
