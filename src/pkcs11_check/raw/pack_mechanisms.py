"""Mechanism-specific parameter packers for PKCS#11 operations.

Callers should import mechanism packers from ``pkcs11_check.raw.pack``
(which re-exports all names), not directly from this module.
"""

from __future__ import annotations

import ctypes
from typing import Any

from .pack import (
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
    CK_CHACHA20_PARAMS,
    CK_ECDH1_DERIVE_PARAMS,
    CK_EDDSA_PARAMS,
    CK_GCM_MESSAGE_PARAMS,
    CK_HKDF_PARAMS,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_PKCS5_PBKD2_PARAMS2,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_RSA_PKCS_PSS_PARAMS,
    CK_SALSA20_CHACHA20_POLY1305_PARAMS,
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
    CKM,
    CKZ_DATA_SPECIFIED,
    CKZ_SALT_SPECIFIED,
)


def mech_gcm(
    mechanism_type: CKM,
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


def mech_gcm_message(
    mechanism_type: CKM,
    iv: bytes,
    *,
    iv_fixed_bits: int = 0,
    iv_generator: int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_GCM_MESSAGE_PARAMS for v3.0 message-based AEAD.

    The ``pTag`` field is a pre-allocated output buffer (tag_bits // 8 bytes)
    that the token writes the authentication tag to.
    """
    ka: list[Any] = []
    params = CK_GCM_MESSAGE_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvFixedBits = iv_fixed_bits
    params.ivGenerator = iv_generator
    tag_len = tag_bits // 8
    tag_buf = (ctypes.c_ubyte * tag_len)()
    ka.append(tag_buf)
    params.pTag = ctypes.cast(tag_buf, ctypes.c_void_p)
    params.ulTagBits = tag_bits
    return _mech_struct(mechanism_type, params, "mech_gcm_message", ka)


def mech_ccm(
    mechanism_type: CKM,
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
    mechanism_type: CKM,
    *,
    hash_mech: int,
    mgf: int,
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
    mechanism_type: CKM,
    *,
    hash_mech: int,
    mgf: int,
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
    mechanism_type: CKM,
    *,
    kdf: int,
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


def mech_hkdf(
    mechanism_type: CKM,
    *,
    hash_mech: int,
    extract: bool = True,
    expand: bool = True,
    salt_type: int = 1,
    salt: bytes | None = None,
    salt_key: int = 0,
    info: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_HKDF_PARAMS."""
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


def mech_cbc_pad(mechanism_type: CKM, iv: bytes) -> PackedMechanism:
    """Pack 16-byte IV for AES-CBC / AES-CBC-PAD (raw bytes parameter)."""
    return mech_bytes(mechanism_type, iv)


def mech_ctr(mechanism_type: CKM, bits: int = 128) -> PackedMechanism:
    """Pack CK_AES_CTR_PARAMS with ulCounterBits=bits and zeroed counter block."""
    params = CK_AES_CTR_PARAMS()
    params.ulCounterBits = bits
    for i in range(16):
        params.cb[i] = 0
    return _mech_struct(mechanism_type, params, "mech_ctr", sub_mechanisms={"counterBits": bits})


def mech_chacha20(
    mechanism_type: CKM,
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


def mech_chacha20_poly1305(
    mechanism_type: CKM,
    nonce: bytes,
    aad: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_SALSA20_CHACHA20_POLY1305_PARAMS with nonce and optional AAD."""
    ka: list[Any] = []
    params = CK_SALSA20_CHACHA20_POLY1305_PARAMS()
    params.pNonce, params.ulNonceLen = _pack_bytes(nonce, ka)
    params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    return _mech_struct(mechanism_type, params, "mech_chacha20_poly1305", ka)


def mech_eddsa(
    mechanism_type: CKM,
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
    mechanism_type: CKM,
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


def mech_string_data(mechanism_type: CKM, data: bytes) -> PackedMechanism:
    """Pack CK_KEY_DERIVATION_STRING_DATA for concatenation-style derivation."""
    ka: list[Any] = []
    params = CK_KEY_DERIVATION_STRING_DATA()
    params.pData, params.ulLen = _pack_bytes(data, ka)
    return _mech_struct(mechanism_type, params, "mech_string_data", ka)


# ---------------------------------------------------------------------------
# SSL3 / TLS / WTLS mechanism packers
# ---------------------------------------------------------------------------


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
    mechanism_type: CKM,
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
    mechanism_type: CKM,
    client_random: bytes,
    server_random: bytes,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 128,
    is_export: bool = False,
) -> PackedMechanism:
    """Pack CK_SSL3_KEY_MAT_PARAMS.

    Used for CKM_SSL3_KEY_AND_MAC_DERIVE and CKM_TLS_KEY_AND_MAC_DERIVE.
    Returns a PackedMechanism whose .params.pReturnedKeyMaterial points to a
    CK_SSL3_KEY_MAT_OUT struct (accessible as pm.params._key_mat_out_ref).
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
    result = _mech_struct(mechanism_type, params, "mech_ssl3_key_mat", ka)
    # Stash for callers to read output key handles
    result._key_mat_out_ref = key_mat_out  # type: ignore[attr-defined]
    return result


def mech_tls12_master_key_derive(
    mechanism_type: CKM,
    client_random: bytes,
    server_random: bytes,
    hash_mech: int,
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
    mechanism_type: CKM,
    client_random: bytes,
    server_random: bytes,
    hash_mech: int,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 128,
    is_export: bool = False,
) -> PackedMechanism:
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
    )
    result._key_mat_out_ref = key_mat_out  # type: ignore[attr-defined]
    return result


def mech_tls12_extended_master_key_derive(
    mechanism_type: CKM,
    hash_mech: int,
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
    mechanism_type: CKM,
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
    result._output_buf = out_buf  # type: ignore[attr-defined]
    result._output_len = out_len  # type: ignore[attr-defined]
    return result


def mech_tls_kdf(
    mechanism_type: CKM,
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
    mechanism_type: CKM,
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
    mechanism_type: CKM,
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
    mechanism_type: CKM,
    digest_mechanism: int,
    client_random: bytes,
    server_random: bytes,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 0,
    sequence_number: int = 0,
    is_export: bool = False,
) -> PackedMechanism:
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
    )
    result._key_mat_out_ref = key_mat_out  # type: ignore[attr-defined]
    return result


def mech_wtls_prf(
    mechanism_type: CKM,
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
    result._output_buf = out_buf  # type: ignore[attr-defined]
    result._output_len = out_len  # type: ignore[attr-defined]
    return result


__all__ = [
    "mech_cbc_pad",
    "mech_ccm",
    "mech_chacha20",
    "mech_chacha20_poly1305",
    "mech_ctr",
    "mech_ecdh",
    "mech_eddsa",
    "mech_gcm",
    "mech_gcm_message",
    "mech_hkdf",
    "mech_oaep",
    "mech_pbkdf2",
    "mech_pss",
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
