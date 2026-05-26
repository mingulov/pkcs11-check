"""Wycheproof AES-CMAC, AES Key Wrap, AES-KWP, AES-CCM, AES-GMAC, and AES-XTS vectors."""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_ccm
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    generate_random,
    import_secret_key,
    sign_single,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKK_AES_XTS,
    CKM_AES_CCM,
    CKM_AES_CMAC,
    CKM_AES_GMAC,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKM_AES_XTS,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = pytest.mark.wycheproof

_AES_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _xfail_if_aes_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised AES operation rejects as non-clean findings."""
    xfail_if_known_ckr(
        exc,
        _AES_RUNTIME_REJECT_CKRS,
        f"{label}: advertised AES operation is not operational",
    )
    raise exc


def _load_flat(filename: str) -> list[tuple[str, dict[str, Any]]]:
    """Load vectors from a Wycheproof JSON, flattening groups."""
    path = WYCHEPROOF_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    vectors = []
    for group in data["testGroups"]:
        for test in group["tests"]:
            test["_group"] = {k: v for k, v in group.items() if k != "tests"}
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


# --- AES-CMAC ---

_AES_CMAC_VECTORS = _load_flat("aes_cmac_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_CMAC_VECTORS, ids=[v[0] for v in _AES_CMAC_VECTORS])
def test_aes_cmac(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CMAC verification from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_CMAC"):
        pytest.skip("AES_CMAC not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]
    tag_size = vec["_group"].get("tagSize", 128) // 8

    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        if result == "invalid":
            return
        raise

    mac = None
    try:
        mac = sign_single(rs.raw, rs.sh, key, CKM_AES_CMAC, msg)
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_aes_runtime_reject(exc, f"AES-CMAC {vec_id}")
            pytest.fail(f"AES-CMAC failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and mac is not None:
        assert mac[:tag_size] == tag_expected
    if result == "invalid" and mac is not None and mac[:tag_size] == tag_expected:
        pytest.fail(f"AES-CMAC {vec_id} produced invalid tag")

    generate_random(rs.raw, rs.sh, 64)


# --- AES Key Wrap (RFC 3394) ---

_AES_WRAP_VECTORS = _load_flat("aes_wrap_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_WRAP_VECTORS, ids=[v[0] for v in _AES_WRAP_VECTORS])
def test_aes_key_wrap(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES Key Wrap (RFC 3394) from Wycheproof vectors.

    For valid vectors: wrap(msg) with key should produce ct.
    We test by importing wrapping key, wrapping a target key, comparing output.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # Import wrapping key
    try:
        wrap_key_h = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        pytest.skip("Cannot import AES wrapping key")

    # Import target key (the material being wrapped)
    try:
        target_key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            msg,
            attrs={
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        destroy_quietly(rs.raw, rs.sh, wrap_key_h)
        if result == "invalid":
            return
        pytest.skip("Cannot import target key")

    # Wrap and compare
    wrapped = None
    try:
        wrapped = wrap_key(rs.raw, rs.sh, wrap_key_h, target_key, CKM_AES_KEY_WRAP)
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_aes_runtime_reject(exc, f"AES-KW {vec_id}")
            pytest.fail(f"AES-KW wrap failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, target_key)
        destroy_quietly(rs.raw, rs.sh, wrap_key_h)

    if result == "valid" and wrapped is not None:
        assert wrapped == ct_expected
    if result == "invalid" and wrapped is not None and wrapped == ct_expected:
        pytest.fail(f"AES-KW wrap {vec_id} produced invalid ciphertext")


# --- AES Key Wrap with Padding (RFC 5649) ---

_AES_KWP_VECTORS = _load_flat("aes_kwp_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_KWP_VECTORS, ids=[v[0] for v in _AES_KWP_VECTORS])
def test_aes_kwp(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES Key Wrap with Padding (RFC 5649) from Wycheproof vectors.

    KWP allows wrapping data that is not a multiple of 8 bytes,
    unlike basic AES-KW which requires 8-byte aligned data.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # Import wrapping key
    try:
        wrap_key_h = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        pytest.skip("Cannot import AES wrapping key")

    # Wycheproof KWP vectors are RFC 5649 raw data vectors.  PKCS#11 exposes
    # that exact operation through CKM_AES_KEY_WRAP_KWP C_Encrypt.
    wrapped = None
    try:
        wrapped = encrypt_single(
            rs.raw,
            rs.sh,
            wrap_key_h,
            CKM_AES_KEY_WRAP_KWP,
            msg,
            output_overhead=16,
        )
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_aes_runtime_reject(exc, f"AES-KWP {vec_id}")
            pytest.fail(f"AES-KWP wrap failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, wrap_key_h)

    if result == "valid" and wrapped is not None:
        assert wrapped == ct_expected, (
            f"AES-KWP wrap output differs for {vec_id} "
            f"(got {len(wrapped)}B, expected {len(ct_expected)}B)"
        )
    if result == "invalid" and wrapped is not None and wrapped == ct_expected:
        pytest.fail(f"AES-KWP wrap {vec_id} produced invalid ciphertext")


# --- AES-CCM ---

_AES_CCM_VECTORS = _load_flat("aes_ccm_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_CCM_VECTORS, ids=[v[0] for v in _AES_CCM_VECTORS])
def test_aes_ccm(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CCM AEAD encryption/decryption from Wycheproof vectors.

    For valid vectors: encrypt(msg, aad, iv) should produce ct||tag.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_CCM"):
        pytest.skip("AES_CCM not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    aad = bytes.fromhex(vec["aad"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        if result == "invalid":
            return
        raise

    # Encrypt and compare
    ciphertext = None
    try:
        ccm_param = mech_ccm(
            CKM_AES_CCM,
            iv,
            data_len=len(msg),
            aad=aad if aad else None,
            mac_len=len(tag_expected),
        )
        ciphertext = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CCM,
            msg,
            mech_param=ccm_param,
        )
    except (AssertionError, TypeError, NotImplementedError) as exc:
        if result == "valid":
            if isinstance(exc, AssertionError):
                _xfail_if_aes_runtime_reject(exc, f"AES-CCM {vec_id}")
            pytest.fail(f"AES-CCM encrypt failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    # AES-CCM output is ct||tag
    if result == "valid" and ciphertext is not None:
        assert ciphertext == ct_expected + tag_expected
    if result == "invalid" and ciphertext is not None and ciphertext == ct_expected + tag_expected:
        pytest.fail(f"AES-CCM encrypt {vec_id} produced invalid ciphertext/tag")


# --- AES-GMAC ---

_AES_GMAC_VECTORS = _load_flat("aes_gmac_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_GMAC_VECTORS, ids=[v[0] for v in _AES_GMAC_VECTORS])
def test_aes_gmac(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-GMAC (authentication-only GCM) from Wycheproof vectors.

    GMAC is GCM with empty plaintext - produces only a tag over AAD.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_GMAC"):
        pytest.skip("AES_GMAC not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    msg = bytes.fromhex(vec["msg"])  # AAD in GMAC context
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        if result == "invalid":
            return
        raise

    mac = None
    try:
        mac = sign_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_GMAC,
            msg,
            mech_param=mech_bytes(CKM_AES_GMAC, iv),
        )
    except (AssertionError, TypeError) as exc:
        if result == "valid":
            if isinstance(exc, AssertionError):
                _xfail_if_aes_runtime_reject(exc, f"AES-GMAC {vec_id}")
            pytest.fail(f"AES-GMAC sign failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and mac is not None:
        assert mac == tag_expected
    if result == "invalid" and mac is not None and mac == tag_expected:
        pytest.fail(f"AES-GMAC {vec_id} produced invalid tag")


# --- AES-XTS ---

_AES_XTS_VECTORS = _load_flat("aes_xts_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_XTS_VECTORS, ids=[v[0] for v in _AES_XTS_VECTORS])
def test_aes_xts(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XTS disk encryption mode from Wycheproof vectors.

    XTS uses a double-size key (e.g. 512 bits = two 256-bit keys)
    and a tweak (IV) for sector-based encryption.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_XTS"):
        pytest.skip("AES_XTS not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # XTS uses AES_XTS key type with double-size key
    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES_XTS,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except (AssertionError, AttributeError):
        if result == "invalid":
            return
        pytest.skip("Cannot import AES-XTS key")

    ct = None
    try:
        ct = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_XTS,
            msg,
            mech_param=mech_bytes(CKM_AES_XTS, iv),
        )
    except (AssertionError, TypeError) as exc:
        if result == "valid":
            if isinstance(exc, AssertionError):
                _xfail_if_aes_runtime_reject(exc, f"AES-XTS {vec_id}")
            pytest.fail(f"AES-XTS encrypt failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and ct is not None:
        assert ct == ct_expected
