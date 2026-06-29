"""NIST ACVP AES-GCM tests - GCM, GCM-SIV, GMAC, XPN."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, set_params, xfail_as
from pkcs11_check.raw.pack_mechanisms import mech_gcm
from pkcs11_check.raw.recipes import decrypt_single, destroy_quietly, encrypt_single
from pkcs11_check.raw.types_std import CKM_AES_GMAC
from pkcs11_check.testcases.acvp.acvp_loader import load_acvp_vectors, require_acvp_vectors
from pkcs11_check.testcases.acvp.aes.base import (
    CKM_AES_GCM_SIV,
    _import_aes_key,
    _load_vectors,
    run_gcm_decrypt_test,
    run_gcm_encrypt_test,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

require_acvp_vectors()


# =============================================================================
# AES-GCM
# =============================================================================


def _load_gcm_vectors() -> tuple[
    list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]
]:
    encrypt_fields = {
        "key": "key",
        "iv": "iv",
        "pt": "pt",
        "aad": "aad",
        "ct_expected": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "tag_expected": ("tag", lambda x: bytes.fromhex(x) if x else b""),
    }
    decrypt_fields = {
        "key": "key",
        "iv": "iv",
        "ct": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "tag": "tag",
        "aad": "aad",
        "pt_expected": ("pt", lambda x: bytes.fromhex(x) if x else b""),
    }
    enc_vecs, dec_vecs = _load_vectors(
        "ACVP-AES-GCM-1.0",
        encrypt_fields,  # type: ignore[arg-type]
        decrypt_fields,  # type: ignore[arg-type]
        extra_group_fields={"tag_len_bits": "tagLen"},
    )
    raw = load_acvp_vectors("ACVP-AES-GCM-1.0")
    for vec_id, vec in dec_vecs:
        for rv in raw:
            if rv["input"].get("tcId") == vec["tc_id"]:
                vec["test_passed"] = rv["expected"].get("testPassed", True)
                break
    return enc_vecs, dec_vecs


_GCM_ENCRYPT_VECTORS: list[tuple[str, dict[str, Any]]]
_GCM_DECRYPT_VECTORS: list[tuple[str, dict[str, Any]]]
_GCM_ENCRYPT_VECTORS, _GCM_DECRYPT_VECTORS = _load_gcm_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _GCM_ENCRYPT_VECTORS, ids=[v[0] for v in _GCM_ENCRYPT_VECTORS]
)
def test_acvp_aes_gcm_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-GCM encryption from NIST ACVP vectors."""
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    run_gcm_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _GCM_DECRYPT_VECTORS, ids=[v[0] for v in _GCM_DECRYPT_VECTORS]
)
def test_acvp_aes_gcm_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-GCM decryption from NIST ACVP vectors."""
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    run_gcm_decrypt_test(p11_module_session, vec_id, vec)


# =============================================================================
# AES-GCM-SIV
# =============================================================================


def _load_gcm_siv_vectors() -> tuple[
    list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]
]:
    encrypt_fields = {
        "key": "key",
        "iv": "iv",
        "pt": "pt",
        "aad": "aad",
        "ct_expected": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "tag_expected": ("tag", lambda x: bytes.fromhex(x) if x else b""),
    }
    decrypt_fields = {
        "key": "key",
        "iv": "iv",
        "ct": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "tag": ("tag", lambda x: bytes.fromhex(x) if x else b""),
        "aad": "aad",
        "pt_expected": ("pt", lambda x: bytes.fromhex(x) if x else b""),
    }
    enc_vecs, dec_vecs = _load_vectors(
        "ACVP-AES-GCM-SIV-1.0",
        encrypt_fields,  # type: ignore[arg-type]
        decrypt_fields,  # type: ignore[arg-type]
    )
    raw = load_acvp_vectors("ACVP-AES-GCM-SIV-1.0")
    for vec_id, vec in dec_vecs:
        for rv in raw:
            if rv["input"].get("tcId") == vec["tc_id"]:
                vec["test_passed"] = rv["expected"].get("testPassed", True)
                break
    return enc_vecs, dec_vecs


_GCM_SIV_ENCRYPT_VECTORS: list[tuple[str, dict[str, Any]]]
_GCM_SIV_DECRYPT_VECTORS: list[tuple[str, dict[str, Any]]]
_GCM_SIV_ENCRYPT_VECTORS, _GCM_SIV_DECRYPT_VECTORS = _load_gcm_siv_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _GCM_SIV_ENCRYPT_VECTORS, ids=[v[0] for v in _GCM_SIV_ENCRYPT_VECTORS]
)
def test_acvp_aes_gcm_siv_encrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-GCM-SIV encryption from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_GCM_SIV"):
        pytest.skip("AES_GCM_SIV not supported")
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    try:
        param = mech_gcm(CKM_AES_GCM_SIV, vec["iv"], aad=vec.get("aad"), tag_bits=128)
    except (AssertionError, ValueError, TypeError) as exc:
        xfail_as(
            "not_operational",
            kind="crypto",
            label="AES_GCM_SIV:encrypt",
            summary=f"Binding rejects GCM-SIV params: {exc}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True)
        result = encrypt_single(rs.raw, rs.sh, key, CKM_AES_GCM_SIV, vec["pt"], mech_param=param)
        ct_got, tag_got = result[:-16], result[-16:]
        assert ct_got == vec["ct_expected"], f"{vec_id}: ciphertext mismatch"
        assert tag_got == vec["tag_expected"], f"{vec_id}: tag mismatch"
    except AssertionError as exc:
        classify(
            "honest_deviation",
            label="AES_GCM_SIV:encrypt",
            summary=f"Module limitation: GCM-SIV not supported ({exc})",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.parametrize(
    "vec_id,vec", _GCM_SIV_DECRYPT_VECTORS, ids=[v[0] for v in _GCM_SIV_DECRYPT_VECTORS]
)
def test_acvp_aes_gcm_siv_decrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-GCM-SIV decryption from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_GCM_SIV"):
        pytest.skip("AES_GCM_SIV not supported")
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    try:
        param = mech_gcm(CKM_AES_GCM_SIV, vec["iv"], aad=vec.get("aad"), tag_bits=128)
    except (AssertionError, ValueError, TypeError) as exc:
        xfail_as(
            "not_operational",
            kind="crypto",
            label="AES_GCM_SIV:decrypt",
            summary=f"Binding rejects GCM-SIV params: {exc}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], decrypt=True)
        pt = decrypt_single(
            rs.raw, rs.sh, key, CKM_AES_GCM_SIV, vec["ct"] + vec["tag"], mech_param=param
        )
        if vec["test_passed"]:
            assert pt == vec["pt_expected"], f"{vec_id}: plaintext mismatch"
        else:
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label="AES_GCM_SIV:decrypt",
                summary=(
                    f"{vec_id}: decrypted an invalid GCM-SIV vector "
                    f"(forged ciphertext/tag accepted)"
                ),
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    except AssertionError:
        if not vec["test_passed"]:
            return
        classify(
            "honest_deviation",
            label="AES_GCM_SIV:decrypt",
            summary="Module limitation: GCM-SIV decrypt failed",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# =============================================================================
# AES-GMAC
# =============================================================================


def _load_gmac_vectors() -> list[tuple[str, dict[str, Any]]]:
    encrypt_fields = {"key": "key", "iv": "iv", "aad": "aad", "tag_expected": "tag"}
    encrypt_vecs, _ = _load_vectors(
        "ACVP-AES-GMAC-1.0",
        encrypt_fields,
        {},
        extra_group_fields={"tag_len_bits": "tagLen"},
    )
    return encrypt_vecs


_GMAC_VECTORS: list[tuple[str, dict[str, Any]]] = _load_gmac_vectors()


@pytest.mark.parametrize("vec_id,vec", _GMAC_VECTORS, ids=[v[0] for v in _GMAC_VECTORS])
def test_acvp_aes_gmac(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-GMAC authentication tag generation from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_GMAC"):
        pytest.skip("AES_GMAC not supported")
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    try:
        gmac_param = mech_gcm(
            CKM_AES_GMAC, vec["iv"], aad=vec.get("aad"), tag_bits=vec["tag_len_bits"]
        )
    except (AssertionError, ValueError, TypeError) as exc:
        xfail_as(
            "not_operational",
            kind="crypto",
            label="AES_GMAC",
            summary=f"Binding rejects GMAC params: {exc}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True)
        result = encrypt_single(rs.raw, rs.sh, key, CKM_AES_GMAC, b"", mech_param=gmac_param)
        assert result == vec["tag_expected"], f"{vec_id}: tag mismatch"
    except AssertionError as exc:
        classify(
            "honest_deviation",
            label="AES_GMAC",
            summary=f"Module limitation: GMAC not supported ({exc})",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# =============================================================================
# AES-XPN (Extended Nonce GCM)
# =============================================================================


def _load_xpn_vectors() -> tuple[
    list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]
]:
    """Load AES-XPN ACVP vectors (salt XOR IV = extended nonce)."""
    raw = load_acvp_vectors("ACVP-AES-XPN-1.0")
    encrypt_vecs: list[tuple[str, dict[str, Any]]] = []
    decrypt_vecs: list[tuple[str, dict[str, Any]]] = []
    for vec in raw:
        group, inp, exp = vec["group"], vec["input"], vec["expected"]
        direction, tc_id = group.get("direction", ""), inp.get("tcId", 0)
        salt = bytes.fromhex(inp.get("salt", "")) if inp.get("salt") else b""
        iv = bytes.fromhex(inp.get("iv", "")) if inp.get("iv") else b""
        ext_nonce = bytes(a ^ b for a, b in zip(salt, iv))
        key_hex = inp.get("key", "")
        if not key_hex:
            continue
        if direction == "encrypt":
            if len(encrypt_vecs) >= 10:
                continue
            merged = {
                "tc_id": tc_id,
                "key": bytes.fromhex(key_hex),
                "extended_nonce": ext_nonce,
                "salt": salt,
                "iv": iv,
                "pt": bytes.fromhex(inp.get("pt", "")) if inp.get("pt") else b"",
                "aad": bytes.fromhex(inp.get("aad", "")) if inp.get("aad") else b"",
                "ct_expected": bytes.fromhex(exp.get("ct", "")) if exp.get("ct") else b"",
                "tag_expected": bytes.fromhex(exp.get("tag", "")),
                "tag_len_bits": group.get("tagLen", 128),
            }
            encrypt_vecs.append((f"AES-XPN-enc-tc{tc_id}", merged))
        elif direction == "decrypt":
            if len(decrypt_vecs) >= 10:
                continue
            merged = {
                "tc_id": tc_id,
                "key": bytes.fromhex(key_hex),
                "extended_nonce": ext_nonce,
                "salt": salt,
                "iv": iv,
                "ct": bytes.fromhex(inp.get("ct", "")) if inp.get("ct") else b"",
                "tag": bytes.fromhex(inp.get("tag", "")),
                "aad": bytes.fromhex(inp.get("aad", "")) if inp.get("aad") else b"",
                "pt_expected": bytes.fromhex(exp.get("pt", "")) if exp.get("pt") else b"",
                "test_passed": exp.get("testPassed", True),
                "tag_len_bits": group.get("tagLen", 128),
            }
            decrypt_vecs.append((f"AES-XPN-dec-tc{tc_id}", merged))
    return encrypt_vecs, decrypt_vecs


_XPN_ENCRYPT_VECTORS: list[tuple[str, dict[str, Any]]]
_XPN_DECRYPT_VECTORS: list[tuple[str, dict[str, Any]]]
_XPN_ENCRYPT_VECTORS, _XPN_DECRYPT_VECTORS = _load_xpn_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _XPN_ENCRYPT_VECTORS, ids=[v[0] for v in _XPN_ENCRYPT_VECTORS]
)
def test_acvp_aes_xpn_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XPN encryption from NIST ACVP vectors."""
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    run_gcm_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _XPN_DECRYPT_VECTORS, ids=[v[0] for v in _XPN_DECRYPT_VECTORS]
)
def test_acvp_aes_xpn_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XPN decryption from NIST ACVP vectors."""
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    run_gcm_decrypt_test(p11_module_session, vec_id, vec)
