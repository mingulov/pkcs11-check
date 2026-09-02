"""NIST ACVP AES-GCM tests - GCM, GCM-SIV, GMAC, XPN."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as, set_mechanism, set_params, xfail_as
from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.pack_mechanisms import mech_gcm
from pkcs11_check.raw.recipes import decrypt_single, destroy_quietly, encrypt_single, sign_single
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_GMAC,
    CKR_AEAD_DECRYPT_FAILED,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)
from pkcs11_check.testcases._operability import Operability, OperabilityResult, probe_operability
from pkcs11_check.testcases.acvp.acvp_loader import load_acvp_vectors, require_acvp_vectors
from pkcs11_check.testcases.acvp.aes.base import (
    CKM_AES_GCM_SIV,
    _import_aes_key,
    _load_vectors,
    run_gcm_decrypt_test,
    run_gcm_encrypt_test,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    assert_correct,
    import_secret_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

require_acvp_vectors()

_GCM_SIV_DATA_REJECT_RVS = (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_AEAD_DECRYPT_FAILED,
)


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


def _gcm_siv_operability(rs: Any) -> OperabilityResult:
    """Probe one valid GCM-SIV decrypt before accepting invalid-vector rejects."""

    def probe() -> OperabilityResult:
        canonical = next(
            (vec for _vec_id, vec in _GCM_SIV_DECRYPT_VECTORS if vec.get("test_passed")),
            None,
        )
        if canonical is None:
            return OperabilityResult(
                Operability.INCONCLUSIVE, "no valid AES-GCM-SIV decrypt vector available"
            )

        param = mech_gcm(CKM_AES_GCM_SIV, canonical["iv"], aad=canonical.get("aad"), tag_bits=128)
        key = 0
        try:
            try:
                key = _import_aes_key(rs, canonical["key"], decrypt=True)
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL,
                    f"canonical AES-GCM-SIV key import rejected: {exc}",
                )
            try:
                plaintext = decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM_SIV,
                    canonical["ct"] + canonical["tag"],
                    mech_param=param,
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL,
                    f"canonical AES-GCM-SIV decrypt rejected: {exc}",
                )
            if plaintext != canonical["pt_expected"]:
                return OperabilityResult(
                    Operability.WRONG_OUTPUT,
                    "canonical AES-GCM-SIV decrypt output mismatch",
                )
            return OperabilityResult(Operability.OPERATIONAL, "canonical AES-GCM-SIV decrypt OK")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    return probe_operability("AES_GCM_SIV:decrypt", probe)


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
    param = mech_gcm(CKM_AES_GCM_SIV, vec["iv"], aad=vec.get("aad"), tag_bits=128)
    key = 0
    try:
        try:
            key = _import_aes_key(rs, vec["key"], encrypt=True)
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                KEYPAIR_RUNTIME_REJECT_RVS,
                "AES_GCM_SIV advertised but key import is not operational",
            )
            raise
        try:
            result = encrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM_SIV, vec["pt"], mech_param=param
            )
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                CIPHER_OP_RUNTIME_REJECT_RVS,
                "AES_GCM_SIV advertised but encrypt is not operational",
            )
            raise
        ct_got, tag_got = result[:-16], result[-16:]
        assert_correct(
            actual=ct_got,
            expected=vec["ct_expected"],
            label=f"AES-GCM-SIV:C_Encrypt KAT {vec_id} (ciphertext)",
            operation="C_Encrypt",
            mechanism="CKM_AES_GCM_SIV",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
        assert_correct(
            actual=tag_got,
            expected=vec["tag_expected"],
            label=f"AES-GCM-SIV:C_Encrypt KAT {vec_id} (tag)",
            operation="C_Encrypt",
            mechanism="CKM_AES_GCM_SIV",
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
    param = mech_gcm(CKM_AES_GCM_SIV, vec["iv"], aad=vec.get("aad"), tag_bits=128)
    key = 0
    try:
        try:
            key = _import_aes_key(rs, vec["key"], decrypt=True)
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                KEYPAIR_RUNTIME_REJECT_RVS,
                "AES_GCM_SIV advertised but key import is not operational",
            )
            raise
        try:
            pt = decrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM_SIV, vec["ct"] + vec["tag"], mech_param=param
            )
        except CkrAssertionError as exc:
            if not vec["test_passed"] and is_known_error(exc, _GCM_SIV_DATA_REJECT_RVS):
                operability = _gcm_siv_operability(rs)
                if operability.status is Operability.NOT_OPERATIONAL:
                    xfail_as(
                        "not_operational",
                        kind="crypto",
                        label="AES_GCM_SIV:decrypt",
                        summary=(
                            "AES_GCM_SIV invalid-vector rejection was vacuous: "
                            f"{operability.detail}"
                        ),
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                if operability.status is Operability.INCONCLUSIVE:
                    xfail_as(
                        "not_operational",
                        kind="crypto",
                        label="AES_GCM_SIV:decrypt",
                        summary=(
                            "AES_GCM_SIV invalid-vector rejection could not be validated: "
                            f"{operability.detail}"
                        ),
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                if operability.status is Operability.WRONG_OUTPUT:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="AES_GCM_SIV:decrypt",
                        summary=(
                            "AES_GCM_SIV canonical valid decrypt produced wrong output: "
                            f"{operability.detail}"
                        ),
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                return
            xfail_if_known_ckr(
                exc,
                CIPHER_OP_RUNTIME_REJECT_RVS,
                "AES_GCM_SIV advertised but decrypt is not operational",
            )
            raise
        if vec["test_passed"]:
            assert_correct(
                actual=pt,
                expected=vec["pt_expected"],
                label=f"AES-GCM-SIV:C_Decrypt KAT {vec_id}",
                operation="C_Decrypt",
                mechanism="CKM_AES_GCM_SIV",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        else:
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label="AES_GCM_SIV:decrypt",
                summary=(
                    f"{vec_id}: decrypted an invalid GCM-SIV vector "
                    "(forged ciphertext/tag accepted)"
                ),
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
    encrypt_fields = {
        "key": "key",
        "iv": "iv",
        "aad": "aad",
        "tag_expected": ("tag", lambda x: bytes.fromhex(x) if x else b""),
    }
    encrypt_vecs, _ = _load_vectors(
        "ACVP-AES-GMAC-1.0",
        encrypt_fields,  # type: ignore[arg-type]
        {},
        extra_group_fields={"tag_len_bits": "tagLen"},
    )
    return encrypt_vecs


_GMAC_VECTORS: list[tuple[str, dict[str, Any]]] = _load_gmac_vectors()


@pytest.mark.parametrize("vec_id,vec", _GMAC_VECTORS, ids=[v[0] for v in _GMAC_VECTORS])
def test_acvp_aes_gmac(
    p11_module_session: Any,
    p11_interface_version: str,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """AES-GMAC authentication tag generation from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_GMAC"):
        pytest.skip("AES_GMAC not supported")
    set_params({"aes_bits": str(len(vec.get("key") or b"") * 8)})
    set_mechanism("AES_GMAC", operation="C_Sign", expect_success=True)
    gmac_param = (
        mech_bytes(CKM_AES_GMAC, vec["iv"])
        if p11_interface_version == "2.40"
        else mech_gcm(CKM_AES_GMAC, vec["iv"], aad=None, tag_bits=vec["tag_len_bits"])
    )
    key = 0
    try:
        try:
            key = import_secret_key_negotiated(
                rs,
                int(CKK_AES),
                vec["key"],
                attrs={CKA_SIGN: True, CKA_TOKEN: False, CKA_SENSITIVE: False},
                purpose="ACVP AES-GMAC key import",
            )
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                KEYPAIR_RUNTIME_REJECT_RVS,
                "AES_GMAC advertised but key import is not operational",
            )
            raise
        try:
            result = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GMAC,
                vec.get("aad") or b"",
                mech_param=gmac_param,
            )
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                CIPHER_OP_RUNTIME_REJECT_RVS,
                "AES_GMAC advertised but generate-tag is not operational",
            )
            raise
        assert_correct(
            actual=result,
            expected=vec["tag_expected"],
            label=f"AES-GMAC:C_Sign KAT {vec_id} (tag)",
            operation="C_Sign",
            mechanism="CKM_AES_GMAC",
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
