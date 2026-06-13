"""ACVP AES AEAD mode test runners (GCM, CCM)."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.pack_mechanisms import mech_ccm, mech_gcm
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_WRAP,
    CKK_AES,
    CKM,
    CKM_AES_CCM,
    CKM_AES_GCM,
    CKR_AEAD_DECRYPT_FAILED,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    classify_kat_clean_error,
    probe_operability,
    xfail_vacuous_reject,
)
from pkcs11_check.testcases.conftest import is_known_error

# GCM-SIV is not a standard PKCS#11 mechanism; use vendor extension if available
CKM_AES_GCM_SIV = CKM(0x80000100, "CKM_AES_GCM_SIV")

# Clean codes a module may use to reject AEAD ciphertext whose tag does not
# authenticate -- the expected PASS for invalid-tag vectors. On a VALID-tag
# vector they are only a tag-auth finding if canonical decrypt works.
_GCM_DATA_REJECTS = (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_AEAD_DECRYPT_FAILED,
)
# kryoptic reports tag-auth failure as CKR_DEVICE_ERROR (its OpenSSL-failure
# fallback) -- accepted as an invalid-tag rejection for CCM, as before.
_CCM_DATA_REJECTS = _GCM_DATA_REJECTS + (CKR_DEVICE_ERROR,)

# --- Canonical operability probe (triage H2) ---------------------------------
# One canonical known-answer operation per (mechanism, direction) per process
# decides how clean vector errors classify (see testcases/_operability.py).
# Expected outputs are derived from `cryptography`, so canonical truth is
# spec-derived, not provider-derived.
PROBE_KEY = bytes(range(16))
PROBE_PT = bytes(range(24))
PROBE_GCM_IV = bytes(range(12))
PROBE_CCM_NONCE = bytes(range(13))


def _probe_expected_ct(mech_name: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM

    if mech_name == "AES_GCM":
        return AESGCM(PROBE_KEY).encrypt(PROBE_GCM_IV, PROBE_PT, None)
    return AESCCM(PROBE_KEY, tag_length=16).encrypt(PROBE_CCM_NONCE, PROBE_PT, None)


def _canonical_aead_probe(rs: Any, mech_name: str, direction: str) -> OperabilityResult:
    mech = CKM_AES_GCM if mech_name == "AES_GCM" else CKM_AES_CCM
    try:
        if mech_name == "AES_GCM":
            param = mech_gcm(CKM_AES_GCM, PROBE_GCM_IV, aad=None, tag_bits=128)
        else:
            param = mech_ccm(
                CKM_AES_CCM, PROBE_CCM_NONCE, data_len=len(PROBE_PT), aad=None, mac_len=16
            )
        expected_ct = _probe_expected_ct(mech_name)
    except (AssertionError, ValueError, TypeError) as exc:
        return OperabilityResult(
            Operability.INCONCLUSIVE, f"canonical {mech_name} staging failed: {exc}"
        )
    key = 0
    try:
        try:
            key = _import_aes_key(rs, PROBE_KEY, encrypt=True, decrypt=True)
        except CkrAssertionError as exc:
            return OperabilityResult(
                Operability.INCONCLUSIVE, f"canonical {mech_name} key import failed: {exc}"
            )
        try:
            if direction == "encrypt":
                overhead = 16 if mech_name == "AES_GCM" else 0
                got = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    mech,
                    PROBE_PT,
                    mech_param=param,
                    output_overhead=overhead,
                )
                want = expected_ct
            else:
                got = decrypt_single(rs.raw, rs.sh, key, mech, expected_ct, mech_param=param)
                want = PROBE_PT
        except CkrAssertionError as exc:
            return OperabilityResult(
                Operability.NOT_OPERATIONAL,
                f"canonical {mech_name} {direction} rejected: {exc}",
            )
        if got != want:
            return OperabilityResult(
                Operability.WRONG_OUTPUT,
                f"canonical {mech_name} {direction} output mismatch: "
                f"got {got.hex()}, want {want.hex()}",
            )
        return OperabilityResult(Operability.OPERATIONAL, f"canonical {mech_name} {direction} OK")
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def _aead_operability(rs: Any, mech_name: str, direction: str) -> OperabilityResult:
    return probe_operability(
        f"{mech_name}:{direction}", lambda: _canonical_aead_probe(rs, mech_name, direction)
    )


def _import_aes_key(
    rs: Any,
    key_bytes: bytes,
    *,
    encrypt: bool = True,
    decrypt: bool = True,
    wrap: bool = False,
    unwrap: bool = False,
) -> int:
    """Import a raw AES key into the session as a session object."""
    attrs: dict[Any, bool] = {
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
    }
    if encrypt:
        attrs[CKA_ENCRYPT] = True
    if decrypt:
        attrs[CKA_DECRYPT] = True
    if wrap:
        attrs[CKA_WRAP] = True
    if unwrap:
        attrs[CKA_UNWRAP] = True
    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_AES,
        key_bytes,
        attrs=attrs,
    )


def run_gcm_encrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-GCM encrypt test with tag extraction.

    Args:
        p11_module_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary with key, iv, pt, aad, ct_expected, tag_expected, tag_len_bits
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("AES_GCM not supported by module")

    tag_bytes = vec["tag_len_bits"] // 8
    iv = vec.get("extended_nonce", vec["iv"])
    aad = vec.get("aad") or None

    try:
        gcm_param = mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=vec["tag_len_bits"])
    except (AssertionError, ValueError, TypeError):
        xfail_as(
            "not_operational",
            kind="crypto",
            label="AES_GCM:encrypt",
            summary=f"Binding rejects GCM params iv={len(iv)}B tag={tag_bytes}B",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    key = 0
    try:
        try:
            key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
            result = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                vec["pt"],
                mech_param=gcm_param,
                output_overhead=tag_bytes,
            )
        except AssertionError as exc:
            classify_kat_clean_error(
                exc,
                result=_aead_operability(rs, "AES_GCM", "encrypt"),
                label=f"AES_GCM encrypt iv={len(iv)}B tag={tag_bytes}B",
            )

        if len(result) < tag_bytes:
            fail_as(
                "self_contradiction",
                kind="crypto",
                label="AES_GCM:encrypt",
                summary=(
                    f"{vec_id}: encrypt output too short: {len(result)}B, "
                    f"expected at least {tag_bytes}B for tag"
                ),
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        ct_got = result[: len(result) - tag_bytes]
        tag_got = result[len(result) - tag_bytes :]

        assert ct_got == vec["ct_expected"], (
            f"{vec_id}: ciphertext mismatch: got {ct_got.hex()}, "
            f"expected {vec['ct_expected'].hex()}"
        )
        assert tag_got == vec["tag_expected"], (
            f"{vec_id}: tag mismatch: got {tag_got.hex()}, expected {vec['tag_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_gcm_decrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-GCM decrypt test with tag verification.

    Args:
        p11_module_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data with key, iv, ct, tag, aad, pt_expected, test_passed, tag_len_bits
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("AES_GCM not supported by module")

    tag_bytes = vec["tag_len_bits"] // 8
    iv = vec.get("extended_nonce", vec["iv"])
    aad = vec.get("aad") or None
    test_passed = vec["test_passed"]

    try:
        gcm_param = mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=vec["tag_len_bits"])
    except (AssertionError, ValueError, TypeError):
        xfail_as(
            "not_operational",
            kind="crypto",
            label="AES_GCM:decrypt",
            summary=f"Binding rejects GCM params iv={len(iv)}B tag={tag_bytes}B",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    ct_with_tag = vec["ct"] + vec["tag"]

    key = 0
    try:
        try:
            key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                ct_with_tag,
                mech_param=gcm_param,
            )
        except AssertionError as exc:
            if is_known_error(exc, _GCM_DATA_REJECTS):
                if not test_passed:
                    xfail_vacuous_reject(
                        _aead_operability(rs, "AES_GCM", "decrypt"),
                        label=f"{vec_id}: AES_GCM decrypt invalid-tag reject",
                    )
                    return
                result = _aead_operability(rs, "AES_GCM", "decrypt")
                if result.status is Operability.NOT_OPERATIONAL:
                    xfail_as(
                        "not_operational",
                        kind="crypto",
                        label="AES_GCM:decrypt",
                        summary=(
                            f"AES_GCM advertised but decrypt is not operational "
                            f"({result.detail}); vector: {exc}"
                        ),
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="AES_GCM:decrypt",
                    summary=(
                        f"{vec_id}: valid-tag GCM vector rejected with tag auth failure ({exc})"
                    ),
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            classify_kat_clean_error(
                exc,
                result=_aead_operability(rs, "AES_GCM", "decrypt"),
                label=f"AES_GCM decrypt iv={len(iv)}B tag={tag_bytes}B",
            )

        if test_passed:
            assert pt == vec["pt_expected"], (
                f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
            )
        else:
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label="AES_GCM:decrypt",
                summary=(
                    f"{vec_id}: module accepted GCM ciphertext with invalid tag (tag auth bypass)"
                ),
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_ccm_encrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-CCM encrypt test.

    Args:
        p11_module_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary with key, nonce, pt, aad, ct_expected, tag_len
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_CCM"):
        pytest.skip("AES_CCM not supported by module")

    nonce = vec["nonce"]
    aad = vec.get("aad") or None

    try:
        ccm_param = mech_ccm(
            CKM_AES_CCM,
            nonce,
            data_len=len(vec["pt"]),
            aad=aad,
            mac_len=vec["tag_len"],
        )
    except (AssertionError, ValueError, TypeError) as exc:
        xfail_as(
            "not_operational",
            kind="crypto",
            label="AES_CCM:encrypt",
            summary=f"Binding rejects CCM params: {exc}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    key = 0
    try:
        try:
            key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
            result = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CCM,
                vec["pt"],
                mech_param=ccm_param,
            )
        except AssertionError as exc:
            classify_kat_clean_error(
                exc,
                result=_aead_operability(rs, "AES_CCM", "encrypt"),
                label=f"AES_CCM encrypt nonce={len(nonce)}B tag={vec['tag_len']}B",
            )

        tag_len = vec["tag_len"]
        if len(result) < tag_len:
            fail_as(
                "self_contradiction",
                kind="crypto",
                label="AES_CCM:encrypt",
                summary=f"{vec_id}: encrypt output too short",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        ct_got = result[: len(result) - tag_len]
        tag_got = result[len(result) - tag_len :]
        ct_expected = vec["ct_expected"]

        expected_tag = (
            ct_expected[len(ct_expected) - tag_len :] if len(ct_expected) >= tag_len else b""
        )
        expected_ct = (
            ct_expected[: len(ct_expected) - tag_len]
            if len(ct_expected) >= tag_len
            else ct_expected
        )

        assert ct_got == expected_ct, (
            f"{vec_id}: ciphertext mismatch: got {ct_got.hex()}, expected {expected_ct.hex()}"
        )
        if expected_tag:
            assert tag_got == expected_tag, (
                f"{vec_id}: tag mismatch: got {tag_got.hex()}, expected {expected_tag.hex()}"
            )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_ccm_decrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-CCM decrypt test.

    Args:
        p11_module_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary with key, nonce, ct, aad, pt_expected, test_passed, tag_len
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_CCM"):
        pytest.skip("AES_CCM not supported by module")

    nonce = vec["nonce"]
    aad = vec.get("aad") or None
    test_passed = vec["test_passed"]

    try:
        ccm_param = mech_ccm(
            CKM_AES_CCM,
            nonce,
            data_len=len(vec["ct"]) - vec["tag_len"],
            aad=aad,
            mac_len=vec["tag_len"],
        )
    except (AssertionError, ValueError, TypeError) as exc:
        xfail_as(
            "not_operational",
            kind="crypto",
            label="AES_CCM:decrypt",
            summary=f"Binding rejects CCM params: {exc}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    key = 0
    try:
        try:
            key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CCM,
                vec["ct"],
                mech_param=ccm_param,
            )
        except AssertionError as exc:
            if is_known_error(exc, _CCM_DATA_REJECTS):
                if not test_passed:
                    xfail_vacuous_reject(
                        _aead_operability(rs, "AES_CCM", "decrypt"),
                        label=f"{vec_id}: AES_CCM decrypt invalid-tag reject",
                    )
                    return  # Expected: module rejected invalid-tag ciphertext
                result = _aead_operability(rs, "AES_CCM", "decrypt")
                if result.status is Operability.NOT_OPERATIONAL:
                    xfail_as(
                        "not_operational",
                        kind="crypto",
                        label="AES_CCM:decrypt",
                        summary=(
                            f"AES_CCM advertised but decrypt is not operational "
                            f"({result.detail}); vector: {exc}"
                        ),
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="AES_CCM:decrypt",
                    summary=(
                        f"{vec_id}: valid-tag CCM vector rejected with tag auth failure ({exc})"
                    ),
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            classify_kat_clean_error(
                exc,
                result=_aead_operability(rs, "AES_CCM", "decrypt"),
                label=f"AES_CCM decrypt nonce={len(nonce)}B tag={vec['tag_len']}B",
            )

        if test_passed:
            assert pt == vec["pt_expected"], (
                f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
            )
        else:
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label="AES_CCM:decrypt",
                summary=f"{vec_id}: module accepted CCM ciphertext with invalid tag",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
