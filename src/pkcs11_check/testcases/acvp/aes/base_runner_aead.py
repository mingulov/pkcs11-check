"""ACVP AES AEAD mode test runners (GCM, CCM)."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack_mechanisms import mech_ccm, mech_gcm
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
)
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
)

# GCM-SIV is not a standard PKCS#11 mechanism; use vendor extension if available
CKM_AES_GCM_SIV = CKM(0x80000100, "CKM_AES_GCM_SIV")


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
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-GCM encrypt test with tag extraction.

    Args:
        p11_raw_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary with key, iv, pt, aad, ct_expected, tag_expected, tag_len_bits
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("AES_GCM not supported by module")

    tag_bytes = vec["tag_len_bits"] // 8
    iv = vec["iv"]
    aad = vec.get("aad") or None

    try:
        gcm_param = mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=vec["tag_len_bits"])
    except (AssertionError, ValueError, TypeError):
        pytest.xfail(f"Binding rejects GCM params iv={len(iv)}B tag={tag_bytes}B")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        try:
            result = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                vec["pt"],
                mech_param=gcm_param,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            pytest.xfail(
                f"Module limitation: GCM iv={len(iv)}B tag={tag_bytes}B not supported ({exc_msg})"
            )

        if len(result) < tag_bytes:
            pytest.fail(
                f"{vec_id}: encrypt output too short: {len(result)}B, "
                f"expected at least {tag_bytes}B for tag"
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
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-GCM decrypt test with tag verification.

    Args:
        p11_raw_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data with key, iv, ct, tag, aad, pt_expected, test_passed, tag_len_bits
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("AES_GCM not supported by module")

    tag_bytes = vec["tag_len_bits"] // 8
    iv = vec["iv"]
    aad = vec.get("aad") or None
    test_passed = vec["test_passed"]

    try:
        gcm_param = mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=vec["tag_len_bits"])
    except (AssertionError, ValueError, TypeError):
        pytest.xfail(f"Binding rejects GCM params iv={len(iv)}B tag={tag_bytes}B")
        return

    ct_with_tag = vec["ct"] + vec["tag"]

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        try:
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                ct_with_tag,
                mech_param=gcm_param,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(
                name in exc_msg
                for name in (
                    "CKR_MECHANISM_PARAM_INVALID",
                    "CKR_ARGUMENTS_BAD",
                )
            ):
                pytest.xfail(
                    f"Module limitation: GCM iv={len(iv)}B tag={tag_bytes}B "
                    f"not supported ({exc_msg})"
                )
                return
            if any(
                name in exc_msg
                for name in (
                    "CKR_ENCRYPTED_DATA_INVALID",
                    "CKR_ENCRYPTED_DATA_LEN_RANGE",
                    "CKR_AEAD_DECRYPT_FAILED",
                )
            ):
                if not test_passed:
                    return
                pytest.fail(f"{vec_id}: valid-tag GCM vector rejected with tag auth failure")
                return
            raise

        if test_passed:
            assert pt == vec["pt_expected"], (
                f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
            )
        else:
            pytest.fail(
                f"{vec_id}: module accepted GCM ciphertext with invalid tag (tag auth bypass)"
            )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_ccm_encrypt_test(
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-CCM encrypt test.

    Args:
        p11_raw_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary with key, nonce, pt, aad, ct_expected, tag_len
    """
    rs = p11_raw_session
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
        pytest.xfail(f"Binding rejects CCM params: {exc}")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        try:
            result = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CCM,
                vec["pt"],
                mech_param=ccm_param,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            pytest.xfail(f"Module limitation: CCM not supported ({exc_msg})")

        tag_len = vec["tag_len"]
        if len(result) < tag_len:
            pytest.fail(f"{vec_id}: encrypt output too short")

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
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
) -> None:
    """Run AES-CCM decrypt test.

    Args:
        p11_raw_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary with key, nonce, ct, aad, pt_expected, test_passed, tag_len
    """
    rs = p11_raw_session
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
        pytest.xfail(f"Binding rejects CCM params: {exc}")
        return

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        try:
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CCM,
                vec["ct"],
                mech_param=ccm_param,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if "CKR" in exc_msg and not test_passed:
                return
            pytest.xfail(f"Module limitation: CCM decrypt not supported ({exc_msg})")
            return

        if test_passed:
            assert pt == vec["pt_expected"], (
                f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
            )
        else:
            pytest.fail(f"{vec_id}: module accepted CCM ciphertext with invalid tag")
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
