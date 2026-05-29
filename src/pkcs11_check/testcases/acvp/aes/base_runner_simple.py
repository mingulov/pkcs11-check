"""ACVP AES simple mode test runners (CFB, OFB)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes
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
    CKM_AES_CFB8,
    CKM_AES_OFB,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import is_known_error

_AES_RUNTIME_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _cfb1_mask(data: bytes, payload_len_bits: int) -> bytes:
    """Mask a byte string to keep only the top *payload_len_bits* bits.

    PKCS#11 CKM_AES_CFB1 processes full bytes (8 CFB1 operations per byte),
    but ACVP vectors may specify fewer significant bits via payloadLen.
    Mask the output so only the significant bits are compared.
    """
    n_bytes = (payload_len_bits + 7) // 8
    result = bytearray(n_bytes)
    for i in range(min(payload_len_bits, len(data) * 8)):
        byte_idx = i // 8
        bit_idx = 7 - (i % 8)
        if byte_idx < len(data) and (data[byte_idx] & (1 << bit_idx)):
            result[byte_idx] |= 1 << bit_idx
    return bytes(result)


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


def run_simple_encrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run a simple encrypt test for CFB/OFB modes.

    Args:
        p11_module_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary
        mech_name: Mechanism name for has_mechanism check (e.g., "AES_CFB128")
        mech_constant: CKM constant for the mechanism
        mech_param_func: Optional function to create mechanism parameter
    """
    rs = p11_module_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        try:
            if mech_param_func:
                mech = mech_param_func()
            else:
                mech = mech_bytes(mech_constant, vec["iv"])
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                mech_constant,
                vec["pt"],
                mech_param=mech,
                # CFB/OFB: ciphertext length == plaintext length, so skip the
                # NULL-buffer size query (one fewer round-trip per op on
                # transport-bound modules). retry recovers if a module disagrees.
                output_size_hint=len(vec["pt"]),
                retry_on_buffer_too_small=True,
            )
        except AssertionError as exc:
            if is_known_error(exc, _AES_RUNTIME_REJECT_RVS):
                pytest.xfail(f"{mech_name} advertised but encrypt is not operational: {exc}")
            raise

        expected = vec["ct_expected"]
        payload_bits = vec.get("payload_len_bits")
        if payload_bits is not None and payload_bits % 8 != 0:
            ct = _cfb1_mask(ct, payload_bits)
            expected = _cfb1_mask(expected, payload_bits)
        assert ct == expected, (
            f"{vec_id}: ciphertext mismatch: got {ct.hex()}, expected {expected.hex()}"
            + (f" (payloadLen={payload_bits} bits)" if payload_bits is not None else "")
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_simple_decrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run a simple decrypt test for CFB/OFB modes.

    Args:
        p11_module_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary
        mech_name: Mechanism name for has_mechanism check
        mech_constant: CKM constant for the mechanism
        mech_param_func: Optional function to create mechanism parameter
    """
    rs = p11_module_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        try:
            if mech_param_func:
                mech = mech_param_func()
            else:
                mech = mech_bytes(mech_constant, vec["iv"])
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                mech_constant,
                vec["ct"],
                mech_param=mech,
                # CFB/OFB: plaintext length == ciphertext length (see encrypt).
                output_size_hint=len(vec["ct"]),
                retry_on_buffer_too_small=True,
            )
        except AssertionError as exc:
            if is_known_error(exc, _AES_RUNTIME_REJECT_RVS):
                pytest.xfail(f"{mech_name} advertised but decrypt is not operational: {exc}")
            raise

        expected = vec["pt_expected"]
        payload_bits = vec.get("payload_len_bits")
        if payload_bits is not None and payload_bits % 8 != 0:
            pt = _cfb1_mask(pt, payload_bits)
            expected = _cfb1_mask(expected, payload_bits)
        assert pt == expected, (
            f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {expected.hex()}"
            + (f" (payloadLen={payload_bits} bits)" if payload_bits is not None else "")
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


_MCT_ITERATIONS = 1000


def _mct_next_iv(
    mech_constant: CKM,
    iv: bytes,
    ct: bytes,
    pt: bytes,
) -> bytes:
    """Compute the IV for the next independent MCT call.

    * CFB128/CFB8: shift register = previous ciphertext output.
      For CFB128 this is the full 16-byte ct.
      For CFB8 the 16-byte register shifts left by 1 byte; ct is appended.
    * OFB: keystream output = ct XOR pt; this becomes the next IV.
    """
    if mech_constant == CKM_AES_OFB:
        return bytes(a ^ b for a, b in zip(ct, pt))
    if mech_constant == CKM_AES_CFB8:
        return iv[1:] + ct  # shift register: drop first byte, append ct
    # CFB128 (and any other mode): IV = ciphertext output
    return ct


def _mct_enc_next_input(
    mech_constant: CKM,
    j: int,
    initial_iv: bytes,
    output_history: list[bytes],
) -> bytes:
    """Compute the next plaintext for MCT encrypt (per ACVP spec).

    CFB128/OFB: PT[1]=IV, PT[j>=2]=CT[j-2].
    CFB8: PT[1..16]=IV[0..15] (one byte each), PT[j>16]=CT[j-17].
    """
    if mech_constant == CKM_AES_CFB8:
        if j <= 16:
            return initial_iv[j - 1 : j]
        return output_history[j - 17]
    # CFB128, OFB
    if j == 1:
        return initial_iv
    return output_history[j - 2]


def _mct_dec_next_input(
    mech_constant: CKM,
    j: int,
    initial_iv: bytes,
    output_history: list[bytes],
) -> bytes:
    """Compute the next ciphertext for MCT decrypt (PT<->CT swap)."""
    if mech_constant == CKM_AES_CFB8:
        if j <= 16:
            return initial_iv[j - 1 : j]
        return output_history[j - 17]
    if j == 1:
        return initial_iv
    return output_history[j - 2]


def run_multiblock_encrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run ACVP MCT encryption test (1000 iterations per block).

    Each MCT ``resultsArray`` entry has a unique key/IV and records the
    final ciphertext after 1000 inner encrypt-with-feedback iterations.
    The feedback pattern is mode-specific (see ACVP spec Sec.4).
    """
    rs = p11_module_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    blocks = vec.get("blocks", [])
    if not blocks:
        pytest.fail(f"{vec_id}: No blocks found in multi-block test")

    for block in blocks:
        key_handle = 0
        try:
            key_handle = _import_aes_key(
                rs,
                block["key"],
                encrypt=True,
                decrypt=False,
            )
            initial_iv = block["iv"]
            iv = initial_iv
            pt = block["pt"]
            ct_history: list[bytes] = []

            for j in range(_MCT_ITERATIONS):
                if mech_param_func:
                    mech = mech_param_func()
                else:
                    mech = mech_bytes(mech_constant, iv)
                try:
                    ct = encrypt_single(
                        rs.raw,
                        rs.sh,
                        key_handle,
                        mech_constant,
                        pt,
                        mech_param=mech,
                        # MCT inner loop is the hot path: ~100k chained ops, each
                        # a fresh init+encrypt. CFB/OFB ct len == pt len, so skip
                        # the size-query round-trip; retry recovers a bad guess.
                        output_size_hint=len(pt),
                        retry_on_buffer_too_small=True,
                    )
                except AssertionError as exc:
                    if is_known_error(exc, _AES_RUNTIME_REJECT_RVS):
                        pytest.xfail(
                            f"{mech_name} advertised but MCT encrypt is not operational: {exc}"
                        )
                    raise
                ct_history.append(ct)
                iv = _mct_next_iv(mech_constant, iv, ct, pt)
                if j + 1 < _MCT_ITERATIONS:
                    pt = _mct_enc_next_input(
                        mech_constant,
                        j + 1,
                        initial_iv,
                        ct_history,
                    )

            assert ct == block["ct_expected"], (
                f"{vec_id}: block {block['block_index']} ciphertext mismatch "
                f"after {_MCT_ITERATIONS} MCT iterations: "
                f"got {ct.hex()}, expected {block['ct_expected'].hex()}"
            )
        finally:
            if key_handle:
                destroy_quietly(rs.raw, rs.sh, key_handle)


def run_multiblock_decrypt_test(
    p11_module_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run ACVP MCT decryption test (1000 iterations per block).

    Mirrors the encrypt MCT with PT<->CT swapped (per ACVP spec).
    For CFB modes the IV/shift-register tracks the ciphertext input,
    not the plaintext output.
    """
    rs = p11_module_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    blocks = vec.get("blocks", [])
    if not blocks:
        pytest.fail(f"{vec_id}: No blocks found in multi-block test")

    for block in blocks:
        key_handle = 0
        try:
            key_handle = _import_aes_key(
                rs,
                block["key"],
                encrypt=False,
                decrypt=True,
            )
            initial_iv = block["iv"]
            iv = initial_iv
            ct = block["ct"]
            pt_history: list[bytes] = []

            for j in range(_MCT_ITERATIONS):
                if mech_param_func:
                    mech = mech_param_func()
                else:
                    mech = mech_bytes(mech_constant, iv)
                try:
                    pt = decrypt_single(
                        rs.raw,
                        rs.sh,
                        key_handle,
                        mech_constant,
                        ct,
                        mech_param=mech,
                        # MCT inner loop (see encrypt): CFB/OFB pt len == ct len.
                        output_size_hint=len(ct),
                        retry_on_buffer_too_small=True,
                    )
                except AssertionError as exc:
                    if is_known_error(exc, _AES_RUNTIME_REJECT_RVS):
                        pytest.xfail(
                            f"{mech_name} advertised but MCT decrypt is not operational: {exc}"
                        )
                    raise
                pt_history.append(pt)
                # CFB: shift register tracks ct INPUT (not pt output)
                iv = _mct_next_iv(mech_constant, iv, ct, pt)
                if j + 1 < _MCT_ITERATIONS:
                    ct = _mct_dec_next_input(
                        mech_constant,
                        j + 1,
                        initial_iv,
                        pt_history,
                    )

            assert pt == block["pt_expected"], (
                f"{vec_id}: block {block['block_index']} plaintext mismatch "
                f"after {_MCT_ITERATIONS} MCT iterations: "
                f"got {pt.hex()}, expected {block['pt_expected'].hex()}"
            )
        finally:
            if key_handle:
                destroy_quietly(rs.raw, rs.sh, key_handle)
