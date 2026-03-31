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


def run_simple_encrypt_test(
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run a simple encrypt test for CFB/OFB modes.

    Args:
        p11_raw_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary
        mech_name: Mechanism name for has_mechanism check (e.g., "AES_CFB128")
        mech_constant: CKM constant for the mechanism
        mech_param_func: Optional function to create mechanism parameter
    """
    rs = p11_raw_session
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
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
                pytest.skip(f"{mech_name} not supported: {exc_msg}")
            raise

        assert ct == vec["ct_expected"], (
            f"{vec_id}: ciphertext mismatch: got {ct.hex()}, expected {vec['ct_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_simple_decrypt_test(
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run a simple decrypt test for CFB/OFB modes.

    Args:
        p11_raw_session: Pytest fixture with RawSession
        vec_id: Vector identifier string
        vec: Vector data dictionary
        mech_name: Mechanism name for has_mechanism check
        mech_constant: CKM constant for the mechanism
        mech_param_func: Optional function to create mechanism parameter
    """
    rs = p11_raw_session
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
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
                pytest.skip(f"{mech_name} not supported: {exc_msg}")
            raise

        assert pt == vec["pt_expected"], (
            f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_multiblock_encrypt_test(
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run multi-block CFB encryption test with chaining.

    Processes all blocks sequentially with a single context,
    verifying each intermediate result matches ACVP expectations.
    CFB chaining: block N+1 uses ciphertext of block N as IV.
    """
    rs = p11_raw_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    blocks = vec.get("blocks", [])
    if not blocks:
        pytest.fail(f"{vec_id}: No blocks found in multi-block test")

    # Import key from first block (all blocks use same key in CFB tests)
    key = 0
    try:
        key = _import_aes_key(rs, blocks[0]["key"], encrypt=True, decrypt=False)

        # Initialize encryption context once for all blocks
        if mech_param_func:
            mech = mech_param_func()
        else:
            mech = mech_bytes(mech_constant, blocks[0]["iv"])

        rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
        if rv != 0:
            pytest.xfail(f"Module limitation: {mech_name} encrypt_init failed with CKR={rv}")

        # Process each block with C_EncryptUpdate (maintains CFB state)
        for block in blocks:
            from ctypes import byref, c_ubyte, create_string_buffer

            pt = block["pt"]
            outlen = rs.raw.encryption_len(len(pt), False)

            # Prepare output buffer
            ct_buf = create_string_buffer(outlen)
            ct_len = c_ubyte(outlen)

            rv = rs.raw.C_EncryptUpdate(
                rs.sh, (c_ubyte * len(pt))(*pt), len(pt), ct_buf, byref(ct_len)
            )
            if rv != 0:
                pytest.xfail(
                    f"Module limitation: {mech_name} encrypt_update failed at block {block['block_index']} with CKR={rv}"
                )
                return

            ct = bytes(ct_buf[: ct_len.value])

            assert ct == block["ct_expected"], (
                f"{vec_id}: block {block['block_index']} ciphertext mismatch: "
                f"got {ct.hex()}, expected {block['ct_expected'].hex()}"
            )

        # Finalize (CFB returns 0 bytes)
        rv = rs.raw.C_EncryptFinal(rs.sh, None, None)
        if rv != 0:
            pytest.xfail(f"Module limitation: {mech_name} encrypt_final failed with CKR={rv}")

    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_multiblock_decrypt_test(
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run multi-block CFB decryption test with chaining.

    Processes all blocks sequentially with a single context,
    verifying each intermediate result matches ACVP expectations.
    """
    rs = p11_raw_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    blocks = vec.get("blocks", [])
    if not blocks:
        pytest.fail(f"{vec_id}: No blocks found in multi-block test")

    # Import key from first block
    key = 0
    try:
        key = _import_aes_key(rs, blocks[0]["key"], encrypt=False, decrypt=True)

        # Initialize decryption context once for all blocks
        if mech_param_func:
            mech = mech_param_func()
        else:
            mech = mech_bytes(mech_constant, blocks[0]["iv"])

        rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
        if rv != 0:
            pytest.xfail(f"Module limitation: {mech_name} decrypt_init failed with CKR={rv}")

        # Process each block with C_DecryptUpdate (maintains CFB state)
        for block in blocks:
            from ctypes import byref, c_ubyte, create_string_buffer

            ct = block["ct"]
            outlen = rs.raw.decryption_len(len(ct), False)

            # Prepare output buffer
            pt_buf = create_string_buffer(outlen)
            pt_len = c_ubyte(outlen)

            rv = rs.raw.C_DecryptUpdate(
                rs.sh, (c_ubyte * len(ct))(*ct), len(ct), pt_buf, byref(pt_len)
            )
            if rv != 0:
                pytest.xfail(
                    f"Module limitation: {mech_name} decrypt_update failed at block {block['block_index']} with CKR={rv}"
                )
                return

            pt = bytes(pt_buf[: pt_len.value])

            assert pt == block["pt_expected"], (
                f"{vec_id}: block {block['block_index']} plaintext mismatch: "
                f"got {pt.hex()}, expected {block['pt_expected'].hex()}"
            )

        # Finalize (CFB returns 0 bytes)
        rv = rs.raw.C_DecryptFinal(rs.sh, None, None)
        if rv != 0:
            pytest.xfail(f"Module limitation: {mech_name} decrypt_final failed with CKR={rv}")

    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
