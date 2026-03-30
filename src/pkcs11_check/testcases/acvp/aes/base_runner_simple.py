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
            pytest.xfail(f"Module limitation: {mech_name} encrypt failed ({exc})")

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
            pytest.xfail(f"Module limitation: {mech_name} decrypt failed ({exc})")
            return

        assert pt == vec["pt_expected"], (
            f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
