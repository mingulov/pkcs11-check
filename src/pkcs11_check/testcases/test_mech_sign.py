"""Mechanism-driven sign/verify tests.

Parametrized by mech_sign_entry — tests every sign mechanism advertised by the
module that also has a registry config.

Key types covered:
- HMAC (SHA-1/224/256/384/512, SHA3, BLAKE2b, RIPEMD): generic secret key
- AES-MAC / AES-CMAC / AES-GMAC: AES key
- RSA-PKCS, RSA-PSS, RSA-X9.31, SHA*-RSA-PKCS, SHA*-RSA-PKCS-PSS: RSA keypair
- ECDSA, ECDSA-SHA*, EdDSA: EC keypair
- ML-DSA, SLH-DSA: PQC keypair
- DSA/GOSTR/KEA: require domain parameters — skipped

The tampered-data test verifies that C_Verify returns False (CKR_SIGNATURE_INVALID
or CKR_SIGNATURE_LEN_RANGE) when the data does not match the signature.
"""
from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import destroy_quietly, pack_attrs, sign_single, verify_single
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_SEED,
    CKM,
    CKM_AES_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKR_OK,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig
from pkcs11_check.testcases.test_mech_keygen import (
    _gen_keypair,
    _needs_domain_params,
    _pick_key_size,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.sign]

# Fixed-length key types: must not set CKA_VALUE_LEN
_FIXED_LENGTH_KEY_TYPES: set[int] = {
    int(CKK_DES), int(CKK_DES2), int(CKK_DES3), int(CKK_SEED)
}


def _make_sign_mech_param(entry: MechEntry, config: MechConfig) -> Any:
    """Create mechanism parameter for sign/verify, or None for no-param mechanisms.

    Returns None for mechanisms that take no parameters.
    Skips for param recipes that need runtime data.
    """
    from pkcs11_check.testcases.mechanism_helpers import build_test_params

    if not config.param_required:
        return None

    result = build_test_params(entry.mech_id, config.param_recipe)
    if result == "SKIP":
        pytest.skip(
            f"{entry.mech_name}: param recipe '{config.param_recipe.style}' needs runtime data"
        )
    return result


def _generate_key_for_sign(
    rs: RawSession,
    entry: MechEntry,
    config: MechConfig,
) -> tuple[int, int | None]:
    """Generate key(s) for sign/verify.

    Returns (sign_key, verify_key).
    For symmetric: same handle; verify_key is None.
    For asymmetric: (priv_handle, pub_handle).
    """
    if config.key_type is None:
        pytest.skip(f"{entry.mech_name}: no key_type in registry config")

    if _needs_domain_params(config):
        pytest.skip(
            f"{entry.mech_name}: requires external domain parameters (DSA/DH/GOSTR/KEA)"
        )

    if config.is_keypair:
        pub, priv = _gen_keypair(rs, entry, config)
        return priv, pub  # sign with private, verify with public

    # Symmetric: use keygen_mech from config
    keygen = config.keygen_mech
    if keygen is None:
        kt = int(config.key_type)
        if kt == int(CKK_AES):
            keygen = int(CKM_AES_KEY_GEN)
        else:
            # HMAC and similar: use generic secret key gen
            keygen = int(CKM_GENERIC_SECRET_KEY_GEN)

    kt = int(config.key_type)
    is_fixed = kt in _FIXED_LENGTH_KEY_TYPES

    attrs: dict[int, Any] = {
        CKA_SIGN: True,
        CKA_VERIFY: True,
        CKA_TOKEN: False,
        CKA_KEY_TYPE: config.key_type,
    }
    packed = []
    key_size = _pick_key_size(entry, config)
    if not is_fixed:
        if key_size is None:
            # For HMAC with no key_sizes, use a sensible default (32 bytes)
            key_size = 256
        packed.append(attr_ulong(CKA_VALUE_LEN, key_size // 8))
        packed.extend(pack_attrs(attrs, skip={CKA_VALUE_LEN}))
    else:
        packed.extend(pack_attrs(attrs))

    tmpl = template(*packed)
    mech = mech_simple(CKM(keygen))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKey(  # type: ignore[attr-defined]
        rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(handle)
    )
    assert rv == CKR_OK, f"C_GenerateKey failed: {rv} for {entry.mech_name}"
    return handle.value, None


class TestMechSignRoundtrip:
    """Sign then verify roundtrip for every advertised sign mechanism."""

    def test_roundtrip(self, p11_raw_session: RawSession, mech_sign_entry: MechEntry) -> None:
        """Sign data then verify — must return True."""
        rs = p11_raw_session
        entry = mech_sign_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        sign_key, verify_key = _generate_key_for_sign(rs, entry, config)
        verify_key_handle = verify_key if verify_key is not None else sign_key

        try:
            data = b"hello pkcs11 sign test" * 2
            mech_param = _make_sign_mech_param(entry, config)

            sig = sign_single(
                rs.raw, rs.sh, sign_key, CKM(entry.mech_id), data, mech_param=mech_param
            )
            ok = verify_single(
                rs.raw,
                rs.sh,
                verify_key_handle,
                CKM(entry.mech_id),
                data,
                sig,
                mech_param=mech_param,
            )
            assert ok, (
                f"{entry.mech_name}: verify failed after valid sign "
                f"(sig={sig.hex()!r})"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    def test_tampered_data_fails_verify(
        self, p11_raw_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Sign data A, verify with data B — must return False."""
        rs = p11_raw_session
        entry = mech_sign_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        sign_key, verify_key = _generate_key_for_sign(rs, entry, config)
        verify_key_handle = verify_key if verify_key is not None else sign_key

        try:
            data_a = b"original data for signing"
            data_b = b"tampered data XXXXXXXXXXX"
            mech_param = _make_sign_mech_param(entry, config)

            sig = sign_single(
                rs.raw, rs.sh, sign_key, CKM(entry.mech_id), data_a, mech_param=mech_param
            )
            ok = verify_single(
                rs.raw,
                rs.sh,
                verify_key_handle,
                CKM(entry.mech_id),
                data_b,
                sig,
                mech_param=mech_param,
            )
            assert not ok, (
                f"{entry.mech_name}: verify should have failed for tampered data "
                f"but returned True (sig={sig.hex()!r})"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None:
                destroy_quietly(rs.raw, rs.sh, verify_key)
