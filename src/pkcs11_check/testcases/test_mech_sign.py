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

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.recipes import destroy_quietly, sign_single, verify_single
from pkcs11_check.raw.types_std import (
    CKM,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    generate_key_for_sign,
    make_mech_param_or_skip,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.sign]


class TestMechSignRoundtrip:
    """Sign then verify roundtrip for every advertised sign mechanism."""

    def test_roundtrip(self, p11_raw_session: RawSession, mech_sign_entry: MechEntry) -> None:
        """Sign data then verify — must return True."""
        rs = p11_raw_session
        entry = mech_sign_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        sign_key, verify_key = generate_key_for_sign(rs, entry, config)
        verify_key_handle = verify_key if verify_key is not None else sign_key

        try:
            data = b"hello pkcs11 sign test" * 2
            mech_param = make_mech_param_or_skip(entry)

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

        sign_key, verify_key = generate_key_for_sign(rs, entry, config)
        verify_key_handle = verify_key if verify_key is not None else sign_key

        try:
            data_a = b"original data for signing"
            data_b = b"tampered data XXXXXXXXXXX"
            mech_param = make_mech_param_or_skip(entry)

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
