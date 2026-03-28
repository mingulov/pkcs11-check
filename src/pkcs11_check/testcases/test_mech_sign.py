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
from pkcs11_check.raw.recipes import destroy_quietly, import_secret_key, sign_single, verify_single
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKK,
    CKM,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    build_params_from_vector,
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
            assert ok, f"{entry.mech_name}: verify failed after valid sign (sig={sig.hex()!r})"
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


class TestMechSignKAT:
    """Known-answer sign/MAC tests from pre-generated vectors."""

    def test_kat_vector(self, p11_raw_session: RawSession, mech_sign_entry: MechEntry) -> None:
        """Compute MAC with known key and input — verify output matches vector."""
        rs = p11_raw_session
        entry = mech_sign_entry
        config = entry.config
        if config is None or not config.vector_file:
            pytest.skip("No KAT vectors for this mechanism")

        from pkcs11_check.testcases.mechanism_vectors import load_positive_vectors

        vectors = load_positive_vectors(config.vector_file)
        if not vectors:
            pytest.skip(f"No positive vectors in {config.vector_file}")

        for vec in vectors:
            # HMAC vector files may contain multiple mechanisms; filter to this one
            vec_mech = vec.get("mechanism_name")
            if vec_mech and vec_mech != f"CKM_{entry.mech_name}" and vec_mech != entry.mech_name:
                continue
            key_hex = vec.get("key_hex")
            mac_hex = vec.get("mac_hex")
            if not key_hex or not mac_hex:
                continue
            if config.key_type is None:
                continue
            key_bytes = bytes.fromhex(key_hex)
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK(int(config.key_type)),
                key_bytes,
                attrs={CKA_SIGN: True, CKA_TOKEN: False},
            )
            try:
                params = build_params_from_vector(entry.mech_id, config.param_recipe, vec)
                if params == "SKIP":
                    continue
                mac = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM(entry.mech_id),
                    bytes.fromhex(vec["input_hex"]),
                    mech_param=params,
                )
                expected = bytes.fromhex(mac_hex)
                assert mac == expected, (
                    f"KAT MAC mismatch for {vec.get('id', '?')}: "
                    f"got {mac.hex()!r}, expected {expected.hex()!r}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
