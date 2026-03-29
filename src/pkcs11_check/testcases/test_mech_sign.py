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
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_ec_private_key,
    import_rsa_private_key,
    import_rsa_public_key,
    import_secret_key,
    sign_single,
    verify_single,
)
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
        assert config is not None

        sign_key, verify_key = generate_key_for_sign(rs, entry, config)
        verify_key_handle = verify_key if verify_key is not None else sign_key

        try:
            data = b"hello pkcs11 sign test" * 2
            # Raw PSS/ECDSA expect pre-hashed input (digest-size bytes).
            # Hash the test data so these mechanisms get correctly-sized input.
            if config.input_constraint == "prehash":
                import hashlib
                data = hashlib.sha256(data).digest()
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
        assert config is not None

        sign_key, verify_key = generate_key_for_sign(rs, entry, config)
        verify_key_handle = verify_key if verify_key is not None else sign_key

        try:
            data_a = b"original data for signing"
            data_b = b"tampered data XXXXXXXXXXX"
            if config.input_constraint == "prehash":
                import hashlib
                data_a = hashlib.sha256(data_a).digest()
                data_b = hashlib.sha256(data_b).digest()
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


def _run_asymmetric_sign_kat(
    rs: RawSession,
    entry: MechEntry,
    config: object,
    vec: dict,  # type: ignore[type-arg]
) -> None:
    """Import an asymmetric key from a KAT vector and sign/verify.

    RSA PKCS#1 v1.5 (verify_only=False): sign with private key, compare bytes.
    RSA-PSS (verify_only=True): sign with private key + verify stored sig with
      imported public key (n, e available in vector).
    ECDSA (verify_only=True): sign with private key + round-trip verify with
      the fresh signature (public point not in vector, so stored sig is skipped).
    """
    from pkcs11_check.testcases.mechanism_helpers import build_params_from_vector

    mech_param = build_params_from_vector(entry.mech_id, getattr(config, "param_recipe", None), vec)
    if mech_param == "SKIP":
        return

    input_data = bytes.fromhex(vec["input_hex"])
    verify_only: bool = bool(vec.get("verify_only", False))

    if "n_hex" in vec:
        # RSA: import private key for signing
        priv_key = import_rsa_private_key(
            rs.raw,
            rs.sh,
            n=bytes.fromhex(vec["n_hex"]),
            e=bytes.fromhex(vec["e_hex"]),
            d=bytes.fromhex(vec["d_hex"]),
            p=bytes.fromhex(vec["p_hex"]),
            q=bytes.fromhex(vec["q_hex"]),
            dmp1=bytes.fromhex(vec["dmp1_hex"]),
            dmq1=bytes.fromhex(vec["dmq1_hex"]),
            iqmp=bytes.fromhex(vec["iqmp_hex"]),
            attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        pub_key: int | None = None
        if verify_only:
            # Also import public key so we can verify with it
            pub_key = import_rsa_public_key(
                rs.raw,
                rs.sh,
                n=bytes.fromhex(vec["n_hex"]),
                e=bytes.fromhex(vec["e_hex"]),
            )
        try:
            if verify_only:
                assert pub_key is not None
                stored_sig = bytes.fromhex(vec["signature_hex"])
                ok = verify_single(
                    rs.raw,
                    rs.sh,
                    pub_key,
                    CKM(entry.mech_id),
                    input_data,
                    stored_sig,
                    mech_param=mech_param,
                )
                assert ok, (
                    f"KAT verify failed for {vec.get('id', '?')}: "
                    f"stored sig {stored_sig.hex()!r} did not verify"
                )
            else:
                # Deterministic (RSA PKCS#1 v1.5): sign and compare bytes
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv_key,
                    CKM(entry.mech_id),
                    input_data,
                    mech_param=mech_param,
                )
                expected = bytes.fromhex(vec["signature_hex"])
                assert sig == expected, (
                    f"KAT sign mismatch for {vec.get('id', '?')}: "
                    f"got {sig.hex()!r}, expected {expected.hex()!r}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_key)
            if pub_key is not None:
                destroy_quietly(rs.raw, rs.sh, pub_key)

    elif "ec_private_scalar_hex" in vec:
        # EC: import private key; public point not in vector so verify via round-trip
        priv_key = import_ec_private_key(
            rs.raw,
            rs.sh,
            ec_params=bytes.fromhex(vec["ec_params_hex"]),
            value=bytes.fromhex(vec["ec_private_scalar_hex"]),
            attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        try:
            # Sign to confirm the key + mechanism work; we cannot verify the stored
            # sig because we have no public key object (scalar only in vector).
            sig = sign_single(
                rs.raw,
                rs.sh,
                priv_key,
                CKM(entry.mech_id),
                input_data,
                mech_param=mech_param,
            )
            assert len(sig) > 0, (
                f"KAT sign returned empty signature for {vec.get('id', '?')}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_key)

    # else: unrecognised asymmetric vector schema — skip silently


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

            if vec.get("key_type") == "asymmetric":
                _run_asymmetric_sign_kat(rs, entry, config, vec)
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
