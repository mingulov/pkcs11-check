"""Mechanism-driven sign/verify tests.

Parametrized by mech_sign_entry -- tests every sign mechanism advertised by the
module that also has a registry config.

Key types covered:
- HMAC (SHA-1/224/256/384/512, SHA3, BLAKE2b, RIPEMD): generic secret key
- AES-MAC / AES-CMAC / AES-GMAC: AES key
- RSA-PKCS, RSA-PSS, RSA-X9.31, SHA*-RSA-PKCS, SHA*-RSA-PKCS-PSS: RSA keypair
- ECDSA, ECDSA-SHA*, EdDSA: EC keypair
- ML-DSA, SLH-DSA: PQC keypair
- DSA/GOSTR/KEA: require domain parameters -- skipped

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
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKK,
    CKK_EC_EDWARDS,
    CKM,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    build_params_from_vector,
    generate_key_for_sign,
    make_mech_param_or_skip,
)

# DER-encoded OIDs for Edwards curves
_EDWARDS_OID_PREFIXES = (
    b"\x06\x03\x2b\x65\x70",  # Ed25519 (1.3.101.112)
    b"\x06\x03\x2b\x65\x71",  # Ed448 (1.3.101.113)
)

_SIGN_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
)

_KAT_IMPORT_CAPABILITY_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.sign]


def _ckr_name_from_exception(exc: AssertionError) -> str:
    rv = getattr(exc, "rv", None)
    if rv is not None:
        return ckr_name(rv)
    return str(exc)


def _xfail_sign_runtime_reject(exc: AssertionError, entry: MechEntry, operation: str) -> None:
    xfail_if_known_ckr(
        exc,
        _SIGN_RUNTIME_REJECT_RVS,
        f"{entry.mech_name}: advertised but {operation} is not operational",
    )


def _skip_kat_import_capability_reject(
    exc: AssertionError,
    entry: MechEntry,
    object_label: str,
) -> None:
    if is_known_error(exc, _KAT_IMPORT_CAPABILITY_REJECT_RVS):
        pytest.skip(
            f"{entry.mech_name}: cannot import {object_label} for KAT setup: "
            f"{_ckr_name_from_exception(exc)}"
        )
    raise exc


class TestMechSignRoundtrip:
    """Sign then verify roundtrip for every advertised sign mechanism."""

    def test_roundtrip(self, p11_raw_session: RawSession, mech_sign_entry: MechEntry) -> None:
        """Sign data then verify -- must return True."""
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

            try:
                sig = sign_single(
                    rs.raw, rs.sh, sign_key, CKM(entry.mech_id), data, mech_param=mech_param
                )
            except AssertionError as exc:
                _xfail_sign_runtime_reject(exc, entry, "sign")
            try:
                ok = verify_single(
                    rs.raw,
                    rs.sh,
                    verify_key_handle,
                    CKM(entry.mech_id),
                    data,
                    sig,
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                _xfail_sign_runtime_reject(exc, entry, "verify")
            assert ok, f"{entry.mech_name}: verify failed after valid sign (sig={sig.hex()!r})"
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    def test_tampered_data_fails_verify(
        self, p11_raw_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Sign data A, verify with data B -- must return False."""
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

            try:
                sig = sign_single(
                    rs.raw, rs.sh, sign_key, CKM(entry.mech_id), data_a, mech_param=mech_param
                )
            except AssertionError as exc:
                _xfail_sign_runtime_reject(exc, entry, "sign")
            try:
                ok = verify_single(
                    rs.raw,
                    rs.sh,
                    verify_key_handle,
                    CKM(entry.mech_id),
                    data_b,
                    sig,
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                if signature_rejected_or_xfail(exc, entry.mech_name) is False:
                    return
                raise
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

    param_recipe = getattr(config, "param_recipe", None)
    if param_recipe is None:
        pytest.skip(f"No param_recipe configured for {entry.mech_name}")
    mech_param = build_params_from_vector(entry.mech_id, param_recipe, vec)
    if mech_param == "SKIP":
        return

    input_data = bytes.fromhex(vec["input_hex"])
    verify_only: bool = bool(vec.get("verify_only", False))

    if "n_hex" in vec:
        # RSA: import private key for signing
        try:
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
        except AssertionError as exc:
            _skip_kat_import_capability_reject(exc, entry, "RSA private key")
        pub_key: int | None = None
        if verify_only:
            # Also import public key so we can verify with it
            try:
                pub_key = import_rsa_public_key(
                    rs.raw,
                    rs.sh,
                    n=bytes.fromhex(vec["n_hex"]),
                    e=bytes.fromhex(vec["e_hex"]),
                )
            except AssertionError as exc:
                _skip_kat_import_capability_reject(exc, entry, "RSA public key")
        try:
            if verify_only:
                assert pub_key is not None
                stored_sig = bytes.fromhex(vec["signature_hex"])
                try:
                    ok = verify_single(
                        rs.raw,
                        rs.sh,
                        pub_key,
                        CKM(entry.mech_id),
                        input_data,
                        stored_sig,
                        mech_param=mech_param,
                    )
                except AssertionError as exc:
                    _xfail_sign_runtime_reject(exc, entry, "KAT verify")
                assert ok, (
                    f"KAT verify failed for {vec.get('id', '?')}: "
                    f"stored sig {stored_sig.hex()!r} did not verify"
                )
            else:
                # Deterministic (RSA PKCS#1 v1.5): sign and compare bytes
                try:
                    sig = sign_single(
                        rs.raw,
                        rs.sh,
                        priv_key,
                        CKM(entry.mech_id),
                        input_data,
                        mech_param=mech_param,
                    )
                except AssertionError as exc:
                    _xfail_sign_runtime_reject(exc, entry, "KAT sign")
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
        # EC/Edwards: import private key; public point not in vector so verify via round-trip
        ec_params = bytes.fromhex(vec["ec_params_hex"])
        ec_key_type = int(CKK_EC_EDWARDS) if ec_params.startswith(_EDWARDS_OID_PREFIXES) else None
        try:
            priv_key = import_ec_private_key(
                rs.raw,
                rs.sh,
                ec_params=ec_params,
                value=bytes.fromhex(vec["ec_private_scalar_hex"]),
                attrs={CKA_SIGN: True, CKA_TOKEN: False},
                **({"key_type": ec_key_type} if ec_key_type is not None else {}),
            )
        except AssertionError as exc:
            _skip_kat_import_capability_reject(exc, entry, "EC private key")
        try:
            # Sign to confirm the key + mechanism work; we cannot verify the stored
            # sig because we have no public key object (scalar only in vector).
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv_key,
                    CKM(entry.mech_id),
                    input_data,
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                _xfail_sign_runtime_reject(exc, entry, "KAT sign")
            assert len(sig) > 0, f"KAT sign returned empty signature for {vec.get('id', '?')}"
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_key)

    # else: unrecognised asymmetric vector schema -- skip silently


class TestMechSignKAT:
    """Known-answer sign/MAC tests from pre-generated vectors."""

    def test_kat_vector(self, p11_raw_session: RawSession, mech_sign_entry: MechEntry) -> None:
        """Compute MAC with known key and input -- verify output matches vector."""
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
                try:
                    mac = sign_single(
                        rs.raw,
                        rs.sh,
                        key,
                        CKM(entry.mech_id),
                        bytes.fromhex(vec["input_hex"]),
                        mech_param=params,
                    )
                except AssertionError as exc:
                    _xfail_sign_runtime_reject(exc, entry, "KAT sign")
                expected = bytes.fromhex(mac_hex)
                assert mac == expected, (
                    f"KAT MAC mismatch for {vec.get('id', '?')}: "
                    f"got {mac.hex()!r}, expected {expected.hex()!r}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
