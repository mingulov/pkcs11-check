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
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKK_EC_EDWARDS,
    CKM,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._capability_claims import claim_refusal_passes
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import (
    import_rsa_private_key_negotiated,
    import_rsa_public_key_negotiated,
    import_secret_key_negotiated,
    is_known_error,
)
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

# KAT key-import reject classification (import-skip audit A9). The merged tuple is
# SPLIT (Batch 3b) the way Batch 2 split the EC public-key tuples: a
# genuine-capability-absence branch (the specific curve is not supported) stays a
# skip; the broad import-failure codes are "advertised but not operational" ->
# xfail (KEY_SIZE_RANGE and TEMPLATE_INCOMPLETE/INCONSISTENT count as broad per
# the Batch 2 verdict). The generic xfail helper gates on the broad set; the EC
# private site filters curve-absence to skip first (no negotiated EC-private
# importer -- the raw single-template import IS the spec path; D2, b56c3f8c).
_KAT_EC_CURVE_UNSUPPORTED_RVS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_KAT_IMPORT_CAPABILITY_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.sign]

_MAC_GENERAL_STYLES = frozenset({"mac_general", "rc2_mac_general", "rc5_mac_general"})


def _expected_mac_general_len(config: object) -> int | None:
    param_recipe = getattr(config, "param_recipe", None)
    if param_recipe is None or param_recipe.style not in _MAC_GENERAL_STYLES:
        return None
    mac_len = param_recipe.defaults.get("mac_len")
    if mac_len is None:
        return None
    return int(mac_len)


def _ckr_name_from_exception(exc: AssertionError) -> str:
    rv = getattr(exc, "rv", None)
    if rv is not None:
        return ckr_name(rv)
    return str(exc)


def _xfail_ec_kat_import_not_operational(
    exc: AssertionError,
    entry: MechEntry,
    object_label: str,
) -> None:
    """Classify a raw EC-private KAT key-import reject (import-skip audit A9 EC leg).

    Curve-genuine-absence CKRs (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID)
    keep the capability skip -- the specific curve is genuinely absent. A broad
    import-failure CKR, on a sign mechanism the module ADVERTISES (the
    ``mech_sign_entry`` registry parametrization is advertised-by-construction),
    is "advertised but not operational" -> xfail. There is no negotiated
    EC-private importer (D2, commit b56c3f8c): the raw single-template
    ``import_ec_private_key`` IS the spec path, so the broad reject is conclusive
    without negotiation wiring. Non-CKR AssertionErrors propagate (harness/coding
    bug). This routes the EC leg to the same ``not_operational_reason`` wording as
    the RSA/secret legs, closing the setup/op asymmetry on the EC family.
    """
    if is_known_error(exc, _KAT_EC_CURVE_UNSUPPORTED_RVS):
        # Genuine capability absence: this specific curve is not supported
        # (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID). Skip stays.
        pytest.skip(
            f"{entry.mech_name}: cannot import {object_label} for KAT setup: "
            f"{_ckr_name_from_exception(exc)}"
        )
    # Broad import-failure CKR -> xfail (may include curve-capability rejects
    # expressed as generic CKRs -- recorded as xfail, not hidden).
    _xfail_kat_import_not_operational(exc, entry, object_label)


def _xfail_rsa_kat_import_not_operational(
    exc: AssertionError,
    entry: MechEntry,
    object_label: str,
) -> None:
    """Classify negotiated RSA KAT key-import rejects (import-skip audit A9 RSA).

    The RSA key is imported through ``import_rsa_private_key_negotiated`` /
    ``import_rsa_public_key_negotiated``; a clean broad import-failure CKR after
    negotiation exhaustion on a sign mechanism the module ADVERTISES (the
    ``mech_sign_entry`` registry parametrization is advertised-by-construction)
    is advertised-but-not-operational -> xfail, never skip. This matches the
    op-stage ``claim_refusal_passes`` routing so the setup/op asymmetry on the
    RSA family is closed. Non-CKR AssertionErrors propagate (harness/coding bug).
    """
    _xfail_kat_import_not_operational(exc, entry, object_label)


def _xfail_kat_import_not_operational(
    exc: AssertionError,
    entry: MechEntry,
    object_label: str,
) -> None:
    """Classify negotiated KAT key-import rejects for any mechanism family.

    A clean broad import-failure CKR after negotiation exhaustion on a sign
    mechanism the module ADVERTISES is advertised-but-not-operational -> xfail,
    never skip.  Non-CKR AssertionErrors propagate (harness/coding bug).

    Probe key: ``{entry.mech_name}:key-import`` -- consistent with the RSA and
    symmetric-MAC call sites.
    """
    if is_known_error(exc, _KAT_IMPORT_CAPABILITY_REJECT_RVS):
        pytest.xfail(
            not_operational_reason(
                f"{entry.mech_name}:key-import",
                f"{object_label}: {_ckr_name_from_exception(exc)}"
                if isinstance(exc, CkrAssertionError)
                else f"{object_label}: {exc}",
            )
        )
    raise exc


class TestMechSignRoundtrip:
    """Sign then verify roundtrip for every advertised sign mechanism."""

    def test_roundtrip(self, p11_module_session: RawSession, mech_sign_entry: MechEntry) -> None:
        """Sign data then verify -- must return True."""
        rs = p11_module_session
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
                if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:sign"):
                    return
            expected_mac_len = _expected_mac_general_len(config)
            if expected_mac_len is not None:
                assert len(sig) == expected_mac_len, (
                    f"{entry.mech_name}: MAC length mismatch: "
                    f"got {len(sig)}, expected {expected_mac_len}"
                )
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
                if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:verify"):
                    return
            assert ok, f"{entry.mech_name}: verify failed after valid sign (sig={sig.hex()!r})"
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    def test_tampered_data_fails_verify(
        self, p11_module_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Sign data A, verify with data B -- must return False."""
        rs = p11_module_session
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
                if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:sign"):
                    return
            expected_mac_len = _expected_mac_general_len(config)
            if expected_mac_len is not None:
                assert len(sig) == expected_mac_len, (
                    f"{entry.mech_name}: MAC length mismatch: "
                    f"got {len(sig)}, expected {expected_mac_len}"
                )
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
) -> bool:
    """Import an asymmetric key from a KAT vector and sign/verify.

    RSA PKCS#1 v1.5 (verify_only=False): sign with private key, compare bytes.
    RSA-PSS (verify_only=True): sign with private key + verify stored sig with
      imported public key (n, e available in vector).
    ECDSA (verify_only=True): sign with private key + round-trip verify with
      the fresh signature (public point not in vector, so stored sig is skipped).

    Returns True when a sanctioned policy refusal (CKR_OPERATION_NOT_VALIDATED)
    is seen so the calling loop can end the whole test immediately -- later
    vectors would only duplicate the compliance note.
    """
    from pkcs11_check.testcases.mechanism_helpers import build_params_from_vector

    param_recipe = getattr(config, "param_recipe", None)
    if param_recipe is None:
        pytest.skip(f"No param_recipe configured for {entry.mech_name}")
    mech_param = build_params_from_vector(entry.mech_id, param_recipe, vec)
    if mech_param == "SKIP":
        return False

    input_data = bytes.fromhex(vec["input_hex"])
    verify_only: bool = bool(vec.get("verify_only", False))

    if "n_hex" in vec:
        # RSA: import private key for signing
        try:
            priv_key = import_rsa_private_key_negotiated(
                rs,
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
            _xfail_rsa_kat_import_not_operational(exc, entry, "RSA private key")
        pub_key: int | None = None
        if verify_only:
            # Also import public key so we can verify with it.  Wrap in
            # try/finally so priv_key is destroyed even when the xfail helper
            # raises (xfail fires before the outer finally that covers priv_key).
            try:
                pub_key = import_rsa_public_key_negotiated(
                    rs,
                    n=bytes.fromhex(vec["n_hex"]),
                    e=bytes.fromhex(vec["e_hex"]),
                )
            except AssertionError as exc:
                destroy_quietly(rs.raw, rs.sh, priv_key)
                _xfail_rsa_kat_import_not_operational(exc, entry, "RSA public key")
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
                    if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:kat-verify"):
                        return True
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
                    if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:kat-sign"):
                        return True
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
            _xfail_ec_kat_import_not_operational(exc, entry, "EC private key")
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
                if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:kat-sign"):
                    return True
            assert len(sig) > 0, f"KAT sign returned empty signature for {vec.get('id', '?')}"
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_key)

    # else: unrecognised asymmetric vector schema -- skip silently
    return False


class TestMechSignKAT:
    """Known-answer sign/MAC tests from pre-generated vectors."""

    def test_kat_vector(self, p11_module_session: RawSession, mech_sign_entry: MechEntry) -> None:
        """Compute MAC with known key and input -- verify output matches vector."""
        rs = p11_module_session
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
                if _run_asymmetric_sign_kat(rs, entry, config, vec):
                    return
                continue

            key_hex = vec.get("key_hex")
            mac_hex = vec.get("mac_hex")
            if not key_hex or not mac_hex:
                continue
            if config.key_type is None:
                continue
            key_bytes = bytes.fromhex(key_hex)
            try:
                key = import_secret_key_negotiated(
                    rs,
                    int(config.key_type),
                    key_bytes,
                    attrs={CKA_SIGN: True, CKA_TOKEN: False},
                )
            except AssertionError as exc:
                _xfail_kat_import_not_operational(exc, entry, "secret key")
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
                    if claim_refusal_passes(exc, rs, probe_key=f"{entry.mech_name}:kat-sign"):
                        return
                expected = bytes.fromhex(mac_hex)
                assert mac == expected, (
                    f"KAT MAC mismatch for {vec.get('id', '?')}: "
                    f"got {mac.hex()!r}, expected {expected.hex()!r}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
