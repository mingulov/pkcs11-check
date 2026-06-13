"""Wycheproof edge-case test vectors for cryptographic implementation bugs.

Loads JSON test vectors from the Wycheproof project (C2SP/wycheproof)
and runs them against the PKCS#11 module. Tests are parametrized per vector.

For "invalid" vectors: the operation MUST fail (or produce different output).
The test also asserts no session corruption after invalid operations.
"""

from __future__ import annotations

from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_bytes, mech_gcm
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    generate_random,
    import_secret_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKM_AES_CBC_PAD,
    CKM_AES_GCM,
    CKM_ECDSA,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import (
    import_ec_public_key_negotiated,
    import_rsa_public_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: F401
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex
from pkcs11_check.testcases.wycheproof.wycheproof_loader import load_vectors as load_wycheproof

pytestmark = pytest.mark.wycheproof

_GENERIC_WYCHEPROOF_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


# EC public-key import reject classification (import-skip audit A13). The reject
# is split: a genuine-capability-absence branch (the specific curve is not
# supported) stays a skip; a broad import-failure branch on a module that
# ADVERTISES ECDSA is "advertised but not operational" -> xfail. Mirrors the
# Batch 2 split in test_wycheproof_ecdsa.py.
_EC_CURVE_UNSUPPORTED_CKRS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _classify_ec_public_import_reject(exc: AssertionError, curve: str) -> NoReturn:
    """Classify an EC public-key import reject (import-skip audit A13).

    Curve-genuine-absence CKRs (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID)
    keep the capability skip. A broad import-failure CKR after the negotiated
    importer has exhausted every storage shape, on a module that ADVERTISES ECDSA
    (the ``_skip_unless_mechanism(rs, "ECDSA")`` gate passed upstream), is
    "advertised but not operational" -> xfail per the classification model.
    Non-CKR AssertionErrors propagate (harness/coding bug).
    """
    if is_known_error(exc, _EC_CURVE_UNSUPPORTED_CKRS):
        # Genuine capability absence: this specific curve is not supported
        # (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID). Skip stays.
        pytest.skip(f"Cannot import EC public key on this module ({curve}): {exc}")
    if isinstance(exc, CkrAssertionError) and is_known_error(
        exc, _EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS
    ):
        # ECDSA is advertised (has_mechanism gate passed above) and the
        # negotiated import is exhausted -> "advertised but not operational"
        # -> xfail per the classification model (not skip).
        # May include curve-capability rejects expressed as generic CKRs --
        # recorded as xfail, not hidden.
        classify(
            "not_operational",
            label="ECDSA:key-import",
            summary=not_operational_reason("ECDSA:key-import", f"{curve}: {ckr_name(exc.rv)}"),
        )
    raise exc


def _vec_id(vec: dict[str, Any]) -> str:
    return f"tc{vec['tcId']}-{vec['result']}"


def _skip_unless_mechanism(rs: Any, name: str) -> None:
    """Skip vector tests when the required PKCS#11 mechanism is unavailable."""
    if not rs.has_mechanism(name):
        pytest.skip(f"CKM_{name} not supported")


def _xfail_if_generic_runtime_reject(
    exc: AssertionError,
    label: str,
    operation: str,
) -> NoReturn:
    """Classify advertised generic Wycheproof operation rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _GENERIC_WYCHEPROOF_RUNTIME_REJECT_CKRS,
        f"{label}: advertised {operation} is not operational",
    )
    raise exc


# --- AES-GCM ---


def _load_aes_gcm_vectors() -> list[dict[str, Any]]:
    if not (WYCHEPROOF_DIR / "aes_gcm_test.json").exists():
        return []
    return load_wycheproof("aes_gcm_test.json")


class TestAESGCMWycheproof:
    """Wycheproof AES-GCM vectors - tests AEAD correctness and tag validation."""

    @pytest.mark.parametrize("vec", _load_aes_gcm_vectors(), ids=_vec_id)
    def test_aes_gcm(self, p11_module_session: Any, vec: dict[str, Any]) -> None:
        rs = p11_module_session
        _skip_unless_mechanism(rs, "AES_GCM")
        key_bytes = bytes.fromhex(vec["key"])
        iv = bytes.fromhex(vec["iv"])
        aad = bytes.fromhex(vec["aad"])
        msg = bytes.fromhex(vec["msg"])
        ct_expected = bytes.fromhex(vec["ct"])
        tag_expected = bytes.fromhex(vec["tag"])
        result = vec["result"]

        # Import key
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                key_bytes,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                },
            )
        except AssertionError:
            if result == "invalid":
                return  # invalid key rejected - correct
            raise

        # Wycheproof GCM vectors are best tested via decrypt (authenticated)
        # This verifies: given (key, iv, aad, ct, tag) -> module accepts valid, rejects invalid
        from pkcs11_check.compliance import ComplianceLevel, note

        tag_bits = len(tag_expected) * 8
        ciphertext_with_tag = ct_expected + tag_expected

        # Track non-recommended IV sizes
        if len(iv) != 12 and result == "valid":
            note(
                f"GCM with {len(iv)}-byte IV (not 96-bit)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="NIST SP 800-38D Sec.8.2 recommends 96-bit IVs",
            )

        try:
            gcm_param = mech_gcm(
                CKM_AES_GCM,
                iv,
                aad=aad if aad else None,
                tag_bits=tag_bits,
            )
        except (AssertionError, ValueError, TypeError):
            # Binding rejects non-standard IV/tag sizes
            if result == "valid":
                classify(
                    "not_operational",
                    label="AES-GCM:binding",
                    summary=f"Binding rejects GCM iv={len(iv)}B tag={len(tag_expected)}B",
                )
            return  # invalid vectors correctly rejected

        try:
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                ciphertext_with_tag,
                mech_param=gcm_param,
            )
            # Decryption succeeded
            if result == "valid" or result == "acceptable":
                assert pt == msg
            elif result == "invalid":
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="AES-GCM",
                    summary=f"Invalid AES-GCM vector tc{vec['tcId']} decrypted successfully",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        except AssertionError as exc:
            exc_msg = str(exc)
            if result == "valid":
                iv_len = len(iv)
                tag_len = len(tag_expected)
                if iv_len > 16:
                    # NIST SP 800-38D: support for non-96-bit IVs is optional.
                    # All tested providers reject oversized IVs -- acceptable.
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        f"GCM with {iv_len}-byte IV rejected (optional per NIST SP 800-38D)",
                        ComplianceLevel.NOT_RECOMMENDED,
                        reference="NIST SP 800-38D Sec.8.2: non-96-bit IV support is optional",
                    )
                else:
                    _xfail_if_generic_runtime_reject(
                        exc,
                        f"AES-GCM tc{vec['tcId']}",
                        "AES-GCM decrypt",
                    )
                    classify(
                        "not_operational",
                        label="AES-GCM",
                        summary=(
                            f"Valid GCM vector tc{vec['tcId']} rejected: "
                            f"iv={iv_len}B tag={tag_len}B ({exc_msg})"
                        ),
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
            # invalid/acceptable failing is expected - good!
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

        # Verify session is still usable after any failure
        generate_random(rs.raw, rs.sh, 64)


# --- HMAC-SHA256 ---


def _load_hmac_sha256_vectors() -> list[dict[str, Any]]:
    if not (WYCHEPROOF_DIR / "hmac_sha256_test.json").exists():
        return []
    return load_wycheproof("hmac_sha256_test.json")


class TestHMACSHA256Wycheproof:
    """Wycheproof HMAC-SHA256 vectors."""

    @pytest.mark.parametrize("vec", _load_hmac_sha256_vectors(), ids=_vec_id)
    def test_hmac_sha256(self, p11_module_session: Any, vec: dict[str, Any]) -> None:
        rs = p11_module_session
        _skip_unless_mechanism(rs, "SHA256_HMAC")
        key_bytes = bytes.fromhex(vec["key"])
        msg = bytes.fromhex(vec["msg"])
        tag_expected = bytes.fromhex(vec["tag"])
        result = vec["result"]
        tag_size = vec["_group"].get("tagSize", 256) // 8

        # Track non-recommended key sizes
        if len(key_bytes) < 32 and result == "valid":
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"HMAC-SHA256 with {len(key_bytes)}-byte key (< hash output)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="FIPS 198-1 Sec.3 recommends key >= hash output length",
            )

        # Try SHA256_HMAC key type first; fall back to GENERIC_SECRET
        # (some modules require min key length for typed HMAC keys)
        key = None
        last_import_exc = None
        for key_type in (CKK_SHA256_HMAC, CKK_GENERIC_SECRET):
            try:
                key = import_secret_key(
                    rs.raw,
                    rs.sh,
                    key_type,
                    key_bytes,
                    attrs={
                        CKA_SIGN: True,
                        CKA_VERIFY: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
                break
            except AssertionError as exc:
                last_import_exc = exc
                continue
        if key is None:
            if result == "invalid":
                return  # Invalid key correctly rejected
            if last_import_exc is not None:
                _xfail_if_generic_runtime_reject(
                    last_import_exc,
                    f"HMAC-SHA256 tc{vec['tcId']}",
                    "HMAC-SHA256 key import",
                )
            classify(
                "not_operational",
                label="HMAC-SHA256:key-import",
                summary=f"Module cannot import {len(key_bytes)}-byte HMAC key",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        try:
            mac = sign_single(rs.raw, rs.sh, key, CKM_SHA256_HMAC, msg)
            # Truncate to expected tag size
            truncated = mac[:tag_size]
            if result == "valid":
                assert truncated == tag_expected
            elif result == "invalid" and truncated == tag_expected:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="HMAC-SHA256",
                    summary=f"Invalid HMAC tag tc{vec['tcId']} accepted by module",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        except AssertionError as exc:
            if result == "valid":
                _xfail_if_generic_runtime_reject(
                    exc,
                    f"HMAC-SHA256 tc{vec['tcId']}",
                    "HMAC-SHA256 sign",
                )
                exc_msg = str(exc)
                classify(
                    "not_operational",
                    label="HMAC-SHA256",
                    summary=(
                        f"Valid HMAC vector tc{vec['tcId']} failed: "
                        f"{len(key_bytes)}-byte key ({exc_msg})"
                    ),
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# --- ECDSA P-256 SHA-256 ---


def _load_ecdsa_p256_vectors() -> list[dict[str, Any]]:
    if not (WYCHEPROOF_DIR / "ecdsa_secp256r1_sha256_test.json").exists():
        return []
    return load_wycheproof("ecdsa_secp256r1_sha256_test.json")


class TestECDSAP256Wycheproof:
    """Wycheproof ECDSA P-256/SHA-256 vectors - tests signature verification."""

    @pytest.mark.parametrize("vec", _load_ecdsa_p256_vectors(), ids=_vec_id)
    def test_ecdsa_p256_sha256_verify(self, p11_module_session: Any, vec: dict[str, Any]) -> None:
        import hashlib

        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        rs = p11_module_session
        _skip_unless_mechanism(rs, "ECDSA")
        msg = bytes.fromhex(vec["msg"])
        sig_der = bytes.fromhex(vec["sig"])
        result = vec["result"]
        group = vec["_group"]

        # Get EC public key point from the group's publicKey dict
        pub_key_info = group.get("publicKey", {})
        uncompressed_hex = pub_key_info.get("uncompressed", "")
        if not uncompressed_hex:
            pytest.skip("No uncompressed point in vector group")

        uncompressed = bytes.fromhex(uncompressed_hex)

        # Wrap in DER OCTET STRING for PKCS#11: 04 || length || point
        if len(uncompressed) < 128:
            ec_point_der = bytes([0x04, len(uncompressed)]) + uncompressed
        else:
            ec_point_der = bytes([0x04, 0x81, len(uncompressed)]) + uncompressed

        try:
            pub_key = import_ec_public_key_negotiated(
                rs,
                ec_params=encode_named_curve_parameters("secp256r1"),
                ec_point=ec_point_der,
                attrs={CKA_VERIFY: True},
                purpose="wycheproof ECDSA P-256 public key import",
            )
        except AssertionError as exc:
            _classify_ec_public_import_reject(exc, "secp256r1")

        # Convert DER signature to raw r||s (32+32 bytes for P-256)
        try:
            r_int, s_int = decode_dss_signature(sig_der)
            raw_sig = r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big")
        except (ValueError, OverflowError):
            if result == "invalid":
                return  # Malformed DER is correctly rejected
            classify(
                "not_operational",
                label="ECDSA:DER-decode",
                summary=f"Cannot decode valid DER sig for tc{vec['tcId']}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        digest = hashlib.sha256(msg).digest()

        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_ECDSA, digest, raw_sig)
            if result == "invalid":
                if verified:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label="ECDSA",
                        summary=f"Invalid ECDSA sig tc{vec['tcId']} accepted by module",
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                return
            if result == "valid" and not verified:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="ECDSA",
                    summary=f"Valid ECDSA sig tc{vec['tcId']} rejected by module",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        except AssertionError as exc:
            if result == "valid":
                classify(
                    "not_operational",
                    label="ECDSA",
                    summary=f"Valid ECDSA sig tc{vec['tcId']} rejected by module",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            signature_rejected_or_xfail(exc, f"tc{vec['tcId']}")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)

        # Session must still be usable
        generate_random(rs.raw, rs.sh, 64)


# --- AES-CBC-PKCS5 (padding tests) ---


def _load_aes_cbc_pkcs5_vectors() -> list[dict[str, Any]]:
    if not (WYCHEPROOF_DIR / "aes_cbc_pkcs5_test.json").exists():
        return []
    return load_wycheproof("aes_cbc_pkcs5_test.json")


class TestAESCBCPKCS5Wycheproof:
    """Wycheproof AES-CBC-PKCS5 vectors - tests padding correctness."""

    @pytest.mark.parametrize("vec", _load_aes_cbc_pkcs5_vectors(), ids=_vec_id)
    def test_aes_cbc_pkcs5(self, p11_module_session: Any, vec: dict[str, Any]) -> None:
        rs = p11_module_session
        _skip_unless_mechanism(rs, "AES_CBC_PAD")
        key_bytes = bytes.fromhex(vec["key"])
        iv = bytes.fromhex(vec["iv"])
        msg = bytes.fromhex(vec["msg"])
        ct_expected = bytes.fromhex(vec["ct"])
        result = vec["result"]

        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                key_bytes,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                },
            )
        except AssertionError:
            if result == "invalid":
                return
            raise

        # Test decryption (verify padding handling)
        try:
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                ct_expected,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            if result == "valid" or result == "acceptable":
                assert pt == msg
            elif result == "invalid":
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="AES-CBC-PAD",
                    summary=f"Invalid AES-CBC vector tc{vec['tcId']} decrypted successfully",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        except AssertionError as exc:
            if result == "valid":
                _xfail_if_generic_runtime_reject(
                    exc,
                    f"AES-CBC-PAD tc{vec['tcId']}",
                    "AES-CBC-PAD decrypt",
                )
                classify(
                    "not_operational",
                    label="AES-CBC-PAD",
                    summary=f"Valid AES-CBC vector tc{vec['tcId']} failed",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

        generate_random(rs.raw, rs.sh, 64)


# --- ECDSA P-384 SHA-384 ---


def _load_ecdsa_p384_vectors() -> list[dict[str, Any]]:
    if not (WYCHEPROOF_DIR / "ecdsa_secp384r1_sha384_test.json").exists():
        return []
    return load_wycheproof("ecdsa_secp384r1_sha384_test.json")


class TestECDSAP384Wycheproof:
    """Wycheproof ECDSA P-384/SHA-384 signature verification vectors."""

    @pytest.mark.parametrize("vec", _load_ecdsa_p384_vectors(), ids=_vec_id)
    def test_ecdsa_p384_sha384_verify(self, p11_module_session: Any, vec: dict[str, Any]) -> None:
        import hashlib

        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        rs = p11_module_session
        _skip_unless_mechanism(rs, "ECDSA")
        msg = bytes.fromhex(vec["msg"])
        sig_der = bytes.fromhex(vec["sig"])
        result = vec["result"]
        group = vec["_group"]

        pub_key_info = group.get("publicKey", {})
        uncompressed_hex = pub_key_info.get("uncompressed", "")
        if not uncompressed_hex:
            pytest.skip("No uncompressed point in vector group")

        uncompressed = bytes.fromhex(uncompressed_hex)

        # DER OCTET STRING wrapper: 04 <len> <point> (P-384: 97 bytes < 128)
        if len(uncompressed) < 128:
            ec_point_der = bytes([0x04, len(uncompressed)]) + uncompressed
        else:
            ec_point_der = bytes([0x04, 0x81, len(uncompressed)]) + uncompressed

        try:
            pub_key = import_ec_public_key_negotiated(
                rs,
                ec_params=encode_named_curve_parameters("secp384r1"),
                ec_point=ec_point_der,
                attrs={CKA_VERIFY: True},
                purpose="wycheproof ECDSA P-384 public key import",
            )
        except AssertionError as exc:
            _classify_ec_public_import_reject(exc, "secp384r1")

        # Convert DER sig to raw r||s (48+48 bytes for P-384)
        try:
            r_int, s_int = decode_dss_signature(sig_der)
            raw_sig = r_int.to_bytes(48, "big") + s_int.to_bytes(48, "big")
        except (ValueError, OverflowError):
            if result == "invalid":
                return
            classify(
                "not_operational",
                label="ECDSA:DER-decode",
                summary=f"Cannot decode valid DER sig for tc{vec['tcId']}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        digest = hashlib.sha384(msg).digest()

        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_ECDSA, digest, raw_sig)
            if result == "invalid":
                if verified:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label="ECDSA-P384",
                        summary=f"Invalid ECDSA P-384 sig tc{vec['tcId']} accepted",
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                return
            if result == "valid" and not verified:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="ECDSA-P384",
                    summary=f"Valid ECDSA P-384 sig tc{vec['tcId']} rejected",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        except AssertionError as exc:
            if result == "valid":
                classify(
                    "not_operational",
                    label="ECDSA-P384",
                    summary=f"Valid ECDSA P-384 sig tc{vec['tcId']} rejected",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            signature_rejected_or_xfail(exc, f"tc{vec['tcId']}")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)

        generate_random(rs.raw, rs.sh, 64)


# --- RSA Signature 2048 SHA-256 ---


def _load_rsa_sig_vectors() -> list[dict[str, Any]]:
    if not (WYCHEPROOF_DIR / "rsa_signature_2048_sha256_test.json").exists():
        return []
    return load_wycheproof("rsa_signature_2048_sha256_test.json")


class TestRSASigWycheproof:
    """Wycheproof RSA PKCS#1 v1.5 signature verification vectors."""

    @pytest.mark.parametrize("vec", _load_rsa_sig_vectors(), ids=_vec_id)
    def test_rsa_sig_2048_sha256(self, p11_module_session: Any, vec: dict[str, Any]) -> None:
        rs = p11_module_session
        _skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        msg = bytes.fromhex(vec["msg"])
        sig = bytes.fromhex(vec["sig"])
        result = vec["result"]
        group = vec["_group"]

        pk = group.get("publicKey", {})
        modulus_hex = pk.get("modulus", "")
        exp_hex = pk.get("publicExponent", "")
        if not modulus_hex or not exp_hex:
            pytest.skip("No RSA public key in vector group")

        modulus = pkcs11_bigint_from_hex(modulus_hex)
        exponent = pkcs11_bigint_from_hex(exp_hex)

        try:
            pub_key = import_rsa_public_key_negotiated(
                rs,
                n=modulus,
                e=exponent,
                attrs={CKA_VERIFY: True},
            )
        except AssertionError as exc:
            if not isinstance(exc, CkrAssertionError):
                raise
            # Mechanism was advertised (has_mechanism gate passed above); a
            # negotiation-exhausted import refusal is "advertised but not
            # operational" -> xfail per the classification model.
            classify(
                "not_operational",
                label="SHA256_RSA_PKCS:key-import",
                summary=not_operational_reason(
                    "SHA256_RSA_PKCS:key-import",
                    ckr_name(exc.rv),
                ),
            )

        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_SHA256_RSA_PKCS, msg, sig)
            if result == "invalid":
                if verified:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label="SHA256_RSA_PKCS",
                        summary=f"Invalid RSA sig tc{vec['tcId']} accepted",
                        source=vec.get("_source"),
                        vector_id=vec.get("_vector_id"),
                    )
                return
            if result == "valid" and not verified:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="SHA256_RSA_PKCS",
                    summary=f"Valid RSA sig tc{vec['tcId']} rejected",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        except AssertionError as exc:
            if result == "valid":
                _xfail_if_generic_runtime_reject(
                    exc,
                    f"RSA PKCS#1 tc{vec['tcId']}",
                    "RSA PKCS#1 verify",
                )
                classify(
                    "not_operational",
                    label="SHA256_RSA_PKCS",
                    summary=f"Valid RSA sig tc{vec['tcId']} rejected",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            signature_rejected_or_xfail(exc, f"tc{vec['tcId']}")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)

        generate_random(rs.raw, rs.sh, 64)
