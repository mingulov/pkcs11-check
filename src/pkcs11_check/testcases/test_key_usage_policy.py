"""Key usage policy enforcement tests.

Verifies that PKCS#11 modules enforce CKA_ENCRYPT, CKA_DECRYPT,
CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_ENCAPSULATE, and
CKA_DECAPSULATE capability flags.

These tests verify at the raw API level that C_EncryptInit / C_SignInit /
C_EncapsulateKey / C_DecapsulateKey etc. fail with appropriate CKR when the
key lacks the corresponding capability flag.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template, template_ptr_count
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_keypair,
    read_attributes,
    to_ubyte_buf,
)
from pkcs11_check.raw.rv import CkrAssertionError, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_DECRYPT,
    CKA_ENCAPSULATE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_ECB,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKP_ML_KEM_768,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_PARAMETER_SET_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    assert_correct,
    gen_rsa_keypair_or_xfail,
    require_operational_aes_keygen,
)

# Key-usage-policy guards classify 3-way via classify_negative_rv: running the
# forbidden function (CKR_OK) -> fail, the spec code
# CKR_KEY_FUNCTION_NOT_PERMITTED -> pass, any other clean reject (e.g.
# CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD, CKR_KEY_TYPE_INCONSISTENT) ->
# xfail.

pytestmark = pytest.mark.security


def _record_bool_readback(
    value: Any,
    *,
    attr: int,
    expected: bool | None,
    label: str,
    producer_operation: str,
    producer_mechanism: str,
) -> classification.Classification | None:
    """Record a present flag shape/value contradiction without stopping siblings."""
    if value is MISSING_ATTRIBUTE:
        return None
    detail: dict[str, Any] = {
        "attribute": {"name": ATTR_NAMES.get(int(attr), str(attr)), "id": int(attr)},
        "expected": "CK_BBOOL boolean" if expected is None else expected,
        "actual": repr(value),
        "producer_operation": producer_operation,
        "producer_mechanism": producer_mechanism,
    }
    if type(value) is not bool:
        detail["expected"] = "CK_BBOOL boolean"
        return classification.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=producer_mechanism,
            detail=detail,
            summary=f"{label}: present value has invalid CK_BBOOL shape: {value!r}",
        )
    if expected is None or value is expected:
        return None
    return classification.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=producer_mechanism,
        detail=detail,
        summary=f"{label}: expected {expected!r}, got {value!r}",
    )


def _raise_deferred_hard(records: list[classification.Classification]) -> None:
    """Raise a deferred provider contradiction after independent probes complete."""
    if records:
        # A later honest deviation must never hide an earlier hard contradiction.
        # Keep the reduction independent of probe/append order.
        priorities = {
            "CRITICAL": 3,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 0,
            "INFO": 0,
        }
        strongest = max(
            records,
            key=lambda record: (
                record.outcome == "fail",
                priorities.get(record.severity, 0),
            ),
        )
        classification.raise_for_record(strongest)


def _classify_policy_negative_rv(
    rv: int,
    *,
    operation: str,
    mechanism: str,
    label: str,
    expected: tuple[int, ...] = (CKR_KEY_FUNCTION_NOT_PERMITTED,),
) -> None:
    """Classify a raw policy return with exact operation and mechanism metadata.

    The operation identity is supplied directly on the record.  This avoids a
    nested set/clear context that can overwrite a caller's unrelated operation.
    """
    record = _record_policy_negative_rv(
        rv,
        operation=operation,
        mechanism=mechanism,
        label=label,
        expected=expected,
    )
    if record is not None:
        classification.raise_for_record(record)


def _record_policy_negative_rv(
    rv: int,
    *,
    operation: str,
    mechanism: str,
    label: str,
    expected: tuple[int, ...] = (CKR_KEY_FUNCTION_NOT_PERMITTED,),
) -> classification.Classification | None:
    """Record a policy return without terminating, for later precedence reduction."""
    if rv == CKR_OK:
        return classification.record_as(
            "accepted_invalid",
            kind="policy",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=expected,
            actual=rv,
            summary=f"{label}: accepted invalid (CKR_OK) -- must reject",
        )
    if rv in expected:
        return None
    reason = (
        "nonspec_reject"
        if is_standard_ckr(rv) or is_vendor_defined_ckr(rv)
        else "self_contradiction"
    )
    kind = "policy" if reason == "nonspec_reject" else "metadata"
    return classification.record_as(
        reason,
        kind=kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=expected,
        actual=rv,
    )


class TestAESKeyUsagePolicy:
    """Test AES key capability enforcement."""

    def test_encrypt_only_key_cannot_decrypt(self, p11_raw_session: Any) -> None:
        """AES key with ENCRYPT=True, DECRYPT=False cannot be used for decrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: False,
                CKA_SIGN: False,
                CKA_VERIFY: False,
            },
        )
        try:
            # Encrypt should succeed
            data = b"\x00" * 16
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
            assert_correct(
                actual=len(ct),
                expected=16,
                label="AES-ECB encryption output length",
                operation="C_Encrypt",
                mechanism="CKM_AES_ECB",
            )

            # DecryptInit should fail with KEY_FUNCTION_NOT_PERMITTED
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            _classify_policy_negative_rv(
                rv,
                operation="C_DecryptInit",
                mechanism="CKM_AES_ECB",
                label="C_DecryptInit on an AES key created CKA_DECRYPT=False",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_decrypt_only_key_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """AES key with DECRYPT=True, ENCRYPT=False cannot be used for encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: False,
                CKA_DECRYPT: True,
                CKA_SIGN: False,
                CKA_VERIFY: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_DECRYPT])
            decrypt = attr_or_record(
                attrs,
                CKA_DECRYPT,
                label="CKA_DECRYPT on decrypt-only AES key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_AES_KEY_GEN",
            )
            hard_records: list[classification.Classification] = []
            record = _record_bool_readback(
                decrypt,
                attr=CKA_DECRYPT,
                expected=True,
                label="CKA_DECRYPT on decrypt-only AES key",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            if record is not None:
                hard_records.append(record)

            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            _classify_policy_negative_rv(
                rv,
                operation="C_EncryptInit",
                mechanism="CKM_AES_ECB",
                label="C_EncryptInit on an AES key created CKA_ENCRYPT=False",
            )
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sign_only_key_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """Key with SIGN=True but ENCRYPT=False cannot encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_ENCRYPT: False,
                CKA_DECRYPT: False,
            },
        )
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            _classify_policy_negative_rv(
                rv,
                operation="C_EncryptInit",
                mechanism="CKM_AES_ECB",
                label="C_EncryptInit on a SIGN-only AES key created CKA_ENCRYPT=False",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_full_capabilities_key(self, p11_raw_session: Any) -> None:
        """Key with all capabilities can encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
            },
        )
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            assert_correct(
                actual=len(ct),
                expected=16,
                label="AES-ECB full-capability encryption output length",
                operation="C_Encrypt",
                mechanism="CKM_AES_ECB",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestRSAKeyUsagePolicy:
    """Test RSA key capability enforcement."""

    def test_sign_only_rsa_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """RSA key pair generated for signing only cannot encrypt."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={
                CKA_ENCRYPT: False,
                CKA_VERIFY: True,
                CKA_WRAP: False,
            },
            private_attrs={
                CKA_DECRYPT: False,
                CKA_SIGN: True,
                CKA_UNWRAP: False,
            },
        )
        try:
            hard_records: list[classification.Classification] = []
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SIGN])
            sign = attr_or_record(
                priv_attrs,
                CKA_SIGN,
                label="CKA_SIGN on sign-only RSA private key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            record = _record_bool_readback(
                sign,
                attr=CKA_SIGN,
                expected=True,
                label="CKA_SIGN on sign-only RSA private key",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if record is not None:
                hard_records.append(record)

            # Verify VERIFY is True on public
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_VERIFY])
            verify = attr_or_record(
                pub_attrs,
                CKA_VERIFY,
                label="CKA_VERIFY on sign-only RSA public key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            record = _record_bool_readback(
                verify,
                attr=CKA_VERIFY,
                expected=True,
                label="CKA_VERIFY on sign-only RSA public key",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if record is not None:
                hard_records.append(record)

            # Encrypt should fail on public key
            from pkcs11_check.raw.types_std import CKM_RSA_PKCS

            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), pub)
            _classify_policy_negative_rv(
                rv,
                operation="C_EncryptInit",
                mechanism="CKM_RSA_PKCS",
                label="C_EncryptInit on an RSA public key created CKA_ENCRYPT=False",
            )
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_encrypt_only_rsa_cannot_sign(self, p11_raw_session: Any) -> None:
        """RSA key pair generated for encryption only cannot sign."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={
                CKA_ENCRYPT: True,
                CKA_VERIFY: False,
                CKA_WRAP: False,
            },
            private_attrs={
                CKA_DECRYPT: True,
                CKA_SIGN: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            hard_records: list[classification.Classification] = []
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCRYPT])
            encrypt = attr_or_record(
                pub_attrs,
                CKA_ENCRYPT,
                label="CKA_ENCRYPT on encrypt-only RSA public key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            record = _record_bool_readback(
                encrypt,
                attr=CKA_ENCRYPT,
                expected=True,
                label="CKA_ENCRYPT on encrypt-only RSA public key",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if record is not None:
                hard_records.append(record)

            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DECRYPT])
            decrypt = attr_or_record(
                priv_attrs,
                CKA_DECRYPT,
                label="CKA_DECRYPT on encrypt-only RSA private key",
                reason="not_operational",
                kind="metadata",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            record = _record_bool_readback(
                decrypt,
                attr=CKA_DECRYPT,
                expected=True,
                label="CKA_DECRYPT on encrypt-only RSA private key",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if record is not None:
                hard_records.append(record)

            # Sign should fail on private key
            from pkcs11_check.raw.types_std import CKM_SHA256_RSA_PKCS

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            _classify_policy_negative_rv(
                rv,
                operation="C_SignInit",
                mechanism="CKM_SHA256_RSA_PKCS",
                label="C_SignInit on an RSA private key created CKA_SIGN=False",
            )
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestCapabilityReadback:
    """Verify capability flags are readable and consistent."""

    def test_aes_capabilities_match_template(self, p11_raw_session: Any) -> None:
        """Generated key's capability flags match what was requested."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: False,
                CKA_SIGN: False,
                CKA_VERIFY: False,
                CKA_WRAP: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            hard_records: list[classification.Classification] = []
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                key,
                [CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN],
            )
            for attr, expected, label in (
                (CKA_ENCRYPT, True, "CKA_ENCRYPT on AES capability key"),
                (CKA_DECRYPT, False, "CKA_DECRYPT on AES capability key"),
                (CKA_SIGN, False, "CKA_SIGN on AES capability key"),
            ):
                value = attr_or_record(
                    attrs,
                    attr,
                    label=label,
                    reason="not_operational",
                    kind="metadata",
                    mechanism="CKM_AES_KEY_GEN",
                )
                record = _record_bool_readback(
                    value,
                    attr=attr,
                    expected=expected,
                    label=label,
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                )
                if record is not None:
                    hard_records.append(record)
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_capabilities_match_template(self, p11_raw_session: Any) -> None:
        """RSA keypair flags match what was requested."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_VERIFY: False},
            private_attrs={CKA_DECRYPT: True, CKA_SIGN: False},
        )
        try:
            hard_records: list[classification.Classification] = []
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCRYPT, CKA_VERIFY])
            for attr, expected, label in (
                (CKA_ENCRYPT, True, "CKA_ENCRYPT on RSA capability public key"),
                (CKA_VERIFY, False, "CKA_VERIFY on RSA capability public key"),
            ):
                value = attr_or_record(
                    pub_attrs,
                    attr,
                    label=label,
                    reason="not_operational",
                    kind="metadata",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                record = _record_bool_readback(
                    value,
                    attr=attr,
                    expected=expected,
                    label=label,
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                if record is not None:
                    hard_records.append(record)

            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DECRYPT, CKA_SIGN])
            for attr, expected, label in (
                (CKA_DECRYPT, True, "CKA_DECRYPT on RSA capability private key"),
                (CKA_SIGN, False, "CKA_SIGN on RSA capability private key"),
            ):
                value = attr_or_record(
                    priv_attrs,
                    attr,
                    label=label,
                    reason="not_operational",
                    kind="metadata",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                record = _record_bool_readback(
                    value,
                    attr=attr,
                    expected=expected,
                    label=label,
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                if record is not None:
                    hard_records.append(record)
            _raise_deferred_hard(hard_records)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# ML-KEM shared-secret size used in encapsulation templates (FIPS 203)
# ---------------------------------------------------------------------------
_ML_KEM_SHARED_SECRET_BYTES = 32
_ML_KEM_768_CIPHERTEXT_BYTES = 1088
_ML_KEM_MAX_CIPHERTEXT_BYTES = 1568

_ML_KEM_SETUP_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_PARAMETER_SET_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _xfail_ml_kem_setup_reject(
    exc: CkrAssertionError,
    label: str,
    *,
    operation: str,
    mechanism: str,
) -> None:
    """Expose a clean advertised ML-KEM setup refusal with exact context."""
    rv = exc.rv
    if rv == CKR_OK:
        record = classification.record_as(
            "accepted_invalid",
            kind="policy",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_OK,
            actual=rv,
            summary=f"{label}: setup unexpectedly returned CKR_OK",
        )
        classification.raise_for_record(record)
    if rv in _ML_KEM_SETUP_REJECT_RVS or is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        record = classification.record_as(
            "not_operational",
            kind="policy",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_OK,
            actual=rv,
            summary=f"{label}: setup refused with CK_RV",
        )
        classification.raise_for_record(record)
    record = classification.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=CKR_OK,
        actual=rv,
        summary=f"{label}: setup returned an undefined CK_RV",
    )
    classification.raise_for_record(record)


def _gen_ml_kem_keypair(
    rs: Any,
    *,
    encapsulate: bool = True,
    decapsulate: bool = True,
) -> tuple[int, int]:
    """Generate an ML-KEM-768 keypair with the given usage flags.

    Returns ``(pub_handle, priv_handle)``.  The caller owns both objects and
    must destroy them in a ``finally`` block.

    If the module does not support ``CKM_ML_KEM_KEY_PAIR_GEN`` the caller
    should guard with ``rs.has_mechanism("ML_KEM")`` before calling this.
    """
    pub, priv = gen_keypair(
        rs.raw,
        rs.sh,
        CKM_ML_KEM_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768)],
        priv_base=[],
        public_attrs={
            CKA_TOKEN: False,
            CKA_ENCAPSULATE: encapsulate,
        },
        private_attrs={
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: False,
            CKA_DECAPSULATE: decapsulate,
        },
        pub_skip={CKA_PARAMETER_SET},
    )
    return pub, priv


def _ml_kem_secret_template() -> dict[int, Any]:
    """Minimal encapsulation/decapsulation output template (GENERIC_SECRET, 32 B)."""
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_VALUE_LEN: _ML_KEM_SHARED_SECRET_BYTES,
    }


def _remember_handle(handles: list[int], seen: set[int], handle: Any) -> None:
    """Retain a raw output handle exactly once, including exceptional writes."""
    value = int(getattr(handle, "value", handle) or 0)
    if value and value not in seen:
        seen.add(value)
        handles.append(value)


def _destroy_owned_handles(
    raw: Any,
    session: Any,
    handles: list[int],
    *,
    pending: BaseException | None,
) -> None:
    """Destroy every deduplicated handle while preserving an earlier exception."""
    cleanup_errors: list[tuple[int, BaseException]] = []
    for handle in handles:
        try:
            destroy_quietly(raw, session, handle)
        except BaseException as exc:
            cleanup_errors.append((handle, exc))
    for handle, cleanup_exc in cleanup_errors:
        classification.record_as(
            "harness_error",
            kind="lifecycle",
            label=f"C_DestroyObject cleanup for owned handle {handle}",
            operation="C_DestroyObject",
            detail={
                "handle": handle,
                "exception_type": type(cleanup_exc).__name__,
                "exception": repr(cleanup_exc),
            },
            summary=(
                "C_DestroyObject cleanup raised "
                f"{type(cleanup_exc).__name__} for owned handle {handle}"
            ),
        )
    if cleanup_errors:
        cleanup_error = cleanup_errors[0][1]
        if pending is None or getattr(pending, "_pkcs11_check_classification", None) is not None:
            raise cleanup_error


def _record_handle_on_rejection(
    *,
    operation: str,
    rv: int,
    handle: Any,
) -> classification.Classification | None:
    """Expose an output handle written on a rejecting call, without treating it as effect."""
    value = int(getattr(handle, "value", handle) or 0)
    if rv == CKR_OK or value == 0:
        return None
    return classification.record_as(
        "wrong_result",
        kind="lifecycle",
        label=f"{operation} output handle on rejecting return",
        operation=operation,
        mechanism="CKM_ML_KEM",
        expected=(CKR_OK,),
        actual=rv,
        detail={
            "expected_handle": 0,
            "actual_handle": value,
            "return_value": rv,
        },
        summary=(
            f"{operation} wrote output handle {value} while returning a rejection; "
            "the handle is retained for cleanup but is not policy effect evidence"
        ),
    )


def _record_kem_length(
    *,
    phase: str,
    operation: str,
    rv: int,
    length: int,
    capacity: int,
) -> classification.Classification | None:
    """Record a malformed ML-KEM ciphertext length without consuming it."""
    if rv == CKR_BUFFER_TOO_SMALL:
        valid = length in (0, _ML_KEM_768_CIPHERTEXT_BYTES)
    else:
        valid = length == _ML_KEM_768_CIPHERTEXT_BYTES
    if valid and length <= capacity:
        return None
    return classification.record_as(
        "wrong_result",
        kind="crypto",
        label=f"ML-KEM-768 {phase} ciphertext output",
        operation=operation,
        mechanism="CKM_ML_KEM",
        expected=(CKR_OK, CKR_BUFFER_TOO_SMALL),
        actual=rv,
        detail={
            "phase": phase,
            "expected_length": _ML_KEM_768_CIPHERTEXT_BYTES,
            "actual_length": length,
            "capacity": capacity,
            "return_value": rv,
        },
        summary=(
            f"ML-KEM-768 {phase} ciphertext output has invalid length/capacity; "
            "the result is not safe policy input"
        ),
    )


def _record_kem_setup_rv(
    rv: int,
    *,
    operation: str,
    label: str,
    expected: tuple[int, ...] = (CKR_OK, CKR_BUFFER_TOO_SMALL),
) -> classification.Classification | None:
    """Record a setup/query CK_RV deviation while allowing independent probes."""
    if rv in expected:
        return None
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        reason = "not_operational"
        kind = "policy"
    else:
        reason = "self_contradiction"
        kind = "metadata"
    return classification.record_as(
        reason,
        kind=kind,
        label=label,
        operation=operation,
        mechanism="CKM_ML_KEM",
        expected=expected,
        actual=rv,
    )


@pytest.mark.v32
@pytest.mark.needs_function("C_EncapsulateKey")
class TestKEMKeyUsagePolicy:
    """Verify CKA_ENCAPSULATE and CKA_DECAPSULATE flag enforcement.

    PKCS#11 v3.2 Sec.5.14.7 requires ``CKR_KEY_FUNCTION_NOT_PERMITTED`` when
    ``CKA_ENCAPSULATE`` is ``False`` on the public key supplied to
    ``C_EncapsulateKey``.  Sec.5.14.8 imposes the same requirement for
    ``CKA_DECAPSULATE`` on the private key supplied to ``C_DecapsulateKey``.

    Classification (3-way via ``classify_negative_rv`` / ``classify_policy_enforcement``):
    - ``CKR_OK`` from the forbidden operation → ``fail`` (policy bypass).
    - ``CKR_KEY_FUNCTION_NOT_PERMITTED`` → ``pass`` (spec-correct enforcement).
    - any other clean rejection → ``xfail`` (noted deviation).

    Setup failures (keypair creation refused, keygen not operational) remain
    visible as context-rich xfails; only an unadvertised mechanism is skipped.
    """

    def test_encapsulate_flag_false_rejected(self, p11_raw_session: Any) -> None:
        """C_EncapsulateKey is rejected when public key has CKA_ENCAPSULATE=False.

        Spec: PKCS#11 v3.2 Sec.5.14.7 — ``CKR_KEY_FUNCTION_NOT_PERMITTED``
        when ``CKA_ENCAPSULATE`` is ``False``.

        This probe drives the *full* encapsulation, not just the size-query
        call, because some modules validate output-buffer availability before
        checking key permissions and return ``CKR_BUFFER_TOO_SMALL`` on a
        size-query-only call.  We use the reported ciphertext length when the
        module supplies it, and fall back to a buffer larger than the largest
        standard ML-KEM ciphertext (1568 B for ML-KEM-1024) otherwise.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("CKM_ML_KEM not supported")

        try:
            pub, priv = _gen_ml_kem_keypair(rs, encapsulate=False)
        except CkrAssertionError as exc:
            _xfail_ml_kem_setup_reject(
                exc,
                "ML-KEM keypair generation with CKA_ENCAPSULATE=False is not operational",
                operation="C_GenerateKeyPair",
                mechanism="CKM_ML_KEM_KEY_PAIR_GEN",
            )

        from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CK_ULONG

        returned_handles: list[int] = []
        seen_handles: set[int] = set()
        deferred_records: list[classification.Classification] = []
        pending: BaseException | None = None
        try:
            mech = mech_simple(CKM_ML_KEM)
            tmpl_attrs = _ml_kem_secret_template()
            packed = [
                attr_ulong(CKA_CLASS, tmpl_attrs[CKA_CLASS]),
                attr_ulong(CKA_KEY_TYPE, tmpl_attrs[CKA_KEY_TYPE]),
                attr_ulong(CKA_VALUE_LEN, tmpl_attrs[CKA_VALUE_LEN]),
                attr_bool(CKA_SENSITIVE, tmpl_attrs[CKA_SENSITIVE]),
                attr_bool(CKA_EXTRACTABLE, tmpl_attrs[CKA_EXTRACTABLE]),
            ]
            tmpl = template(*packed)

            # Each raw call has its own mutable output state.  Providers may
            # overwrite the handle between calls, or write it before raising.
            query_handle = CK_OBJECT_HANDLE(0)
            query_len = CK_ULONG(0)
            try:
                size_rv = rs.raw.C_EncapsulateKey(
                    rs.sh,
                    mech.byref(),
                    pub,
                    *template_ptr_count(tmpl),
                    None,
                    byref(query_len),
                    byref(query_handle),
                )
            finally:
                _remember_handle(returned_handles, seen_handles, query_handle)

            query_record = _record_kem_setup_rv(
                size_rv,
                operation="C_EncapsulateKey",
                label="ML-KEM C_EncapsulateKey size query",
                expected=(CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_KEY_FUNCTION_NOT_PERMITTED),
            )
            if query_record is not None:
                deferred_records.append(query_record)
            query_handle_record = _record_handle_on_rejection(
                operation="C_EncapsulateKey",
                rv=size_rv,
                handle=query_handle,
            )
            if query_handle_record is not None:
                deferred_records.append(query_handle_record)
            if size_rv == CKR_KEY_FUNCTION_NOT_PERMITTED:
                _classify_policy_negative_rv(
                    size_rv,
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    label="C_EncapsulateKey with CKA_ENCAPSULATE=False on public key "
                    "(PKCS#11 v3.2 Sec.5.14.7)",
                )
                if query_handle_record is not None:
                    classification.raise_for_record(query_handle_record)
                return

            reported_query_len = int(query_len.value)
            query_capacity = min(
                max(reported_query_len, _ML_KEM_768_CIPHERTEXT_BYTES),
                _ML_KEM_MAX_CIPHERTEXT_BYTES,
            )
            query_length_record = (
                _record_kem_length(
                    phase="size-query",
                    operation="C_EncapsulateKey",
                    rv=size_rv,
                    length=reported_query_len,
                    capacity=query_capacity,
                )
                if size_rv in (CKR_OK, CKR_BUFFER_TOO_SMALL)
                else None
            )
            if query_length_record is not None:
                deferred_records.append(query_length_record)

            full_handle = CK_OBJECT_HANDLE(0)
            full_len = CK_ULONG(query_capacity)
            ct_buf = (ctypes.c_ubyte * query_capacity)()
            try:
                rv = rs.raw.C_EncapsulateKey(
                    rs.sh,
                    mech.byref(),
                    pub,
                    *template_ptr_count(tmpl),
                    ct_buf,
                    byref(full_len),
                    byref(full_handle),
                )
            finally:
                _remember_handle(returned_handles, seen_handles, full_handle)

            # BUFFER_TOO_SMALL is useful for negotiating a size query only.  A
            # clean refusal from the full call remains an xfail unless it is the
            # exact policy CKR; a handle from the query cannot change that.  Defer
            # the refusal until any earlier query effect has been inspected.
            full_refusal_record = None
            if rv != CKR_OK:
                full_refusal_record = _record_policy_negative_rv(
                    rv,
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    label="C_EncapsulateKey with CKA_ENCAPSULATE=False on public key "
                    "(PKCS#11 v3.2 Sec.5.14.7)",
                )
                if full_refusal_record is not None:
                    deferred_records.append(full_refusal_record)
                full_handle_record = _record_handle_on_rejection(
                    operation="C_EncapsulateKey",
                    rv=rv,
                    handle=full_handle,
                )
                if full_handle_record is not None:
                    deferred_records.append(full_handle_record)

            full_effect = rv == CKR_OK and bool(full_handle.value)
            if rv == CKR_OK and not full_effect:
                deferred_records.append(
                    classification.record_as(
                        "wrong_result",
                        kind="crypto",
                        label="ML-KEM C_EncapsulateKey full-call output handle",
                        operation="C_EncapsulateKey",
                        mechanism="CKM_ML_KEM",
                        expected=(CKR_OK,),
                        actual=CKR_OK,
                        detail={"expected_handle": "non-zero", "actual_handle": 0},
                        summary=("C_EncapsulateKey returned CKR_OK without an output handle"),
                    )
                )
            full_length_record = (
                _record_kem_length(
                    phase="full-call",
                    operation="C_EncapsulateKey",
                    rv=rv,
                    length=int(full_len.value),
                    capacity=query_capacity,
                )
                if rv in (CKR_OK, CKR_BUFFER_TOO_SMALL)
                else None
            )
            if full_length_record is not None:
                deferred_records.append(full_length_record)

            size_query_effect = size_rv == CKR_OK and bool(query_handle.value)
            # A successful query handle proves an effect independently of the
            # reported ciphertext length. Malformed full output still disables
            # its dependent oracle without suppressing the query handle effect.
            if size_query_effect or (full_effect and full_length_record is None):
                encap_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCAPSULATE])
                encap = attr_or_record(
                    encap_attrs,
                    CKA_ENCAPSULATE,
                    label="CKA_ENCAPSULATE=False on ML-KEM public key",
                    reason="not_operational",
                    kind="policy",
                    mechanism="CKM_ML_KEM",
                )
                hard_record = _record_bool_readback(
                    encap,
                    attr=CKA_ENCAPSULATE,
                    expected=None,
                    label="CKA_ENCAPSULATE=False on ML-KEM public key",
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism="CKM_ML_KEM_KEY_PAIR_GEN",
                )
                if hard_record is not None:
                    deferred_records.append(hard_record)
                elif encap is MISSING_ATTRIBUTE:
                    deferred_records.append(
                        classification.record_as(
                            "not_operational",
                            kind="policy",
                            label=(
                                "C_EncapsulateKey with missing CKA_ENCAPSULATE readback "
                                "on public key"
                            ),
                            operation="C_EncapsulateKey",
                            mechanism="CKM_ML_KEM",
                            expected=(CKR_KEY_FUNCTION_NOT_PERMITTED,),
                            actual=CKR_OK,
                            summary=(
                                "C_EncapsulateKey returned CKR_OK but CKA_ENCAPSULATE "
                                "was unavailable; policy effect is unobservable"
                            ),
                        )
                    )
                else:
                    reason = "accepted_invalid" if encap is False else "honest_deviation"
                    deferred_records.append(
                        classification.record_as(
                            reason,
                            kind="policy",
                            label="C_EncapsulateKey with CKA_ENCAPSULATE=False on public key",
                            operation="C_EncapsulateKey",
                            mechanism="CKM_ML_KEM",
                            expected=(CKR_KEY_FUNCTION_NOT_PERMITTED,),
                            actual=CKR_OK,
                            summary=(
                                "C_EncapsulateKey returned CKR_OK for a public key claiming "
                                "CKA_ENCAPSULATE=False"
                            ),
                        )
                    )
        except BaseException as exc:
            pending = exc
            raise
        finally:
            _remember_handle(returned_handles, seen_handles, pub)
            _remember_handle(returned_handles, seen_handles, priv)
            _destroy_owned_handles(
                rs.raw,
                rs.sh,
                returned_handles,
                pending=pending,
            )
        _raise_deferred_hard(deferred_records)

    def test_decapsulate_flag_false_rejected(self, p11_raw_session: Any) -> None:
        """C_DecapsulateKey is rejected when private key has CKA_DECAPSULATE=False.

        Spec: PKCS#11 v3.2 Sec.5.14.8 — ``CKR_KEY_FUNCTION_NOT_PERMITTED``
        when ``CKA_DECAPSULATE`` is ``False``.

        A valid ciphertext is obtained with the restricted public key itself
        (``CKA_ENCAPSULATE=True``) so the decapsulation attempt is well-formed;
        only the private key's permission flag is restricted.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("CKM_ML_KEM not supported")

        # Use the restricted keypair for both setup and the policy probe.  This
        # keeps the ciphertext/key relationship explicit and avoids creating an
        # unrelated normal pair that can mask lifecycle failures.
        restr_pub = restr_priv = 0
        try:
            restr_pub, restr_priv = _gen_ml_kem_keypair(rs, encapsulate=True, decapsulate=False)
        except CkrAssertionError as exc:
            _xfail_ml_kem_setup_reject(
                exc,
                "ML-KEM keypair generation with CKA_DECAPSULATE=False is not operational",
                operation="C_GenerateKeyPair",
                mechanism="CKM_ML_KEM_KEY_PAIR_GEN",
            )

        returned_handles: list[int] = []
        seen_handles: set[int] = set()
        deferred_records: list[classification.Classification] = []
        pending: BaseException | None = None
        try:
            # Build the setup operation locally so both two-call output handles
            # remain available for teardown if the provider overwrites or writes
            # them before raising.
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CK_ULONG

            encap_mech = mech_simple(CKM_ML_KEM)
            encap_template = _ml_kem_secret_template()
            encap_packed = [
                attr_ulong(CKA_CLASS, encap_template[CKA_CLASS]),
                attr_ulong(CKA_KEY_TYPE, encap_template[CKA_KEY_TYPE]),
                attr_ulong(CKA_VALUE_LEN, encap_template[CKA_VALUE_LEN]),
                attr_bool(CKA_SENSITIVE, encap_template[CKA_SENSITIVE]),
                attr_bool(CKA_EXTRACTABLE, encap_template[CKA_EXTRACTABLE]),
            ]
            encap_tmpl = template(*encap_packed)

            query_handle = CK_OBJECT_HANDLE(0)
            query_len = CK_ULONG(0)
            try:
                size_rv = rs.raw.C_EncapsulateKey(
                    rs.sh,
                    encap_mech.byref(),
                    restr_pub,
                    *template_ptr_count(encap_tmpl),
                    None,
                    byref(query_len),
                    byref(query_handle),
                )
            finally:
                _remember_handle(returned_handles, seen_handles, query_handle)

            if size_rv not in (CKR_OK, CKR_BUFFER_TOO_SMALL):
                query_record = _record_kem_setup_rv(
                    size_rv,
                    operation="C_EncapsulateKey",
                    label="ML-KEM C_EncapsulateKey setup size query",
                    expected=(CKR_OK,),
                )
                if query_record is not None:
                    deferred_records.append(query_record)
                query_handle_record = _record_handle_on_rejection(
                    operation="C_EncapsulateKey",
                    rv=size_rv,
                    handle=query_handle,
                )
                if query_handle_record is not None:
                    deferred_records.append(query_handle_record)
                _raise_deferred_hard(deferred_records)
            query_handle_record = _record_handle_on_rejection(
                operation="C_EncapsulateKey",
                rv=size_rv,
                handle=query_handle,
            )
            if query_handle_record is not None:
                deferred_records.append(query_handle_record)
            query_capacity = min(
                max(int(query_len.value), _ML_KEM_768_CIPHERTEXT_BYTES),
                _ML_KEM_MAX_CIPHERTEXT_BYTES,
            )
            query_length_record = (
                _record_kem_length(
                    phase="size-query",
                    operation="C_EncapsulateKey",
                    rv=size_rv,
                    length=int(query_len.value),
                    capacity=query_capacity,
                )
                if size_rv in (CKR_OK, CKR_BUFFER_TOO_SMALL)
                else None
            )
            if query_length_record is not None:
                deferred_records.append(query_length_record)

            full_handle = CK_OBJECT_HANDLE(0)
            full_len = CK_ULONG(query_capacity)
            ct_buf = (ctypes.c_ubyte * query_capacity)()
            try:
                full_rv = rs.raw.C_EncapsulateKey(
                    rs.sh,
                    encap_mech.byref(),
                    restr_pub,
                    *template_ptr_count(encap_tmpl),
                    ct_buf,
                    byref(full_len),
                    byref(full_handle),
                )
            finally:
                _remember_handle(returned_handles, seen_handles, full_handle)

            if full_rv != CKR_OK:
                full_record = _record_kem_setup_rv(
                    full_rv,
                    operation="C_EncapsulateKey",
                    label="ML-KEM C_EncapsulateKey setup full call",
                    expected=(CKR_OK,),
                )
                if full_record is not None:
                    deferred_records.append(full_record)
                full_handle_record = _record_handle_on_rejection(
                    operation="C_EncapsulateKey",
                    rv=full_rv,
                    handle=full_handle,
                )
                if full_handle_record is not None:
                    deferred_records.append(full_handle_record)
                _raise_deferred_hard(deferred_records)
            full_length_record = (
                _record_kem_length(
                    phase="full-call",
                    operation="C_EncapsulateKey",
                    rv=full_rv,
                    length=int(full_len.value),
                    capacity=query_capacity,
                )
                if full_rv in (CKR_OK, CKR_BUFFER_TOO_SMALL)
                else None
            )
            if full_length_record is not None:
                deferred_records.append(full_length_record)
            if not full_handle.value:
                deferred_records.append(
                    classification.record_as(
                        "wrong_result",
                        kind="crypto",
                        label="ML-KEM C_EncapsulateKey setup output handle",
                        operation="C_EncapsulateKey",
                        mechanism="CKM_ML_KEM",
                        expected=(CKR_OK,),
                        actual=CKR_OK,
                        detail={"expected_handle": "non-zero", "actual_handle": 0},
                        summary="ML-KEM C_EncapsulateKey returned CKR_OK without an output handle",
                    )
                )

            # Never truncate a malformed provider result into apparently valid
            # ciphertext.  Decapsulation is skipped until both length and
            # capacity are exact.
            if full_length_record is None and full_handle.value:
                ct = bytes(ct_buf[: int(full_len.value)])
                handle = CK_OBJECT_HANDLE(0)
                mech = mech_simple(CKM_ML_KEM)
                packed = [
                    attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                    attr_ulong(CKA_KEY_TYPE, CKK_AES),
                ]
                tmpl = template(*packed)
                decap_buf = to_ubyte_buf(ct)
                try:
                    rv = rs.raw.C_DecapsulateKey(
                        rs.sh,
                        mech.byref(),
                        restr_priv,
                        *template_ptr_count(tmpl),
                        decap_buf,
                        len(ct),
                        byref(handle),
                    )
                finally:
                    _remember_handle(returned_handles, seen_handles, handle)

                if rv != CKR_OK:
                    refusal_record = _record_policy_negative_rv(
                        rv,
                        operation="C_DecapsulateKey",
                        mechanism="CKM_ML_KEM",
                        label="C_DecapsulateKey with CKA_DECAPSULATE=False on private key "
                        "(PKCS#11 v3.2 Sec.5.14.8)",
                    )
                    if refusal_record is not None:
                        deferred_records.append(refusal_record)
                    handle_record = _record_handle_on_rejection(
                        operation="C_DecapsulateKey",
                        rv=rv,
                        handle=handle,
                    )
                    if handle_record is not None:
                        deferred_records.append(handle_record)
                elif not handle.value:
                    deferred_records.append(
                        classification.record_as(
                            "wrong_result",
                            kind="crypto",
                            label="ML-KEM C_DecapsulateKey output handle",
                            operation="C_DecapsulateKey",
                            mechanism="CKM_ML_KEM",
                            expected=(CKR_OK,),
                            actual=CKR_OK,
                            detail={"expected_handle": "non-zero", "actual_handle": 0},
                            summary="C_DecapsulateKey returned CKR_OK without an output handle",
                        )
                    )
                else:
                    # rv == CKR_OK — check whether the flag was actually claimed.
                    decap_attrs = read_attributes(rs.raw, rs.sh, restr_priv, [CKA_DECAPSULATE])
                    decap = attr_or_record(
                        decap_attrs,
                        CKA_DECAPSULATE,
                        label="CKA_DECAPSULATE=False on ML-KEM private key",
                        reason="not_operational",
                        kind="policy",
                        mechanism="CKM_ML_KEM",
                    )
                    hard_record = _record_bool_readback(
                        decap,
                        attr=CKA_DECAPSULATE,
                        expected=None,
                        label="CKA_DECAPSULATE=False on ML-KEM private key",
                        producer_operation="C_GenerateKeyPair",
                        producer_mechanism="CKM_ML_KEM_KEY_PAIR_GEN",
                    )
                    if hard_record is not None:
                        deferred_records.append(hard_record)
                    elif decap is MISSING_ATTRIBUTE:
                        deferred_records.append(
                            classification.record_as(
                                "not_operational",
                                kind="policy",
                                label=(
                                    "C_DecapsulateKey with missing CKA_DECAPSULATE "
                                    "readback on private key"
                                ),
                                operation="C_DecapsulateKey",
                                mechanism="CKM_ML_KEM",
                                expected=(CKR_KEY_FUNCTION_NOT_PERMITTED,),
                                actual=CKR_OK,
                                summary=(
                                    "C_DecapsulateKey returned CKR_OK but "
                                    "CKA_DECAPSULATE was unavailable; policy effect "
                                    "is unobservable"
                                ),
                            )
                        )
                    else:
                        reason = "accepted_invalid" if decap is False else "honest_deviation"
                        deferred_records.append(
                            classification.record_as(
                                reason,
                                kind="policy",
                                label=(
                                    "C_DecapsulateKey with CKA_DECAPSULATE=False on private key"
                                ),
                                operation="C_DecapsulateKey",
                                mechanism="CKM_ML_KEM",
                                expected=(CKR_KEY_FUNCTION_NOT_PERMITTED,),
                                actual=CKR_OK,
                                summary=(
                                    "C_DecapsulateKey returned CKR_OK for a private "
                                    "key claiming CKA_DECAPSULATE=False"
                                ),
                            )
                        )
        except BaseException as exc:
            pending = exc
            raise
        finally:
            _remember_handle(returned_handles, seen_handles, restr_pub)
            _remember_handle(returned_handles, seen_handles, restr_priv)
            _destroy_owned_handles(
                rs.raw,
                rs.sh,
                returned_handles,
                pending=pending,
            )
        _raise_deferred_hard(deferred_records)
