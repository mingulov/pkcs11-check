"""Centralized PKCS#11 CKR spec tables and assertion helpers.

Each CkrExpectation maps a (function, error condition) pair to:
- The spec-mandated CKR code(s)
- A broader acceptable error tuple for compat mode
- A reference to the OASIS spec section

Source of truth: https://github.com/oasis-tcs/pkcs11.git working/doc/spec/

NEVER catch generic PKCS11Error in CKR tests. Use assert_ckr() which
validates against the spec table — broad PKCS11Error catch in tests is
intentional because assert_ckr is the enforcement mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from pkcs11.exceptions import (
    DeviceError,
    DeviceMemory,
    DeviceRemoved,
    FunctionFailed,
    GeneralError,
    HostMemory,
    PKCS11Error,
    SessionClosed,
    SessionHandleInvalid,
    TokenNotPresent,
)

from p11test.testcases._error_tuples import (
    DATA_ERRORS,
    HANDLE_ERRORS,
    KEY_SIZE_ERRORS,
    MECHANISM_ERRORS,
    RESOURCE_ERRORS,
    SECURITY_POLICY_ERRORS,
    SESSION_ERRORS,
    TEMPLATE_ERRORS,
)

# ---------------------------------------------------------------------------
# Universal CKR codes (spec §5.1.1 – §5.1.3)
# ---------------------------------------------------------------------------

# Any function may return these (spec §5.1.1)
_UNIVERSAL = (GeneralError, HostMemory, FunctionFailed)

# Session-using functions additionally (spec §5.1.2)
_SESSION_UNIVERSAL = (SessionHandleInvalid, DeviceRemoved, SessionClosed)

# Token-using functions additionally (spec §5.1.3)
_TOKEN_UNIVERSAL = (DeviceMemory, DeviceError, TokenNotPresent)


def full_compat(base_tuple: tuple[type, ...], uses_session: bool = True) -> tuple[type, ...]:
    """Build full acceptable error set from base + universals.

    Duplicates with base_tuple (e.g. FunctionFailed already in most tuples)
    are harmless for isinstance() and kept for clarity — each layer adds
    what the spec says it may return.
    """
    result = base_tuple + _UNIVERSAL
    if uses_session:
        result += _SESSION_UNIVERSAL + _TOKEN_UNIVERSAL
    return result


# ---------------------------------------------------------------------------
# CkrExpectation dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CkrExpectation:
    """One error condition for one C_* function.

    Maps a (function, condition) pair to spec-mandated CKR code(s)
    and a broader acceptable set for compat mode.
    """

    function: str
    """C_* function name, e.g. 'C_EncryptInit'."""

    condition: str
    """Error condition description, e.g. 'mechanism_not_supported'."""

    spec_ckr: type | tuple[type, ...]
    """Spec-mandated CKR. Tuple if multiple are valid (first = preferred)."""

    compat_tuple: tuple[type, ...]
    """Acceptable CKR codes in compat mode (before universal injection)."""

    spec_ref: str
    """OASIS spec reference, e.g. 'PKCS#11 v3.1 §5.8.1'."""

    allow_success: bool = False
    """True if permissive modules may accept the operation."""

    testable: bool = True
    """False for conditions requiring NULL pointers or C-memory semantics."""

    mechanisms: list[str] = field(default_factory=list)
    """If mechanism-specific, which mechanisms this applies to."""

    priority_note: str = ""
    """Priority info, e.g. 'Higher priority than CKR_DATA_INVALID'."""


# ---------------------------------------------------------------------------
# assert_ckr — the single validation point
# ---------------------------------------------------------------------------


def assert_ckr(
    expectation: CkrExpectation,
    actual: PKCS11Error,
    strict: bool,
) -> None:
    """Validate CKR matches spec (strict) or is in acceptable set (compat).

    - Strict mode: error must match spec_ckr exactly. Deviation = test failure.
    - Compat mode: error must be in full_compat(compat_tuple). Deviation from
      spec_ckr is logged as compliance note, not failure.
    - Both modes: error outside the acceptable set = test failure.
    """
    spec_types = (
        expectation.spec_ckr
        if isinstance(expectation.spec_ckr, tuple)
        else (expectation.spec_ckr,)
    )

    if strict:
        if not isinstance(actual, spec_types):
            pytest.fail(
                f"{expectation.function}({expectation.condition}): "
                f"spec requires {[t.__name__ for t in spec_types]}, "
                f"got {type(actual).__name__} [{expectation.spec_ref}]"
            )
    else:
        full = full_compat(expectation.compat_tuple)
        if not isinstance(actual, full):
            pytest.fail(
                f"{expectation.function}({expectation.condition}): "
                f"got {type(actual).__name__}, not in acceptable set "
                f"{[t.__name__ for t in expectation.compat_tuple]}"
            )
        if not isinstance(actual, spec_types):
            from p11test.compliance import ComplianceLevel, note

            note(
                f"{expectation.function}({expectation.condition}): "
                f"spec says {[t.__name__ for t in spec_types]}, "
                f"got {type(actual).__name__}",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=expectation.spec_ref,
            )


# ---------------------------------------------------------------------------
# Spec tables — Encrypt family
# ---------------------------------------------------------------------------

# Imports for CKR types used in spec tables
from pkcs11.exceptions import (  # noqa: E402
    ArgumentsBad,
    AttributeReadOnly,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    CurveNotSupported,
    DataInvalid,
    DataLenRange,
    DomainParamsInvalid,
    EncryptedDataInvalid,
    EncryptedDataLenRange,
    KeyFunctionNotPermitted,
    KeyHandleInvalid,
    KeySizeRange,
    KeyTypeInconsistent,
    MechanismInvalid,
    MechanismParamInvalid,
    ObjectHandleInvalid,
    OperationActive,
    OperationNotInitialized,
    SignatureInvalid,
    SignatureLenRange,
    TemplateIncomplete,
    TemplateInconsistent,
)

CKR_ENCRYPT: dict[str, CkrExpectation] = {
    # --- C_EncryptInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="mechanism_not_supported",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.1",
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_EncryptInit",
        condition="key_CKA_ENCRYPT_is_False",
        spec_ckr=KeyFunctionNotPermitted,
        compat_tuple=(KeyFunctionNotPermitted, KeyTypeInconsistent, MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_EncryptInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        priority_note="Higher priority than CKR_KEY_FUNCTION_NOT_PERMITTED",
    ),
    "init_key_handle_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="invalid_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.1",
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        mechanisms=["AES_CBC"],
    ),
    # --- C_Encrypt errors ---
    "data_len_range": CkrExpectation(
        function="C_Encrypt",
        condition="data_not_block_aligned",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        priority_note="Higher priority than CKR_DATA_INVALID",
        mechanisms=["AES_ECB"],
    ),
    "data_empty": CkrExpectation(
        function="C_Encrypt",
        condition="empty_plaintext",
        spec_ckr=(DataLenRange, DataInvalid),
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        allow_success=True,
    ),
    "data_too_long_rsa": CkrExpectation(
        function="C_Encrypt",
        condition="RSA_PKCS_data_exceeds_k_minus_11",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        mechanisms=["RSA_PKCS"],
    ),
    "operation_not_initialized": CkrExpectation(
        function="C_Encrypt",
        condition="no_prior_C_EncryptInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.2",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Decrypt family (§5.9)
# ---------------------------------------------------------------------------

# Decrypt compat tuple: encrypted data errors + universal data errors
_DECRYPT_DATA_ERRORS = (
    EncryptedDataInvalid,
    EncryptedDataLenRange,
    DataLenRange,
    DataInvalid,
    ArgumentsBad,
    FunctionFailed,
)

CKR_DECRYPT: dict[str, CkrExpectation] = {
    # --- C_DecryptInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="mechanism_not_supported",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.1",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_DecryptInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.1",
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.1",
        mechanisms=["AES_CBC"],
    ),
    # --- C_Decrypt errors ---
    "encrypted_data_len_range": CkrExpectation(
        function="C_Decrypt",
        condition="ciphertext_not_block_aligned",
        spec_ckr=EncryptedDataLenRange,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        priority_note="Higher priority than CKR_ENCRYPTED_DATA_INVALID",
        mechanisms=["AES_ECB"],
    ),
    "encrypted_data_invalid": CkrExpectation(
        function="C_Decrypt",
        condition="garbage_ciphertext",
        spec_ckr=(EncryptedDataInvalid, EncryptedDataLenRange),
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        mechanisms=["AES_ECB"],
    ),
    "rsa_ciphertext_wrong_length": CkrExpectation(
        function="C_Decrypt",
        condition="RSA_ciphertext_wrong_length",
        spec_ckr=EncryptedDataLenRange,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        mechanisms=["RSA_PKCS"],
        allow_success=True,  # Kryoptic accepts wrong-length ciphertext (spec deviation)
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Sign family (§5.10)
# ---------------------------------------------------------------------------

CKR_SIGN: dict[str, CkrExpectation] = {
    # --- C_SignInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_SignInit",
        condition="mechanism_not_supported",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.1",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_SignInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.1",
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_SignInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.1",
    ),
    # --- C_Sign errors ---
    "data_len_range": CkrExpectation(
        function="C_Sign",
        condition="data_too_long_for_mechanism",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.2",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Verify family (§5.11)
# ---------------------------------------------------------------------------

CKR_VERIFY: dict[str, CkrExpectation] = {
    # --- C_VerifyInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_VerifyInit",
        condition="mechanism_not_supported",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.11.1",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_VerifyInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.1",
        allow_success=True,  # SoftHSM2 accepts AES key with RSA verify mechanism
    ),
    # --- C_Verify errors ---
    "signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="tampered_signature",
        spec_ckr=SignatureInvalid,
        compat_tuple=(SignatureInvalid, SignatureLenRange, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
    ),
    "signature_len_range": CkrExpectation(
        function="C_Verify",
        condition="signature_wrong_length",
        spec_ckr=SignatureLenRange,
        compat_tuple=(SignatureLenRange, SignatureInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
        priority_note="Higher priority than CKR_SIGNATURE_INVALID",
        allow_success=True,  # SoftHSM2 + Kryoptic accept wrong-length, then fail at verify
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Digest family (§5.12)
# ---------------------------------------------------------------------------

CKR_DIGEST: dict[str, CkrExpectation] = {
    # --- C_DigestInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_DigestInit",
        condition="mechanism_not_supported",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.12.1",
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_DigestInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.12.1",
    ),
    "init_encrypt_mechanism": CkrExpectation(
        function="C_DigestInit",
        condition="using_encrypt_mechanism_for_digest",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.12.1",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Key Generation family (§5.14)
# ---------------------------------------------------------------------------

CKR_KEYGEN: dict[str, CkrExpectation] = {
    # --- C_GenerateKey errors ---
    "genkey_mechanism_invalid": CkrExpectation(
        function="C_GenerateKey",
        condition="unsupported_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.1",
    ),
    "genkey_bad_size": CkrExpectation(
        function="C_GenerateKey",
        condition="invalid_key_size",
        spec_ckr=AttributeValueInvalid,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.1",
        allow_success=True,  # Kryoptic accepts AES key size 0 and non-standard sizes
    ),
    "genkey_template_incomplete": CkrExpectation(
        function="C_GenerateKey",
        condition="missing_required_attribute",
        spec_ckr=TemplateIncomplete,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.1",
    ),
    "genkey_template_inconsistent": CkrExpectation(
        function="C_GenerateKey",
        condition="conflicting_attributes",
        spec_ckr=TemplateInconsistent,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.1",
    ),
    # --- C_GenerateKeyPair errors ---
    "genkeypair_bad_size": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="invalid_key_size",
        spec_ckr=AttributeValueInvalid,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.2",
    ),
    "genkeypair_mechanism_invalid": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="unsupported_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.2",
    ),
    "genkeypair_curve_not_supported": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="unsupported_EC_curve",
        spec_ckr=CurveNotSupported,
        compat_tuple=(CurveNotSupported, DomainParamsInvalid, AttributeValueInvalid,
                      MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.2",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Derive family (§5.14.5)
# ---------------------------------------------------------------------------

CKR_DERIVE: dict[str, CkrExpectation] = {
    "mechanism_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="unsupported_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "key_type_inconsistent": CkrExpectation(
        function="C_DeriveKey",
        condition="base_key_type_wrong_for_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "mechanism_param_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
}
