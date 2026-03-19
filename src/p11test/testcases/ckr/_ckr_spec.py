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
    ActionProhibited,
    ArgumentsBad,
    AttributeReadOnly,
    AttributeSensitive,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    BufferTooSmall,
    CurveNotSupported,
    DataInvalid,
    DataLenRange,
    DomainParamsInvalid,
    EncryptedDataInvalid,
    EncryptedDataLenRange,
    FunctionNotSupported,
    KeyFunctionNotPermitted,
    KeyHandleInvalid,
    KeyIndigestible,
    KeySizeRange,
    KeyTypeInconsistent,
    MechanismInvalid,
    MechanismParamInvalid,
    ObjectHandleInvalid,
    OperationActive,
    OperationNotInitialized,
    PinExpired,
    SessionReadOnly,
    SignatureInvalid,
    SignatureLenRange,
    TemplateIncomplete,
    TemplateInconsistent,
    UserNotLoggedIn,
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
    "init_key_size_range": CkrExpectation(
        function="C_EncryptInit",
        condition="key_size_out_of_range",
        spec_ckr=KeySizeRange,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.1",
    ),
    "data_invalid_cbc_padding": CkrExpectation(
        function="C_Encrypt",
        condition="AES_CBC_PAD_non_block_aligned_accepted",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        mechanisms=["AES_CBC_PAD"],
        allow_success=True,  # CBC-PAD handles non-aligned data by design
    ),
    "data_gcm_aad_only": CkrExpectation(
        function="C_Encrypt",
        condition="AES_GCM_empty_plaintext_with_AAD",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        mechanisms=["AES_GCM"],
        allow_success=True,  # GCM can encrypt 0 bytes with just AAD
    ),
    # --- C_EncryptUpdate errors ---
    "update_data_len_range": CkrExpectation(
        function="C_EncryptUpdate",
        condition="non_aligned_partial_block",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.3",
        mechanisms=["AES_ECB"],
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_EncryptUpdate",
        condition="no_prior_C_EncryptInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.3",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    # --- C_EncryptFinal errors ---
    "final_data_len_range": CkrExpectation(
        function="C_EncryptFinal",
        condition="incomplete_block_at_finalize",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.4",
        mechanisms=["AES_ECB"],
        testable=False,
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_EncryptFinal",
        condition="no_prior_C_EncryptInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.4",
        testable=False,
    ),
    # --- Additional C_EncryptInit errors ---
    "init_operation_active": CkrExpectation(
        function="C_EncryptInit",
        condition="init_called_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        testable=False,  # Wrapper manages state
    ),
    "init_user_not_logged_in": CkrExpectation(
        function="C_EncryptInit",
        condition="key_requires_login",
        spec_ckr=UserNotLoggedIn,
        compat_tuple=(UserNotLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        testable=False,  # Would need logout-then-encrypt, risky
    ),
    # --- Additional C_Encrypt errors ---
    "data_invalid_general": CkrExpectation(
        function="C_Encrypt",
        condition="invalid_plaintext_content",
        spec_ckr=DataInvalid,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        allow_success=True,
    ),
    # --- Mechanism-specific C_EncryptInit errors ---
    "rsa_oaep_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="RSA_OAEP_with_wrong_hash_in_params",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    "aes_gcm_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="AES_GCM_with_wrong_IV_length",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        mechanisms=["AES_GCM"],
    ),
    "aes_cbc_iv_wrong_length": CkrExpectation(
        function="C_EncryptInit",
        condition="AES_CBC_with_8_byte_IV",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        mechanisms=["AES_CBC"],
    ),
    # --- Mechanism-specific C_Encrypt errors ---
    "rsa_pkcs_data_too_short": CkrExpectation(
        function="C_Encrypt",
        condition="RSA_PKCS_zero_byte_plaintext",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        mechanisms=["RSA_PKCS"],
        allow_success=True,  # Some modules accept empty plaintext for RSA-PKCS
    ),
    "rsa_oaep_data_too_long": CkrExpectation(
        function="C_Encrypt",
        condition="RSA_OAEP_plaintext_exceeds_k_minus_2hLen_minus_2",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    "aes_gcm_data_overflow": CkrExpectation(
        function="C_Encrypt",
        condition="AES_GCM_plaintext_exceeds_theoretical_limit",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
        mechanisms=["AES_GCM"],
        testable=False,  # Limit is 2^39-256 bits — impractical to test
    ),
    # --- Additional C_EncryptInit errors ---
    "init_function_canceled": CkrExpectation(
        function="C_EncryptInit",
        condition="operation_canceled_by_callback",
        spec_ckr=FunctionFailed,  # FunctionCanceled not in fork — use FunctionFailed
        compat_tuple=(FunctionFailed,),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        testable=False,  # Requires registered callback to cancel — not exposed by python-pkcs11
    ),
    "init_operation_cancel_failed": CkrExpectation(
        function="C_EncryptInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=FunctionFailed,  # OperationCancelFailed not in fork — use FunctionFailed
        compat_tuple=(FunctionFailed,),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        testable=False,  # Requires active operation + cancel attempt — not exposed by python-pkcs11
    ),
    "init_pin_expired": CkrExpectation(
        function="C_EncryptInit",
        condition="PIN_has_expired",
        spec_ckr=PinExpired,
        compat_tuple=(PinExpired, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.1",
        testable=False,  # Requires token with PIN expiration policy — not available in test tokens
    ),
    # --- Additional C_Encrypt errors ---
    "arguments_bad": CkrExpectation(
        function="C_Encrypt",
        condition="NULL_pointer_argument",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.2",
    ),
    "buffer_too_small": CkrExpectation(
        function="C_Encrypt",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.2",
    ),
    "function_canceled": CkrExpectation(
        function="C_Encrypt",
        condition="operation_canceled",
        spec_ckr=FunctionFailed,  # FunctionCanceled not in fork — use FunctionFailed
        compat_tuple=(FunctionFailed,),
        spec_ref="PKCS#11 v3.1 §5.8.2",
        testable=False,  # Requires registered callback to cancel — not exposed by python-pkcs11
    ),
    "operation_active": CkrExpectation(
        function="C_Encrypt",
        condition="called_during_multipart",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.2",
        testable=False,  # python-pkcs11 manages multipart state internally
    ),
    # --- Additional C_EncryptUpdate errors ---
    "update_arguments_bad": CkrExpectation(
        function="C_EncryptUpdate",
        condition="NULL_pointer",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.3",
    ),
    "update_buffer_too_small": CkrExpectation(
        function="C_EncryptUpdate",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.3",
        testable=False,  # python-pkcs11 handles buffer sizing internally
    ),
    "update_function_canceled": CkrExpectation(
        function="C_EncryptUpdate",
        condition="canceled",
        spec_ckr=FunctionFailed,  # FunctionCanceled not in fork — use FunctionFailed
        compat_tuple=(FunctionFailed,),
        spec_ref="PKCS#11 v3.1 §5.8.3",
        testable=False,  # Requires registered callback to cancel — not exposed by python-pkcs11
    ),
    "update_operation_active": CkrExpectation(
        function="C_EncryptUpdate",
        condition="called_after_C_Encrypt",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.3",
        testable=False,  # python-pkcs11 manages multipart state internally
    ),
    # --- Additional C_EncryptFinal errors ---
    "final_arguments_bad": CkrExpectation(
        function="C_EncryptFinal",
        condition="NULL_pointer",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.4",
    ),
    "final_buffer_too_small": CkrExpectation(
        function="C_EncryptFinal",
        condition="output_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.4",
        testable=False,  # python-pkcs11 handles buffer sizing internally
    ),
    "final_function_canceled": CkrExpectation(
        function="C_EncryptFinal",
        condition="canceled",
        spec_ckr=FunctionFailed,  # FunctionCanceled not in fork — use FunctionFailed
        compat_tuple=(FunctionFailed,),
        spec_ref="PKCS#11 v3.1 §5.8.4",
        testable=False,  # Requires registered callback to cancel — not exposed by python-pkcs11
    ),
    "final_operation_active": CkrExpectation(
        function="C_EncryptFinal",
        condition="called_during_single_part",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.8.4",
        testable=False,  # python-pkcs11 manages single-part vs multipart state internally
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
    # --- C_DecryptUpdate/Final errors ---
    "update_encrypted_data_len_range": CkrExpectation(
        function="C_DecryptUpdate",
        condition="non_aligned_partial_ciphertext",
        spec_ckr=EncryptedDataLenRange,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.3",
        testable=False,
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_DecryptUpdate",
        condition="no_prior_C_DecryptInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.3",
        testable=False,
    ),
    "final_encrypted_data_invalid": CkrExpectation(
        function="C_DecryptFinal",
        condition="incomplete_ciphertext_at_finalize",
        spec_ckr=EncryptedDataInvalid,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.4",
        testable=False,
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_DecryptFinal",
        condition="no_prior_C_DecryptInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.4",
        testable=False,
    ),
    "init_operation_active": CkrExpectation(
        function="C_DecryptInit",
        condition="init_called_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.1",
        testable=False,
    ),
    "encrypted_data_cbc_wrong_padding": CkrExpectation(
        function="C_Decrypt",
        condition="AES_CBC_PAD_ciphertext_with_bad_padding",
        spec_ckr=EncryptedDataInvalid,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        mechanisms=["AES_CBC_PAD"],
    ),
    "rsa_oaep_garbage": CkrExpectation(
        function="C_Decrypt",
        condition="RSA_OAEP_garbage_ciphertext",
        spec_ckr=EncryptedDataInvalid,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_DecryptInit",
        condition="key_CKA_DECRYPT_is_False",
        spec_ckr=KeyFunctionNotPermitted,
        compat_tuple=(KeyFunctionNotPermitted, KeyTypeInconsistent, MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.1",
    ),
    "init_key_handle_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="invalid_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.1",
    ),
    "init_key_size_range": CkrExpectation(
        function="C_DecryptInit",
        condition="key_size_out_of_range",
        spec_ckr=KeySizeRange,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.1",
    ),
    "operation_not_initialized": CkrExpectation(
        function="C_Decrypt",
        condition="no_prior_C_DecryptInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.2",
    ),
    # --- Mechanism-specific C_DecryptInit errors ---
    "rsa_oaep_mechanism_param_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="RSA_OAEP_with_wrong_hash_in_params",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.9.1",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    # --- Mechanism-specific C_Decrypt errors ---
    "aes_gcm_auth_failed": CkrExpectation(
        function="C_Decrypt",
        condition="AES_GCM_tampered_ciphertext_or_tag",
        spec_ckr=EncryptedDataInvalid,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        mechanisms=["AES_GCM"],
    ),
    "aes_cbc_pad_wrong_length": CkrExpectation(
        function="C_Decrypt",
        condition="AES_CBC_PAD_ciphertext_not_block_aligned",
        spec_ckr=EncryptedDataLenRange,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        mechanisms=["AES_CBC_PAD"],
    ),
    "rsa_pkcs_ciphertext_format_invalid": CkrExpectation(
        function="C_Decrypt",
        condition="RSA_PKCS_valid_length_but_malformed_ciphertext",
        spec_ckr=EncryptedDataInvalid,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.9.2",
        mechanisms=["RSA_PKCS"],
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
    "init_key_handle_invalid": CkrExpectation(
        function="C_SignInit",
        condition="invalid_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.1",
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_SignInit",
        condition="key_CKA_SIGN_is_False",
        spec_ckr=KeyFunctionNotPermitted,
        compat_tuple=(KeyFunctionNotPermitted, KeyTypeInconsistent, MechanismInvalid, FunctionFailed),
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
    "operation_not_initialized": CkrExpectation(
        function="C_Sign",
        condition="no_prior_C_SignInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.2",
    ),
    "data_invalid": CkrExpectation(
        function="C_Sign",
        condition="data_format_error",
        spec_ckr=DataInvalid,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.2",
        allow_success=True,  # Most mechanisms hash data, so format doesn't matter
    ),
    # --- C_SignInit additional errors ---
    "init_key_size_range": CkrExpectation(
        function="C_SignInit",
        condition="key_size_too_small_for_mechanism",
        spec_ckr=KeySizeRange,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.1",
    ),
    "init_operation_active": CkrExpectation(
        function="C_SignInit",
        condition="init_called_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.1",
        testable=False,  # python-pkcs11 manages operation state
    ),
    # --- C_SignUpdate errors ---
    "update_data_len_range": CkrExpectation(
        function="C_SignUpdate",
        condition="partial_data_too_long",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.3",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_SignUpdate",
        condition="no_prior_C_SignInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.3",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    # --- C_SignFinal errors ---
    "final_data_len_range": CkrExpectation(
        function="C_SignFinal",
        condition="incomplete_data_at_finalize",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.4",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_SignFinal",
        condition="no_prior_C_SignInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.4",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    "final_buffer_too_small": CkrExpectation(
        function="C_SignFinal",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.4",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    # --- C_SignRecover errors ---
    "recover_init_mechanism_invalid": CkrExpectation(
        function="C_SignRecoverInit",
        condition="mechanism_not_supported_for_recover",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.5",
    ),
    "recover_data_len_range": CkrExpectation(
        function="C_SignRecover",
        condition="data_too_long_for_recover",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.6",
    ),
    "recover_operation_not_initialized": CkrExpectation(
        function="C_SignRecover",
        condition="no_prior_C_SignRecoverInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.6",
        testable=False,  # python-pkcs11 wraps SignRecover internally
    ),
    # --- Mechanism-specific C_SignInit errors ---
    "ecdsa_mechanism_invalid": CkrExpectation(
        function="C_SignInit",
        condition="ECDSA_mechanism_with_AES_key",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted,
                      FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.1",
        mechanisms=["ECDSA"],
    ),
    "hmac_mechanism_param_invalid": CkrExpectation(
        function="C_SignInit",
        condition="HMAC_with_wrong_mechanism_params",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.1",
        mechanisms=["SHA256_HMAC_GENERAL"],
    ),
    "rsa_pss_mechanism_param_invalid": CkrExpectation(
        function="C_SignInit",
        condition="RSA_PSS_with_wrong_salt_hash_combo",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.10.1",
        mechanisms=["RSA_PKCS_PSS"],
    ),
    # --- Mechanism-specific C_Sign errors ---
    "eddsa_data_too_long": CkrExpectation(
        function="C_Sign",
        condition="Ed25519_message_exceeds_max_size",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.2",
        mechanisms=["EDDSA"],
        allow_success=True,  # Ed25519 has no practical message size limit in most impls
    ),
    "rsa_pkcs_data_len_range": CkrExpectation(
        function="C_Sign",
        condition="RSA_PKCS_data_exceeds_k_minus_11",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.10.2",
        mechanisms=["RSA_PKCS"],
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
    "init_key_handle_invalid": CkrExpectation(
        function="C_VerifyInit",
        condition="invalid_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.11.1",
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_VerifyInit",
        condition="key_CKA_VERIFY_is_False",
        spec_ckr=KeyFunctionNotPermitted,
        compat_tuple=(KeyFunctionNotPermitted, KeyTypeInconsistent, MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.1",
        allow_success=True,  # SoftHSM2 doesn't check CKA_VERIFY at init
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
    "data_len_range": CkrExpectation(
        function="C_Verify",
        condition="oversized_data_for_raw_verify",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.11.2",
    ),
    "operation_not_initialized": CkrExpectation(
        function="C_Verify",
        condition="no_prior_C_VerifyInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
    ),
    # --- C_VerifyInit additional errors ---
    "init_key_size_range": CkrExpectation(
        function="C_VerifyInit",
        condition="key_size_too_small_for_mechanism",
        spec_ckr=KeySizeRange,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.11.1",
    ),
    "init_operation_active": CkrExpectation(
        function="C_VerifyInit",
        condition="init_called_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.1",
        testable=False,  # python-pkcs11 manages operation state
    ),
    # --- C_VerifyUpdate errors ---
    "update_data_len_range": CkrExpectation(
        function="C_VerifyUpdate",
        condition="partial_data_too_long",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.11.3",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_VerifyUpdate",
        condition="no_prior_C_VerifyInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.3",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    # --- C_VerifyFinal errors ---
    "final_signature_invalid": CkrExpectation(
        function="C_VerifyFinal",
        condition="tampered_signature_at_finalize",
        spec_ckr=SignatureInvalid,
        compat_tuple=(SignatureInvalid, SignatureLenRange, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.4",
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_VerifyFinal",
        condition="no_prior_C_VerifyInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.4",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    # --- C_VerifyRecover errors ---
    "recover_init_mechanism_invalid": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="mechanism_not_supported_for_recover",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.11.5",
    ),
    "recover_signature_invalid": CkrExpectation(
        function="C_VerifyRecover",
        condition="tampered_signature_for_recover",
        spec_ckr=SignatureInvalid,
        compat_tuple=(SignatureInvalid, SignatureLenRange, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.6",
    ),
    "recover_operation_not_initialized": CkrExpectation(
        function="C_VerifyRecover",
        condition="no_prior_C_VerifyRecoverInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.6",
        testable=False,  # python-pkcs11 wraps VerifyRecover internally
    ),
    # --- C_Verify additional errors ---
    "data_invalid": CkrExpectation(
        function="C_Verify",
        condition="data_format_error",
        spec_ckr=DataInvalid,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.11.2",
        allow_success=True,  # Most mechanisms hash data, so format doesn't matter
    ),
    # --- Mechanism-specific C_Verify errors ---
    "ecdsa_signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="ECDSA_tampered_signature",
        spec_ckr=SignatureInvalid,
        compat_tuple=(SignatureInvalid, SignatureLenRange, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
        mechanisms=["ECDSA"],
    ),
    "hmac_signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="HMAC_tampered_signature",
        spec_ckr=SignatureInvalid,
        compat_tuple=(SignatureInvalid, SignatureLenRange, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
        mechanisms=["SHA256_HMAC"],
    ),
    "ecdsa_signature_len_range": CkrExpectation(
        function="C_Verify",
        condition="ECDSA_wrong_length_signature",
        spec_ckr=SignatureLenRange,
        compat_tuple=(SignatureLenRange, SignatureInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
        mechanisms=["ECDSA"],
        priority_note="Higher priority than CKR_SIGNATURE_INVALID",
    ),
    "hmac_signature_len_range": CkrExpectation(
        function="C_Verify",
        condition="HMAC_truncated_signature",
        spec_ckr=SignatureLenRange,
        compat_tuple=(SignatureLenRange, SignatureInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
        mechanisms=["SHA256_HMAC"],
        priority_note="Higher priority than CKR_SIGNATURE_INVALID",
    ),
    "rsa_pss_signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="RSA_PSS_tampered_signature",
        spec_ckr=SignatureInvalid,
        compat_tuple=(SignatureInvalid, SignatureLenRange, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.2",
        mechanisms=["RSA_PKCS_PSS"],
    ),
    # --- C_VerifyInit mechanism-specific errors ---
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_VerifyInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.11.1",
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
    # --- C_Digest errors ---
    "operation_not_initialized": CkrExpectation(
        function="C_Digest",
        condition="no_prior_C_DigestInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.12.2",
    ),
    # --- C_DigestInit additional errors ---
    "init_operation_active": CkrExpectation(
        function="C_DigestInit",
        condition="init_called_while_digest_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.12.1",
        testable=False,  # python-pkcs11 manages operation state
    ),
    # --- C_Digest additional errors ---
    "digest_buffer_too_small": CkrExpectation(
        function="C_Digest",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.12.2",
        testable=False,  # python-pkcs11 handles buffer sizing internally
    ),
    "empty_data": CkrExpectation(
        function="C_Digest",
        condition="digest_of_empty_bytes",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.12.2",
        allow_success=True,  # Digesting empty data is valid per most implementations
    ),
    # --- C_DigestUpdate errors ---
    "update_operation_not_initialized": CkrExpectation(
        function="C_DigestUpdate",
        condition="no_prior_C_DigestInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.12.3",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    # --- C_DigestKey errors ---
    "key_indigestible": CkrExpectation(
        function="C_DigestKey",
        condition="non_secret_key_for_digest",
        spec_ckr=KeyIndigestible,
        compat_tuple=(KeyIndigestible, KeyHandleInvalid, FunctionFailed, FunctionNotSupported),
        spec_ref="PKCS#11 v3.1 §5.12.4",
        allow_success=True,  # Some modules may accept any key type
    ),
    "key_handle_invalid": CkrExpectation(
        function="C_DigestKey",
        condition="destroyed_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.12.4",
    ),
    # --- C_DigestFinal errors ---
    "final_operation_not_initialized": CkrExpectation(
        function="C_DigestFinal",
        condition="no_prior_C_DigestInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.12.5",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    "final_buffer_too_small": CkrExpectation(
        function="C_DigestFinal",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.12.5",
        testable=False,  # python-pkcs11 handles buffer sizing internally
    ),
    # --- C_DigestXofInit errors (v3.0+) ---
    "xof_init_mechanism_invalid": CkrExpectation(
        function="C_DigestXofInit",
        condition="mechanism_not_supported_for_xof",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.12.7",
        testable=False,  # v3.0+ only, not widely supported
    ),
    # --- C_DigestUpdate additional errors ---
    "update_data_len_range": CkrExpectation(
        function="C_DigestUpdate",
        condition="partial_data_exceeds_limits",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.12.3",
        testable=False,  # python-pkcs11 handles multipart internally
    ),
    # --- C_DigestKey additional errors ---
    "key_function_not_permitted": CkrExpectation(
        function="C_DigestKey",
        condition="key_not_suitable_for_digest",
        spec_ckr=KeyFunctionNotPermitted,
        compat_tuple=(KeyFunctionNotPermitted, KeyIndigestible, FunctionFailed,
                      FunctionNotSupported),
        spec_ref="PKCS#11 v3.1 §5.12.4",
        allow_success=True,  # Most modules don't restrict DigestKey by CKA flags
    ),
    "key_digest_operation_not_initialized": CkrExpectation(
        function="C_DigestKey",
        condition="DigestKey_without_DigestInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed, FunctionNotSupported),
        spec_ref="PKCS#11 v3.1 §5.12.4",
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
    "genkey_attribute_type_invalid": CkrExpectation(
        function="C_GenerateKey",
        condition="bogus_attribute_in_template",
        spec_ckr=AttributeTypeInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.1",
        allow_success=True,  # Some modules ignore unknown attributes
    ),
    "genkey_attribute_read_only": CkrExpectation(
        function="C_GenerateKey",
        condition="CKA_CLASS_in_keygen_template",
        spec_ckr=AttributeReadOnly,
        compat_tuple=(AttributeReadOnly, AttributeTypeInvalid, TemplateInconsistent, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.1",
        allow_success=True,  # Module may ignore CKA_CLASS in keygen
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
    "genkeypair_domain_params_invalid": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="malformed_EC_params",
        spec_ckr=DomainParamsInvalid,
        compat_tuple=(DomainParamsInvalid, CurveNotSupported, AttributeValueInvalid,
                      MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.2",
    ),
    "genkeypair_template_inconsistent": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="conflicting_pub_priv_templates",
        spec_ckr=TemplateInconsistent,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.2",
    ),
    # --- C_GenerateKey additional errors ---
    "genkey_session_read_only": CkrExpectation(
        function="C_GenerateKey",
        condition="token_key_in_read_only_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.1",
    ),
    "genkey_operation_active": CkrExpectation(
        function="C_GenerateKey",
        condition="keygen_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.1",
        testable=False,  # python-pkcs11 manages operation state
    ),
    "genkey_user_not_logged_in": CkrExpectation(
        function="C_GenerateKey",
        condition="private_key_without_login",
        spec_ckr=UserNotLoggedIn,
        compat_tuple=(UserNotLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.1",
        allow_success=True,  # Modules without login requirements accept this
    ),
    # --- C_GenerateKeyPair additional errors ---
    "genkeypair_session_read_only": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="token_keypair_in_read_only_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.2",
    ),
    "genkeypair_operation_active": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="keygen_pair_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.2",
        testable=False,  # python-pkcs11 manages operation state
    ),
    "genkeypair_attribute_type_invalid": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="bogus_attribute_in_template",
        spec_ckr=AttributeTypeInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.2",
        allow_success=True,  # Some modules ignore unknown attributes
    ),
    "genkeypair_attribute_read_only": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="CKA_CLASS_in_keypair_template",
        spec_ckr=AttributeReadOnly,
        compat_tuple=(AttributeReadOnly, AttributeTypeInvalid,
                      TemplateInconsistent, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.2",
        allow_success=True,  # Module may ignore CKA_CLASS in keygen
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
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted,
                      MechanismParamInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
        # OpenCryptoki: MechanismParamInvalid, Kryoptic: ArgumentsBad, NSS: UserTypeInvalid
    ),
    "mechanism_param_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "key_function_not_permitted": CkrExpectation(
        function="C_DeriveKey",
        condition="key_CKA_DERIVE_is_False",
        spec_ckr=KeyFunctionNotPermitted,
        compat_tuple=(KeyFunctionNotPermitted, KeyTypeInconsistent, MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "template_incomplete": CkrExpectation(
        function="C_DeriveKey",
        condition="missing_output_key_type",
        spec_ckr=TemplateIncomplete,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "domain_params_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="ECDH_with_invalid_domain_params",
        spec_ckr=DomainParamsInvalid,
        compat_tuple=(DomainParamsInvalid, MechanismParamInvalid, AttributeValueInvalid,
                      FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
        mechanisms=["ECDH1_DERIVE"],
    ),
    "template_inconsistent": CkrExpectation(
        function="C_DeriveKey",
        condition="conflicting_output_attributes",
        spec_ckr=TemplateInconsistent,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "key_handle_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="destroyed_base_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "key_size_range": CkrExpectation(
        function="C_DeriveKey",
        condition="output_key_size_invalid",
        spec_ckr=KeySizeRange,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "operation_active": CkrExpectation(
        function="C_DeriveKey",
        condition="derive_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
        testable=False,  # python-pkcs11 manages operation state
    ),
    "session_read_only": CkrExpectation(
        function="C_DeriveKey",
        condition="derive_token_key_in_RO_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "user_not_logged_in": CkrExpectation(
        function="C_DeriveKey",
        condition="private_derived_key_without_login",
        spec_ckr=UserNotLoggedIn,
        compat_tuple=(UserNotLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
        allow_success=True,  # Modules without login requirements accept this
    ),
    "attribute_type_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="bogus_attr_in_derive_template",
        spec_ckr=AttributeTypeInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.5",
        allow_success=True,  # Some modules ignore unknown attributes
    ),
    "attribute_value_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="bad_value_in_derive_template",
        spec_ckr=AttributeValueInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.5",
    ),
    "attribute_read_only": CkrExpectation(
        function="C_DeriveKey",
        condition="CKA_CLASS_in_derive_template",
        spec_ckr=AttributeReadOnly,
        compat_tuple=(AttributeReadOnly, AttributeTypeInvalid,
                      TemplateInconsistent, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
        allow_success=True,  # Module may ignore CKA_CLASS in derive
    ),
    "ecdh_mechanism_param_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="wrong_KDF_in_ECDH_params",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
        mechanisms=["ECDH1_DERIVE"],
    ),
    "hkdf_mechanism_param_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="wrong_params_for_HKDF_derive",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.5",
        mechanisms=["HKDF_DERIVE"],
        testable=False,  # HKDF not widely supported yet
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — KEM family (§5.14.7–5.14.8, v3.2 only)
# ---------------------------------------------------------------------------

CKR_KEM: dict[str, CkrExpectation] = {
    # --- C_EncapsulateKey errors ---
    "encap_mechanism_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="unsupported_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2 §5.14.7",
    ),
    "encap_key_type_inconsistent": CkrExpectation(
        function="C_EncapsulateKey",
        condition="RSA_key_with_ML_KEM_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted,
                      ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.2 §5.14.7",
    ),
    # --- C_DecapsulateKey errors ---
    "decap_mechanism_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="unsupported_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2 §5.14.8",
    ),
    "decap_ciphertext_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="garbage_ciphertext",
        spec_ckr=EncryptedDataInvalid,
        compat_tuple=(EncryptedDataInvalid, EncryptedDataLenRange, ArgumentsBad,
                      MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.2 §5.14.8",
        allow_success=True,  # ML-KEM implicit rejection may produce a key anyway
    ),
    "encap_mechanism_param_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.2 §5.14.7",
    ),
    "encap_key_handle_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="destroyed_public_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2 §5.14.7",
    ),
    "encap_operation_active": CkrExpectation(
        function="C_EncapsulateKey",
        condition="encapsulate_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.2 §5.14.7",
        testable=False,  # python-pkcs11 manages operation state
    ),
    "encap_template_incomplete": CkrExpectation(
        function="C_EncapsulateKey",
        condition="missing_output_key_attrs",
        spec_ckr=TemplateIncomplete,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 §5.14.7",
    ),
    "encap_key_size_range": CkrExpectation(
        function="C_EncapsulateKey",
        condition="output_key_size_invalid",
        spec_ckr=KeySizeRange,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2 §5.14.7",
    ),
    "decap_key_handle_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="destroyed_private_key_handle",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2 §5.14.8",
    ),
    "decap_operation_active": CkrExpectation(
        function="C_DecapsulateKey",
        condition="decapsulate_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.2 §5.14.8",
        testable=False,  # python-pkcs11 manages operation state
    ),
    "decap_template_incomplete": CkrExpectation(
        function="C_DecapsulateKey",
        condition="missing_output_key_attrs",
        spec_ckr=TemplateIncomplete,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 §5.14.8",
    ),
    "decap_key_type_inconsistent": CkrExpectation(
        function="C_DecapsulateKey",
        condition="RSA_key_with_ML_KEM_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted,
                      ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.2 §5.14.8",
    ),
    "decap_mechanism_param_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.2 §5.14.8",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Wrap/Unwrap family (§5.14.3–5.14.4)
# ---------------------------------------------------------------------------

# Import additional types needed for wrap
from pkcs11.exceptions import (  # noqa: E402
    KeyUnextractable,
    KeyNotWrappable,
    WrappedKeyInvalid,
    WrappedKeyLenRange,
)

CKR_WRAP: dict[str, CkrExpectation] = {
    "wrap_key_unextractable": CkrExpectation(
        function="C_WrapKey",
        condition="key_CKA_EXTRACTABLE_is_False",
        spec_ckr=KeyUnextractable,
        compat_tuple=(KeyUnextractable, KeyNotWrappable, KeyFunctionNotPermitted, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.3",
    ),
    "wrap_mechanism_invalid": CkrExpectation(
        function="C_WrapKey",
        condition="unsupported_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.3",
    ),
    "unwrap_wrapped_key_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="garbage_wrapped_data",
        spec_ckr=WrappedKeyInvalid,
        compat_tuple=(WrappedKeyInvalid, WrappedKeyLenRange, EncryptedDataInvalid,
                      ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.4",
    ),
    "wrap_key_type_inconsistent": CkrExpectation(
        function="C_WrapKey",
        condition="wrapping_key_wrong_type_for_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted,
                      FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.3",
    ),
    "wrap_mechanism_param_invalid": CkrExpectation(
        function="C_WrapKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=MechanismParamInvalid,
        compat_tuple=(MechanismParamInvalid, MechanismInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.3",
    ),
    "unwrap_wrapped_key_len_range": CkrExpectation(
        function="C_UnwrapKey",
        condition="wrapped_data_wrong_length",
        spec_ckr=WrappedKeyLenRange,
        compat_tuple=(WrappedKeyLenRange, WrappedKeyInvalid, EncryptedDataInvalid,
                      ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.4",
        priority_note="Higher priority than CKR_WRAPPED_KEY_INVALID",
    ),
    "unwrap_template_incomplete": CkrExpectation(
        function="C_UnwrapKey",
        condition="missing_required_unwrap_attrs",
        spec_ckr=TemplateIncomplete,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.4",
    ),
    "wrap_key_handle_invalid": CkrExpectation(
        function="C_WrapKey",
        condition="destroyed_key_to_wrap",
        spec_ckr=KeyHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.3",
    ),
    "wrap_key_not_wrappable": CkrExpectation(
        function="C_WrapKey",
        condition="key_CKA_WRAP_is_False_on_wrapping_key",
        spec_ckr=KeyNotWrappable,
        compat_tuple=(KeyNotWrappable, KeyUnextractable, KeyFunctionNotPermitted, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.3",
    ),
    "wrap_operation_active": CkrExpectation(
        function="C_WrapKey",
        condition="wrap_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.3",
        testable=False,  # python-pkcs11 manages operation state
    ),
    "wrap_buffer_too_small": CkrExpectation(
        function="C_WrapKey",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.3",
        testable=False,  # python-pkcs11 handles buffer sizing internally
    ),
    "wrap_session_read_only": CkrExpectation(
        function="C_WrapKey",
        condition="token_wrap_in_RO_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.3",
        allow_success=True,  # Wrap doesn't create token objects, most modules allow it
    ),
    "unwrap_mechanism_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="unsupported_unwrap_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.14.4",
    ),
    "unwrap_key_type_inconsistent": CkrExpectation(
        function="C_UnwrapKey",
        condition="wrong_key_type_for_unwrap_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted,
                      FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.4",
    ),
    "unwrap_operation_active": CkrExpectation(
        function="C_UnwrapKey",
        condition="unwrap_while_operation_active",
        spec_ckr=OperationActive,
        compat_tuple=(OperationActive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.4",
        testable=False,  # python-pkcs11 manages operation state
    ),
    "unwrap_session_read_only": CkrExpectation(
        function="C_UnwrapKey",
        condition="unwrap_to_token_object_in_RO_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.4",
    ),
    "unwrap_user_not_logged_in": CkrExpectation(
        function="C_UnwrapKey",
        condition="private_key_unwrap_without_login",
        spec_ckr=UserNotLoggedIn,
        compat_tuple=(UserNotLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.14.4",
        allow_success=True,  # Modules without login requirements accept this
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Object management (§5.7)
# ---------------------------------------------------------------------------

CKR_OBJECT: dict[str, CkrExpectation] = {
    "create_missing_class": CkrExpectation(
        function="C_CreateObject",
        condition="missing_CKA_CLASS",
        spec_ckr=TemplateIncomplete,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.1",
    ),
    "create_invalid_class": CkrExpectation(
        function="C_CreateObject",
        condition="CKA_CLASS_is_0xDEADBEEF",
        spec_ckr=AttributeValueInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.1",
    ),
    "get_attr_sensitive": CkrExpectation(
        function="C_GetAttributeValue",
        condition="read_VALUE_on_SENSITIVE_key",
        spec_ckr=AttributeSensitive,
        compat_tuple=(AttributeSensitive, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.5",
    ),
    "get_attr_destroyed": CkrExpectation(
        function="C_GetAttributeValue",
        condition="destroyed_object_handle",
        spec_ckr=ObjectHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.5",
        allow_success=True,  # Some modules don't detect invalid handles
    ),
    "set_attr_readonly": CkrExpectation(
        function="C_SetAttributeValue",
        condition="modify_read_only_CKA_CLASS",
        spec_ckr=AttributeReadOnly,
        compat_tuple=(AttributeReadOnly, AttributeTypeInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.6",
        allow_success=True,  # Kryoptic accepts CKA_CLASS modification
    ),
    "destroy_already_destroyed": CkrExpectation(
        function="C_DestroyObject",
        condition="double_destroy",
        spec_ckr=ObjectHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.3",
        allow_success=True,  # Some modules silently accept double destroy
    ),
    # --- C_CreateObject additional errors ---
    "create_attr_type_invalid": CkrExpectation(
        function="C_CreateObject",
        condition="bogus_attribute_type",
        spec_ckr=AttributeTypeInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.1",
        allow_success=True,  # Module may ignore unknown attributes
    ),
    "create_user_not_logged_in": CkrExpectation(
        function="C_CreateObject",
        condition="private_object_without_login",
        spec_ckr=AttributeValueInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.1",
        allow_success=True,  # Modules without login requirements accept this
    ),
    # --- C_CopyObject errors ---
    "copy_action_prohibited": CkrExpectation(
        function="C_CopyObject",
        condition="CKA_COPYABLE_is_False",
        spec_ckr=ActionProhibited,
        compat_tuple=(ActionProhibited, AttributeValueInvalid, FunctionFailed, FunctionNotSupported),
        spec_ref="PKCS#11 v3.1 §5.7.2",
        allow_success=True,  # Module may not enforce CKA_COPYABLE
    ),
    "copy_destroyed_handle": CkrExpectation(
        function="C_CopyObject",
        condition="copy_destroyed_object",
        spec_ckr=ObjectHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.2",
        allow_success=True,
    ),
    # --- C_GetObjectSize errors ---
    "get_size_handle_invalid": CkrExpectation(
        function="C_GetObjectSize",
        condition="destroyed_handle",
        spec_ckr=ObjectHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.4",
        allow_success=True,
    ),
    # --- C_SetAttributeValue additional errors ---
    "set_attr_action_prohibited": CkrExpectation(
        function="C_SetAttributeValue",
        condition="CKA_MODIFIABLE_is_False",
        spec_ckr=ActionProhibited,
        compat_tuple=(ActionProhibited, AttributeReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.6",
        allow_success=True,
    ),
    # --- C_FindObjects* errors ---
    "find_not_initialized": CkrExpectation(
        function="C_FindObjects",
        condition="FindObjects_without_FindObjectsInit",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.8",
    ),
    # --- C_CreateObject session/domain errors ---
    "create_session_read_only": CkrExpectation(
        function="C_CreateObject",
        condition="token_object_in_RO_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.1",
    ),
    "create_curve_not_supported": CkrExpectation(
        function="C_CreateObject",
        condition="EC_key_with_unsupported_curve",
        spec_ckr=CurveNotSupported,
        compat_tuple=(CurveNotSupported, DomainParamsInvalid, AttributeValueInvalid,
                      MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.1",
    ),
    "create_domain_params_invalid": CkrExpectation(
        function="C_CreateObject",
        condition="EC_key_with_malformed_params",
        spec_ckr=DomainParamsInvalid,
        compat_tuple=(DomainParamsInvalid, CurveNotSupported, AttributeValueInvalid,
                      FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.1",
    ),
    # --- C_CopyObject additional errors ---
    "copy_template_inconsistent": CkrExpectation(
        function="C_CopyObject",
        condition="conflicting_copy_template_attrs",
        spec_ckr=TemplateInconsistent,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.2",
    ),
    "copy_session_read_only": CkrExpectation(
        function="C_CopyObject",
        condition="copy_to_token_object_in_RO_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.2",
    ),
    "copy_handle_invalid": CkrExpectation(
        function="C_CopyObject",
        condition="non_existent_object_handle",
        spec_ckr=ObjectHandleInvalid,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.2",
    ),
    # --- C_DestroyObject additional errors ---
    "destroy_action_prohibited": CkrExpectation(
        function="C_DestroyObject",
        condition="CKA_DESTROYABLE_is_False",
        spec_ckr=ActionProhibited,
        compat_tuple=(ActionProhibited, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.3",
        allow_success=True,  # Not all modules enforce CKA_DESTROYABLE
    ),
    "destroy_session_read_only": CkrExpectation(
        function="C_DestroyObject",
        condition="destroy_token_object_in_RO_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.7.3",
    ),
    # --- C_SetAttributeValue additional errors ---
    "set_attr_type_invalid": CkrExpectation(
        function="C_SetAttributeValue",
        condition="set_bogus_attribute_type",
        spec_ckr=AttributeTypeInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.6",
        allow_success=True,  # Module may ignore unknown attributes
    ),
    "set_attr_value_invalid": CkrExpectation(
        function="C_SetAttributeValue",
        condition="set_wrong_value_for_known_attr",
        spec_ckr=AttributeValueInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.6",
    ),
    "set_attr_template_inconsistent": CkrExpectation(
        function="C_SetAttributeValue",
        condition="conflicting_attribute_modifications",
        spec_ckr=TemplateInconsistent,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.6",
    ),
    # --- C_FindObjectsInit additional errors ---
    "find_attr_value_invalid": CkrExpectation(
        function="C_FindObjectsInit",
        condition="search_with_bogus_attr_value",
        spec_ckr=AttributeValueInvalid,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.7.7",
        allow_success=True,  # Module may return empty results instead of error
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Session management (§5.6)
# ---------------------------------------------------------------------------

from pkcs11.exceptions import (  # noqa: E402
    AnotherUserAlreadyLoggedIn,
    PinIncorrect,
    PinLenRange,
    PinLocked,
    SessionCount,
    SessionExists,
    SlotIDInvalid,
    TokenWriteProtected,
    UserAlreadyLoggedIn,
    UserNotLoggedIn,
    UserTypeInvalid,
)

CKR_SESSION: dict[str, CkrExpectation] = {
    "login_wrong_pin": CkrExpectation(
        function="C_Login",
        condition="incorrect_PIN",
        spec_ckr=PinIncorrect,
        compat_tuple=(PinIncorrect, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.7",
    ),
    "login_already_logged_in": CkrExpectation(
        function="C_Login",
        condition="double_login",
        spec_ckr=UserAlreadyLoggedIn,
        compat_tuple=(UserAlreadyLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.7",
    ),
    "logout_not_logged_in": CkrExpectation(
        function="C_Logout",
        condition="logout_without_login",
        spec_ckr=UserNotLoggedIn,
        compat_tuple=(UserNotLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.8",
        allow_success=True,  # Some modules don't error on logout without login
    ),
    # --- C_OpenSession errors ---
    "open_slot_invalid": CkrExpectation(
        function="C_OpenSession",
        condition="non_existent_slot_ID",
        spec_ckr=SlotIDInvalid,
        compat_tuple=(SlotIDInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.1",
    ),
    # --- C_CloseSession errors ---
    "close_handle_invalid": CkrExpectation(
        function="C_CloseSession",
        condition="invalid_session_handle",
        spec_ckr=SessionHandleInvalid,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.6.2",
    ),
    # --- C_Login additional errors ---
    "login_user_type_invalid": CkrExpectation(
        function="C_Login",
        condition="invalid_user_type",
        spec_ckr=UserTypeInvalid,
        compat_tuple=(UserTypeInvalid, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.7",
    ),
    "login_pin_locked": CkrExpectation(
        function="C_Login",
        condition="PIN_locked_after_too_many_attempts",
        spec_ckr=PinLocked,
        compat_tuple=(PinLocked, PinIncorrect, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.7",
        testable=False,  # Would lock the token — needs @destructive
    ),
    # --- C_OpenSession additional errors ---
    "open_session_count": CkrExpectation(
        function="C_OpenSession",
        condition="exhaust_session_limit",
        spec_ckr=SessionCount,
        compat_tuple=(SessionCount, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.1",
    ),
    "open_token_write_protected": CkrExpectation(
        function="C_OpenSession",
        condition="RW_session_on_write_protected_token",
        spec_ckr=TokenWriteProtected,
        compat_tuple=(TokenWriteProtected, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.1",
    ),
    # --- C_GetSessionInfo errors ---
    "get_session_info_handle_invalid": CkrExpectation(
        function="C_GetSessionInfo",
        condition="invalid_session_handle",
        spec_ckr=SessionHandleInvalid,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.6.4",
    ),
    # --- C_CloseAllSessions errors ---
    "close_all_slot_invalid": CkrExpectation(
        function="C_CloseAllSessions",
        condition="non_existent_slot_ID",
        spec_ckr=SlotIDInvalid,
        compat_tuple=(SlotIDInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.3",
    ),
    # --- C_Login additional errors ---
    "login_user_another_logged_in": CkrExpectation(
        function="C_Login",
        condition="SO_login_when_user_logged_in",
        spec_ckr=AnotherUserAlreadyLoggedIn,
        compat_tuple=(AnotherUserAlreadyLoggedIn, UserAlreadyLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.7",
    ),
    # --- C_Login additional PIN errors ---
    "login_pin_len_range": CkrExpectation(
        function="C_Login",
        condition="PIN_too_short_or_too_long",
        spec_ckr=PinLenRange,
        compat_tuple=(PinLenRange, PinIncorrect, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.7",
    ),
    # --- C_GetOperationState session error ---
    "get_op_state_session_invalid": CkrExpectation(
        function="C_GetOperationState",
        condition="invalid_session_handle",
        spec_ckr=SessionHandleInvalid,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.6.5",
    ),
    # --- C_SetOperationState session error ---
    "set_op_state_session_invalid": CkrExpectation(
        function="C_SetOperationState",
        condition="invalid_session_handle",
        spec_ckr=SessionHandleInvalid,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.6.6",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Random (§5.18)
# ---------------------------------------------------------------------------

from pkcs11.exceptions import (  # noqa: E402
    RandomSeedNotSupported,
)

CKR_RANDOM: dict[str, CkrExpectation] = {
    "seed_not_supported": CkrExpectation(
        function="C_SeedRandom",
        condition="seeding_not_supported",
        spec_ckr=RandomSeedNotSupported,
        compat_tuple=(RandomSeedNotSupported, FunctionNotSupported, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.18.1",
        allow_success=True,  # Module may accept seeding
    ),
    # --- C_GenerateRandom errors ---
    "generate_random_args_bad": CkrExpectation(
        function="C_GenerateRandom",
        condition="NULL_buffer_pointer",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.18.2",
        testable=True,  # Via ctypes
    ),
    "generate_random_zero_length": CkrExpectation(
        function="C_GenerateRandom",
        condition="zero_byte_request",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.18.2",
        allow_success=True,  # Most modules accept 0-length request
    ),
    "generate_random_large": CkrExpectation(
        function="C_GenerateRandom",
        condition="one_megabyte_request",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.18.2",
        allow_success=True,  # Most modules handle large requests
    ),
    # --- C_SeedRandom additional errors ---
    "seed_random_args_bad": CkrExpectation(
        function="C_SeedRandom",
        condition="NULL_seed_pointer",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, RandomSeedNotSupported, FunctionNotSupported, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.18.1",
        testable=True,  # Via ctypes
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Operation State (§5.6.5–5.6.6)
# ---------------------------------------------------------------------------

from pkcs11.exceptions import (  # noqa: E402
    KeyNeeded,
    KeyNotNeeded,
    SavedStateInvalid,
    StateUnsaveable,
)

CKR_STATE: dict[str, CkrExpectation] = {
    "get_state_no_op": CkrExpectation(
        function="C_GetOperationState",
        condition="no_active_operation",
        spec_ckr=OperationNotInitialized,
        compat_tuple=(OperationNotInitialized, StateUnsaveable, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.5",
    ),
    "set_state_invalid": CkrExpectation(
        function="C_SetOperationState",
        condition="garbage_state_data",
        spec_ckr=SavedStateInvalid,
        compat_tuple=(SavedStateInvalid, OperationNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.6",
    ),
    # --- C_GetOperationState additional errors ---
    "get_state_buffer_too_small": CkrExpectation(
        function="C_GetOperationState",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, StateUnsaveable, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.5",
        testable=False,  # python-pkcs11 handles buffer sizing internally
    ),
    # --- C_SetOperationState additional errors ---
    "set_state_key_needed": CkrExpectation(
        function="C_SetOperationState",
        condition="state_requires_key_but_none_supplied",
        spec_ckr=KeyNeeded,
        compat_tuple=(KeyNeeded, SavedStateInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.6",
        testable=False,  # Requires saved state with key reference
    ),
    "set_state_key_not_needed": CkrExpectation(
        function="C_SetOperationState",
        condition="state_does_not_need_key_but_key_supplied",
        spec_ckr=KeyNotNeeded,
        compat_tuple=(KeyNotNeeded, SavedStateInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.6.6",
        testable=False,  # Requires saved state without key reference
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — Slot/Token Management (§5.5)
# ---------------------------------------------------------------------------

from pkcs11.exceptions import (  # noqa: E402
    NoEvent,
)

CKR_SLOT_TOKEN: dict[str, CkrExpectation] = {
    "get_slot_info_invalid_slot": CkrExpectation(
        function="C_GetSlotInfo",
        condition="non_existent_slot_ID",
        spec_ckr=SlotIDInvalid,
        compat_tuple=(SlotIDInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.2",
    ),
    "get_token_info_invalid_slot": CkrExpectation(
        function="C_GetTokenInfo",
        condition="non_existent_slot_ID",
        spec_ckr=SlotIDInvalid,
        compat_tuple=(SlotIDInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.3",
    ),
    "get_mech_list_invalid_slot": CkrExpectation(
        function="C_GetMechanismList",
        condition="non_existent_slot_ID",
        spec_ckr=SlotIDInvalid,
        compat_tuple=(SlotIDInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.5",
    ),
    "get_mech_info_invalid": CkrExpectation(
        function="C_GetMechanismInfo",
        condition="non_existent_mechanism",
        spec_ckr=MechanismInvalid,
        compat_tuple=(MechanismInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.6",
    ),
    "wait_for_slot_event_no_event": CkrExpectation(
        function="C_WaitForSlotEvent",
        condition="non_blocking_no_event",
        spec_ckr=NoEvent,
        compat_tuple=(NoEvent, FunctionNotSupported, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.4",
    ),
    # --- C_GetSlotList additional errors ---
    "get_slot_list_buffer_too_small": CkrExpectation(
        function="C_GetSlotList",
        condition="output_buffer_too_small",
        spec_ckr=BufferTooSmall,
        compat_tuple=(BufferTooSmall, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.1",
        testable=False,  # python-pkcs11 handles buffer sizing internally
    ),
    # --- C_GetTokenInfo additional errors ---
    "get_token_info_token_not_present": CkrExpectation(
        function="C_GetTokenInfo",
        condition="token_not_present_in_slot",
        spec_ckr=TokenNotPresent,
        compat_tuple=(TokenNotPresent, SlotIDInvalid, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.3",
        testable=False,  # Requires physical token removal
    ),
    # --- C_InitToken errors ---
    "init_token_session_exists": CkrExpectation(
        function="C_InitToken",
        condition="open_sessions_exist",
        spec_ckr=SessionExists,
        compat_tuple=(SessionExists, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.7",
        testable=False,  # Destructive — would reinitialize token
    ),
    "init_token_pin_incorrect": CkrExpectation(
        function="C_InitToken",
        condition="wrong_SO_PIN",
        spec_ckr=PinIncorrect,
        compat_tuple=(PinIncorrect, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.7",
        testable=False,  # Destructive — could lock SO PIN
    ),
    # --- C_InitPIN errors ---
    "init_pin_user_not_logged_in": CkrExpectation(
        function="C_InitPIN",
        condition="not_logged_in_as_SO",
        spec_ckr=UserNotLoggedIn,
        compat_tuple=(UserNotLoggedIn, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.8",
    ),
    # --- C_SetPIN errors ---
    "set_pin_incorrect": CkrExpectation(
        function="C_SetPIN",
        condition="wrong_old_PIN",
        spec_ckr=PinIncorrect,
        compat_tuple=(PinIncorrect, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.9",
    ),
    "set_pin_len_range": CkrExpectation(
        function="C_SetPIN",
        condition="new_PIN_too_short",
        spec_ckr=PinLenRange,
        compat_tuple=(PinLenRange, PinIncorrect, ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.9",
    ),
    "set_pin_session_read_only": CkrExpectation(
        function="C_SetPIN",
        condition="read_only_session",
        spec_ckr=SessionReadOnly,
        compat_tuple=(SessionReadOnly, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.5.9",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables — General Purpose (§5.4)
# ---------------------------------------------------------------------------

from pkcs11.exceptions import (  # noqa: E402
    CryptokiAlreadyInitialized,
    CryptokiNotInitialized,
)

CKR_GENERAL: dict[str, CkrExpectation] = {
    "double_initialize": CkrExpectation(
        function="C_Initialize",
        condition="already_initialized",
        spec_ckr=CryptokiAlreadyInitialized,
        compat_tuple=(CryptokiAlreadyInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.4.1",
        allow_success=True,  # Some modules accept double init
    ),
    "finalize_not_initialized": CkrExpectation(
        function="C_Finalize",
        condition="not_initialized",
        spec_ckr=CryptokiNotInitialized,
        compat_tuple=(CryptokiNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.4.2",
    ),
    "get_info_null": CkrExpectation(
        function="C_GetInfo",
        condition="NULL_pInfo_pointer",
        spec_ckr=ArgumentsBad,
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.4.3",
        testable=True,  # Via ctypes
    ),
    # --- C_GetFunctionList ---
    "get_function_list_ok": CkrExpectation(
        function="C_GetFunctionList",
        condition="successful_call",
        spec_ckr=ArgumentsBad,  # Only possible error is NULL pointer
        compat_tuple=(ArgumentsBad, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.4.4",
        allow_success=True,  # Normal call succeeds
        testable=True,
    ),
    # --- C_Finalize additional errors ---
    "finalize_twice": CkrExpectation(
        function="C_Finalize",
        condition="double_finalize",
        spec_ckr=CryptokiNotInitialized,
        compat_tuple=(CryptokiNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.4.2",
    ),
    # --- C_GetInfo after finalize ---
    "get_info_after_finalize": CkrExpectation(
        function="C_GetInfo",
        condition="called_after_C_Finalize",
        spec_ckr=CryptokiNotInitialized,
        compat_tuple=(CryptokiNotInitialized, FunctionFailed),
        spec_ref="PKCS#11 v3.1 §5.4.3",
    ),
}
