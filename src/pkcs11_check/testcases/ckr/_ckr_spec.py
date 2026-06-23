"""Centralized PKCS#11 CKR spec tables and assertion helpers.

Each CkrExpectation maps a (function, error condition) pair to:
- The spec-mandated CKR code(s) as integer constants
- A broader acceptable error tuple for compat mode
- A reference to the OASIS spec section

Source of truth: https://github.com/oasis-tcs/pkcs11.git working/doc/spec/

All CKR codes are represented as integers from pkcs11_check.raw.types_std.
Tests check raw CK_RV return values, not exception types.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pkcs11_check import classification as C
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_EXCEEDED_MAX_ITERATIONS,
    CKR_FIPS_SELF_TEST_FAILED,
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_FUNCTION_REJECTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_INDIGESTIBLE,
    CKR_KEY_NEEDED,
    CKR_KEY_NOT_NEEDED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_KEY_UNEXTRACTABLE,
    CKR_LIBRARY_LOAD_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_NO_EVENT,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_OPERATION_NOT_VALIDATED,
    CKR_PARAMETER_SET_NOT_SUPPORTED,
    CKR_PENDING,
    CKR_PIN_EXPIRED,
    CKR_PIN_INCORRECT,
    CKR_PIN_INVALID,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_PIN_TOO_WEAK,
    CKR_PUBLIC_KEY_INVALID,
    CKR_RANDOM_NO_RNG,
    CKR_RANDOM_SEED_NOT_SUPPORTED,
    CKR_SAVED_STATE_INVALID,
    CKR_SESSION_ASYNC_NOT_SUPPORTED,
    CKR_SESSION_CLOSED,
    CKR_SESSION_COUNT,
    CKR_SESSION_EXISTS,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_SESSION_READ_WRITE_SO_EXISTS,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_SLOT_ID_INVALID,
    CKR_STATE_UNSAVEABLE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TOKEN_NOT_INITIALIZED,
    CKR_TOKEN_NOT_PRESENT,
    CKR_TOKEN_NOT_RECOGNIZED,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_PIN_NOT_INITIALIZED,
    CKR_USER_TOO_MANY_TYPES,
    CKR_USER_TYPE_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
)
from pkcs11_check.testcases._error_tuples import (
    DATA_ERRORS,
    HANDLE_ERRORS,
    KEY_SIZE_ERRORS,
    MECHANISM_ERRORS,
    SESSION_ERRORS,
    TEMPLATE_ERRORS,
)

# ---------------------------------------------------------------------------
# Universal CKR codes (spec Sec.5.1.1 - Sec.5.1.3)
# ---------------------------------------------------------------------------

# Any function may return these (spec Sec.5.1.1)
_UNIVERSAL = (CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_FUNCTION_FAILED)

# Session-using functions additionally (spec Sec.5.1.2)
_SESSION_UNIVERSAL = (
    CKR_SESSION_HANDLE_INVALID,
    CKR_DEVICE_REMOVED,
    CKR_SESSION_CLOSED,
)

# Token-using functions additionally (spec Sec.5.1.3)
_TOKEN_UNIVERSAL = (CKR_DEVICE_MEMORY, CKR_DEVICE_ERROR, CKR_TOKEN_NOT_PRESENT)


def full_compat(base_tuple: tuple[int, ...], uses_session: bool = True) -> tuple[int, ...]:
    """Build full acceptable error set from base + universals.

    Duplicates with base_tuple (e.g. CKR_FUNCTION_FAILED already in most tuples)
    are harmless for `in` checks and kept for clarity - each layer adds
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
    and a broader acceptable set for compat mode.  All CKR codes are
    represented as plain ints (values of CKR_* constants).
    """

    function: str
    """C_* function name, e.g. 'C_EncryptInit'."""

    condition: str
    """Error condition description, e.g. 'mechanism_not_supported'."""

    spec_ckr: int | tuple[int, ...]
    """Spec-mandated CKR int(s). Tuple if multiple are valid (first = preferred)."""

    compat_tuple: tuple[int, ...]
    """Acceptable CKR codes in compat mode (before universal injection)."""

    spec_ref: str
    """OASIS spec reference, e.g. 'PKCS#11 v3.2'."""

    allow_success: bool = False
    """True if permissive modules may accept the operation."""

    kind: str = "policy"
    """'crypto' (correctness) | 'policy' (attribute/permission) | 'lifecycle' (state) |
    'metadata'."""

    testable: bool = True
    """False for conditions requiring NULL pointers or C-memory semantics."""

    mechanisms: list[str] = field(default_factory=list)
    """If mechanism-specific, which mechanisms this applies to."""

    priority_note: str = ""
    """Priority info, e.g. 'Higher priority than CKR_DATA_INVALID'."""

    spec_ckr_code: str = ""
    """Override CKR code name for coverage tracking.

    When the spec mandates a CKR code that has no distinct constant
    (e.g., CKR_TOKEN_RESOURCE_EXCEEDED), spec_ckr may be set to
    CKR_FUNCTION_FAILED but this field records the actual CKR code name
    so the coverage script can count it correctly.
    """


# ---------------------------------------------------------------------------
# assert_ckr - the single validation point
# ---------------------------------------------------------------------------


def _ckr_summary_prefix(expectation: CkrExpectation) -> str:
    """Build the summary prefix string: ``function(condition)``."""
    return f"{expectation.function}({expectation.condition})"


def _classify_outside_acceptable_set(
    expectation: CkrExpectation,
    actual: int,
    spec_codes: tuple[int, ...],
    full: tuple[int, ...],
) -> None:
    """Emit a Classification (always fail) for a code outside the full acceptable set.

    Mirrors the ``_classify_unexpected_clean_rv`` logic in testcases/conftest.py:
    - vendor-defined CK_RV      -> self_contradiction (fail) to preserve pre-refactor
                                   pytest.fail outcome [flagged for review].
    - undefined (not standard)  -> self_contradiction(kind="metadata") -> fail/HIGH.
    - defined standard code     -> self_contradiction(kind=expectation.kind) -> fail;
                                   NOTE: flagged for design review — see assert_ckr docstring.

    All branches here currently produce ``fail`` outcomes (this function is only reached
    when the existing code called ``pytest.fail``).  The nonspec_reject reason maps to
    xfail, which would change the outcome; hence vendor-defined codes here also use
    self_contradiction so the fail outcome is preserved.
    """
    prefix = _ckr_summary_prefix(expectation)
    accepted = list(dict.fromkeys(ckr_name(c) for c in full))
    summary = (
        f"{prefix}: got {ckr_name(actual)}, "
        f"not in acceptable set {accepted} "
        f"[{expectation.spec_ref}]"
    )
    if not is_standard_ckr(actual) and not is_vendor_defined_ckr(actual):
        # Completely undefined CK_RV: return-value-contract violation.
        C.classify(
            "self_contradiction",
            kind="metadata",
            label=expectation.condition,
            operation=expectation.function,
            actual=actual,
            expected=spec_codes,
            spec_ref=expectation.spec_ref,
            summary=f"{prefix}: rejected with undefined CK_RV {ckr_name(actual)}, "
            f"not in acceptable set {accepted} [{expectation.spec_ref}]",
        )
        return
    # Vendor-defined or standard-but-outside-set: both are outside the gate, so both
    # produce fail here (consistent with the pre-refactor pytest.fail call).
    # REVIEW NOTE: a vendor-defined code might arguably be nonspec_reject (xfail) in a
    # future design iteration; a standard-but-outside-set code might also be nonspec_reject
    # if the acceptable-set definition is widened.  For now both stay as fail (outcome
    # preserved from pre-refactor) via self_contradiction(kind=expectation.kind).
    C.classify(
        "self_contradiction",
        kind=expectation.kind,
        label=expectation.condition,
        operation=expectation.function,
        actual=actual,
        expected=spec_codes,
        spec_ref=expectation.spec_ref,
        summary=summary,
    )


def assert_ckr(
    expectation: CkrExpectation,
    actual: int,
    strict: bool,
) -> None:
    """Validate a negative-op CKR three ways (compat) or exactly (strict).

    actual is a raw CK_RV integer (e.g. from raw.C_EncryptInit()).

    - Strict mode: rv must match spec_ckr exactly. Deviation = test failure.
    - Compat mode (the provider-general classifier):
        * rv == CKR_OK            -> fail (accepted invalid; must reject),
                                     unless allow_success is set -> pass.
        * rv not in full_compat   -> fail (rejected with a code outside the
                                     acceptable set).
        * rv in spec_codes        -> pass (spec-preferred rejection).
        * rv in full_compat but
          not in spec_codes       -> xfail (clean but non-spec rejection;
                                     a noted deviation to investigate later).

    Each decision point emits a structured :class:`~pkcs11_check.classification.Classification`
    record via :func:`~pkcs11_check.classification.classify` (emit-only refactor: outcomes
    are unchanged from pre-refactor behavior).

    Design note — branches flagged for review:
    - Compat "not in acceptable set" with a vendor-defined OR a defined-standard-but-outside-set
      code: both remain ``fail`` (via ``self_contradiction``) to preserve the pre-refactor
      ``pytest.fail`` outcome.  A future revision might treat vendor-defined or
      standard-but-outside-set codes as ``nonspec_reject`` (xfail) if the acceptable-set
      definition is widened.
    - Strict "not in spec_codes" with a non-CKR_OK code: also ``fail`` (via
      ``self_contradiction(kind="metadata")``) to preserve the strict-mode fail outcome
      for compat-acceptable deviations.
    """
    spec_codes = (
        expectation.spec_ckr if isinstance(expectation.spec_ckr, tuple) else (expectation.spec_ckr,)
    )
    prefix = _ckr_summary_prefix(expectation)

    if strict:
        # A permissive op (allow_success) returning CKR_OK is a pass in both modes;
        # CKR_OK is never in spec_codes, so this short-circuit is required for strict
        # mode to agree with the compat branch (audit M-CLASS-3).
        if actual == CKR_OK and expectation.allow_success:
            return
        if actual not in spec_codes:
            if actual == CKR_OK:
                # Accepted when it must reject (strict mode, no allow_success).
                C.classify(
                    "accepted_invalid",
                    kind=expectation.kind,
                    label=expectation.condition,
                    operation=expectation.function,
                    actual=actual,
                    expected=spec_codes,
                    spec_ref=expectation.spec_ref,
                    summary=f"{prefix}: accepted (CKR_OK) but must reject [{expectation.spec_ref}]",
                )
            else:
                # Non-CKR_OK deviation from spec in strict mode: preserve fail outcome.
                # REVIEW NOTE: compat-acceptable codes (e.g. CKR_FUNCTION_FAILED) that are
                # not spec-mandated land here in strict mode and stay as fail/self_contradiction
                # rather than xfail/nonspec_reject — consistent with pre-refactor behavior.
                C.classify(
                    "self_contradiction",
                    kind="metadata",
                    label=expectation.condition,
                    operation=expectation.function,
                    actual=actual,
                    expected=spec_codes,
                    spec_ref=expectation.spec_ref,
                    summary=(
                        f"{prefix}: spec requires {[ckr_name(c) for c in spec_codes]}, "
                        f"got {ckr_name(actual)} [{expectation.spec_ref}]"
                    ),
                )
    else:
        if actual == CKR_OK:
            if expectation.allow_success:
                return
            C.classify(
                "accepted_invalid",
                kind=expectation.kind,
                label=expectation.condition,
                operation=expectation.function,
                actual=actual,
                expected=spec_codes,
                spec_ref=expectation.spec_ref,
                summary=f"{prefix}: accepted (CKR_OK) but must reject [{expectation.spec_ref}]",
            )
            return
        full = full_compat(expectation.compat_tuple)
        if actual not in full:
            _classify_outside_acceptable_set(expectation, actual, spec_codes, full)
            return
        if actual not in spec_codes:
            C.classify(
                "nonspec_reject",
                kind=expectation.kind,
                label=expectation.condition,
                operation=expectation.function,
                actual=actual,
                expected=spec_codes,
                spec_ref=expectation.spec_ref,
                summary=(
                    f"{prefix}: rejected with {ckr_name(actual)}, "
                    f"spec prefers {[ckr_name(c) for c in spec_codes]} "
                    f"[{expectation.spec_ref}]"
                ),
            )


# ---------------------------------------------------------------------------
# Spec tables - Encrypt family
# ---------------------------------------------------------------------------

CKR_ENCRYPT: dict[str, CkrExpectation] = {
    # --- C_EncryptInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_EncryptInit",
        condition="key_CKA_ENCRYPT_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_EncryptInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        priority_note="Higher priority than CKR_KEY_FUNCTION_NOT_PERMITTED",
    ),
    "init_key_handle_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_CBC"],
    ),
    # --- C_Encrypt errors ---
    "data_len_range": CkrExpectation(
        function="C_Encrypt",
        condition="data_not_block_aligned",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        priority_note="Higher priority than CKR_DATA_INVALID",
        mechanisms=["AES_ECB"],
    ),
    "data_empty": CkrExpectation(
        function="C_Encrypt",
        condition="empty_plaintext",
        spec_ckr=(CKR_DATA_LEN_RANGE, CKR_DATA_INVALID),
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,
    ),
    "data_too_long_rsa": CkrExpectation(
        function="C_Encrypt",
        condition="RSA_PKCS_data_exceeds_k_minus_11",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS"],
    ),
    "operation_not_initialized": CkrExpectation(
        function="C_Encrypt",
        condition="no_prior_C_EncryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_size_range": CkrExpectation(
        function="C_EncryptInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "data_invalid_cbc_padding": CkrExpectation(
        function="C_Encrypt",
        condition="AES_CBC_PAD_non_block_aligned_accepted",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_CBC_PAD"],
        allow_success=True,  # CBC-PAD handles non-aligned data by design
    ),
    "data_gcm_aad_only": CkrExpectation(
        function="C_Encrypt",
        condition="AES_GCM_empty_plaintext_with_AAD",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_GCM"],
        allow_success=True,  # GCM can encrypt 0 bytes with just AAD
    ),
    # --- C_EncryptUpdate errors ---
    "update_data_len_range": CkrExpectation(
        function="C_EncryptUpdate",
        condition="non_aligned_partial_block",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_ECB"],
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_EncryptUpdate",
        condition="no_prior_C_EncryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    # --- C_EncryptFinal errors ---
    "final_data_len_range": CkrExpectation(
        function="C_EncryptFinal",
        condition="incomplete_block_at_finalize",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_ECB"],
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_EncryptFinal",
        condition="no_prior_C_EncryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    # --- Additional C_EncryptInit errors ---
    "init_operation_active": CkrExpectation(
        function="C_EncryptInit",
        condition="init_called_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_state.py)
    ),
    "init_user_not_logged_in": CkrExpectation(
        function="C_EncryptInit",
        condition="key_requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    # --- Additional C_Encrypt errors ---
    "data_invalid_general": CkrExpectation(
        function="C_Encrypt",
        condition="invalid_plaintext_content",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,
    ),
    # --- Mechanism-specific C_EncryptInit errors ---
    "rsa_oaep_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="RSA_OAEP_with_wrong_hash_in_params",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    "aes_gcm_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptInit",
        condition="AES_GCM_with_wrong_IV_length",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_GCM"],
    ),
    "aes_cbc_iv_wrong_length": CkrExpectation(
        function="C_EncryptInit",
        condition="AES_CBC_with_8_byte_IV",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_CBC"],
    ),
    # --- Mechanism-specific C_Encrypt errors ---
    "rsa_pkcs_data_too_short": CkrExpectation(
        function="C_Encrypt",
        condition="RSA_PKCS_zero_byte_plaintext",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS"],
        allow_success=True,  # Some modules accept empty plaintext for RSA-PKCS
    ),
    "rsa_oaep_data_too_long": CkrExpectation(
        function="C_Encrypt",
        condition="RSA_OAEP_plaintext_exceeds_k_minus_2hLen_minus_2",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    "aes_gcm_data_overflow": CkrExpectation(
        function="C_Encrypt",
        condition="AES_GCM_plaintext_exceeds_theoretical_limit",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_GCM"],
        testable=True,  # Testable via RawPKCS11
    ),
    # --- Additional C_EncryptInit errors ---
    "init_function_canceled": CkrExpectation(
        function="C_EncryptInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback to cancel - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "init_operation_cancel_failed": CkrExpectation(
        function="C_EncryptInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # OperationCancelFailed not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires active operation + cancel attempt - not exposed by python-pkcs11
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "init_pin_expired": CkrExpectation(
        function="C_EncryptInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy - not available in test tokens
        # Untestable: cannot force PIN expiry on software tokens
    ),
    # --- Additional C_Encrypt errors ---
    "arguments_bad": CkrExpectation(
        function="C_Encrypt",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "buffer_too_small": CkrExpectation(
        function="C_Encrypt",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "function_canceled": CkrExpectation(
        function="C_Encrypt",
        condition="operation_canceled",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback to cancel - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "operation_active": CkrExpectation(
        function="C_Encrypt",
        condition="called_during_multipart",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    # --- Additional C_EncryptUpdate errors ---
    "update_arguments_bad": CkrExpectation(
        function="C_EncryptUpdate",
        condition="NULL_pointer",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "update_buffer_too_small": CkrExpectation(
        function="C_EncryptUpdate",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "update_function_canceled": CkrExpectation(
        function="C_EncryptUpdate",
        condition="canceled",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback to cancel - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "update_operation_active": CkrExpectation(
        function="C_EncryptUpdate",
        condition="called_after_C_Encrypt",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    # --- Additional C_EncryptFinal errors ---
    "final_arguments_bad": CkrExpectation(
        function="C_EncryptFinal",
        condition="NULL_pointer",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "final_buffer_too_small": CkrExpectation(
        function="C_EncryptFinal",
        condition="output_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_function_canceled": CkrExpectation(
        function="C_EncryptFinal",
        condition="canceled",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback to cancel - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "final_operation_active": CkrExpectation(
        function="C_EncryptFinal",
        condition="called_during_single_part",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Decrypt family (Sec.5.9)
# ---------------------------------------------------------------------------

# Decrypt compat tuple: encrypted data errors + universal data errors
_DECRYPT_DATA_ERRORS = (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_DATA_LEN_RANGE,
    CKR_DATA_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
)

CKR_DECRYPT: dict[str, CkrExpectation] = {
    # --- C_DecryptInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_DecryptInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_CBC"],
    ),
    # --- C_Decrypt errors ---
    "encrypted_data_len_range": CkrExpectation(
        function="C_Decrypt",
        condition="ciphertext_not_block_aligned",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        priority_note="Higher priority than CKR_ENCRYPTED_DATA_INVALID",
        mechanisms=["AES_ECB"],
    ),
    "encrypted_data_invalid": CkrExpectation(
        function="C_Decrypt",
        condition="garbage_ciphertext",
        spec_ckr=(CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE),
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_ECB"],
    ),
    "rsa_ciphertext_wrong_length": CkrExpectation(
        function="C_Decrypt",
        condition="RSA_ciphertext_wrong_length",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS"],
        kind="crypto",
        # crypto-correctness: a wrong-length RSA ciphertext that decrypts
        # is a break for any provider, so acceptance (CKR_OK) must fail -- no
        # allow_success exemption (no per-provider demotion).
    ),
    # --- C_DecryptUpdate/Final errors ---
    "update_encrypted_data_len_range": CkrExpectation(
        function="C_DecryptUpdate",
        condition="non_aligned_partial_ciphertext",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_DecryptUpdate",
        condition="no_prior_C_DecryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    "final_encrypted_data_invalid": CkrExpectation(
        function="C_DecryptFinal",
        condition="incomplete_ciphertext_at_finalize",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_DecryptFinal",
        condition="no_prior_C_DecryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    "init_operation_active": CkrExpectation(
        function="C_DecryptInit",
        condition="init_called_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_state.py)
    ),
    "encrypted_data_cbc_wrong_padding": CkrExpectation(
        function="C_Decrypt",
        condition="AES_CBC_PAD_ciphertext_with_bad_padding",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_CBC_PAD"],
    ),
    "rsa_oaep_garbage": CkrExpectation(
        function="C_Decrypt",
        condition="RSA_OAEP_garbage_ciphertext",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_DecryptInit",
        condition="key_CKA_DECRYPT_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_handle_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_size_range": CkrExpectation(
        function="C_DecryptInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "operation_not_initialized": CkrExpectation(
        function="C_Decrypt",
        condition="no_prior_C_DecryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- Mechanism-specific C_DecryptInit errors ---
    "rsa_oaep_mechanism_param_invalid": CkrExpectation(
        function="C_DecryptInit",
        condition="RSA_OAEP_with_wrong_hash_in_params",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS_OAEP"],
    ),
    # --- Mechanism-specific C_Decrypt errors ---
    "aes_gcm_auth_failed": CkrExpectation(
        function="C_Decrypt",
        condition="AES_GCM_tampered_ciphertext_or_tag",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_GCM"],
    ),
    "aes_cbc_pad_wrong_length": CkrExpectation(
        function="C_Decrypt",
        condition="AES_CBC_PAD_ciphertext_not_block_aligned",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["AES_CBC_PAD"],
    ),
    "rsa_pkcs_ciphertext_format_invalid": CkrExpectation(
        function="C_Decrypt",
        condition="RSA_PKCS_valid_length_but_malformed_ciphertext",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS"],
    ),
    # --- Missing v2.40 entries ---
    "init_arguments_bad": CkrExpectation(
        function="C_DecryptInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "init_function_canceled": CkrExpectation(
        function="C_DecryptInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "init_operation_cancel_failed": CkrExpectation(
        function="C_DecryptInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires active operation + cancel attempt - not exposed
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "init_pin_expired": CkrExpectation(
        function="C_DecryptInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "init_user_not_logged_in": CkrExpectation(
        function="C_DecryptInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "arguments_bad": CkrExpectation(
        function="C_Decrypt",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "buffer_too_small": CkrExpectation(
        function="C_Decrypt",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "function_canceled": CkrExpectation(
        function="C_Decrypt",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "operation_active": CkrExpectation(
        function="C_Decrypt",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "user_not_logged_in": CkrExpectation(
        function="C_Decrypt",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "update_arguments_bad": CkrExpectation(
        function="C_DecryptUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "update_buffer_too_small": CkrExpectation(
        function="C_DecryptUpdate",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "update_encrypted_data_invalid": CkrExpectation(
        function="C_DecryptUpdate",
        condition="invalid_ciphertext_content",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "update_function_canceled": CkrExpectation(
        function="C_DecryptUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "update_operation_active": CkrExpectation(
        function="C_DecryptUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "update_user_not_logged_in": CkrExpectation(
        function="C_DecryptUpdate",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "final_arguments_bad": CkrExpectation(
        function="C_DecryptFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "final_buffer_too_small": CkrExpectation(
        function="C_DecryptFinal",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "final_encrypted_data_len_range": CkrExpectation(
        function="C_DecryptFinal",
        condition="incomplete_ciphertext_block",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_function_canceled": CkrExpectation(
        function="C_DecryptFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "final_operation_active": CkrExpectation(
        function="C_DecryptFinal",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "final_user_not_logged_in": CkrExpectation(
        function="C_DecryptFinal",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "decrypt_digest_update_arguments_bad": CkrExpectation(
        function="C_DecryptDigestUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "decrypt_digest_update_buffer_too_small": CkrExpectation(
        function="C_DecryptDigestUpdate",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "decrypt_digest_update_encrypted_data_invalid": CkrExpectation(
        function="C_DecryptDigestUpdate",
        condition="invalid_ciphertext_in_dual_op",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "decrypt_digest_update_encrypted_data_len_range": CkrExpectation(
        function="C_DecryptDigestUpdate",
        condition="ciphertext_wrong_length_in_dual_op",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "decrypt_digest_update_function_canceled": CkrExpectation(
        function="C_DecryptDigestUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "decrypt_digest_update_operation_active": CkrExpectation(
        function="C_DecryptDigestUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "decrypt_digest_update_operation_not_initialized": CkrExpectation(
        function="C_DecryptDigestUpdate",
        condition="operation_not_initialized",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "decrypt_verify_update_arguments_bad": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "decrypt_verify_update_buffer_too_small": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "decrypt_verify_update_data_len_range": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="verify_data_length_error",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "decrypt_verify_update_encrypted_data_invalid": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="invalid_ciphertext_in_dual_op",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "decrypt_verify_update_encrypted_data_len_range": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="ciphertext_wrong_length_in_dual_op",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=_DECRYPT_DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "decrypt_verify_update_function_canceled": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "decrypt_verify_update_operation_active": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "decrypt_verify_update_operation_not_initialized": CkrExpectation(
        function="C_DecryptVerifyUpdate",
        condition="operation_not_initialized",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Sign family (Sec.5.10)
# ---------------------------------------------------------------------------

CKR_SIGN: dict[str, CkrExpectation] = {
    # --- C_SignInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_SignInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_SignInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        kind="crypto",
        # crypto-correctness: an AES key under an RSA signing mechanism is
        # key-type confusion; acceptance must fail for any provider.
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_SignInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_handle_invalid": CkrExpectation(
        function="C_SignInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_SignInit",
        condition="key_CKA_SIGN_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_Sign errors ---
    "data_len_range": CkrExpectation(
        function="C_Sign",
        condition="data_too_long_for_mechanism",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "operation_not_initialized": CkrExpectation(
        function="C_Sign",
        condition="no_prior_C_SignInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "data_invalid": CkrExpectation(
        function="C_Sign",
        condition="data_format_error",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Most mechanisms hash data, so format doesn't matter
    ),
    # --- C_SignInit additional errors ---
    "init_key_size_range": CkrExpectation(
        function="C_SignInit",
        condition="key_size_too_small_for_mechanism",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_operation_active": CkrExpectation(
        function="C_SignInit",
        condition="init_called_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_state.py)
    ),
    # --- C_SignUpdate errors ---
    "update_data_len_range": CkrExpectation(
        function="C_SignUpdate",
        condition="partial_data_too_long",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_SignUpdate",
        condition="no_prior_C_SignInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    # --- C_SignFinal errors ---
    "final_data_len_range": CkrExpectation(
        function="C_SignFinal",
        condition="incomplete_data_at_finalize",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_SignFinal",
        condition="no_prior_C_SignInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    "final_buffer_too_small": CkrExpectation(
        function="C_SignFinal",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    # --- C_SignRecover errors ---
    "recover_init_mechanism_invalid": CkrExpectation(
        function="C_SignRecoverInit",
        condition="mechanism_not_supported_for_recover",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "recover_data_len_range": CkrExpectation(
        function="C_SignRecover",
        condition="data_too_long_for_recover",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "recover_operation_not_initialized": CkrExpectation(
        function="C_SignRecover",
        condition="no_prior_C_SignRecoverInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    # --- Mechanism-specific C_SignInit errors ---
    "ecdsa_mechanism_invalid": CkrExpectation(
        function="C_SignInit",
        condition="ECDSA_mechanism_with_AES_key",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["ECDSA"],
    ),
    "hmac_mechanism_param_invalid": CkrExpectation(
        function="C_SignInit",
        condition="HMAC_with_wrong_mechanism_params",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["SHA256_HMAC_GENERAL"],
    ),
    "rsa_pss_mechanism_param_invalid": CkrExpectation(
        function="C_SignInit",
        condition="RSA_PSS_with_wrong_salt_hash_combo",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS_PSS"],
    ),
    # --- Mechanism-specific C_Sign errors ---
    "eddsa_data_too_long": CkrExpectation(
        function="C_Sign",
        condition="Ed25519_message_exceeds_max_size",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["EDDSA"],
        allow_success=True,  # Ed25519 has no practical message size limit in most impls
    ),
    "rsa_pkcs_data_len_range": CkrExpectation(
        function="C_Sign",
        condition="RSA_PKCS_data_exceeds_k_minus_11",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS"],
    ),
    # --- Missing v2.40 entries ---
    "init_arguments_bad": CkrExpectation(
        function="C_SignInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "init_function_canceled": CkrExpectation(
        function="C_SignInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "init_operation_cancel_failed": CkrExpectation(
        function="C_SignInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires active operation + cancel attempt - not exposed
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "init_pin_expired": CkrExpectation(
        function="C_SignInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "init_user_not_logged_in": CkrExpectation(
        function="C_SignInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "arguments_bad": CkrExpectation(
        function="C_Sign",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "buffer_too_small": CkrExpectation(
        function="C_Sign",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_buffer.py)
    ),
    "function_canceled": CkrExpectation(
        function="C_Sign",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "function_rejected": CkrExpectation(
        function="C_Sign",
        condition="operation_rejected_by_policy",
        spec_ckr=CKR_FUNCTION_REJECTED,
        compat_tuple=(CKR_FUNCTION_REJECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "operation_active": CkrExpectation(
        function="C_Sign",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "token_resource_exceeded": CkrExpectation(
        function="C_Sign",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "user_not_logged_in": CkrExpectation(
        function="C_Sign",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "update_arguments_bad": CkrExpectation(
        function="C_SignUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "update_function_canceled": CkrExpectation(
        function="C_SignUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "update_operation_active": CkrExpectation(
        function="C_SignUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "update_token_resource_exceeded": CkrExpectation(
        function="C_SignUpdate",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "update_user_not_logged_in": CkrExpectation(
        function="C_SignUpdate",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "final_arguments_bad": CkrExpectation(
        function="C_SignFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "final_function_canceled": CkrExpectation(
        function="C_SignFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "final_function_rejected": CkrExpectation(
        function="C_SignFinal",
        condition="operation_rejected_by_policy",
        spec_ckr=CKR_FUNCTION_REJECTED,
        compat_tuple=(CKR_FUNCTION_REJECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_operation_active": CkrExpectation(
        function="C_SignFinal",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "final_token_resource_exceeded": CkrExpectation(
        function="C_SignFinal",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "final_user_not_logged_in": CkrExpectation(
        function="C_SignFinal",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "recover_init_arguments_bad": CkrExpectation(
        function="C_SignRecoverInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "recover_init_function_canceled": CkrExpectation(
        function="C_SignRecoverInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "recover_init_key_function_not_permitted": CkrExpectation(
        function="C_SignRecoverInit",
        condition="key_CKA_SIGN_RECOVER_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_key_handle_invalid": CkrExpectation(
        function="C_SignRecoverInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_key_size_range": CkrExpectation(
        function="C_SignRecoverInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_key_type_inconsistent": CkrExpectation(
        function="C_SignRecoverInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_mechanism_param_invalid": CkrExpectation(
        function="C_SignRecoverInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_operation_active": CkrExpectation(
        function="C_SignRecoverInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "recover_init_operation_cancel_failed": CkrExpectation(
        function="C_SignRecoverInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires active operation + cancel attempt - not exposed
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "recover_init_pin_expired": CkrExpectation(
        function="C_SignRecoverInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "recover_init_user_not_logged_in": CkrExpectation(
        function="C_SignRecoverInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "recover_arguments_bad": CkrExpectation(
        function="C_SignRecover",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "recover_buffer_too_small": CkrExpectation(
        function="C_SignRecover",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "recover_data_invalid": CkrExpectation(
        function="C_SignRecover",
        condition="invalid_data_for_recover",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_function_canceled": CkrExpectation(
        function="C_SignRecover",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "recover_operation_active": CkrExpectation(
        function="C_SignRecover",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "recover_token_resource_exceeded": CkrExpectation(
        function="C_SignRecover",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "recover_user_not_logged_in": CkrExpectation(
        function="C_SignRecover",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "sign_encrypt_update_arguments_bad": CkrExpectation(
        function="C_SignEncryptUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "sign_encrypt_update_buffer_too_small": CkrExpectation(
        function="C_SignEncryptUpdate",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "sign_encrypt_update_data_len_range": CkrExpectation(
        function="C_SignEncryptUpdate",
        condition="data_length_error_in_dual_op",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "sign_encrypt_update_function_canceled": CkrExpectation(
        function="C_SignEncryptUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "sign_encrypt_update_operation_active": CkrExpectation(
        function="C_SignEncryptUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "sign_encrypt_update_operation_not_initialized": CkrExpectation(
        function="C_SignEncryptUpdate",
        condition="operation_not_initialized",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "sign_encrypt_update_user_not_logged_in": CkrExpectation(
        function="C_SignEncryptUpdate",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Verify family (Sec.5.11)
# ---------------------------------------------------------------------------

CKR_VERIFY: dict[str, CkrExpectation] = {
    # --- C_VerifyInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_VerifyInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_VerifyInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        kind="crypto",
        # crypto-correctness: initializing verify with an AES key under
        # an RSA mechanism is key-type confusion; acceptance must fail for any
        # provider (no allow_success exemption).
    ),
    "init_key_handle_invalid": CkrExpectation(
        function="C_VerifyInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_key_function_not_permitted": CkrExpectation(
        function="C_VerifyInit",
        condition="key_CKA_VERIFY_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # SoftHSM2 doesn't check CKA_VERIFY at init
    ),
    # --- C_Verify errors ---
    "signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="tampered_signature",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "signature_len_range": CkrExpectation(
        function="C_Verify",
        condition="signature_wrong_length",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        priority_note="Higher priority than CKR_SIGNATURE_INVALID",
        kind="crypto",
        # crypto-correctness: a wrong-length RSA signature that verifies
        # (CKR_OK) is a break for any provider; acceptance must fail (no
        # allow_success exemption).
    ),
    "data_len_range": CkrExpectation(
        function="C_Verify",
        condition="oversized_data_for_raw_verify",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "operation_not_initialized": CkrExpectation(
        function="C_Verify",
        condition="no_prior_C_VerifyInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_VerifyInit additional errors ---
    "init_key_size_range": CkrExpectation(
        function="C_VerifyInit",
        condition="key_size_too_small_for_mechanism",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_operation_active": CkrExpectation(
        function="C_VerifyInit",
        condition="init_called_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_state.py)
    ),
    # --- C_VerifyUpdate errors ---
    "update_data_len_range": CkrExpectation(
        function="C_VerifyUpdate",
        condition="partial_data_too_long",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "update_operation_not_initialized": CkrExpectation(
        function="C_VerifyUpdate",
        condition="no_prior_C_VerifyInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    # --- C_VerifyFinal errors ---
    "final_signature_invalid": CkrExpectation(
        function="C_VerifyFinal",
        condition="tampered_signature_at_finalize",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "final_operation_not_initialized": CkrExpectation(
        function="C_VerifyFinal",
        condition="no_prior_C_VerifyInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    # --- C_VerifyRecover errors ---
    "recover_init_mechanism_invalid": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="mechanism_not_supported_for_recover",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "recover_signature_invalid": CkrExpectation(
        function="C_VerifyRecover",
        condition="tampered_signature_for_recover",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "recover_operation_not_initialized": CkrExpectation(
        function="C_VerifyRecover",
        condition="no_prior_C_VerifyRecoverInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    # --- C_Verify additional errors ---
    "data_invalid": CkrExpectation(
        function="C_Verify",
        condition="data_format_error",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Most mechanisms hash data, so format doesn't matter
    ),
    # --- Mechanism-specific C_Verify errors ---
    "ecdsa_signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="ECDSA_tampered_signature",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["ECDSA"],
    ),
    "hmac_signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="HMAC_tampered_signature",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["SHA256_HMAC"],
    ),
    "ecdsa_signature_len_range": CkrExpectation(
        function="C_Verify",
        condition="ECDSA_wrong_length_signature",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["ECDSA"],
        priority_note="Higher priority than CKR_SIGNATURE_INVALID",
    ),
    "hmac_signature_len_range": CkrExpectation(
        function="C_Verify",
        condition="HMAC_truncated_signature",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["SHA256_HMAC"],
        priority_note="Higher priority than CKR_SIGNATURE_INVALID",
    ),
    "eddsa_signature_len_range": CkrExpectation(
        function="C_Verify",
        condition="EdDSA_wrong_length_signature",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["EDDSA"],
        priority_note="Higher priority than CKR_SIGNATURE_INVALID",
    ),
    "rsa_pss_signature_invalid": CkrExpectation(
        function="C_Verify",
        condition="RSA_PSS_tampered_signature",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["RSA_PKCS_PSS"],
    ),
    # --- C_VerifyInit mechanism-specific errors ---
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_VerifyInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- Missing v2.40 entries ---
    "init_arguments_bad": CkrExpectation(
        function="C_VerifyInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "init_function_canceled": CkrExpectation(
        function="C_VerifyInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "init_operation_cancel_failed": CkrExpectation(
        function="C_VerifyInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires active operation + cancel attempt - not exposed
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "init_pin_expired": CkrExpectation(
        function="C_VerifyInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "init_user_not_logged_in": CkrExpectation(
        function="C_VerifyInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "arguments_bad": CkrExpectation(
        function="C_Verify",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "function_canceled": CkrExpectation(
        function="C_Verify",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "operation_active": CkrExpectation(
        function="C_Verify",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "token_resource_exceeded": CkrExpectation(
        function="C_Verify",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "update_arguments_bad": CkrExpectation(
        function="C_VerifyUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "update_function_canceled": CkrExpectation(
        function="C_VerifyUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "update_operation_active": CkrExpectation(
        function="C_VerifyUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "update_token_resource_exceeded": CkrExpectation(
        function="C_VerifyUpdate",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "final_arguments_bad": CkrExpectation(
        function="C_VerifyFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "final_data_len_range": CkrExpectation(
        function="C_VerifyFinal",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_function_canceled": CkrExpectation(
        function="C_VerifyFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "final_operation_active": CkrExpectation(
        function="C_VerifyFinal",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "final_signature_len_range": CkrExpectation(
        function="C_VerifyFinal",
        condition="signature_wrong_length_at_finalize",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "final_token_resource_exceeded": CkrExpectation(
        function="C_VerifyFinal",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "recover_init_arguments_bad": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "recover_init_function_canceled": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "recover_init_key_function_not_permitted": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="key_CKA_VERIFY_RECOVER_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_key_handle_invalid": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_key_size_range": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_key_type_inconsistent": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_mechanism_param_invalid": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_init_operation_active": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "recover_init_operation_cancel_failed": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires active operation + cancel attempt - not exposed
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "recover_init_pin_expired": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "recover_init_user_not_logged_in": CkrExpectation(
        function="C_VerifyRecoverInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "recover_arguments_bad": CkrExpectation(
        function="C_VerifyRecover",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "recover_buffer_too_small": CkrExpectation(
        function="C_VerifyRecover",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "recover_data_invalid": CkrExpectation(
        function="C_VerifyRecover",
        condition="recovered_data_invalid",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_data_len_range": CkrExpectation(
        function="C_VerifyRecover",
        condition="recovered_data_length_error",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_function_canceled": CkrExpectation(
        function="C_VerifyRecover",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "recover_operation_active": CkrExpectation(
        function="C_VerifyRecover",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "recover_signature_len_range": CkrExpectation(
        function="C_VerifyRecover",
        condition="signature_wrong_length_for_recover",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "recover_token_resource_exceeded": CkrExpectation(
        function="C_VerifyRecover",
        condition="token_storage_exhausted",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via stress test
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Digest family (Sec.5.12)
# ---------------------------------------------------------------------------

CKR_DIGEST: dict[str, CkrExpectation] = {
    # --- C_DigestInit errors ---
    "init_mechanism_invalid": CkrExpectation(
        function="C_DigestInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "init_mechanism_param_invalid": CkrExpectation(
        function="C_DigestInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "init_encrypt_mechanism": CkrExpectation(
        function="C_DigestInit",
        condition="using_encrypt_mechanism_for_digest",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_Digest errors ---
    "operation_not_initialized": CkrExpectation(
        function="C_Digest",
        condition="no_prior_C_DigestInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_DigestInit additional errors ---
    "init_operation_active": CkrExpectation(
        function="C_DigestInit",
        condition="init_called_while_digest_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_state.py)
    ),
    # --- C_Digest additional errors ---
    "digest_buffer_too_small": CkrExpectation(
        function="C_Digest",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_buffer.py)
    ),
    "empty_data": CkrExpectation(
        function="C_Digest",
        condition="digest_of_empty_bytes",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Digesting empty data is valid per most implementations
    ),
    # --- C_DigestUpdate errors ---
    "update_operation_not_initialized": CkrExpectation(
        function="C_DigestUpdate",
        condition="no_prior_C_DigestInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    # --- C_DigestKey errors ---
    "key_indigestible": CkrExpectation(
        function="C_DigestKey",
        condition="non_secret_key_for_digest",
        spec_ckr=CKR_KEY_INDIGESTIBLE,
        compat_tuple=(
            CKR_KEY_INDIGESTIBLE,
            CKR_KEY_HANDLE_INVALID,
            CKR_FUNCTION_FAILED,
            CKR_FUNCTION_NOT_SUPPORTED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules may accept any key type
    ),
    "key_handle_invalid": CkrExpectation(
        function="C_DigestKey",
        condition="destroyed_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_DigestFinal errors ---
    "final_operation_not_initialized": CkrExpectation(
        function="C_DigestFinal",
        condition="no_prior_C_DigestInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_raw_multipart.py)
    ),
    "final_buffer_too_small": CkrExpectation(
        function="C_DigestFinal",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    # --- C_DigestXofInit errors (v3.0+) ---
    "xof_init_mechanism_invalid": CkrExpectation(
        function="C_DigestXofInit",
        condition="mechanism_not_supported_for_xof",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DigestUpdate additional errors ---
    "update_data_len_range": CkrExpectation(
        function="C_DigestUpdate",
        condition="partial_data_exceeds_limits",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    # --- C_DigestKey additional errors ---
    "key_function_not_permitted": CkrExpectation(
        function="C_DigestKey",
        condition="key_not_suitable_for_digest",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_INDIGESTIBLE,
            CKR_FUNCTION_FAILED,
            CKR_FUNCTION_NOT_SUPPORTED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Most modules don't restrict DigestKey by CKA flags
    ),
    "key_digest_operation_not_initialized": CkrExpectation(
        function="C_DigestKey",
        condition="DigestKey_without_DigestInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_FUNCTION_FAILED,
            CKR_FUNCTION_NOT_SUPPORTED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- Missing v2.40 entries ---
    "init_arguments_bad": CkrExpectation(
        function="C_DigestInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "init_function_canceled": CkrExpectation(
        function="C_DigestInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "init_operation_cancel_failed": CkrExpectation(
        function="C_DigestInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires active operation + cancel attempt - not exposed
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "init_pin_expired": CkrExpectation(
        function="C_DigestInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "init_user_not_logged_in": CkrExpectation(
        function="C_DigestInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "arguments_bad": CkrExpectation(
        function="C_Digest",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "function_canceled": CkrExpectation(
        function="C_Digest",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "operation_active": CkrExpectation(
        function="C_Digest",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "update_arguments_bad": CkrExpectation(
        function="C_DigestUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "update_function_canceled": CkrExpectation(
        function="C_DigestUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "update_operation_active": CkrExpectation(
        function="C_DigestUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "key_function_canceled": CkrExpectation(
        function="C_DigestKey",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "key_key_size_range": CkrExpectation(
        function="C_DigestKey",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "key_operation_active": CkrExpectation(
        function="C_DigestKey",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "final_arguments_bad": CkrExpectation(
        function="C_DigestFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "final_function_canceled": CkrExpectation(
        function="C_DigestFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "final_operation_active": CkrExpectation(
        function="C_DigestFinal",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "digest_encrypt_update_arguments_bad": CkrExpectation(
        function="C_DigestEncryptUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "digest_encrypt_update_buffer_too_small": CkrExpectation(
        function="C_DigestEncryptUpdate",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "digest_encrypt_update_data_len_range": CkrExpectation(
        function="C_DigestEncryptUpdate",
        condition="data_length_error_in_dual_op",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    "digest_encrypt_update_function_canceled": CkrExpectation(
        function="C_DigestEncryptUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "digest_encrypt_update_operation_active": CkrExpectation(
        function="C_DigestEncryptUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "digest_encrypt_update_operation_not_initialized": CkrExpectation(
        function="C_DigestEncryptUpdate",
        condition="operation_not_initialized",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
    # --- C_DigestXofInit additional errors (v3.0+) ---
    "xof_init_arguments_bad": CkrExpectation(
        function="C_DigestXofInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_init_function_canceled": CkrExpectation(
        function="C_DigestXofInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "xof_init_mechanism_param_invalid": CkrExpectation(
        function="C_DigestXofInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_init_operation_active": CkrExpectation(
        function="C_DigestXofInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_init_operation_cancel_failed": CkrExpectation(
        function="C_DigestXofInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # v3.0+ - not widely implemented
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "xof_init_pin_expired": CkrExpectation(
        function="C_DigestXofInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "xof_init_user_not_logged_in": CkrExpectation(
        function="C_DigestXofInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DigestXof errors (v3.0+) ---
    "xof_arguments_bad": CkrExpectation(
        function="C_DigestXof",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_function_canceled": CkrExpectation(
        function="C_DigestXof",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "xof_operation_active": CkrExpectation(
        function="C_DigestXof",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_operation_not_initialized": CkrExpectation(
        function="C_DigestXof",
        condition="no_prior_C_DigestXofInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DigestXofUpdate errors (v3.0+) ---
    "xof_update_arguments_bad": CkrExpectation(
        function="C_DigestXofUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_update_exceeded_max_iterations": CkrExpectation(
        function="C_DigestXofUpdate",
        condition="maximum_iterations_exceeded",
        spec_ckr=CKR_EXCEEDED_MAX_ITERATIONS,
        compat_tuple=(CKR_EXCEEDED_MAX_ITERATIONS, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_update_function_canceled": CkrExpectation(
        function="C_DigestXofUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "xof_update_operation_active": CkrExpectation(
        function="C_DigestXofUpdate",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_update_operation_not_initialized": CkrExpectation(
        function="C_DigestXofUpdate",
        condition="no_prior_C_DigestXofInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DigestXofExtract errors (v3.0+) ---
    "xof_extract_arguments_bad": CkrExpectation(
        function="C_DigestXofExtract",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_extract_function_canceled": CkrExpectation(
        function="C_DigestXofExtract",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "xof_extract_operation_active": CkrExpectation(
        function="C_DigestXofExtract",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_extract_operation_not_initialized": CkrExpectation(
        function="C_DigestXofExtract",
        condition="no_prior_C_DigestXofInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DigestXofFinal errors (v3.0+) ---
    "xof_final_arguments_bad": CkrExpectation(
        function="C_DigestXofFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_final_function_canceled": CkrExpectation(
        function="C_DigestXofFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "xof_final_operation_active": CkrExpectation(
        function="C_DigestXofFinal",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_final_operation_not_initialized": CkrExpectation(
        function="C_DigestXofFinal",
        condition="no_prior_C_DigestXofInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DigestXofKeyValue errors (v3.0+) ---
    "xof_key_value_function_canceled": CkrExpectation(
        function="C_DigestXofKeyValue",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "xof_key_value_key_handle_invalid": CkrExpectation(
        function="C_DigestXofKeyValue",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_key_value_key_indigestible": CkrExpectation(
        function="C_DigestXofKeyValue",
        condition="key_not_digestible",
        spec_ckr=CKR_KEY_INDIGESTIBLE,
        compat_tuple=(CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_key_value_key_size_range": CkrExpectation(
        function="C_DigestXofKeyValue",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_key_value_operation_active": CkrExpectation(
        function="C_DigestXofKeyValue",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "xof_key_value_operation_not_initialized": CkrExpectation(
        function="C_DigestXofKeyValue",
        condition="no_prior_C_DigestXofInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Key Generation family (Sec.5.14)
# ---------------------------------------------------------------------------

CKR_KEYGEN: dict[str, CkrExpectation] = {
    # --- C_GenerateKey errors ---
    "genkey_mechanism_invalid": CkrExpectation(
        function="C_GenerateKey",
        condition="unsupported_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "genkey_bad_size": CkrExpectation(
        function="C_GenerateKey",
        condition="invalid_key_size",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        # tpm2 has no symmetric-keygen surface -> CKR_FUNCTION_NOT_SUPPORTED for any
        # negative keygen probe; accept it as a clean reject (xfail, not fail). PC-6.
        compat_tuple=(*KEY_SIZE_ERRORS, CKR_FUNCTION_NOT_SUPPORTED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Kryoptic accepts AES key size 0 and non-standard sizes
    ),
    "genkey_template_incomplete": CkrExpectation(
        function="C_GenerateKey",
        condition="missing_required_attribute",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "genkey_template_inconsistent": CkrExpectation(
        function="C_GenerateKey",
        condition="conflicting_attributes",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        # PC-6: tpm2 has no symmetric-keygen surface -> FUNCTION_NOT_SUPPORTED (xfail).
        compat_tuple=(*TEMPLATE_ERRORS, CKR_FUNCTION_NOT_SUPPORTED),
        spec_ref="PKCS#11 v3.2",
    ),
    "genkey_attribute_type_invalid": CkrExpectation(
        function="C_GenerateKey",
        condition="bogus_attribute_in_template",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        # PC-6: tpm2 has no symmetric-keygen surface -> FUNCTION_NOT_SUPPORTED (xfail).
        compat_tuple=(*TEMPLATE_ERRORS, CKR_FUNCTION_NOT_SUPPORTED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules ignore unknown attributes
    ),
    "genkey_attribute_read_only": CkrExpectation(
        function="C_GenerateKey",
        condition="CKA_CLASS_in_keygen_template",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may ignore CKA_CLASS in keygen
    ),
    # --- C_GenerateKeyPair errors ---
    "genkeypair_bad_size": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="invalid_key_size",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "genkeypair_mechanism_invalid": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="unsupported_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "genkeypair_curve_not_supported": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="unsupported_EC_curve",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(
            CKR_CURVE_NOT_SUPPORTED,
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "genkeypair_domain_params_invalid": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="malformed_EC_params",
        spec_ckr=CKR_DOMAIN_PARAMS_INVALID,
        compat_tuple=(
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_CURVE_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "genkeypair_template_inconsistent": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="conflicting_pub_priv_templates",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_GenerateKey additional errors ---
    "genkey_session_read_only": CkrExpectation(
        function="C_GenerateKey",
        condition="token_key_in_read_only_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "genkey_operation_active": CkrExpectation(
        function="C_GenerateKey",
        condition="keygen_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "genkey_user_not_logged_in": CkrExpectation(
        function="C_GenerateKey",
        condition="private_key_without_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Modules without login requirements accept this
    ),
    # --- C_GenerateKeyPair additional errors ---
    "genkeypair_session_read_only": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="token_keypair_in_read_only_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "genkeypair_operation_active": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="keygen_pair_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "genkeypair_attribute_type_invalid": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="bogus_attribute_in_template",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules ignore unknown attributes
    ),
    "genkeypair_attribute_read_only": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="CKA_CLASS_in_keypair_template",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may ignore CKA_CLASS in keygen
    ),
    # --- Missing v2.40 entries ---
    "genkey_arguments_bad": CkrExpectation(
        function="C_GenerateKey",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "genkey_curve_not_supported_gen": CkrExpectation(
        function="C_GenerateKey",
        condition="unsupported_curve_for_symmetric_keygen",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(
            CKR_CURVE_NOT_SUPPORTED,
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "genkey_function_canceled": CkrExpectation(
        function="C_GenerateKey",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "genkey_mechanism_param_invalid": CkrExpectation(
        function="C_GenerateKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "genkey_pin_expired": CkrExpectation(
        function="C_GenerateKey",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "genkey_token_write_protected": CkrExpectation(
        function="C_GenerateKey",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "genkeypair_arguments_bad": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "genkeypair_function_canceled": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "genkeypair_mechanism_param_invalid": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "genkeypair_parameter_set_not_supported": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="unsupported_parameter_set",
        spec_ckr=CKR_PARAMETER_SET_NOT_SUPPORTED,
        compat_tuple=(
            CKR_PARAMETER_SET_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "genkeypair_pin_expired": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "genkeypair_template_incomplete": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="missing_required_attribute_in_template",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "genkeypair_token_write_protected": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "genkeypair_user_not_logged_in": CkrExpectation(
        function="C_GenerateKeyPair",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Derive family (Sec.5.14.5)
# ---------------------------------------------------------------------------

CKR_DERIVE: dict[str, CkrExpectation] = {
    "mechanism_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="unsupported_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "key_type_inconsistent": CkrExpectation(
        function="C_DeriveKey",
        condition="base_key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_MECHANISM_PARAM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_TEMPLATE_INCOMPLETE,
            CKR_FUNCTION_FAILED,
            CKR_KEY_HANDLE_INVALID,
        ),
        spec_ref="PKCS#11 v3.2",
        # SoftHSM2: CKR_TEMPLATE_INCOMPLETE, OpenCryptoki: CKR_MECHANISM_PARAM_INVALID
        # NSS: CKR_KEY_HANDLE_INVALID
    ),
    "mechanism_param_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "key_function_not_permitted": CkrExpectation(
        function="C_DeriveKey",
        condition="key_CKA_DERIVE_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "template_incomplete": CkrExpectation(
        function="C_DeriveKey",
        condition="missing_output_key_type",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "domain_params_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="ECDH_with_invalid_domain_params",
        spec_ckr=CKR_DOMAIN_PARAMS_INVALID,
        compat_tuple=(
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_MECHANISM_PARAM_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["ECDH1_DERIVE"],
    ),
    "template_inconsistent": CkrExpectation(
        function="C_DeriveKey",
        condition="conflicting_output_attributes",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "key_handle_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="destroyed_base_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "key_size_range": CkrExpectation(
        function="C_DeriveKey",
        condition="output_key_size_invalid",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "operation_active": CkrExpectation(
        function="C_DeriveKey",
        condition="derive_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "session_read_only": CkrExpectation(
        function="C_DeriveKey",
        condition="derive_token_key_in_RO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "user_not_logged_in": CkrExpectation(
        function="C_DeriveKey",
        condition="private_derived_key_without_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Modules without login requirements accept this
    ),
    "attribute_type_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="bogus_attr_in_derive_template",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules ignore unknown attributes
    ),
    "attribute_value_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="bad_value_in_derive_template",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "attribute_read_only": CkrExpectation(
        function="C_DeriveKey",
        condition="CKA_CLASS_in_derive_template",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may ignore CKA_CLASS in derive
    ),
    "ecdh_mechanism_param_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="wrong_KDF_in_ECDH_params",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["ECDH1_DERIVE"],
    ),
    "hkdf_mechanism_param_invalid": CkrExpectation(
        function="C_DeriveKey",
        condition="wrong_params_for_HKDF_derive",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        mechanisms=["HKDF_DERIVE"],
        testable=True,  # Testable via RawPKCS11
    ),
    # --- Missing v2.40 entries ---
    "arguments_bad": CkrExpectation(
        function="C_DeriveKey",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "curve_not_supported": CkrExpectation(
        function="C_DeriveKey",
        condition="unsupported_EC_curve_for_derive",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(
            CKR_CURVE_NOT_SUPPORTED,
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "function_canceled": CkrExpectation(
        function="C_DeriveKey",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "pin_expired": CkrExpectation(
        function="C_DeriveKey",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "token_write_protected": CkrExpectation(
        function="C_DeriveKey",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - KEM family (Sec.5.14.7-5.14.8, v3.2 only)
# ---------------------------------------------------------------------------

CKR_KEM: dict[str, CkrExpectation] = {
    # --- C_EncapsulateKey errors ---
    "encap_mechanism_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="unsupported_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            *MECHANISM_ERRORS[1:],
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
    ),
    "encap_key_type_inconsistent": CkrExpectation(
        function="C_EncapsulateKey",
        condition="RSA_key_with_ML_KEM_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_ARGUMENTS_BAD,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
            # NSS-PQC: RSA keys are not visible in the PQC-slot context so the
            # handle resolves as invalid instead of producing CKR_KEY_TYPE_INCONSISTENT.
            CKR_KEY_HANDLE_INVALID,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
    ),
    # --- C_DecapsulateKey errors ---
    "decap_mechanism_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="unsupported_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            *MECHANISM_ERRORS[1:],
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
    ),
    "decap_ciphertext_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="garbage_ciphertext",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=(
            CKR_ENCRYPTED_DATA_INVALID,
            CKR_ENCRYPTED_DATA_LEN_RANGE,
            CKR_ARGUMENTS_BAD,
            CKR_MECHANISM_INVALID,
            CKR_TEMPLATE_INCOMPLETE,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        allow_success=True,  # ML-KEM implicit rejection may produce a key anyway
    ),
    "encap_mechanism_param_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
    ),
    "encap_key_handle_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="destroyed_public_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
    ),
    "encap_operation_active": CkrExpectation(
        function="C_EncapsulateKey",
        condition="encapsulate_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "encap_template_incomplete": CkrExpectation(
        function="C_EncapsulateKey",
        condition="missing_output_key_attrs",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
    ),
    "encap_key_size_range": CkrExpectation(
        function="C_EncapsulateKey",
        condition="output_key_size_invalid",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
    ),
    "decap_key_handle_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="destroyed_private_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
    ),
    "decap_operation_active": CkrExpectation(
        function="C_DecapsulateKey",
        condition="decapsulate_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "decap_template_incomplete": CkrExpectation(
        function="C_DecapsulateKey",
        condition="missing_output_key_attrs",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
    ),
    "decap_key_type_inconsistent": CkrExpectation(
        function="C_DecapsulateKey",
        condition="RSA_key_with_ML_KEM_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
    ),
    "decap_mechanism_param_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
    ),
    # --- Missing v2.40 entries ---
    "encap_arguments_bad": CkrExpectation(
        function="C_EncapsulateKey",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "encap_attribute_read_only": CkrExpectation(
        function="C_EncapsulateKey",
        condition="read_only_attribute_in_template",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "encap_attribute_type_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="unknown_attribute_type",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11
    ),
    "encap_attribute_value_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="invalid_attribute_value",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11
    ),
    "encap_curve_not_supported": CkrExpectation(
        function="C_EncapsulateKey",
        condition="unsupported_EC_curve",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(
            CKR_CURVE_NOT_SUPPORTED,
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11
    ),
    "encap_domain_params_invalid": CkrExpectation(
        function="C_EncapsulateKey",
        condition="malformed_domain_parameters",
        spec_ckr=CKR_DOMAIN_PARAMS_INVALID,
        compat_tuple=(
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_CURVE_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11
    ),
    "encap_function_canceled": CkrExpectation(
        function="C_EncapsulateKey",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "encap_parameter_set_not_supported": CkrExpectation(
        function="C_EncapsulateKey",
        condition="unsupported_parameter_set",
        spec_ckr=CKR_PARAMETER_SET_NOT_SUPPORTED,
        compat_tuple=(
            CKR_PARAMETER_SET_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11
    ),
    "encap_pin_expired": CkrExpectation(
        function="C_EncapsulateKey",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "encap_session_read_only": CkrExpectation(
        function="C_EncapsulateKey",
        condition="token_object_in_read_only_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "encap_template_inconsistent": CkrExpectation(
        function="C_EncapsulateKey",
        condition="conflicting_template_attributes",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11
    ),
    "encap_token_write_protected": CkrExpectation(
        function="C_EncapsulateKey",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "encap_user_not_logged_in": CkrExpectation(
        function="C_EncapsulateKey",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.7",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "decap_arguments_bad": CkrExpectation(
        function="C_DecapsulateKey",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "decap_attribute_read_only": CkrExpectation(
        function="C_DecapsulateKey",
        condition="read_only_attribute_in_template",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "decap_attribute_type_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="unknown_attribute_type",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_attribute_value_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="invalid_attribute_value",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_buffer_too_small": CkrExpectation(
        function="C_DecapsulateKey",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "decap_curve_not_supported": CkrExpectation(
        function="C_DecapsulateKey",
        condition="unsupported_EC_curve",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(
            CKR_CURVE_NOT_SUPPORTED,
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_domain_params_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="malformed_domain_parameters",
        spec_ckr=CKR_DOMAIN_PARAMS_INVALID,
        compat_tuple=(
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_CURVE_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_function_canceled": CkrExpectation(
        function="C_DecapsulateKey",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "decap_parameter_set_not_supported": CkrExpectation(
        function="C_DecapsulateKey",
        condition="unsupported_parameter_set",
        spec_ckr=CKR_PARAMETER_SET_NOT_SUPPORTED,
        compat_tuple=(
            CKR_PARAMETER_SET_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_pin_expired": CkrExpectation(
        function="C_DecapsulateKey",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "decap_session_read_only": CkrExpectation(
        function="C_DecapsulateKey",
        condition="token_object_in_read_only_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "decap_template_inconsistent": CkrExpectation(
        function="C_DecapsulateKey",
        condition="conflicting_template_attributes",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_token_write_protected": CkrExpectation(
        function="C_DecapsulateKey",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "decap_unwrapping_key_handle_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="invalid_private_key_handle",
        spec_ckr=CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        compat_tuple=(
            CKR_UNWRAPPING_KEY_HANDLE_INVALID,
            CKR_KEY_HANDLE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_unwrapping_key_size_range": CkrExpectation(
        function="C_DecapsulateKey",
        condition="private_key_size_out_of_range",
        spec_ckr=CKR_UNWRAPPING_KEY_SIZE_RANGE,
        compat_tuple=(CKR_UNWRAPPING_KEY_SIZE_RANGE, CKR_KEY_SIZE_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_unwrapping_key_type_inconsistent": CkrExpectation(
        function="C_DecapsulateKey",
        condition="private_key_type_wrong_for_mechanism",
        spec_ckr=CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_user_not_logged_in": CkrExpectation(
        function="C_DecapsulateKey",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "decap_wrapped_key_invalid": CkrExpectation(
        function="C_DecapsulateKey",
        condition="invalid_ciphertext_data",
        spec_ckr=CKR_WRAPPED_KEY_INVALID,
        compat_tuple=(CKR_WRAPPED_KEY_INVALID, CKR_WRAPPED_KEY_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
    "decap_wrapped_key_len_range": CkrExpectation(
        function="C_DecapsulateKey",
        condition="ciphertext_wrong_length",
        spec_ckr=CKR_WRAPPED_KEY_LEN_RANGE,
        compat_tuple=(CKR_WRAPPED_KEY_LEN_RANGE, CKR_WRAPPED_KEY_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.14.8",
        testable=True,  # Testable via RawPKCS11
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Wrap/Unwrap family (Sec.5.14.3-5.14.4)
# ---------------------------------------------------------------------------

CKR_WRAP: dict[str, CkrExpectation] = {
    "wrap_key_unextractable": CkrExpectation(
        function="C_WrapKey",
        condition="key_CKA_EXTRACTABLE_is_False",
        spec_ckr=CKR_KEY_UNEXTRACTABLE,
        compat_tuple=(
            CKR_KEY_UNEXTRACTABLE,
            CKR_KEY_NOT_WRAPPABLE,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "wrap_mechanism_invalid": CkrExpectation(
        function="C_WrapKey",
        condition="unsupported_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "unwrap_wrapped_key_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="garbage_wrapped_data",
        spec_ckr=CKR_WRAPPED_KEY_INVALID,
        compat_tuple=(
            CKR_WRAPPED_KEY_INVALID,
            CKR_WRAPPED_KEY_LEN_RANGE,
            CKR_ENCRYPTED_DATA_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "wrap_key_type_inconsistent": CkrExpectation(
        function="C_WrapKey",
        condition="wrapping_key_wrong_type_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "wrap_wrapping_key_size_range": CkrExpectation(
        function="C_WrapKey",
        condition="wrapping_key_size_out_of_range",
        # Spec mandates CKR_WRAPPING_KEY_SIZE_RANGE; the size-or-type family of
        # codes is accepted as spec-correct (some modules classify an undersized
        # AES key as type-inconsistent rather than size-out-of-range).
        spec_ckr=(
            CKR_WRAPPING_KEY_SIZE_RANGE,
            CKR_KEY_SIZE_RANGE,
            CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
            CKR_KEY_TYPE_INCONSISTENT,
        ),
        # Universal codes (CKR_GENERAL_ERROR / CKR_FUNCTION_FAILED) are injected
        # by full_compat(), so a catch-all reject (e.g. softhsm2's
        # CKR_GENERAL_ERROR) is an honest xfail, not a pass.
        compat_tuple=(
            CKR_WRAPPING_KEY_SIZE_RANGE,
            CKR_KEY_SIZE_RANGE,
            CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        kind="metadata",
        testable=True,  # Testable via RawPKCS11
    ),
    "wrap_mechanism_param_invalid": CkrExpectation(
        function="C_WrapKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "unwrap_wrapped_key_len_range": CkrExpectation(
        function="C_UnwrapKey",
        condition="wrapped_data_wrong_length",
        spec_ckr=CKR_WRAPPED_KEY_LEN_RANGE,
        compat_tuple=(
            CKR_WRAPPED_KEY_LEN_RANGE,
            CKR_WRAPPED_KEY_INVALID,
            CKR_ENCRYPTED_DATA_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        priority_note="Higher priority than CKR_WRAPPED_KEY_INVALID",
    ),
    "unwrap_template_incomplete": CkrExpectation(
        function="C_UnwrapKey",
        condition="missing_required_unwrap_attrs",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "wrap_key_handle_invalid": CkrExpectation(
        function="C_WrapKey",
        condition="destroyed_key_to_wrap",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "wrap_key_not_wrappable": CkrExpectation(
        function="C_WrapKey",
        condition="key_CKA_WRAP_is_False_on_wrapping_key",
        spec_ckr=CKR_KEY_NOT_WRAPPABLE,
        compat_tuple=(
            CKR_KEY_NOT_WRAPPABLE,
            CKR_KEY_UNEXTRACTABLE,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "wrap_operation_active": CkrExpectation(
        function="C_WrapKey",
        condition="wrap_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "wrap_buffer_too_small": CkrExpectation(
        function="C_WrapKey",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "wrap_session_read_only": CkrExpectation(
        function="C_WrapKey",
        condition="token_wrap_in_RO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Wrap doesn't create token objects, most modules allow it
    ),
    "unwrap_mechanism_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="unsupported_unwrap_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "unwrap_key_type_inconsistent": CkrExpectation(
        function="C_UnwrapKey",
        condition="wrong_key_type_for_unwrap_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "unwrap_operation_active": CkrExpectation(
        function="C_UnwrapKey",
        condition="unwrap_while_operation_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "unwrap_session_read_only": CkrExpectation(
        function="C_UnwrapKey",
        condition="unwrap_to_token_object_in_RO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "unwrap_user_not_logged_in": CkrExpectation(
        function="C_UnwrapKey",
        condition="private_key_unwrap_without_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Modules without login requirements accept this
    ),
    # --- Missing v2.40 entries ---
    "unwrap_arguments_bad": CkrExpectation(
        function="C_UnwrapKey",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "unwrap_attribute_read_only": CkrExpectation(
        function="C_UnwrapKey",
        condition="read_only_attribute_in_unwrap_template",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "unwrap_attribute_type_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="unknown_attribute_in_unwrap_template",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_attribute_value_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="invalid_value_in_unwrap_template",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_buffer_too_small": CkrExpectation(
        function="C_UnwrapKey",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "unwrap_curve_not_supported": CkrExpectation(
        function="C_UnwrapKey",
        condition="unsupported_EC_curve_in_unwrap",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(
            CKR_CURVE_NOT_SUPPORTED,
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_domain_params_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="malformed_domain_params_in_unwrap",
        spec_ckr=CKR_DOMAIN_PARAMS_INVALID,
        compat_tuple=(
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_CURVE_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_function_canceled": CkrExpectation(
        function="C_UnwrapKey",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "unwrap_mechanism_param_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_parameter_set_not_supported": CkrExpectation(
        function="C_UnwrapKey",
        condition="unsupported_parameter_set",
        spec_ckr=CKR_PARAMETER_SET_NOT_SUPPORTED,
        compat_tuple=(
            CKR_PARAMETER_SET_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_pin_expired": CkrExpectation(
        function="C_UnwrapKey",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "unwrap_template_inconsistent": CkrExpectation(
        function="C_UnwrapKey",
        condition="conflicting_unwrap_template_attrs",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_token_write_protected": CkrExpectation(
        function="C_UnwrapKey",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "unwrap_unwrapping_key_handle_invalid": CkrExpectation(
        function="C_UnwrapKey",
        condition="invalid_unwrapping_key_handle",
        spec_ckr=CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        compat_tuple=(
            CKR_UNWRAPPING_KEY_HANDLE_INVALID,
            CKR_KEY_HANDLE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_unwrapping_key_size_range": CkrExpectation(
        function="C_UnwrapKey",
        condition="unwrapping_key_size_out_of_range",
        spec_ckr=CKR_UNWRAPPING_KEY_SIZE_RANGE,
        compat_tuple=(CKR_UNWRAPPING_KEY_SIZE_RANGE, CKR_KEY_SIZE_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "unwrap_unwrapping_key_type_inconsistent": CkrExpectation(
        function="C_UnwrapKey",
        condition="unwrapping_key_type_wrong_for_mechanism",
        spec_ckr=CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Object management (Sec.5.7)
# ---------------------------------------------------------------------------

CKR_OBJECT: dict[str, CkrExpectation] = {
    "create_missing_class": CkrExpectation(
        function="C_CreateObject",
        condition="missing_CKA_CLASS",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "create_invalid_class": CkrExpectation(
        function="C_CreateObject",
        condition="CKA_CLASS_is_0xDEADBEEF",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "get_attr_sensitive": CkrExpectation(
        function="C_GetAttributeValue",
        condition="read_VALUE_on_SENSITIVE_key",
        spec_ckr=CKR_ATTRIBUTE_SENSITIVE,
        compat_tuple=(CKR_ATTRIBUTE_SENSITIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "get_attr_destroyed": CkrExpectation(
        function="C_GetAttributeValue",
        condition="destroyed_object_handle",
        spec_ckr=CKR_OBJECT_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules don't detect invalid handles
    ),
    "set_attr_readonly": CkrExpectation(
        function="C_SetAttributeValue",
        condition="modify_read_only_CKA_CLASS",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Kryoptic accepts CKA_CLASS modification
    ),
    "destroy_already_destroyed": CkrExpectation(
        function="C_DestroyObject",
        condition="double_destroy",
        spec_ckr=CKR_OBJECT_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules silently accept double destroy
    ),
    # --- C_CreateObject additional errors ---
    "create_attr_type_invalid": CkrExpectation(
        function="C_CreateObject",
        condition="bogus_attribute_type",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may ignore unknown attributes
    ),
    "create_private_object_not_logged_in": CkrExpectation(
        function="C_CreateObject",
        condition="private_object_without_login",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Modules without login requirements accept this
    ),
    # --- C_CopyObject errors ---
    "copy_action_prohibited": CkrExpectation(
        function="C_CopyObject",
        condition="CKA_COPYABLE_is_False",
        spec_ckr=CKR_ACTION_PROHIBITED,
        compat_tuple=(
            CKR_ACTION_PROHIBITED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
            CKR_FUNCTION_NOT_SUPPORTED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may not enforce CKA_COPYABLE
    ),
    "copy_destroyed_handle": CkrExpectation(
        function="C_CopyObject",
        condition="copy_destroyed_object",
        spec_ckr=CKR_OBJECT_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,
    ),
    # --- C_GetObjectSize errors ---
    "get_size_handle_invalid": CkrExpectation(
        function="C_GetObjectSize",
        condition="destroyed_handle",
        spec_ckr=CKR_OBJECT_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,
    ),
    # --- C_SetAttributeValue additional errors ---
    "set_attr_action_prohibited": CkrExpectation(
        function="C_SetAttributeValue",
        condition="CKA_MODIFIABLE_is_False",
        spec_ckr=CKR_ACTION_PROHIBITED,
        compat_tuple=(CKR_ACTION_PROHIBITED, CKR_ATTRIBUTE_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,
    ),
    # --- C_FindObjects* errors ---
    "find_not_initialized": CkrExpectation(
        function="C_FindObjects",
        condition="FindObjects_without_FindObjectsInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_CreateObject session/domain errors ---
    "create_session_read_only": CkrExpectation(
        function="C_CreateObject",
        condition="token_object_in_RO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "create_curve_not_supported": CkrExpectation(
        function="C_CreateObject",
        condition="EC_key_with_unsupported_curve",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(
            CKR_CURVE_NOT_SUPPORTED,
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    "create_domain_params_invalid": CkrExpectation(
        function="C_CreateObject",
        condition="EC_key_with_malformed_params",
        spec_ckr=CKR_DOMAIN_PARAMS_INVALID,
        compat_tuple=(
            CKR_DOMAIN_PARAMS_INVALID,
            CKR_CURVE_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_CopyObject additional errors ---
    "copy_template_inconsistent": CkrExpectation(
        function="C_CopyObject",
        condition="conflicting_copy_template_attrs",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "copy_session_read_only": CkrExpectation(
        function="C_CopyObject",
        condition="copy_to_token_object_in_RO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "copy_handle_invalid": CkrExpectation(
        function="C_CopyObject",
        condition="non_existent_object_handle",
        spec_ckr=CKR_OBJECT_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_DestroyObject additional errors ---
    "destroy_action_prohibited": CkrExpectation(
        function="C_DestroyObject",
        condition="CKA_DESTROYABLE_is_False",
        spec_ckr=CKR_ACTION_PROHIBITED,
        compat_tuple=(CKR_ACTION_PROHIBITED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Not all modules enforce CKA_DESTROYABLE
    ),
    "destroy_session_read_only": CkrExpectation(
        function="C_DestroyObject",
        condition="destroy_token_object_in_RO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_SetAttributeValue additional errors ---
    "set_attr_type_invalid": CkrExpectation(
        function="C_SetAttributeValue",
        condition="set_bogus_attribute_type",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may ignore unknown attributes
    ),
    "set_attr_value_invalid": CkrExpectation(
        function="C_SetAttributeValue",
        condition="set_wrong_value_for_known_attr",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "set_attr_template_inconsistent": CkrExpectation(
        function="C_SetAttributeValue",
        condition="conflicting_attribute_modifications",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_FindObjectsInit additional errors ---
    "find_attr_value_invalid": CkrExpectation(
        function="C_FindObjectsInit",
        condition="search_with_bogus_attr_value",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may return empty results instead of error
    ),
    # --- Missing v2.40 entries ---
    "create_arguments_bad": CkrExpectation(
        function="C_CreateObject",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "create_attribute_read_only": CkrExpectation(
        function="C_CreateObject",
        condition="read_only_attribute_in_create",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "create_operation_active": CkrExpectation(
        function="C_CreateObject",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "create_parameter_set_not_supported": CkrExpectation(
        function="C_CreateObject",
        condition="unsupported_parameter_set",
        spec_ckr=CKR_PARAMETER_SET_NOT_SUPPORTED,
        compat_tuple=(
            CKR_PARAMETER_SET_NOT_SUPPORTED,
            CKR_ATTRIBUTE_VALUE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "create_pin_expired": CkrExpectation(
        function="C_CreateObject",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "create_template_inconsistent": CkrExpectation(
        function="C_CreateObject",
        condition="conflicting_create_template_attrs",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "create_token_write_protected": CkrExpectation(
        function="C_CreateObject",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "create_user_not_logged_in": CkrExpectation(
        function="C_CreateObject",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "copy_arguments_bad": CkrExpectation(
        function="C_CopyObject",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "copy_attribute_read_only": CkrExpectation(
        function="C_CopyObject",
        condition="read_only_attribute_in_copy_template",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=(
            CKR_ATTRIBUTE_READ_ONLY,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_TEMPLATE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "copy_attribute_type_invalid": CkrExpectation(
        function="C_CopyObject",
        condition="unknown_attribute_in_copy_template",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "copy_attribute_value_invalid": CkrExpectation(
        function="C_CopyObject",
        condition="invalid_value_in_copy_template",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "copy_operation_active": CkrExpectation(
        function="C_CopyObject",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "copy_pin_expired": CkrExpectation(
        function="C_CopyObject",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "copy_token_write_protected": CkrExpectation(
        function="C_CopyObject",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "copy_user_not_logged_in": CkrExpectation(
        function="C_CopyObject",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "destroy_operation_active": CkrExpectation(
        function="C_DestroyObject",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "destroy_pin_expired": CkrExpectation(
        function="C_DestroyObject",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "destroy_token_write_protected": CkrExpectation(
        function="C_DestroyObject",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "get_size_arguments_bad": CkrExpectation(
        function="C_GetObjectSize",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_size_information_sensitive": CkrExpectation(
        function="C_GetObjectSize",
        condition="size_info_is_sensitive",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_INFORMATION_SENSITIVE not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
        spec_ckr_code="CKR_INFORMATION_SENSITIVE",
    ),
    "get_size_operation_active": CkrExpectation(
        function="C_GetObjectSize",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "get_attr_arguments_bad": CkrExpectation(
        function="C_GetAttributeValue",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_attr_type_invalid": CkrExpectation(
        function="C_GetAttributeValue",
        condition="query_unknown_attribute",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "get_attr_buffer_too_small": CkrExpectation(
        function="C_GetAttributeValue",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "get_attr_operation_active": CkrExpectation(
        function="C_GetAttributeValue",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "set_attr_arguments_bad": CkrExpectation(
        function="C_SetAttributeValue",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "set_attr_object_handle_invalid": CkrExpectation(
        function="C_SetAttributeValue",
        condition="destroyed_object_handle",
        spec_ckr=CKR_OBJECT_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "set_attr_operation_active": CkrExpectation(
        function="C_SetAttributeValue",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "set_attr_session_read_only": CkrExpectation(
        function="C_SetAttributeValue",
        condition="modify_token_object_in_RO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "set_attr_token_write_protected": CkrExpectation(
        function="C_SetAttributeValue",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "set_attr_user_not_logged_in": CkrExpectation(
        function="C_SetAttributeValue",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "find_init_arguments_bad": CkrExpectation(
        function="C_FindObjectsInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "find_init_attribute_type_invalid": CkrExpectation(
        function="C_FindObjectsInit",
        condition="unknown_attribute_in_search_template",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    "find_init_operation_active": CkrExpectation(
        function="C_FindObjectsInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "find_init_pin_expired": CkrExpectation(
        function="C_FindObjectsInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "find_arguments_bad": CkrExpectation(
        function="C_FindObjects",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "find_operation_active": CkrExpectation(
        function="C_FindObjects",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "find_final_operation_active": CkrExpectation(
        function="C_FindObjectsFinal",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "find_final_operation_not_initialized": CkrExpectation(
        function="C_FindObjectsFinal",
        condition="operation_not_initialized",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 multipart
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Session management (Sec.5.6)
# ---------------------------------------------------------------------------

CKR_SESSION: dict[str, CkrExpectation] = {
    "login_wrong_pin": CkrExpectation(
        function="C_Login",
        condition="incorrect_PIN",
        spec_ckr=CKR_PIN_INCORRECT,
        compat_tuple=(CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "login_already_logged_in": CkrExpectation(
        function="C_Login",
        condition="double_login",
        spec_ckr=CKR_USER_ALREADY_LOGGED_IN,
        compat_tuple=(CKR_USER_ALREADY_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "logout_not_logged_in": CkrExpectation(
        function="C_Logout",
        condition="logout_without_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules don't error on logout without login
    ),
    # --- C_OpenSession errors ---
    "open_slot_invalid": CkrExpectation(
        function="C_OpenSession",
        condition="non_existent_slot_ID",
        spec_ckr=CKR_SLOT_ID_INVALID,
        compat_tuple=(CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_CloseSession errors ---
    "close_handle_invalid": CkrExpectation(
        function="C_CloseSession",
        condition="invalid_session_handle",
        spec_ckr=CKR_SESSION_HANDLE_INVALID,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_Login additional errors ---
    "login_user_type_invalid": CkrExpectation(
        function="C_Login",
        condition="invalid_user_type",
        spec_ckr=CKR_USER_TYPE_INVALID,
        compat_tuple=(CKR_USER_TYPE_INVALID, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "login_pin_locked": CkrExpectation(
        function="C_Login",
        condition="PIN_locked_after_too_many_attempts",
        spec_ckr=CKR_PIN_LOCKED,
        compat_tuple=(CKR_PIN_LOCKED, CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    # --- C_OpenSession additional errors ---
    "open_session_count": CkrExpectation(
        function="C_OpenSession",
        condition="exhaust_session_limit",
        spec_ckr=CKR_SESSION_COUNT,
        compat_tuple=(CKR_SESSION_COUNT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "open_token_write_protected": CkrExpectation(
        function="C_OpenSession",
        condition="RW_session_on_write_protected_token",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_GetSessionInfo errors ---
    "get_session_info_handle_invalid": CkrExpectation(
        function="C_GetSessionInfo",
        condition="invalid_session_handle",
        spec_ckr=CKR_SESSION_HANDLE_INVALID,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_CloseAllSessions errors ---
    "close_all_slot_invalid": CkrExpectation(
        function="C_CloseAllSessions",
        condition="non_existent_slot_ID",
        spec_ckr=CKR_SLOT_ID_INVALID,
        compat_tuple=(CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_Login additional errors ---
    "login_user_another_logged_in": CkrExpectation(
        function="C_Login",
        condition="SO_login_when_user_logged_in",
        spec_ckr=CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        compat_tuple=(
            CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            CKR_USER_ALREADY_LOGGED_IN,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_Login additional PIN errors ---
    "login_pin_len_range": CkrExpectation(
        function="C_Login",
        condition="PIN_too_short_or_too_long",
        spec_ckr=CKR_PIN_LEN_RANGE,
        compat_tuple=(CKR_PIN_LEN_RANGE, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_GetOperationState session error ---
    "get_op_state_session_invalid": CkrExpectation(
        function="C_GetOperationState",
        condition="invalid_session_handle",
        spec_ckr=CKR_SESSION_HANDLE_INVALID,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_SetOperationState session error ---
    "set_op_state_session_invalid": CkrExpectation(
        function="C_SetOperationState",
        condition="invalid_session_handle",
        spec_ckr=CKR_SESSION_HANDLE_INVALID,
        compat_tuple=SESSION_ERRORS,
        spec_ref="PKCS#11 v3.2",
    ),
    # --- Missing v2.40 entries ---
    "open_arguments_bad": CkrExpectation(
        function="C_OpenSession",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_null_params.py)
    ),
    "open_session_async_not_supported": CkrExpectation(
        function="C_OpenSession",
        condition="async_sessions_not_supported",
        spec_ckr=CKR_SESSION_ASYNC_NOT_SUPPORTED,
        compat_tuple=(CKR_SESSION_ASYNC_NOT_SUPPORTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # v3.0+ async sessions - not widely supported
        # Untestable: v3.2 async sessions not widely supported
    ),
    "open_session_parallel_not_supported": CkrExpectation(
        function="C_OpenSession",
        condition="parallel_sessions_not_supported",
        spec_ckr=CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        compat_tuple=(CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Legacy parallel sessions - not testable
        # Untestable: legacy deprecated function
    ),
    "open_session_rw_so_exists": CkrExpectation(
        function="C_OpenSession",
        condition="RO_session_while_SO_logged_in",
        spec_ckr=CKR_SESSION_READ_WRITE_SO_EXISTS,
        compat_tuple=(CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "open_token_not_recognized": CkrExpectation(
        function="C_OpenSession",
        condition="token_not_recognized_in_slot",
        spec_ckr=CKR_TOKEN_NOT_RECOGNIZED,
        compat_tuple=(CKR_TOKEN_NOT_RECOGNIZED, CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires physical token state change
        # Untestable: requires unrecognized token hardware event
    ),
    "close_operation_active": CkrExpectation(
        function="C_CloseSession",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "get_session_info_arguments_bad": CkrExpectation(
        function="C_GetSessionInfo",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_session_info_operation_active": CkrExpectation(
        function="C_GetSessionInfo",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "login_arguments_bad": CkrExpectation(
        function="C_Login",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "login_function_canceled": CkrExpectation(
        function="C_Login",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "login_operation_active": CkrExpectation(
        function="C_Login",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "login_operation_not_initialized": CkrExpectation(
        function="C_Login",
        condition="operation_not_initialized",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "login_session_read_only_exists": CkrExpectation(
        function="C_Login",
        condition="SO_login_with_RO_sessions_open",
        spec_ckr=CKR_SESSION_READ_ONLY_EXISTS,
        compat_tuple=(CKR_SESSION_READ_ONLY_EXISTS, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "login_user_pin_not_initialized": CkrExpectation(
        function="C_Login",
        condition="user_PIN_not_initialized",
        spec_ckr=CKR_USER_PIN_NOT_INITIALIZED,
        compat_tuple=(CKR_USER_PIN_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "login_user_too_many_types": CkrExpectation(
        function="C_Login",
        condition="too_many_user_types_logged_in",
        spec_ckr=CKR_USER_TOO_MANY_TYPES,
        compat_tuple=(CKR_USER_TOO_MANY_TYPES, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "logout_operation_active": CkrExpectation(
        function="C_Logout",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    # --- C_LoginUser errors (v3.0+) ---
    "login_user_arguments_bad": CkrExpectation(
        function="C_LoginUser",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "login_user_function_canceled": CkrExpectation(
        function="C_LoginUser",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "login_user_operation_active": CkrExpectation(
        function="C_LoginUser",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "login_user_operation_not_initialized": CkrExpectation(
        function="C_LoginUser",
        condition="operation_not_initialized",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "login_user_pin_incorrect": CkrExpectation(
        function="C_LoginUser",
        condition="incorrect_PIN",
        spec_ckr=CKR_PIN_INCORRECT,
        compat_tuple=(CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "login_user_pin_locked": CkrExpectation(
        function="C_LoginUser",
        condition="PIN_locked_after_too_many_attempts",
        spec_ckr=CKR_PIN_LOCKED,
        compat_tuple=(CKR_PIN_LOCKED, CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "login_user_session_read_only_exists": CkrExpectation(
        function="C_LoginUser",
        condition="SO_login_with_RO_sessions_open",
        spec_ckr=CKR_SESSION_READ_ONLY_EXISTS,
        compat_tuple=(CKR_SESSION_READ_ONLY_EXISTS, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "login_user_already_logged_in": CkrExpectation(
        function="C_LoginUser",
        condition="double_login",
        spec_ckr=CKR_USER_ALREADY_LOGGED_IN,
        compat_tuple=(CKR_USER_ALREADY_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "login_user_another_already_logged_in": CkrExpectation(
        function="C_LoginUser",
        condition="another_user_type_already_logged_in",
        spec_ckr=CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        compat_tuple=(
            CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            CKR_USER_ALREADY_LOGGED_IN,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "c_login_user_pin_not_initialized": CkrExpectation(
        function="C_LoginUser",
        condition="user_PIN_not_initialized",
        spec_ckr=CKR_USER_PIN_NOT_INITIALIZED,
        compat_tuple=(CKR_USER_PIN_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "c_login_user_too_many_types": CkrExpectation(
        function="C_LoginUser",
        condition="too_many_user_types_logged_in",
        spec_ckr=CKR_USER_TOO_MANY_TYPES,
        compat_tuple=(CKR_USER_TOO_MANY_TYPES, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "c_login_user_type_invalid": CkrExpectation(
        function="C_LoginUser",
        condition="invalid_user_type",
        spec_ckr=CKR_USER_TYPE_INVALID,
        compat_tuple=(CKR_USER_TYPE_INVALID, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_SessionCancel errors (v3.0+) ---
    "session_cancel_operation_active": CkrExpectation(
        function="C_SessionCancel",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "session_cancel_operation_cancel_failed": CkrExpectation(
        function="C_SessionCancel",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # v3.0+ - not widely implemented
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    # --- C_GetSessionValidationFlags errors (v3.0+) ---
    "get_session_validation_flags_operation_active": CkrExpectation(
        function="C_GetSessionValidationFlags",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Random (Sec.5.18)
# ---------------------------------------------------------------------------

CKR_RANDOM: dict[str, CkrExpectation] = {
    "seed_not_supported": CkrExpectation(
        function="C_SeedRandom",
        condition="seeding_not_supported",
        spec_ckr=CKR_RANDOM_SEED_NOT_SUPPORTED,
        compat_tuple=(
            CKR_RANDOM_SEED_NOT_SUPPORTED,
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Module may accept seeding
    ),
    # --- C_GenerateRandom errors ---
    "generate_random_args_bad": CkrExpectation(
        function="C_GenerateRandom",
        condition="NULL_buffer_pointer",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Via ctypes
    ),
    "generate_random_zero_length": CkrExpectation(
        function="C_GenerateRandom",
        condition="zero_byte_request",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Most modules accept 0-length request
    ),
    "generate_random_large": CkrExpectation(
        function="C_GenerateRandom",
        condition="one_megabyte_request",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Most modules handle large requests
    ),
    # --- C_SeedRandom additional errors ---
    "seed_random_args_bad": CkrExpectation(
        function="C_SeedRandom",
        condition="NULL_seed_pointer",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(
            CKR_ARGUMENTS_BAD,
            CKR_RANDOM_SEED_NOT_SUPPORTED,
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Via ctypes
    ),
    # --- Missing v2.40 entries ---
    "seed_function_canceled": CkrExpectation(
        function="C_SeedRandom",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "seed_operation_active": CkrExpectation(
        function="C_SeedRandom",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "seed_random_no_rng": CkrExpectation(
        function="C_SeedRandom",
        condition="no_random_number_generator",
        spec_ckr=CKR_RANDOM_NO_RNG,
        compat_tuple=(CKR_RANDOM_NO_RNG, CKR_FUNCTION_NOT_SUPPORTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "seed_user_not_logged_in": CkrExpectation(
        function="C_SeedRandom",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
    "generate_function_canceled": CkrExpectation(
        function="C_GenerateRandom",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "generate_operation_active": CkrExpectation(
        function="C_GenerateRandom",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "generate_random_no_rng": CkrExpectation(
        function="C_GenerateRandom",
        condition="no_random_number_generator",
        spec_ckr=CKR_RANDOM_NO_RNG,
        compat_tuple=(CKR_RANDOM_NO_RNG, CKR_FUNCTION_NOT_SUPPORTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "generate_seed_random_required": CkrExpectation(
        function="C_GenerateRandom",
        condition="token_requires_seeding_before_generation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_SEED_RANDOM_REQUIRED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
        spec_ckr_code="CKR_SEED_RANDOM_REQUIRED",
    ),
    "generate_user_not_logged_in": CkrExpectation(
        function="C_GenerateRandom",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 without login
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Operation State (Sec.5.6.5-5.6.6)
# ---------------------------------------------------------------------------

CKR_STATE: dict[str, CkrExpectation] = {
    "get_state_no_op": CkrExpectation(
        function="C_GetOperationState",
        condition="no_active_operation",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_STATE_UNSAVEABLE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "set_state_invalid": CkrExpectation(
        function="C_SetOperationState",
        condition="garbage_state_data",
        spec_ckr=CKR_SAVED_STATE_INVALID,
        compat_tuple=(CKR_SAVED_STATE_INVALID, CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_GetOperationState additional errors ---
    "get_state_buffer_too_small": CkrExpectation(
        function="C_GetOperationState",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_STATE_UNSAVEABLE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    # --- C_SetOperationState additional errors ---
    "set_state_key_needed": CkrExpectation(
        function="C_SetOperationState",
        condition="state_requires_key_but_none_supplied",
        spec_ckr=CKR_KEY_NEEDED,
        compat_tuple=(CKR_KEY_NEEDED, CKR_SAVED_STATE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "set_state_key_not_needed": CkrExpectation(
        function="C_SetOperationState",
        condition="state_does_not_need_key_but_key_supplied",
        spec_ckr=CKR_KEY_NOT_NEEDED,
        compat_tuple=(CKR_KEY_NOT_NEEDED, CKR_SAVED_STATE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    # --- Missing v2.40 entries ---
    "get_state_arguments_bad": CkrExpectation(
        function="C_GetOperationState",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_state_operation_active": CkrExpectation(
        function="C_GetOperationState",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "get_state_state_unsaveable": CkrExpectation(
        function="C_GetOperationState",
        condition="operation_state_cannot_be_saved",
        spec_ckr=CKR_STATE_UNSAVEABLE,
        compat_tuple=(CKR_STATE_UNSAVEABLE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "set_state_arguments_bad": CkrExpectation(
        function="C_SetOperationState",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "set_state_key_changed": CkrExpectation(
        function="C_SetOperationState",
        condition="key_changed_since_state_saved",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_KEY_CHANGED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
        spec_ckr_code="CKR_KEY_CHANGED",
    ),
    "set_state_operation_active": CkrExpectation(
        function="C_SetOperationState",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Slot/Token Management (Sec.5.5)
# ---------------------------------------------------------------------------

CKR_SLOT_TOKEN: dict[str, CkrExpectation] = {
    "get_slot_info_invalid_slot": CkrExpectation(
        function="C_GetSlotInfo",
        condition="non_existent_slot_ID",
        spec_ckr=CKR_SLOT_ID_INVALID,
        compat_tuple=(CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "get_token_info_invalid_slot": CkrExpectation(
        function="C_GetTokenInfo",
        condition="non_existent_slot_ID",
        spec_ckr=CKR_SLOT_ID_INVALID,
        compat_tuple=(CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "get_mech_list_invalid_slot": CkrExpectation(
        function="C_GetMechanismList",
        condition="non_existent_slot_ID",
        spec_ckr=CKR_SLOT_ID_INVALID,
        compat_tuple=(CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "get_mech_info_invalid": CkrExpectation(
        function="C_GetMechanismInfo",
        condition="non_existent_mechanism",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=(CKR_MECHANISM_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "wait_for_slot_event_no_event": CkrExpectation(
        function="C_WaitForSlotEvent",
        condition="non_blocking_no_event",
        spec_ckr=CKR_NO_EVENT,
        compat_tuple=(CKR_NO_EVENT, CKR_FUNCTION_NOT_SUPPORTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_GetSlotList additional errors ---
    "get_slot_list_buffer_too_small": CkrExpectation(
        function="C_GetSlotList",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    # --- C_GetTokenInfo additional errors ---
    "get_token_info_token_not_present": CkrExpectation(
        function="C_GetTokenInfo",
        condition="token_not_present_in_slot",
        spec_ckr=CKR_TOKEN_NOT_PRESENT,
        compat_tuple=(CKR_TOKEN_NOT_PRESENT, CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires physical token removal
        # Untestable: requires physical token removal
    ),
    # --- C_InitToken errors ---
    "init_token_session_exists": CkrExpectation(
        function="C_InitToken",
        condition="open_sessions_exist",
        spec_ckr=CKR_SESSION_EXISTS,
        compat_tuple=(CKR_SESSION_EXISTS, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "init_token_pin_incorrect": CkrExpectation(
        function="C_InitToken",
        condition="wrong_SO_PIN",
        spec_ckr=CKR_PIN_INCORRECT,
        compat_tuple=(CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    # --- C_InitPIN errors ---
    "init_pin_user_not_logged_in": CkrExpectation(
        function="C_InitPIN",
        condition="not_logged_in_as_SO",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_SetPIN errors ---
    "set_pin_incorrect": CkrExpectation(
        function="C_SetPIN",
        condition="wrong_old_PIN",
        spec_ckr=CKR_PIN_INCORRECT,
        compat_tuple=(CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "set_pin_len_range": CkrExpectation(
        function="C_SetPIN",
        condition="new_PIN_too_short",
        spec_ckr=CKR_PIN_LEN_RANGE,
        compat_tuple=(CKR_PIN_LEN_RANGE, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "set_pin_session_read_only": CkrExpectation(
        function="C_SetPIN",
        condition="read_only_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- Missing v2.40 entries ---
    "get_slot_list_arguments_bad": CkrExpectation(
        function="C_GetSlotList",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 (proven in test_ckr_null_params.py)
    ),
    "get_slot_info_arguments_bad": CkrExpectation(
        function="C_GetSlotInfo",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_token_info_arguments_bad": CkrExpectation(
        function="C_GetTokenInfo",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_token_info_token_not_recognized": CkrExpectation(
        function="C_GetTokenInfo",
        condition="token_not_recognized_in_slot",
        spec_ckr=CKR_TOKEN_NOT_RECOGNIZED,
        compat_tuple=(CKR_TOKEN_NOT_RECOGNIZED, CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires physical token state change
        # Untestable: requires unrecognized token hardware event
    ),
    "get_mech_list_arguments_bad": CkrExpectation(
        function="C_GetMechanismList",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_mech_list_buffer_too_small": CkrExpectation(
        function="C_GetMechanismList",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "get_mech_list_token_not_recognized": CkrExpectation(
        function="C_GetMechanismList",
        condition="token_not_recognized_in_slot",
        spec_ckr=CKR_TOKEN_NOT_RECOGNIZED,
        compat_tuple=(CKR_TOKEN_NOT_RECOGNIZED, CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires physical token state change
        # Untestable: requires unrecognized token hardware event
    ),
    "get_mech_info_arguments_bad": CkrExpectation(
        function="C_GetMechanismInfo",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_mech_info_slot_invalid": CkrExpectation(
        function="C_GetMechanismInfo",
        condition="non_existent_slot_ID",
        spec_ckr=CKR_SLOT_ID_INVALID,
        compat_tuple=(CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "get_mech_info_token_not_recognized": CkrExpectation(
        function="C_GetMechanismInfo",
        condition="token_not_recognized_in_slot",
        spec_ckr=CKR_TOKEN_NOT_RECOGNIZED,
        compat_tuple=(CKR_TOKEN_NOT_RECOGNIZED, CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires physical token state change
        # Untestable: requires unrecognized token hardware event
    ),
    "init_token_arguments_bad": CkrExpectation(
        function="C_InitToken",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "init_token_function_canceled": CkrExpectation(
        function="C_InitToken",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "init_token_pin_locked": CkrExpectation(
        function="C_InitToken",
        condition="SO_PIN_locked",
        spec_ckr=CKR_PIN_LOCKED,
        compat_tuple=(CKR_PIN_LOCKED, CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "init_token_slot_invalid": CkrExpectation(
        function="C_InitToken",
        condition="non_existent_slot_ID",
        spec_ckr=CKR_SLOT_ID_INVALID,
        compat_tuple=(CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "init_token_token_not_recognized": CkrExpectation(
        function="C_InitToken",
        condition="token_not_recognized_in_slot",
        spec_ckr=CKR_TOKEN_NOT_RECOGNIZED,
        compat_tuple=(CKR_TOKEN_NOT_RECOGNIZED, CKR_SLOT_ID_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires physical token state change
        # Untestable: requires unrecognized token hardware event
    ),
    "init_token_token_write_protected": CkrExpectation(
        function="C_InitToken",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "init_pin_arguments_bad": CkrExpectation(
        function="C_InitPIN",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "init_pin_function_canceled": CkrExpectation(
        function="C_InitPIN",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "init_pin_operation_active": CkrExpectation(
        function="C_InitPIN",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "init_pin_pin_invalid": CkrExpectation(
        function="C_InitPIN",
        condition="invalid_PIN_format",
        spec_ckr=CKR_PIN_INVALID,
        compat_tuple=(CKR_PIN_INVALID, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "init_pin_pin_len_range": CkrExpectation(
        function="C_InitPIN",
        condition="PIN_length_out_of_range",
        spec_ckr=CKR_PIN_LEN_RANGE,
        compat_tuple=(CKR_PIN_LEN_RANGE, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "init_pin_session_read_only": CkrExpectation(
        function="C_InitPIN",
        condition="not_in_RW_SO_session",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "init_pin_token_write_protected": CkrExpectation(
        function="C_InitPIN",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "init_pin_pin_too_weak": CkrExpectation(
        function="C_InitPIN",
        condition="PIN_too_weak",
        spec_ckr=CKR_PIN_TOO_WEAK,
        compat_tuple=(
            CKR_PIN_TOO_WEAK,
            CKR_PIN_LEN_RANGE,
            CKR_PIN_INCORRECT,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via subprocess with 1-byte PIN
    ),
    "init_pin_token_not_initialized": CkrExpectation(
        function="C_InitPIN",
        condition="token_not_initialized",
        spec_ckr=CKR_TOKEN_NOT_INITIALIZED,
        compat_tuple=(CKR_TOKEN_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via subprocess on uninitialized token
    ),
    "set_pin_arguments_bad": CkrExpectation(
        function="C_SetPIN",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "set_pin_function_canceled": CkrExpectation(
        function="C_SetPIN",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "set_pin_operation_active": CkrExpectation(
        function="C_SetPIN",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "set_pin_pin_invalid": CkrExpectation(
        function="C_SetPIN",
        condition="invalid_new_PIN_format",
        spec_ckr=CKR_PIN_INVALID,
        compat_tuple=(CKR_PIN_INVALID, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "set_pin_pin_locked": CkrExpectation(
        function="C_SetPIN",
        condition="PIN_locked_after_attempts",
        spec_ckr=CKR_PIN_LOCKED,
        compat_tuple=(CKR_PIN_LOCKED, CKR_PIN_INCORRECT, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
    ),
    "set_pin_token_write_protected": CkrExpectation(
        function="C_SetPIN",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11 with R/O session
    ),
    "wait_slot_event_arguments_bad": CkrExpectation(
        function="C_WaitForSlotEvent",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - General Purpose (Sec.5.4)
# ---------------------------------------------------------------------------

CKR_GENERAL: dict[str, CkrExpectation] = {
    "double_initialize": CkrExpectation(
        function="C_Initialize",
        condition="already_initialized",
        spec_ckr=CKR_CRYPTOKI_ALREADY_INITIALIZED,
        compat_tuple=(CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Some modules accept double init
    ),
    "finalize_not_initialized": CkrExpectation(
        function="C_Finalize",
        condition="not_initialized",
        spec_ckr=CKR_CRYPTOKI_NOT_INITIALIZED,
        compat_tuple=(CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    "get_info_null": CkrExpectation(
        function="C_GetInfo",
        condition="NULL_pInfo_pointer",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Via ctypes
    ),
    # --- C_GetFunctionList ---
    "get_function_list_ok": CkrExpectation(
        function="C_GetFunctionList",
        condition="successful_call",
        spec_ckr=CKR_ARGUMENTS_BAD,  # Only possible error is NULL pointer
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        allow_success=True,  # Normal call succeeds
        testable=True,
    ),
    # --- C_Finalize additional errors ---
    "finalize_twice": CkrExpectation(
        function="C_Finalize",
        condition="double_finalize",
        spec_ckr=CKR_CRYPTOKI_NOT_INITIALIZED,
        compat_tuple=(CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- C_GetInfo after finalize ---
    "get_info_after_finalize": CkrExpectation(
        function="C_GetInfo",
        condition="called_after_C_Finalize",
        spec_ckr=CKR_CRYPTOKI_NOT_INITIALIZED,
        compat_tuple=(CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
    ),
    # --- Missing v2.40 entries ---
    "initialize_arguments_bad": CkrExpectation(
        function="C_Initialize",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "initialize_cant_lock": CkrExpectation(
        function="C_Initialize",
        condition="mutex_locking_not_supported",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_CANT_LOCK not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
        spec_ckr_code="CKR_CANT_LOCK",
    ),
    "initialize_need_to_create_threads": CkrExpectation(
        function="C_Initialize",
        condition="thread_creation_required",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_NEED_TO_CREATE_THREADS not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable via RawPKCS11
        spec_ckr_code="CKR_NEED_TO_CREATE_THREADS",
    ),
    "finalize_arguments_bad": CkrExpectation(
        function="C_Finalize",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_func_status_function_not_parallel": CkrExpectation(
        function="C_GetFunctionStatus",
        condition="parallel_execution_not_supported",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_FUNCTION_NOT_PARALLEL not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Legacy v2.01 parallel function - not testable
        # Untestable: legacy deprecated function
        spec_ckr_code="CKR_FUNCTION_NOT_PARALLEL",
    ),
    "get_func_status_operation_active": CkrExpectation(
        function="C_GetFunctionStatus",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "cancel_func_function_not_parallel": CkrExpectation(
        function="C_CancelFunction",
        condition="parallel_execution_not_supported",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_FUNCTION_NOT_PARALLEL not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Legacy v2.01 parallel function - not testable
        # Untestable: legacy deprecated function
        spec_ckr_code="CKR_FUNCTION_NOT_PARALLEL",
    ),
    "cancel_func_operation_active": CkrExpectation(
        function="C_CancelFunction",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_state.py
    ),
    "get_interface_list_arguments_bad": CkrExpectation(
        function="C_GetInterfaceList",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_interface_list_buffer_too_small": CkrExpectation(
        function="C_GetInterfaceList",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
    "get_interface_arguments_bad": CkrExpectation(
        function="C_GetInterface",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_args_bad.py
    ),
    "get_interface_buffer_too_small": CkrExpectation(
        function="C_GetInterface",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Tested via test_ckr_raw_buffer.py
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Verify Signature family (v3.2, Sec.5.11)
# ---------------------------------------------------------------------------

CKR_VERIFY_SIGNATURE: dict[str, CkrExpectation] = {
    # --- C_VerifySignatureInit errors ---
    "verify_signature_init_arguments_bad": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_function_canceled": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "verify_signature_init_key_function_not_permitted": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="key_CKA_VERIFY_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_key_handle_invalid": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_key_size_range": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_key_type_inconsistent": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_mechanism_invalid": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_mechanism_param_invalid": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_operation_active": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_operation_cancel_failed": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=False,  # v3.2 - not widely implemented
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "verify_signature_init_pin_expired": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "verify_signature_init_signature_len_range": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="signature_length_out_of_range",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_init_user_not_logged_in": CkrExpectation(
        function="C_VerifySignatureInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.7",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_VerifySignature errors ---
    "verify_signature_arguments_bad": CkrExpectation(
        function="C_VerifySignature",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_data_invalid": CkrExpectation(
        function="C_VerifySignature",
        condition="invalid_data_content",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_data_len_range": CkrExpectation(
        function="C_VerifySignature",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_function_canceled": CkrExpectation(
        function="C_VerifySignature",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "verify_signature_operation_not_initialized": CkrExpectation(
        function="C_VerifySignature",
        condition="no_prior_C_VerifySignatureInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_signature_invalid": CkrExpectation(
        function="C_VerifySignature",
        condition="signature_verification_failed",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_signature_len_range": CkrExpectation(
        function="C_VerifySignature",
        condition="signature_length_out_of_range",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_token_resource_exceeded": CkrExpectation(
        function="C_VerifySignature",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2 Sec.5.11.8",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    # --- C_VerifySignatureUpdate errors ---
    "verify_signature_update_arguments_bad": CkrExpectation(
        function="C_VerifySignatureUpdate",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.9",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_update_data_len_range": CkrExpectation(
        function="C_VerifySignatureUpdate",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.11.9",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_update_function_canceled": CkrExpectation(
        function="C_VerifySignatureUpdate",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.9",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "verify_signature_update_operation_not_initialized": CkrExpectation(
        function="C_VerifySignatureUpdate",
        condition="no_prior_C_VerifySignatureInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.9",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_update_token_resource_exceeded": CkrExpectation(
        function="C_VerifySignatureUpdate",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2 Sec.5.11.9",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    # --- C_VerifySignatureFinal errors ---
    "verify_signature_final_arguments_bad": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_final_data_len_range": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_final_function_canceled": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "verify_signature_final_operation_not_initialized": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="no_prior_C_VerifySignatureInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_final_signature_invalid": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="signature_verification_failed",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_final_signature_len_range": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="signature_length_out_of_range",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_signature_final_token_resource_exceeded": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "verify_signature_final_operation_not_validated": CkrExpectation(
        function="C_VerifySignatureFinal",
        condition="operation_not_validated",
        spec_ckr=CKR_OPERATION_NOT_VALIDATED,
        compat_tuple=(CKR_OPERATION_NOT_VALIDATED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2 Sec.5.11.10",
        testable=False,  # v3.1+ - requires C_Verify without prior validation, not widely supported
        # Untestable: requires calling C_VerifySignatureFinal on a v3.1+ session
        # that has not been validated via C_Verify, which is not supported by most modules
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Message-based Encrypt family (v3.0, Sec.5.9)
# ---------------------------------------------------------------------------

CKR_MSG_ENCRYPT: dict[str, CkrExpectation] = {
    # --- C_MessageEncryptInit errors ---
    "msg_encrypt_init_function_canceled": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # v3.0+ - not widely implemented
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_encrypt_init_key_function_not_permitted": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="key_CKA_ENCRYPT_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_init_key_handle_invalid": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_init_key_size_range": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_init_key_type_inconsistent": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_init_mechanism_invalid": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_init_mechanism_param_invalid": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_init_operation_active": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_init_operation_cancel_failed": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # v3.0+ - not widely implemented
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "msg_encrypt_init_pin_expired": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "msg_encrypt_init_user_not_logged_in": CkrExpectation(
        function="C_MessageEncryptInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_EncryptMessage errors ---
    "encrypt_message_arguments_bad": CkrExpectation(
        function="C_EncryptMessage",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_buffer_too_small": CkrExpectation(
        function="C_EncryptMessage",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_data_invalid": CkrExpectation(
        function="C_EncryptMessage",
        condition="invalid_plaintext_content",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_data_len_range": CkrExpectation(
        function="C_EncryptMessage",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_function_canceled": CkrExpectation(
        function="C_EncryptMessage",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "encrypt_message_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptMessage",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_operation_active": CkrExpectation(
        function="C_EncryptMessage",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_operation_not_initialized": CkrExpectation(
        function="C_EncryptMessage",
        condition="no_prior_C_MessageEncryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_EncryptMessageBegin errors ---
    "encrypt_message_begin_function_canceled": CkrExpectation(
        function="C_EncryptMessageBegin",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "encrypt_message_begin_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptMessageBegin",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_begin_operation_active": CkrExpectation(
        function="C_EncryptMessageBegin",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_begin_operation_not_initialized": CkrExpectation(
        function="C_EncryptMessageBegin",
        condition="no_prior_C_MessageEncryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_begin_pin_expired": CkrExpectation(
        function="C_EncryptMessageBegin",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "encrypt_message_begin_user_not_logged_in": CkrExpectation(
        function="C_EncryptMessageBegin",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_EncryptMessageNext errors ---
    "encrypt_message_next_arguments_bad": CkrExpectation(
        function="C_EncryptMessageNext",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_next_buffer_too_small": CkrExpectation(
        function="C_EncryptMessageNext",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_next_data_len_range": CkrExpectation(
        function="C_EncryptMessageNext",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_next_function_canceled": CkrExpectation(
        function="C_EncryptMessageNext",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "encrypt_message_next_mechanism_param_invalid": CkrExpectation(
        function="C_EncryptMessageNext",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_next_operation_active": CkrExpectation(
        function="C_EncryptMessageNext",
        condition="called_without_C_EncryptMessageBegin",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "encrypt_message_next_operation_not_initialized": CkrExpectation(
        function="C_EncryptMessageNext",
        condition="no_prior_C_MessageEncryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_MessageEncryptFinal errors ---
    "msg_encrypt_final_arguments_bad": CkrExpectation(
        function="C_MessageEncryptFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_final_function_canceled": CkrExpectation(
        function="C_MessageEncryptFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_encrypt_final_operation_active": CkrExpectation(
        function="C_MessageEncryptFinal",
        condition="multipart_message_still_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_encrypt_final_operation_not_initialized": CkrExpectation(
        function="C_MessageEncryptFinal",
        condition="no_prior_C_MessageEncryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Message-based Decrypt family (v3.0, Sec.5.11)
# ---------------------------------------------------------------------------

CKR_MSG_DECRYPT: dict[str, CkrExpectation] = {
    # --- C_MessageDecryptInit errors ---
    "msg_decrypt_init_arguments_bad": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_function_canceled": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_decrypt_init_key_function_not_permitted": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="key_CKA_DECRYPT_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_key_handle_invalid": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_key_size_range": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_key_type_inconsistent": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_mechanism_invalid": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_mechanism_param_invalid": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_operation_active": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_init_operation_cancel_failed": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # v3.0+ - not widely implemented
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "msg_decrypt_init_pin_expired": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "msg_decrypt_init_user_not_logged_in": CkrExpectation(
        function="C_MessageDecryptInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DecryptMessage errors ---
    "decrypt_message_aead_decrypt_failed": CkrExpectation(
        function="C_DecryptMessage",
        condition="AEAD_authentication_tag_invalid",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_AEAD_DECRYPT_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_AEAD_DECRYPT_FAILED",
    ),
    "decrypt_message_arguments_bad": CkrExpectation(
        function="C_DecryptMessage",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_buffer_too_small": CkrExpectation(
        function="C_DecryptMessage",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_encrypted_data_invalid": CkrExpectation(
        function="C_DecryptMessage",
        condition="invalid_ciphertext",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=(
            CKR_ENCRYPTED_DATA_INVALID,
            CKR_ENCRYPTED_DATA_LEN_RANGE,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_encrypted_data_len_range": CkrExpectation(
        function="C_DecryptMessage",
        condition="ciphertext_length_out_of_range",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=(
            CKR_ENCRYPTED_DATA_LEN_RANGE,
            CKR_ENCRYPTED_DATA_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_function_canceled": CkrExpectation(
        function="C_DecryptMessage",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "decrypt_message_mechanism_param_invalid": CkrExpectation(
        function="C_DecryptMessage",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_operation_active": CkrExpectation(
        function="C_DecryptMessage",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_operation_cancel_failed": CkrExpectation(
        function="C_DecryptMessage",
        condition="cannot_cancel_active_operation",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_OPERATION_CANCEL_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # v3.0+ - not widely implemented
        # Untestable: requires active operation that refuses cancellation
        spec_ckr_code="CKR_OPERATION_CANCEL_FAILED",
    ),
    "decrypt_message_operation_not_initialized": CkrExpectation(
        function="C_DecryptMessage",
        condition="no_prior_C_MessageDecryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_user_not_logged_in": CkrExpectation(
        function="C_DecryptMessage",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DecryptMessageBegin errors ---
    "decrypt_message_begin_arguments_bad": CkrExpectation(
        function="C_DecryptMessageBegin",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_begin_function_canceled": CkrExpectation(
        function="C_DecryptMessageBegin",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "decrypt_message_begin_mechanism_param_invalid": CkrExpectation(
        function="C_DecryptMessageBegin",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_begin_operation_active": CkrExpectation(
        function="C_DecryptMessageBegin",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_begin_operation_not_initialized": CkrExpectation(
        function="C_DecryptMessageBegin",
        condition="no_prior_C_MessageDecryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_begin_pin_expired": CkrExpectation(
        function="C_DecryptMessageBegin",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "decrypt_message_begin_user_not_logged_in": CkrExpectation(
        function="C_DecryptMessageBegin",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_DecryptMessageNext errors ---
    "decrypt_message_next_aead_decrypt_failed": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="AEAD_authentication_tag_invalid",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_AEAD_DECRYPT_FAILED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_AEAD_DECRYPT_FAILED",
    ),
    "decrypt_message_next_arguments_bad": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_next_buffer_too_small": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_next_encrypted_data_invalid": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="invalid_ciphertext",
        spec_ckr=CKR_ENCRYPTED_DATA_INVALID,
        compat_tuple=(
            CKR_ENCRYPTED_DATA_INVALID,
            CKR_ENCRYPTED_DATA_LEN_RANGE,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_next_encrypted_data_len_range": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="ciphertext_length_out_of_range",
        spec_ckr=CKR_ENCRYPTED_DATA_LEN_RANGE,
        compat_tuple=(
            CKR_ENCRYPTED_DATA_LEN_RANGE,
            CKR_ENCRYPTED_DATA_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_next_function_canceled": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "decrypt_message_next_mechanism_param_invalid": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_next_operation_active": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="called_without_C_DecryptMessageBegin",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_next_operation_not_initialized": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="no_prior_C_MessageDecryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "decrypt_message_next_user_not_logged_in": CkrExpectation(
        function="C_DecryptMessageNext",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_MessageDecryptFinal errors ---
    "msg_decrypt_final_arguments_bad": CkrExpectation(
        function="C_MessageDecryptFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_final_function_canceled": CkrExpectation(
        function="C_MessageDecryptFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_decrypt_final_operation_active": CkrExpectation(
        function="C_MessageDecryptFinal",
        condition="multipart_message_still_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_final_operation_not_initialized": CkrExpectation(
        function="C_MessageDecryptFinal",
        condition="no_prior_C_MessageDecryptInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_decrypt_final_user_not_logged_in": CkrExpectation(
        function="C_MessageDecryptFinal",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Message-based Sign family (v3.0, Sec.5.14)
# ---------------------------------------------------------------------------

CKR_MSG_SIGN: dict[str, CkrExpectation] = {
    # --- C_MessageSignInit errors ---
    "msg_sign_init_arguments_bad": CkrExpectation(
        function="C_MessageSignInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_function_canceled": CkrExpectation(
        function="C_MessageSignInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_sign_init_key_function_not_permitted": CkrExpectation(
        function="C_MessageSignInit",
        condition="key_CKA_SIGN_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_key_handle_invalid": CkrExpectation(
        function="C_MessageSignInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_key_size_range": CkrExpectation(
        function="C_MessageSignInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_key_type_inconsistent": CkrExpectation(
        function="C_MessageSignInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_mechanism_invalid": CkrExpectation(
        function="C_MessageSignInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_mechanism_param_invalid": CkrExpectation(
        function="C_MessageSignInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_operation_active": CkrExpectation(
        function="C_MessageSignInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_init_pin_expired": CkrExpectation(
        function="C_MessageSignInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "msg_sign_init_user_not_logged_in": CkrExpectation(
        function="C_MessageSignInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_SignMessage errors ---
    "sign_message_arguments_bad": CkrExpectation(
        function="C_SignMessage",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_buffer_too_small": CkrExpectation(
        function="C_SignMessage",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_data_invalid": CkrExpectation(
        function="C_SignMessage",
        condition="invalid_data_content",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_data_len_range": CkrExpectation(
        function="C_SignMessage",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_function_canceled": CkrExpectation(
        function="C_SignMessage",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "sign_message_function_rejected": CkrExpectation(
        function="C_SignMessage",
        condition="signature_rejected_by_token_policy",
        spec_ckr=CKR_FUNCTION_REJECTED,
        compat_tuple=(CKR_FUNCTION_REJECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_mechanism_param_invalid": CkrExpectation(
        function="C_SignMessage",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_operation_active": CkrExpectation(
        function="C_SignMessage",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_operation_not_initialized": CkrExpectation(
        function="C_SignMessage",
        condition="no_prior_C_MessageSignInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_token_resource_exceeded": CkrExpectation(
        function="C_SignMessage",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "sign_message_user_not_logged_in": CkrExpectation(
        function="C_SignMessage",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_SignMessageBegin errors ---
    "sign_message_begin_arguments_bad": CkrExpectation(
        function="C_SignMessageBegin",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_begin_function_canceled": CkrExpectation(
        function="C_SignMessageBegin",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "sign_message_begin_mechanism_param_invalid": CkrExpectation(
        function="C_SignMessageBegin",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_begin_operation_active": CkrExpectation(
        function="C_SignMessageBegin",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_begin_operation_not_initialized": CkrExpectation(
        function="C_SignMessageBegin",
        condition="no_prior_C_MessageSignInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_begin_pin_expired": CkrExpectation(
        function="C_SignMessageBegin",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "sign_message_begin_token_resource_exceeded": CkrExpectation(
        function="C_SignMessageBegin",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "sign_message_begin_user_not_logged_in": CkrExpectation(
        function="C_SignMessageBegin",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_SignMessageNext errors ---
    "sign_message_next_arguments_bad": CkrExpectation(
        function="C_SignMessageNext",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_next_buffer_too_small": CkrExpectation(
        function="C_SignMessageNext",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_next_data_len_range": CkrExpectation(
        function="C_SignMessageNext",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_next_function_canceled": CkrExpectation(
        function="C_SignMessageNext",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "sign_message_next_function_rejected": CkrExpectation(
        function="C_SignMessageNext",
        condition="signature_rejected_by_token_policy",
        spec_ckr=CKR_FUNCTION_REJECTED,
        compat_tuple=(CKR_FUNCTION_REJECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_next_mechanism_param_invalid": CkrExpectation(
        function="C_SignMessageNext",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_next_operation_active": CkrExpectation(
        function="C_SignMessageNext",
        condition="called_without_C_SignMessageBegin",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_next_operation_not_initialized": CkrExpectation(
        function="C_SignMessageNext",
        condition="no_prior_C_MessageSignInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "sign_message_next_token_resource_exceeded": CkrExpectation(
        function="C_SignMessageNext",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "sign_message_next_user_not_logged_in": CkrExpectation(
        function="C_SignMessageNext",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_MessageSignFinal errors ---
    "msg_sign_final_arguments_bad": CkrExpectation(
        function="C_MessageSignFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_final_function_canceled": CkrExpectation(
        function="C_MessageSignFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_sign_final_function_rejected": CkrExpectation(
        function="C_MessageSignFinal",
        condition="signature_rejected_by_token_policy",
        spec_ckr=CKR_FUNCTION_REJECTED,
        compat_tuple=(CKR_FUNCTION_REJECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_final_operation_active": CkrExpectation(
        function="C_MessageSignFinal",
        condition="multipart_message_still_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_final_operation_not_initialized": CkrExpectation(
        function="C_MessageSignFinal",
        condition="no_prior_C_MessageSignInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_sign_final_token_resource_exceeded": CkrExpectation(
        function="C_MessageSignFinal",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    "msg_sign_final_user_not_logged_in": CkrExpectation(
        function="C_MessageSignFinal",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Message-based Verify family (v3.0, Sec.5.16)
# ---------------------------------------------------------------------------

CKR_MSG_VERIFY: dict[str, CkrExpectation] = {
    # --- C_MessageVerifyInit errors ---
    "msg_verify_init_arguments_bad": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_function_canceled": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_verify_init_key_function_not_permitted": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="key_CKA_VERIFY_is_False",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_key_handle_invalid": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="invalid_key_handle",
        spec_ckr=CKR_KEY_HANDLE_INVALID,
        compat_tuple=HANDLE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_key_size_range": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="key_size_out_of_range",
        spec_ckr=CKR_KEY_SIZE_RANGE,
        compat_tuple=KEY_SIZE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_key_type_inconsistent": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=CKR_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_MECHANISM_INVALID,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_mechanism_invalid": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_mechanism_param_invalid": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_operation_active": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_init_pin_expired": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "msg_verify_init_user_not_logged_in": CkrExpectation(
        function="C_MessageVerifyInit",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_VerifyMessage errors ---
    "verify_message_arguments_bad": CkrExpectation(
        function="C_VerifyMessage",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_data_invalid": CkrExpectation(
        function="C_VerifyMessage",
        condition="invalid_data_content",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_data_len_range": CkrExpectation(
        function="C_VerifyMessage",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_function_canceled": CkrExpectation(
        function="C_VerifyMessage",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "verify_message_mechanism_param_invalid": CkrExpectation(
        function="C_VerifyMessage",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_operation_active": CkrExpectation(
        function="C_VerifyMessage",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_operation_not_initialized": CkrExpectation(
        function="C_VerifyMessage",
        condition="no_prior_C_MessageVerifyInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_signature_invalid": CkrExpectation(
        function="C_VerifyMessage",
        condition="signature_verification_failed",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_signature_len_range": CkrExpectation(
        function="C_VerifyMessage",
        condition="signature_length_out_of_range",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_token_resource_exceeded": CkrExpectation(
        function="C_VerifyMessage",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    # --- C_VerifyMessageBegin errors ---
    "verify_message_begin_arguments_bad": CkrExpectation(
        function="C_VerifyMessageBegin",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_begin_function_canceled": CkrExpectation(
        function="C_VerifyMessageBegin",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "verify_message_begin_mechanism_param_invalid": CkrExpectation(
        function="C_VerifyMessageBegin",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_begin_operation_active": CkrExpectation(
        function="C_VerifyMessageBegin",
        condition="multipart_message_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_begin_operation_not_initialized": CkrExpectation(
        function="C_VerifyMessageBegin",
        condition="no_prior_C_MessageVerifyInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_begin_pin_expired": CkrExpectation(
        function="C_VerifyMessageBegin",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "verify_message_begin_user_not_logged_in": CkrExpectation(
        function="C_VerifyMessageBegin",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    # --- C_VerifyMessageNext errors ---
    "verify_message_next_arguments_bad": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_next_data_len_range": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_next_function_canceled": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "verify_message_next_mechanism_param_invalid": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="wrong_message_specific_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_next_operation_active": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="called_without_C_VerifyMessageBegin",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_next_operation_not_initialized": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="no_prior_C_MessageVerifyInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_next_signature_invalid": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="signature_verification_failed",
        spec_ckr=CKR_SIGNATURE_INVALID,
        compat_tuple=(CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_next_signature_len_range": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="signature_length_out_of_range",
        spec_ckr=CKR_SIGNATURE_LEN_RANGE,
        compat_tuple=(CKR_SIGNATURE_LEN_RANGE, CKR_SIGNATURE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "verify_message_next_token_resource_exceeded": CkrExpectation(
        function="C_VerifyMessageNext",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
    # --- C_MessageVerifyFinal errors ---
    "msg_verify_final_arguments_bad": CkrExpectation(
        function="C_MessageVerifyFinal",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_final_data_len_range": CkrExpectation(
        function="C_MessageVerifyFinal",
        condition="data_length_out_of_range",
        spec_ckr=CKR_DATA_LEN_RANGE,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_final_function_canceled": CkrExpectation(
        function="C_MessageVerifyFinal",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "msg_verify_final_operation_active": CkrExpectation(
        function="C_MessageVerifyFinal",
        condition="multipart_message_still_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_final_operation_not_initialized": CkrExpectation(
        function="C_MessageVerifyFinal",
        condition="no_prior_C_MessageVerifyInit",
        spec_ckr=CKR_OPERATION_NOT_INITIALIZED,
        compat_tuple=(CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
    ),
    "msg_verify_final_token_resource_exceeded": CkrExpectation(
        function="C_MessageVerifyFinal",
        condition="token_resource_limit_reached",
        spec_ckr=CKR_FUNCTION_FAILED,  # CKR_TOKEN_RESOURCE_EXCEEDED not in fork
        compat_tuple=(CKR_FUNCTION_FAILED,),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via RawPKCS11 + funclist3_ptr
        spec_ckr_code="CKR_TOKEN_RESOURCE_EXCEEDED",
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Wrap Authenticated family (v3.0, Sec.5.14)
# ---------------------------------------------------------------------------

CKR_WRAP_AUTH: dict[str, CkrExpectation] = {
    # --- C_UnwrapKeyAuthenticated errors ---
    "unwrap_auth_arguments_bad": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_attribute_read_only": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="template_specifies_read_only_attribute",
        spec_ckr=CKR_ATTRIBUTE_READ_ONLY,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_attribute_type_invalid": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="template_has_invalid_attribute_type",
        spec_ckr=CKR_ATTRIBUTE_TYPE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_attribute_value_invalid": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="template_has_invalid_attribute_value",
        spec_ckr=CKR_ATTRIBUTE_VALUE_INVALID,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_buffer_too_small": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_curve_not_supported": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="EC_curve_not_supported",
        spec_ckr=CKR_CURVE_NOT_SUPPORTED,
        compat_tuple=(CKR_CURVE_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_domain_params_invalid": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="domain_parameters_invalid",
        spec_ckr=CKR_DOMAIN_PARAMS_INVALID,
        compat_tuple=(CKR_DOMAIN_PARAMS_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_function_canceled": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="operation_canceled_by_callback",
        spec_ckr=CKR_FUNCTION_CANCELED,
        compat_tuple=(CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires registered callback - not exposed by python-pkcs11
        # Untestable: requires CKN_SURRENDER callback returning CKR_CANCEL
    ),
    "unwrap_auth_mechanism_invalid": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="mechanism_not_supported",
        spec_ckr=CKR_MECHANISM_INVALID,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_mechanism_param_invalid": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="wrong_mechanism_parameter",
        spec_ckr=CKR_MECHANISM_PARAM_INVALID,
        compat_tuple=(
            CKR_MECHANISM_PARAM_INVALID,
            CKR_MECHANISM_INVALID,
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_operation_active": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="operation_already_active",
        spec_ckr=CKR_OPERATION_ACTIVE,
        compat_tuple=(CKR_OPERATION_ACTIVE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_parameter_set_not_supported": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="PQC_parameter_set_not_supported",
        spec_ckr=CKR_PARAMETER_SET_NOT_SUPPORTED,
        compat_tuple=(CKR_PARAMETER_SET_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_pin_expired": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="PIN_has_expired",
        spec_ckr=CKR_PIN_EXPIRED,
        compat_tuple=(CKR_PIN_EXPIRED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires token with PIN expiration policy
        # Untestable: cannot force PIN expiry on software tokens
    ),
    "unwrap_auth_session_read_only": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="RO_session_cannot_create_objects",
        spec_ckr=CKR_SESSION_READ_ONLY,
        compat_tuple=(CKR_SESSION_READ_ONLY, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_template_incomplete": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="template_missing_required_attributes",
        spec_ckr=CKR_TEMPLATE_INCOMPLETE,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_template_inconsistent": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="template_has_conflicting_attributes",
        spec_ckr=CKR_TEMPLATE_INCONSISTENT,
        compat_tuple=TEMPLATE_ERRORS,
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_token_write_protected": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="token_is_write_protected",
        spec_ckr=CKR_TOKEN_WRITE_PROTECTED,
        compat_tuple=(CKR_TOKEN_WRITE_PROTECTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_unwrapping_key_handle_invalid": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="invalid_unwrapping_key_handle",
        spec_ckr=CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        compat_tuple=(
            CKR_UNWRAPPING_KEY_HANDLE_INVALID,
            CKR_KEY_HANDLE_INVALID,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_unwrapping_key_size_range": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="unwrapping_key_size_out_of_range",
        spec_ckr=CKR_UNWRAPPING_KEY_SIZE_RANGE,
        compat_tuple=(CKR_UNWRAPPING_KEY_SIZE_RANGE, CKR_KEY_SIZE_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_unwrapping_key_type_inconsistent": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="unwrapping_key_type_wrong_for_mechanism",
        spec_ckr=CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        compat_tuple=(
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_FUNCTION_FAILED,
        ),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_user_not_logged_in": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="requires_login",
        spec_ckr=CKR_USER_NOT_LOGGED_IN,
        compat_tuple=(CKR_USER_NOT_LOGGED_IN, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_wrapped_key_invalid": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="wrapped_key_data_invalid",
        spec_ckr=CKR_WRAPPED_KEY_INVALID,
        compat_tuple=(CKR_WRAPPED_KEY_INVALID, CKR_WRAPPED_KEY_LEN_RANGE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "unwrap_auth_wrapped_key_len_range": CkrExpectation(
        function="C_UnwrapKeyAuthenticated",
        condition="wrapped_key_length_out_of_range",
        spec_ckr=CKR_WRAPPED_KEY_LEN_RANGE,
        compat_tuple=(CKR_WRAPPED_KEY_LEN_RANGE, CKR_WRAPPED_KEY_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
}


# ---------------------------------------------------------------------------
# Spec tables - Async family (v3.0, Sec.5.21)
# ---------------------------------------------------------------------------

CKR_ASYNC: dict[str, CkrExpectation] = {
    # --- C_AsyncGetID errors ---
    "async_get_id_arguments_bad": CkrExpectation(
        function="C_AsyncGetID",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "async_get_id_state_unsaveable": CkrExpectation(
        function="C_AsyncGetID",
        condition="async_state_cannot_be_saved",
        spec_ckr=CKR_STATE_UNSAVEABLE,
        compat_tuple=(CKR_STATE_UNSAVEABLE, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    # --- C_AsyncJoin errors ---
    "async_join_arguments_bad": CkrExpectation(
        function="C_AsyncJoin",
        condition="NULL_pointer_argument",
        spec_ckr=CKR_ARGUMENTS_BAD,
        compat_tuple=(CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "async_join_buffer_too_small": CkrExpectation(
        function="C_AsyncJoin",
        condition="output_buffer_too_small",
        spec_ckr=CKR_BUFFER_TOO_SMALL,
        compat_tuple=(CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
    "async_join_saved_state_invalid": CkrExpectation(
        function="C_AsyncJoin",
        condition="saved_async_state_invalid",
        spec_ckr=CKR_SAVED_STATE_INVALID,
        compat_tuple=(CKR_SAVED_STATE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=True,  # Testable on Kryoptic via funclist32_ptr
    ),
}


# ---------------------------------------------------------------------------
# Documented but not practically testable CKR codes
# ---------------------------------------------------------------------------

CKR_UNTESTABLE: dict[str, CkrExpectation] = {
    "ckr_pending": CkrExpectation(
        function="*",
        condition="async_operation_pending",
        spec_ckr=CKR_PENDING,
        compat_tuple=(CKR_PENDING, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires async-capable token with in-flight operation
        # Documented for completeness. CKR_PENDING is returned when an async
        # operation has not yet completed. Requires v3.0+ async session support
        # which is not widely implemented.
    ),
    "ckr_fips_self_test_failed": CkrExpectation(
        function="C_Initialize",
        condition="FIPS_self_test_during_init",
        spec_ckr=CKR_FIPS_SELF_TEST_FAILED,
        compat_tuple=(CKR_FIPS_SELF_TEST_FAILED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires FIPS module with corrupt integrity check
        # Documented for completeness. Returned by C_Initialize when the FIPS
        # module's built-in self-test fails. Cannot trigger without corrupting
        # a FIPS-certified module's integrity data.
    ),
    "ckr_library_load_failed": CkrExpectation(
        function="C_Initialize",
        condition="dependent_library_load_failure",
        spec_ckr=CKR_LIBRARY_LOAD_FAILED,
        compat_tuple=(CKR_LIBRARY_LOAD_FAILED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires missing/corrupt dependent library
        # Documented for completeness. Returned by C_Initialize when a required
        # dependent library cannot be loaded. Cannot trigger without modifying
        # the module's runtime library path.
    ),
    "ckr_public_key_invalid": CkrExpectation(
        function="C_VerifyInit",
        condition="malformed_public_key_used_for_verification",
        spec_ckr=CKR_PUBLIC_KEY_INVALID,
        compat_tuple=(CKR_PUBLIC_KEY_INVALID, CKR_KEY_HANDLE_INVALID, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.2",
        testable=False,  # Requires importing a key with corrupted public key data
        # Could be tested by creating a key object with corrupted EC point or
        # RSA modulus via C_CreateObject with invalid CKA_PUBLIC_KEY_VALUE,
        # but most modules validate at import time and reject with a different CKR.
    ),
}
