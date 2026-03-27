# CKR Spec Completeness Audit

Cross-reference of OASIS PKCS#11 spec `function_return_values.md`
and per-function spec files against `_ckr_spec.py` CkrExpectation entries.

## Summary

| Metric | Count |
|--------|-------|
| Functions documented in OASIS spec | 109 |
| Functions covered in _ckr_spec.py | 109 |
| Functions in spec only (no _ckr_spec entries) | 1 |
| Functions in _ckr_spec only (no spec entries) | 1 |
| Total spec (function, CKR) pairs | 220 |
| Total _ckr_spec (function, CKR) pairs | 872 |
| **Total gaps (spec CKR not in _ckr_spec)** | **91** |

## Gap Categories

Gaps are classified by why they're missing:

| Category | Count | Description |
|----------|-------|-------------|
| Universal errors (Sec 5.1.1) | 75 | CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_FUNCTION_FAILED, CKR_CRYPTOKI_NOT_INITIALIZED |
| Session universal errors (Sec 5.1.2) | 0 | CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED, CKR_DEVICE_REMOVED |
| Token universal errors (Sec 5.1.3) | 0 | CKR_DEVICE_MEMORY, CKR_DEVICE_ERROR, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_INITIALIZED |
| Session-only functions | 15 | Non-session functions with basic error codes |
| v3.0+ new functions | 0 | New functions added in PKCS#11 v3.0+ |
| **Function-specific gaps** | **1** | **Gaps requiring new test entries** |

## Function-Specific Gaps (Actionable)

These gaps represent CKR codes documented in the OASIS spec for specific
functions that do not have corresponding CkrExpectation entries in
`_ckr_spec.py`. These are candidates for implementation.

| Function | Missing CKR Code |
|----------|----------------|
| C_WrapKey | CKR_ARGUMENTS_BAD |

## Functions in Spec Only

Functions documented in the OASIS spec that have NO entries
in `_ckr_spec.py` at all:

- `C_WrapKeyAuthenticated`

## Functions in _ckr_spec Only

Functions with entries in `_ckr_spec.py` that were not found
in the OASIS spec files scanned (may be in other spec sections): none.

## Methodology

- OASIS spec files scanned: asynchronous_function_management_functions.md, decryption_functions.md, dual-function_cryptographic_functions.md, encryption_functions.md, functions.md, functions_for_verifying_signatures_and_macs.md, general_purpose_functions.md, key_management_functions.md, message-based_functions_for_verifying_signatures_and_macs.md, message-based_signing_and_macing_functions.md, message_based_decryption_functions.md, message_based_encryption_functions.md, message_digesting_functions.md, object_mgmt_functions.md, parallel_function_management_functions.md, random_number_generation_functions.md, session_mgmt_functions.md, signing_and_macing_functions.md, slot_and_token_mgmt_functions.md
- CkrExpectation entries parsed from `_ckr_spec.py`
- Universal errors (Sec 5.1.1-5.1.3) are excluded from _ckr_spec as they
  are handled by `full_compat()` at runtime
- Session-only functions (C_Initialize, C_GetSlotList, etc.) are excluded
  as they use a different error model
- CKR_OK is excluded from both sides (success, not an error)

