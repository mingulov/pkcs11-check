"""Shared error tuples for specific CKR code validation.

NEVER treat all nonzero CKR as equivalent - use these tuples instead.
Each tuple lists ONLY the CKR codes (as ints) that are valid responses for
that category of operation. Unexpected errors will fail the test.
"""

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_MEMORY,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TOKEN_WRITE_PROTECTED,
)

# Bad attribute template (create_object, generate_key with wrong attrs)
TEMPLATE_ERRORS = (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
)

# Bad key size (generate_key/keypair with invalid size)
KEY_SIZE_ERRORS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_FUNCTION_FAILED,
)

# Using a destroyed/invalid object handle or key handle
HANDLE_ERRORS = (
    CKR_OBJECT_HANDLE_INVALID,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_FUNCTION_FAILED,
)

# Closed/invalid session
SESSION_ERRORS = (
    CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_CLOSED,
    CKR_FUNCTION_FAILED,
)

# Mechanism not supported or wrong for operation
MECHANISM_ERRORS = (
    CKR_MECHANISM_INVALID,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
)

# Conflicting security attributes (Tookan vectors)
SECURITY_POLICY_ERRORS = (
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_FUNCTION_FAILED,
)

# Storage/memory limits
RESOURCE_ERRORS = (
    CKR_DEVICE_MEMORY,
    CKR_FUNCTION_FAILED,
    CKR_TOKEN_WRITE_PROTECTED,
)

# Crypto data length issues
DATA_ERRORS = (
    CKR_DATA_LEN_RANGE,
    CKR_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
)

# NOTE: SoftHSM2 returns CKR_GENERAL_ERROR for some data-length violations
# where the spec says CKR_DATA_LEN_RANGE. If you see GeneralError for
# data operations, it's a SoftHSM2 quirk - document it, don't add
# CKR_GENERAL_ERROR to DATA_ERRORS (that would hide real bugs).
