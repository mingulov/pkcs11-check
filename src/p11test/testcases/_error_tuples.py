"""Shared error tuples for specific CKR code validation.

NEVER catch generic PKCS11Error in tests — use these tuples instead.
Each tuple lists ONLY the CKR codes that are valid responses for
that category of operation. Unexpected errors will fail the test.
"""

from pkcs11.exceptions import (
    ArgumentsBad,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    DataInvalid,
    DataLenRange,
    DeviceMemory,
    EncryptedDataInvalid,
    EncryptedDataLenRange,
    FunctionFailed,
    FunctionNotSupported,
    KeyFunctionNotPermitted,
    KeyNotWrappable,
    KeySizeRange,
    MechanismInvalid,
    ObjectHandleInvalid,
    SessionClosed,
    SessionHandleInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
    TokenWriteProtected,
)

# Bad attribute template (create_object, generate_key with wrong attrs)
TEMPLATE_ERRORS = (
    AttributeTypeInvalid,
    AttributeValueInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
    ArgumentsBad,
    FunctionFailed,
)

# Bad key size (generate_key/keypair with invalid size)
KEY_SIZE_ERRORS = (
    AttributeValueInvalid,
    KeySizeRange,
    MechanismInvalid,
    ArgumentsBad,
    TemplateIncomplete,
    FunctionFailed,
)

# Using a destroyed/invalid object handle
HANDLE_ERRORS = (
    ObjectHandleInvalid,
    KeyFunctionNotPermitted,
    FunctionFailed,
)

# Closed/invalid session
SESSION_ERRORS = (
    SessionHandleInvalid,
    SessionClosed,
    FunctionFailed,
)

# Mechanism not supported or wrong for operation
MECHANISM_ERRORS = (
    MechanismInvalid,
    KeyNotWrappable,
    KeyFunctionNotPermitted,
    FunctionNotSupported,
    EncryptedDataLenRange,
    DataLenRange,
    FunctionFailed,
)

# Conflicting security attributes (Tookan vectors)
SECURITY_POLICY_ERRORS = (
    TemplateInconsistent,
    AttributeValueInvalid,
    KeyFunctionNotPermitted,
    FunctionFailed,
)

# Storage/memory limits
RESOURCE_ERRORS = (
    DeviceMemory,
    FunctionFailed,
    TokenWriteProtected,
)

# Crypto data length issues
DATA_ERRORS = (
    DataLenRange,
    DataInvalid,
    EncryptedDataLenRange,
    EncryptedDataInvalid,
    ArgumentsBad,
    FunctionFailed,
)

# NOTE: SoftHSM2 returns CKR_GENERAL_ERROR for some data-length violations
# where the spec says CKR_DATA_LEN_RANGE. If you see GeneralError for
# data operations, it's a SoftHSM2 quirk — document it, don't add
# GeneralError to DATA_ERRORS (that would hide real bugs).
