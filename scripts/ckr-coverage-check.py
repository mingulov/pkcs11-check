#!/usr/bin/env python3
"""CKR coverage validation script — the source of truth.

Parses the OASIS PKCS#11 spec, extracts all (function, CKR) pairs,
compares against _ckr_spec.py, and reports gaps.

Usage:
    uv run python scripts/ckr-coverage-check.py
    uv run python scripts/ckr-coverage-check.py --verbose
    uv run python scripts/ckr-coverage-check.py --function C_Encrypt
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# Universal CKR codes — appear in (almost) every function's Return values list
UNIVERSAL_CKRS = {
    "CKR_OK",
    "CKR_GENERAL_ERROR",
    "CKR_HOST_MEMORY",
    "CKR_FUNCTION_FAILED",
    "CKR_DEVICE_ERROR",
    "CKR_DEVICE_MEMORY",
    "CKR_DEVICE_REMOVED",
    "CKR_SESSION_HANDLE_INVALID",
    "CKR_SESSION_CLOSED",
    "CKR_TOKEN_NOT_PRESENT",
    "CKR_CRYPTOKI_NOT_INITIALIZED",
    "CKR_PENDING",
    "CKR_OPERATION_NOT_VALIDATED",
    "CKR_TOKEN_NOT_INITIALIZED",
}

SPEC_DIR = Path("/tmp/pkcs11/working/doc/spec")

SPEC_FILES = [
    "encryption_functions.md",
    "decryption_functions.md",
    "signing_and_macing_functions.md",
    "functions_for_verifying_signatures_and_macs.md",
    "message_digesting_functions.md",
    "key_management_functions.md",
    "object_mgmt_functions.md",
    "session_mgmt_functions.md",
    "slot_and_token_mgmt_functions.md",
    "random_number_generation_functions.md",
    "general_purpose_functions.md",
    "message_based_encryption_functions.md",
    "message_based_decryption_functions.md",
    "message-based_signing_and_macing_functions.md",
    "message-based_functions_for_verifying_signatures_and_macs.md",
    "dual-function_cryptographic_functions.md",
    "parallel_function_management_functions.md",
    "asynchronous_function_management_functions.md",
]


def parse_spec() -> dict[str, set[str]]:
    """Parse OASIS spec files, return {function_name: {CKR_codes}}."""
    functions: dict[str, set[str]] = {}

    for filename in SPEC_FILES:
        path = SPEC_DIR / filename
        if not path.exists():
            continue
        content = path.read_text()

        # Find all function sections and their Return values
        # Pattern: ### C_FuncName ... Return values: CKR_X, CKR_Y, ...
        blocks = re.split(r"(?=^### C_\w+)", content, flags=re.MULTILINE)
        for block in blocks:
            func_match = re.match(r"### (C_\w+)", block)
            if not func_match:
                continue
            func_name = func_match.group(1)

            # Find Return values block
            rv_match = re.search(r"Return values:\s*(.+?)(?=\n\n|\n###|\nExample|\Z)", block, re.DOTALL)
            if not rv_match:
                continue

            ckrs = set(re.findall(r"CKR_\w+", rv_match.group(1)))
            if ckrs:
                functions[func_name] = ckrs

    return functions


def load_ckr_spec() -> dict[str, set[str]]:
    """Load _ckr_spec.py and return {function_name: {covered_CKR_codes}}."""
    # Import the spec module
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    try:
        from p11test.testcases.ckr import _ckr_spec
    except ImportError as e:
        print(f"ERROR: Cannot import _ckr_spec: {e}", file=sys.stderr)
        return {}

    covered: dict[str, set[str]] = {}

    # Map exception class names back to CKR codes
    CKR_MAP = {
        "ActionProhibited": "CKR_ACTION_PROHIBITED",
        "ArgumentsBad": "CKR_ARGUMENTS_BAD",
        "AttributeReadOnly": "CKR_ATTRIBUTE_READ_ONLY",
        "AttributeSensitive": "CKR_ATTRIBUTE_SENSITIVE",
        "AttributeTypeInvalid": "CKR_ATTRIBUTE_TYPE_INVALID",
        "AttributeValueInvalid": "CKR_ATTRIBUTE_VALUE_INVALID",
        "BufferTooSmall": "CKR_BUFFER_TOO_SMALL",
        "CryptokiAlreadyInitialized": "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        "CryptokiNotInitialized": "CKR_CRYPTOKI_NOT_INITIALIZED",
        "CurveNotSupported": "CKR_CURVE_NOT_SUPPORTED",
        "DataInvalid": "CKR_DATA_INVALID",
        "DataLenRange": "CKR_DATA_LEN_RANGE",
        "DeviceError": "CKR_DEVICE_ERROR",
        "DeviceMemory": "CKR_DEVICE_MEMORY",
        "DomainParamsInvalid": "CKR_DOMAIN_PARAMS_INVALID",
        "EncryptedDataInvalid": "CKR_ENCRYPTED_DATA_INVALID",
        "EncryptedDataLenRange": "CKR_ENCRYPTED_DATA_LEN_RANGE",
        "FunctionFailed": "CKR_FUNCTION_FAILED",
        "FunctionNotSupported": "CKR_FUNCTION_NOT_SUPPORTED",
        "GeneralError": "CKR_GENERAL_ERROR",
        "KeyFunctionNotPermitted": "CKR_KEY_FUNCTION_NOT_PERMITTED",
        "KeyHandleInvalid": "CKR_KEY_HANDLE_INVALID",
        "KeyIndigestible": "CKR_KEY_INDIGESTIBLE",
        "KeyNeeded": "CKR_KEY_NEEDED",
        "KeyNotNeeded": "CKR_KEY_NOT_NEEDED",
        "KeyNotWrappable": "CKR_KEY_NOT_WRAPPABLE",
        "KeySizeRange": "CKR_KEY_SIZE_RANGE",
        "KeyTypeInconsistent": "CKR_KEY_TYPE_INCONSISTENT",
        "KeyUnextractable": "CKR_KEY_UNEXTRACTABLE",
        "MechanismInvalid": "CKR_MECHANISM_INVALID",
        "MechanismParamInvalid": "CKR_MECHANISM_PARAM_INVALID",
        "NoEvent": "CKR_NO_EVENT",
        "ObjectHandleInvalid": "CKR_OBJECT_HANDLE_INVALID",
        "OperationActive": "CKR_OPERATION_ACTIVE",
        "OperationNotInitialized": "CKR_OPERATION_NOT_INITIALIZED",
        "PinIncorrect": "CKR_PIN_INCORRECT",
        "PinLenRange": "CKR_PIN_LEN_RANGE",
        "PinLocked": "CKR_PIN_LOCKED",
        "RandomSeedNotSupported": "CKR_RANDOM_SEED_NOT_SUPPORTED",
        "SavedStateInvalid": "CKR_SAVED_STATE_INVALID",
        "SessionCount": "CKR_SESSION_COUNT",
        "SessionExists": "CKR_SESSION_EXISTS",
        "SessionReadOnly": "CKR_SESSION_READ_ONLY",
        "SignatureInvalid": "CKR_SIGNATURE_INVALID",
        "SignatureLenRange": "CKR_SIGNATURE_LEN_RANGE",
        "SlotIDInvalid": "CKR_SLOT_ID_INVALID",
        "StateUnsaveable": "CKR_STATE_UNSAVEABLE",
        "TemplateIncomplete": "CKR_TEMPLATE_INCOMPLETE",
        "TemplateInconsistent": "CKR_TEMPLATE_INCONSISTENT",
        "TokenWriteProtected": "CKR_TOKEN_WRITE_PROTECTED",
        "UserAlreadyLoggedIn": "CKR_USER_ALREADY_LOGGED_IN",
        "UserNotLoggedIn": "CKR_USER_NOT_LOGGED_IN",
        "UserTypeInvalid": "CKR_USER_TYPE_INVALID",
        "AnotherUserAlreadyLoggedIn": "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
        "WrappedKeyInvalid": "CKR_WRAPPED_KEY_INVALID",
        "WrappedKeyLenRange": "CKR_WRAPPED_KEY_LEN_RANGE",
    }

    # Iterate all dicts in _ckr_spec
    for attr_name in dir(_ckr_spec):
        if not attr_name.startswith("CKR_"):
            continue
        d = getattr(_ckr_spec, attr_name)
        if not isinstance(d, dict):
            continue
        for entry in d.values():
            func = entry.function
            # Get the CKR code from spec_ckr
            spec_ckr = entry.spec_ckr
            if isinstance(spec_ckr, tuple):
                for cls in spec_ckr:
                    ckr_name = CKR_MAP.get(cls.__name__, f"UNKNOWN_{cls.__name__}")
                    covered.setdefault(func, set()).add(ckr_name)
            else:
                ckr_name = CKR_MAP.get(spec_ckr.__name__, f"UNKNOWN_{spec_ckr.__name__}")
                covered.setdefault(func, set()).add(ckr_name)

    return covered


def main():
    parser = argparse.ArgumentParser(description="CKR coverage check")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--function", "-f", help="Filter to specific function")
    args = parser.parse_args()

    if not SPEC_DIR.exists():
        print("Cloning OASIS spec...")
        subprocess.run(["git", "clone", "--depth", "1",
                       "https://github.com/oasis-tcs/pkcs11.git", "/tmp/pkcs11"],
                      check=True, capture_output=True)

    spec = parse_spec()
    covered = load_ckr_spec()

    total_functions = 0
    total_specific = 0
    total_covered = 0
    total_missing = 0
    total_universal = 0
    missing_details: list[tuple[str, str]] = []

    for func in sorted(spec.keys()):
        if args.function and args.function not in func:
            continue

        all_ckrs = spec[func]
        universal = all_ckrs & UNIVERSAL_CKRS
        specific = all_ckrs - UNIVERSAL_CKRS
        func_covered = covered.get(func, set())
        # Count specific CKRs that are covered
        specific_covered = specific & func_covered
        specific_missing = specific - func_covered

        total_functions += 1
        total_specific += len(specific)
        total_covered += len(specific_covered)
        total_missing += len(specific_missing)
        total_universal += len(universal)

        for ckr in sorted(specific_missing):
            missing_details.append((func, ckr))

        if args.verbose or specific_missing:
            status = "OK" if not specific_missing else f"GAPS: {len(specific_missing)}"
            print(f"  {func}: {len(specific)} specific, {len(specific_covered)} covered, "
                  f"{len(specific_missing)} missing [{status}]")
            if args.verbose and specific_missing:
                for ckr in sorted(specific_missing):
                    print(f"    MISSING: {ckr}")

    print()
    print("=" * 60)
    print(f"Functions in spec:       {total_functions}")
    print(f"Function-specific CKRs:  {total_specific}")
    print(f"Covered by _ckr_spec.py: {total_covered}")
    print(f"Missing:                 {total_missing}")
    print(f"Universal (via infra):   {total_universal}")
    pct = (total_covered / total_specific * 100) if total_specific else 0
    print(f"Coverage:                {total_covered}/{total_specific} = {pct:.1f}%")
    print("=" * 60)

    if total_missing == 0:
        print("\n✅ 100% function-specific coverage achieved!")
    else:
        print(f"\n❌ {total_missing} gaps remaining")
        if not args.verbose:
            print("Run with --verbose to see all missing entries")

    return 0 if total_missing == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
