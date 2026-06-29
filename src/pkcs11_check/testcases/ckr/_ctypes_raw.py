"""Raw ctypes PKCS#11 caller for NULL parameter testing.

Generates and runs subprocess scripts that call C_* functions directly
via ctypes, bypassing python-pkcs11's safety checks. This allows testing
NULL pointer handling that the wrapper prevents.

Each test runs in a subprocess because modules may segfault on NULL
instead of returning CKR_ARGUMENTS_BAD.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases.ckr._subprocess import ckr_ctypes_subprocess_rv_trace_setup

__all__ = ["CKR_ARGUMENTS_BAD", "run_null_test"]


def run_null_test(
    module_path: str,
    test_code: str,
    timeout: int = 10,
) -> tuple[int, str, str]:
    """Run a ctypes NULL parameter test in a subprocess.

    Args:
        module_path: Path to the PKCS#11 .so module.
        test_code: Python code that uses `lib` (ctypes.CDLL) and `funclist_ptr`
            (pointer to CK_FUNCTION_LIST). The code should print
            "CKR:0x{hex}" with the return value, or "SEGFAULT" on crash.
        timeout: Subprocess timeout in seconds.

    Returns:
        (returncode, stdout, stderr) - returncode < 0 means signal (segfault).
    """
    # Build the full script with boilerplate
    script = textwrap.dedent(f"""\
        import ctypes
        from ctypes import c_ulong, c_void_p, c_ubyte, POINTER, byref, cast
        from pkcs11_check.raw.types_std import (
            CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK,
            CKF_SERIAL_SESSION, CKF_RW_SESSION,
        )
{ckr_ctypes_subprocess_rv_trace_setup(indent="        ")}

        CK_RV = c_ulong

        # Load module
        lib = ctypes.CDLL({module_path!r})

        # Get C_GetFunctionList (the only guaranteed exported symbol)
        C_GetFunctionList = lib.C_GetFunctionList
        C_GetFunctionList.restype = CK_RV
        C_GetFunctionList.argtypes = [POINTER(c_void_p)]

        funclist_ptr = c_void_p()
        rv = C_GetFunctionList(byref(funclist_ptr))
        _p11check_record_rv("C_GetFunctionList", rv)
        if rv != CKR_OK:
            print(f"CKR:0x{{rv:08x}}:GetFunctionList_failed")
            exit(1)

        # CK_FUNCTION_LIST layout: CK_VERSION (2 bytes padded to pointer),
        # then function pointers in pkcs11f.h order.
        # On 64-bit: version at offset 0 (8 bytes with padding),
        # C_Initialize at offset 8, C_Finalize at offset 16, etc.
        ptr_size = ctypes.sizeof(c_void_p)
        base = funclist_ptr.value

        def get_func(index):
            \"\"\"Get function pointer at index in CK_FUNCTION_LIST (after version).\"\"\"
            # Version field is CK_VERSION (2 bytes) but padded to pointer alignment
            offset = ptr_size + (index * ptr_size)
            addr = ctypes.cast(base + offset, POINTER(c_void_p)).contents.value
            return addr

        # Function indices (0-based, after version field):
        # 0=C_Initialize, 1=C_Finalize, 2=C_GetInfo, 3=C_GetFunctionList,
        # 4=C_GetSlotList, 5=C_GetSlotInfo, 6=C_GetTokenInfo,
        # 7=C_GetMechanismList, 8=C_GetMechanismInfo, 9=C_InitToken,
        # 10=C_InitPIN, 11=C_SetPIN, 12=C_OpenSession, 13=C_CloseSession,
        # 14=C_CloseAllSessions, 15=C_GetSessionInfo, 16=C_GetOperationState,
        # 17=C_SetOperationState, 18=C_Login, 19=C_Logout,
        # 20=C_CreateObject, 21=C_CopyObject, 22=C_DestroyObject,
        # 23=C_GetObjectSize, 24=C_GetAttributeValue, 25=C_SetAttributeValue,
        # 26=C_FindObjectsInit, 27=C_FindObjects, 28=C_FindObjectsFinal,
        # 29=C_EncryptInit, 30=C_Encrypt, 31=C_EncryptUpdate, 32=C_EncryptFinal,
        # 33=C_DecryptInit, 34=C_Decrypt, 35=C_DecryptUpdate, 36=C_DecryptFinal,
        # 37=C_DigestInit, 38=C_Digest, 39=C_DigestUpdate, 40=C_DigestKey,
        # 41=C_DigestFinal, 42=C_SignInit, 43=C_Sign, ...

        FUNC_INDICES = {{
            "C_Initialize": 0, "C_Finalize": 1, "C_GetInfo": 2,
            "C_GetSlotList": 4, "C_GetSlotInfo": 5, "C_GetTokenInfo": 6,
            "C_OpenSession": 12, "C_CloseSession": 13,
            "C_EncryptInit": 29, "C_Encrypt": 30,
            "C_DecryptInit": 33, "C_Decrypt": 34,
            "C_DigestInit": 37, "C_Digest": 38,
            "C_SignInit": 42, "C_Sign": 43,
            "C_GenerateRandom": 48,
        }}

        def call_func(name, *args):
            \"\"\"Call a PKCS#11 function by name with given args.\"\"\"
            idx = FUNC_INDICES[name]
            addr = get_func(idx)
            # Create a ctypes function type: CK_RV (*func)(args...)
            arg_types = [type(a) for a in args]
            func_type = ctypes.CFUNCTYPE(CK_RV, *arg_types)
            func = func_type(addr)
            rv = func(*args)
            _p11check_record_rv(name, rv)
            return rv

        # Initialize the module first
        rv = call_func("C_Initialize", c_void_p(None))
        if rv != CKR_OK and rv != CKR_CRYPTOKI_ALREADY_INITIALIZED:
            print(f"CKR:0x{{rv:08x}}:Initialize_failed")
            exit(1)

        # Run the actual test
{textwrap.indent(textwrap.dedent(test_code), "        ")}

        # Cleanup
        call_func("C_Finalize", c_void_p(None))
    """)

    import os

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=os.environ.copy(),  # Inherit env so the child sees the same provider config
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()
