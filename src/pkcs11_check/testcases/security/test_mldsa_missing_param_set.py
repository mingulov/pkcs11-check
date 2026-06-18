"""Crash-safe probe for an ML-DSA key imported without ``CKA_PARAMETER_SET``.

A conformant module must reject a ``C_CreateObject`` template for
``CKO_PRIVATE_KEY`` / ``CKK_ML_DSA`` that omits ``CKA_PARAMETER_SET`` with
``CKR_TEMPLATE_INCOMPLETE`` (or another clean reject code).  A module that
silently creates the param-less key may crash or produce undefined output when
the module's ML-DSA key-init path attempts to use an uninitialised parameter set.

Note: softhsm2 does not advertise ``CKM_ML_DSA``; this probe is gated behind
``rs.has_mechanism("ML_DSA")`` and will cleanly skip on that module.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess, pytest.mark.pqc]

# A conformant module must reject a param-less ML-DSA create with one of these.
_PARAMLESS_REJECT_RVS = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)

_MLDSA_IMPORTS = """
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_ML_DSA,
    CKM_ML_DSA,
    CKO_PRIVATE_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)
"""


def _parse_rv(output: str, prefix: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


class TestMLDSAMissingParamSet:
    """``C_CreateObject`` with a param-less ML-DSA private-key template.

    A conformant module must reject a ``CKO_PRIVATE_KEY`` / ``CKK_ML_DSA``
    template that omits ``CKA_PARAMETER_SET``; it must never crash.
    """

    def test_mldsa_create_without_param_set_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_CreateObject(CKK_ML_DSA) with no CKA_PARAMETER_SET must reject cleanly.

        A missing ``CKA_PARAMETER_SET`` means the module's ML-DSA key-init path
        receives no parameter set; a module that silently accepts the template may
        crash or produce undefined output when signing.  A conformant module rejects
        the template at create time.  If the module accepts it, C_SignInit +
        C_Sign are also attempted -- a crash at any step is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA"):
            pytest.skip("CKM_ML_DSA not advertised")

        body = (
            _MLDSA_IMPORTS
            + """
# Template: CKO_PRIVATE_KEY / CKK_ML_DSA, no CKA_PARAMETER_SET intentionally.
cls_val = CK_ULONG(CKO_PRIVATE_KEY)
key_type_val = CK_ULONG(CKK_ML_DSA)
token_false = ctypes.c_ubyte(0)
sign_true = ctypes.c_ubyte(1)

attrs = (CK_ATTRIBUTE * 4)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(key_type_val)
attrs[2].type = CKA_TOKEN
attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
attrs[2].ulValueLen = 1
attrs[3].type = CKA_SIGN
attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
attrs[3].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    4,
    ctypes.byref(key),
)
print(f"CREATE_RV:0x{rv:08x}")

if rv == CKR_OK:
    # Module accepted the param-less template -- probe the sign path too.
    message = b"mldsa-no-paramset-probe"
    msg_buf = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ML_DSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv_init = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    print(f"SIGNINIT_RV:0x{rv_init:08x}")
    if rv_init == CKR_OK:
        sig_len = CK_ULONG(0)
        rv_sign = raw.C_Sign(sh, msg_buf, len(message), None, ctypes.byref(sig_len))
        print(f"SIGN_RV:0x{rv_sign:08x}")
        if rv_sign == CKR_OK and sig_len.value > 0:
            sig_buf = (ctypes.c_ubyte * sig_len.value)()
            rv_sign2 = raw.C_Sign(
                sh, msg_buf, len(message), sig_buf, ctypes.byref(sig_len)
            )
            print(f"SIGN_RV:0x{rv_sign2:08x}")
    destroy_quietly(raw, sh, key.value)

cleanup()
"""
        )
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_CreateObject(CKO_PRIVATE_KEY/CKK_ML_DSA, no CKA_PARAMETER_SET)",
        )

        # Parse CREATE_RV and classify the module's response.
        create_rv = _parse_rv(stdout, "CREATE_RV:")
        assert create_rv is not None, f"probe did not report CREATE_RV: {stdout[-300:]}"

        classify_negative_rv(
            create_rv,
            _PARAMLESS_REJECT_RVS,
            label="C_CreateObject(CKK_ML_DSA, no CKA_PARAMETER_SET)",
        )

        # When create succeeded, classify the sign outcome too.
        sign_rv = _parse_rv(stdout, "SIGN_RV:")
        if sign_rv is not None:
            classify_negative_rv(
                sign_rv,
                (CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID, CKR_ARGUMENTS_BAD),
                label="C_Sign with param-less ML-DSA key",
                allow_ok=True,
            )
