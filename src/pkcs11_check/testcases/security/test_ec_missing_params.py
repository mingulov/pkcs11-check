"""Crash-safe probes for EC keys imported without ``CKA_EC_PARAMS``.

An EC key created without ``CKA_EC_PARAMS`` has no curve. A conformant module must
reject the incomplete template (e.g. ``CKR_TEMPLATE_INCOMPLETE``) and must never
dereference a missing curve pointer during create / C_GetAttributeValue / C_Sign /
C_Verify / C_DeriveKey. These crash-safe probes assert no crash and classify the
create result.

The C_VerifyInit probe is no-crash-only: the precondition (C_CreateObject success
for a bare public-key template) is expected to be unreachable on a conformant module.
Any clean error is classified via ``classify_negative_rv``; a crash is a finding.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
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

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# A conformant module rejects a curve-less EC template with one of these.
_CURVELESS_REJECT_RVS = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)

_EC_IMPORTS = """
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_ECDH1_DERIVE_PARAMS,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_EC_POINT,
    CKA_EC_PARAMS,
    CKA_SIGN,
    CKD_NULL,
    CKK_EC,
    CKM_ECDSA,
    CKM_ECDH1_DERIVE,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)

# 67-byte DER OCTET STRING wrapping an X9.63 uncompressed point (04 41 04 X||Y).
# Bytes are arbitrary; a conformant module rejects before validating the point.
_POINT = bytes([0x04, 0x41, 0x04] + [0x11] * 64)
"""


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


def _parse_rv(output: str, prefix: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


class TestEcMissingParams:
    """EC create/use without ``CKA_EC_PARAMS``: must reject cleanly, never crash."""

    def test_public_key_import_no_ec_params_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """C_CreateObject with CKA_EC_POINT but no CKA_EC_PARAMS must not crash.

        A conformant module must reject the incomplete template at create time.
        Any crash is a finding.
        """
        body = (
            _EC_IMPORTS
            + """
cls_val = CK_ULONG(CKO_PUBLIC_KEY)
kt_val = CK_ULONG(CKK_EC)
point_buf = (ctypes.c_ubyte * len(_POINT))(*_POINT)

attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_EC_POINT
attrs[2].pValue = ctypes.cast(point_buf, ctypes.c_void_p)
attrs[2].ulValueLen = len(_POINT)

obj = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(obj)
)
print("CREATE_RV:0x%08x" % rv)
if rv == CKR_OK:
    destroy_quietly(raw, sh, obj)
cleanup()
"""
        )
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc, out, err, context="C_CreateObject(EC public, no CKA_EC_PARAMS)"
        )
        rv = _parse_rv(out, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {out[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC public no EC_PARAMS",
        )

    def test_get_ec_params_on_curveless_private_key_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """C_GetAttributeValue(CKA_EC_PARAMS) on a curve-less key must not crash.

        A conformant module rejects the create; if the object is created, reading
        CKA_EC_PARAMS must return a clean error, not crash.
        """
        body = (
            _EC_IMPORTS
            + """
scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
cls_val = CK_ULONG(CKO_PRIVATE_KEY)
kt_val = CK_ULONG(CKK_EC)

attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
attrs[2].ulValueLen = 32

obj = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(obj)
)
print("CREATE_RV:0x%08x" % rv)
if rv == CKR_OK:
    q = CK_ATTRIBUTE()
    q.type = CKA_EC_PARAMS
    q.pValue = None
    q.ulValueLen = 0
    grv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(q), 1)
    print("GETATTR_RV:0x%08x" % grv)
    destroy_quietly(raw, sh, obj)
cleanup()
"""
        )
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc, out, err, context="C_GetAttributeValue(CKA_EC_PARAMS) curve-less key"
        )
        rv = _parse_rv(out, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {out[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC private no EC_PARAMS",
        )

    @pytest.mark.parametrize(
        ("cls_name", "include_value"),
        (
            pytest.param("CKO_PRIVATE_KEY", True, id="private_with_value"),
            pytest.param("CKO_PUBLIC_KEY", False, id="public_bare"),
        ),
    )
    def test_get_ec_point_on_curveless_key_does_not_crash(
        self,
        p11_config: Any,
        cls_name: str,
        include_value: bool,
    ) -> None:
        """C_GetAttributeValue(CKA_EC_POINT) on a curve-less key must not crash.

        Two distinct templates:
        - private_with_value: CKO_PRIVATE_KEY + CKK_EC + CKA_VALUE (3-attr) —
          then C_GetAttributeValue(CKA_EC_POINT).
        - public_bare: CKO_PUBLIC_KEY + CKK_EC only (2-attr, no VALUE/POINT/PARAMS)
          — then C_GetAttributeValue(CKA_EC_POINT).

        A conformant module rejects the create; if the object is created, reading
        CKA_EC_POINT must return a clean error, not crash.
        """
        if include_value:
            value_block = """
scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
attrs[2].ulValueLen = 32
n_attrs = 3
"""
        else:
            value_block = """
attrs = (CK_ATTRIBUTE * 2)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
n_attrs = 2
"""
        body = (
            _EC_IMPORTS
            + f"""
cls_val = CK_ULONG({cls_name})
kt_val = CK_ULONG(CKK_EC)
"""
            + value_block
            + """
obj = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), n_attrs, ctypes.byref(obj)
)
print("CREATE_RV:0x%08x" % rv)
if rv == CKR_OK:
    q = CK_ATTRIBUTE()
    q.type = CKA_EC_POINT
    q.pValue = None
    q.ulValueLen = 0
    grv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(q), 1)
    print("GETATTR_RV:0x%08x" % grv)
    destroy_quietly(raw, sh, obj)
cleanup()
"""
        )
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context=f"C_GetAttributeValue(CKA_EC_POINT) curve-less {cls_name}",
        )
        rv = _parse_rv(out, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {out[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label=f"C_CreateObject {cls_name} no EC_PARAMS",
        )

    def test_ecdh_derive_curveless_base_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(CKM_ECDH1_DERIVE) with a curve-less base key must not crash.

        A conformant module rejects the curve-less create; if the create succeeds,
        the derive call must return a clean error, not crash.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not advertised")
        body = (
            _EC_IMPORTS
            + """
from pkcs11_check.raw.types_std import (
    CKA_VALUE_LEN, CKK_GENERIC_SECRET, CKO_SECRET_KEY,
)
scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
cls_val = CK_ULONG(CKO_PRIVATE_KEY)
kt_val = CK_ULONG(CKK_EC)
attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
attrs[2].ulValueLen = 32
base = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(base)
)
print("CREATE_RV:0x%08x" % rv)
if rv == CKR_OK:
    point_buf = (ctypes.c_ubyte * len(_POINT))(*_POINT)
    params = CK_ECDH1_DERIVE_PARAMS()
    params.kdf = CKD_NULL
    params.ulSharedDataLen = 0
    params.pSharedData = None
    params.ulPublicDataLen = len(_POINT)
    params.pPublicData = ctypes.cast(point_buf, ctypes.c_void_p)
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDH1_DERIVE
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    out_cls = CK_ULONG(CKO_SECRET_KEY)
    out_kt = CK_ULONG(CKK_GENERIC_SECRET)
    out_len = CK_ULONG(32)
    otmpl = (CK_ATTRIBUTE * 3)()
    otmpl[0].type = CKA_CLASS
    otmpl[0].pValue = ctypes.cast(ctypes.pointer(out_cls), ctypes.c_void_p)
    otmpl[0].ulValueLen = ctypes.sizeof(out_cls)
    otmpl[1].type = CKA_KEY_TYPE
    otmpl[1].pValue = ctypes.cast(ctypes.pointer(out_kt), ctypes.c_void_p)
    otmpl[1].ulValueLen = ctypes.sizeof(out_kt)
    otmpl[2].type = CKA_VALUE_LEN
    otmpl[2].pValue = ctypes.cast(ctypes.pointer(out_len), ctypes.c_void_p)
    otmpl[2].ulValueLen = ctypes.sizeof(out_len)
    derived = CK_OBJECT_HANDLE(0)
    drv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base,
        ctypes.cast(otmpl, ctypes.POINTER(CK_ATTRIBUTE)), 3, ctypes.byref(derived),
    )
    print("DERIVE_RV:0x%08x" % drv)
    if drv == CKR_OK:
        destroy_quietly(raw, sh, derived)
    destroy_quietly(raw, sh, base)
cleanup()
"""
        )
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(rc, out, err, context="C_DeriveKey(ECDH1, curve-less base)")
        rv = _parse_rv(out, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {out[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC private no EC_PARAMS (ECDH probe)",
        )

    def test_sign_with_curveless_private_key_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Sign(CKM_ECDSA) with a curve-less private key must not crash.

        Complements x509/test_identity.py (DER import) with a minimal raw-template
        trigger: create a curve-less private key via C_CreateObject, then attempt
        C_SignInit(CKM_ECDSA) + C_Sign with a 32-byte digest. A conformant module
        rejects the create; any crash at create or sign time is a finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not advertised")
        body = (
            _EC_IMPORTS
            + """
scalar = (ctypes.c_ubyte * 32)(*range(1, 33))
cls_val = CK_ULONG(CKO_PRIVATE_KEY)
kt_val = CK_ULONG(CKK_EC)
sign_true = ctypes.c_ubyte(1)

attrs = (CK_ATTRIBUTE * 4)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(scalar, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = CKA_SIGN
attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
attrs[3].ulValueLen = 1

obj = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 4, ctypes.byref(obj)
)
print("CREATE_RV:0x%08x" % rv)
if rv == CKR_OK:
    digest = (ctypes.c_ubyte * 32)(*range(32))
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    irv = raw.C_SignInit(sh, ctypes.byref(mech), obj)
    print("SIGNINIT_RV:0x%08x" % irv)
    if irv == CKR_OK:
        sig_buf = (ctypes.c_ubyte * 256)()
        sig_len = CK_ULONG(0)
        srv = raw.C_Sign(sh, digest, 32, sig_buf, ctypes.byref(sig_len))
        print("SIGN_RV:0x%08x" % srv)
    destroy_quietly(raw, sh, obj)
cleanup()
"""
        )
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(rc, out, err, context="C_Sign(ECDSA, curve-less private key)")
        rv = _parse_rv(out, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {out[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC private no EC_PARAMS (sign probe)",
        )

    def test_verify_with_curveless_public_key_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """C_Verify(CKM_ECDSA) with a curve-less public key must not crash — conditional probe.

        A curve-less public key should not be constructible via C_CreateObject on
        a conformant module. This probe attempts the create anyway (bare public key:
        CKA_CLASS + CKA_KEY_TYPE + CKA_EC_POINT, no CKA_EC_PARAMS); if the create
        is rejected (the conformant case), the rejection is classified via
        classify_negative_rv. If the create succeeds (the bug precondition),
        C_VerifyInit + C_Verify are exercised and any crash is a finding.
        Because the precondition may be unreachable, this probe is no-crash-only:
        any clean error at any stage is classified, never hard-failed.
        """
        body = (
            _EC_IMPORTS
            + """
from pkcs11_check.raw.types_std import CKA_VERIFY
cls_val = CK_ULONG(CKO_PUBLIC_KEY)
kt_val = CK_ULONG(CKK_EC)
point_buf = (ctypes.c_ubyte * len(_POINT))(*_POINT)
verify_true = ctypes.c_ubyte(1)

attrs = (CK_ATTRIBUTE * 4)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_EC_POINT
attrs[2].pValue = ctypes.cast(point_buf, ctypes.c_void_p)
attrs[2].ulValueLen = len(_POINT)
attrs[3].type = CKA_VERIFY
attrs[3].pValue = ctypes.cast(ctypes.pointer(verify_true), ctypes.c_void_p)
attrs[3].ulValueLen = 1

obj = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 4, ctypes.byref(obj)
)
print("CREATE_RV:0x%08x" % rv)
if rv == CKR_OK:
    digest = (ctypes.c_ubyte * 32)(*range(32))
    sig_buf = (ctypes.c_ubyte * 72)(*([0x30, 0x44, 0x02, 0x20] + [0x11] * 32
                                       + [0x02, 0x20] + [0x22] * 32))
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    irv = raw.C_VerifyInit(sh, ctypes.byref(mech), obj)
    print("VERIFYINIT_RV:0x%08x" % irv)
    if irv == CKR_OK:
        vrv = raw.C_Verify(sh, digest, 32, sig_buf, 72)
        print("VERIFY_RV:0x%08x" % vrv)
    destroy_quietly(raw, sh, obj)
cleanup()
"""
        )
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(rc, out, err, context="C_Verify(ECDSA, curve-less public key)")
        rv = _parse_rv(out, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {out[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC public no EC_PARAMS (verify probe)",
        )
