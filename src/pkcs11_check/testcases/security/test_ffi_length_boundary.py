"""FFI length boundary and mechanism parameter probes.

All tests run in subprocess for crash safety. Tests exercise:
- isize::MAX boundary for data length parameters (Rust-specific UB at 2^63)
- OOM allocation guards (large but valid CKA_VALUE_LEN)
- NULL inner pointers in mechanism parameter structures

Inspired by Kryoptic fix/ffi-integer-overflow-hardening which added
check_slice_len(), ffi_slice(), ffi_slice_mut(), and bytes_to_vec() guards.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.types_std import CKA_DERIVE, CKA_ENCRYPT, CKA_SIGN, CKA_TOKEN
from pkcs11_check.testcases._subprocess_preamble import (
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import (
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# ---------------------------------------------------------------------------
# Constants for isize::MAX boundary probing (64-bit)
# ---------------------------------------------------------------------------

# Rust's isize::MAX -- the maximum byte count for slice::from_raw_parts.
_ISIZE_MAX_64 = 0x7FFFFFFFFFFFFFFF

# isize::MAX + 1 -- causes UB in slice::from_raw_parts because total byte
# size exceeds isize::MAX.  This is the exact boundary Kryoptic's
# check_slice_len<u8>() validates.
_ISIZE_MAX_PLUS_1_64 = 0x8000000000000000

# Large but sub-OOM value for allocation guard testing (2 GB).
_ALLOC_GUARD_VALUE_LEN = 0x7FFFFFFF


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


# ---------------------------------------------------------------------------
# TestIsizeMaxDataLength
# ---------------------------------------------------------------------------

_ISIZE_BOUNDARY_LENGTHS = [
    pytest.param(_ISIZE_MAX_64, id="isize_max"),
    pytest.param(_ISIZE_MAX_PLUS_1_64, id="isize_max_plus_1"),
]


class TestIsizeMaxDataLength:
    """Probe data functions with isize::MAX boundary lengths.

    On 64-bit systems, isize::MAX = 0x7FFFFFFFFFFFFFFF.  Passing this
    (or isize::MAX + 1) as the data length to C_Encrypt / C_Decrypt /
    C_Sign / C_Digest with a small real buffer triggers the exact
    boundary that Kryoptic's check_slice_len<u8>() validates.  A module
    that calls Rust's slice::from_raw_parts with byte count > isize::MAX
    hits undefined behavior.
    """

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_encrypt_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Encrypt isize-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_ECB)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_Encrypt(
            sh, buf, {data_len}, out_buf, ctypes.byref(out_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(ulDataLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_decrypt_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Decrypt isize-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_ECB)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_Decrypt(
            sh, buf, {data_len}, out_buf, ctypes.byref(out_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Decrypt(ulDataLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sign_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_SIGN, CKA_TOKEN, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 32-byte HMAC key via C_CreateObject
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
sign_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

attrs = (CK_ATTRIBUTE * 5)()
attrs[0].type = int(CKA_CLASS)
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = int(CKA_KEY_TYPE)
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = int(CKA_VALUE)
attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = int(CKA_SIGN)
attrs[3].pValue = ctypes.cast(
    ctypes.pointer(sign_true), ctypes.c_void_p,
)
attrs[3].ulValueLen = 1
attrs[4].type = int(CKA_TOKEN)
attrs[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"rv={{rv}}")
    cleanup()
    raise SystemExit(0)

try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        sig_len = CK_ULONG(64)
        sig_buf = (ctypes.c_ubyte * 64)()
        rv2 = raw.C_Sign(
            sh, buf, {data_len}, sig_buf, ctypes.byref(sig_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(HMAC_SHA256, ulDataLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_digest_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256, CK_ULONG, CKR_OK,
)

mech = CK_MECHANISM()
mech.mechanism = int(CKM_SHA256)
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
if rv == CKR_OK:
    buf = (ctypes.c_ubyte * 16)(*range(16))
    digest_len = CK_ULONG(64)
    digest_buf = (ctypes.c_ubyte * 64)()
    rv2 = raw.C_Digest(
        sh, buf, {data_len}, digest_buf, ctypes.byref(digest_len),
    )
    print(f"rv={{rv2}}")
else:
    print(f"rv={{rv}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Digest(SHA256, ulDataLen={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestAllocationGuard
# ---------------------------------------------------------------------------


class TestAllocationGuard:
    """Probe key generation with large but valid CKA_VALUE_LEN.

    Kryoptic changed ``vec![0; value_len]`` (panics on OOM) to
    ``try_reserve_exact`` (returns CKR_HOST_MEMORY).  A 2 GB
    CKA_VALUE_LEN is large enough to likely OOM on most systems but
    is NOT in integer-overflow territory (unlike the ULONG_MAX tests
    in test_arithmetic_overflow.py).
    """

    def test_generate_key_oom_value_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_KEY_GEN, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_VALUE_LEN, CKA_TOKEN, CKA_ENCRYPT, CK_ULONG,
)

mech = CK_MECHANISM()
mech.mechanism = int(CKM_AES_KEY_GEN)
mech.pParameter = None
mech.ulParameterLen = 0

val_len = CK_ULONG({_ALLOC_GUARD_VALUE_LEN})
token_false = ctypes.c_ubyte(0)
enc_true = ctypes.c_ubyte(1)

attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = int(CKA_VALUE_LEN)
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(val_len), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(val_len)
attrs[1].type = int(CKA_TOKEN)
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[1].ulValueLen = 1
attrs[2].type = int(CKA_ENCRYPT)
attrs[2].pValue = ctypes.cast(
    ctypes.pointer(enc_true), ctypes.c_void_p,
)
attrs[2].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh, ctypes.byref(mech),
    ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3,
    ctypes.byref(key),
)
print(f"rv={{rv}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=5)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"C_GenerateKey(AES, CKA_VALUE_LEN={_ALLOC_GUARD_VALUE_LEN:#x})"),
        )


# ---------------------------------------------------------------------------
# TestMechanismNullInnerParams
# ---------------------------------------------------------------------------


class TestMechanismNullInnerParams:
    """Probe *Init / DeriveKey with valid mechanism structs whose inner
    parameter structures contain NULL data pointers.

    Distinct from TestMechanismParamNullWithLength in test_api_boundary.py
    which tests NULL pParameter on the outer CK_MECHANISM.  These tests
    put a valid CK_MECHANISM struct with a valid pParameter pointer, but
    the inner struct has NULL data pointers where non-NULL is expected.
    """

    def test_gcm_null_iv(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """AES-GCM with pIv=NULL but ulIvLen=12, ulIvBits=96."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM NULL-IV crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS, CK_MECHANISM, CKM_AES_GCM,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    params = CK_AES_GCM_PARAMS()
    params.pIv = None            # NULL -- should be rejected
    params.ulIvLen = 12
    params.ulIvBits = 96
    params.pAAD = None
    params.ulAADLen = 0
    params.ulTagBits = 128
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_GCM)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12)",
        )

    def test_ecdh_null_public_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """ECDH1 derive with pPublicData=NULL but ulPublicDataLen=65."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_ECDH1_DERIVE_PARAMS, CK_MECHANISM, CKM_ECDH1_DERIVE,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKD_NULL, CK_ULONG,
)
from pkcs11_check.raw.recipes import gen_ec_keypair, destroy_quietly
from pkcs11_check.raw.ec import encode_named_curve_parameters

curve_oid = encode_named_curve_parameters("secp256r1")
pub, priv = gen_ec_keypair(raw, sh, curve_oid,
    private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
)
try:
    params = CK_ECDH1_DERIVE_PARAMS()
    params.kdf = int(CKD_NULL)
    params.ulSharedDataLen = 0
    params.pSharedData = None
    params.ulPublicDataLen = 65  # Claim 65 bytes (uncompressed P-256)
    params.pPublicData = None    # NULL -- should be rejected
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_ECDH1_DERIVE)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Template for the derived key
    cls_val = CK_ULONG(int(CKO_SECRET_KEY))
    kt_val = CK_ULONG(int(CKK_GENERIC_SECRET))
    vl_val = CK_ULONG(32)
    token_false = ctypes.c_ubyte(0)
    tmpl = (CK_ATTRIBUTE * 4)()
    tmpl[0].type = int(CKA_CLASS)
    tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(cls_val), ctypes.c_void_p,
    )
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = int(CKA_KEY_TYPE)
    tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(kt_val), ctypes.c_void_p,
    )
    tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
    tmpl[2].type = int(CKA_VALUE_LEN)
    tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(vl_val), ctypes.c_void_p,
    )
    tmpl[2].ulValueLen = ctypes.sizeof(vl_val)
    tmpl[3].type = int(CKA_TOKEN)
    tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(token_false), ctypes.c_void_p,
    )
    tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), priv,
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(ECDH1, pPublicData=NULL, ulPublicDataLen=65)"),
        )

    def test_oaep_null_source_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """RSA-OAEP with pSourceData=NULL but ulSourceDataLen=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_RSA_PKCS_OAEP_PARAMS, CK_MECHANISM, CKM_RSA_PKCS_OAEP,
    CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED,
    CKA_ENCRYPT, CKA_TOKEN, CKA_VERIFY,
)
from pkcs11_check.raw.recipes import gen_rsa_keypair, destroy_quietly

pub, priv = gen_rsa_keypair(raw, sh, 2048,
    public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
    private_attrs={CKA_TOKEN: False},
)
try:
    params = CK_RSA_PKCS_OAEP_PARAMS()
    params.hashAlg = int(CKM_SHA256)
    params.mgf = int(CKG_MGF1_SHA256)
    params.source = int(CKZ_DATA_SPECIFIED)
    params.pSourceData = None     # NULL -- should be rejected
    params.ulSourceDataLen = 16   # Claim 16 bytes
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_RSA_PKCS_OAEP)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), pub)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_EncryptInit(RSA_OAEP, pSourceData=NULL, ulSourceDataLen=16)"),
        )

    def test_hkdf_null_salt(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """HKDF derive with pSalt=NULL but ulSaltLen=16,
        ulSaltType=CKF_HKDF_SALT_DATA.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_HKDF_PARAMS, CK_MECHANISM, CKM_HKDF_DERIVE, CKM_SHA256,
    CKF_HKDF_SALT_DATA,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import an HMAC key for HKDF input
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = int(CKA_CLASS)
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = int(CKA_KEY_TYPE)
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = int(CKA_VALUE)
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = int(CKA_DERIVE)
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = int(CKA_TOKEN)
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    info_data = (ctypes.c_ubyte * 4)(*b"test")
    params = CK_HKDF_PARAMS()
    params.bExtract = 1
    params.bExpand = 1
    params.prfHashMechanism = int(CKM_SHA256)
    params.ulSaltType = int(CKF_HKDF_SALT_DATA)
    params.pSalt = None          # NULL -- should be rejected
    params.ulSaltLen = 16        # Claim 16 bytes
    params.hSaltKey = 0
    params.pInfo = ctypes.cast(info_data, ctypes.c_void_p)
    params.ulInfoLen = 4
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_HKDF_DERIVE)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(int(CKO_SECRET_KEY))
    d_kt = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = int(CKA_CLASS)
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = int(CKA_KEY_TYPE)
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = int(CKA_VALUE_LEN)
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = int(CKA_TOKEN)
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(HKDF, pSalt=NULL, ulSaltLen=16, ulSaltType=CKF_HKDF_SALT_DATA)"),
        )


# ---------------------------------------------------------------------------
# TestIsizeMaxOutputLength
# ---------------------------------------------------------------------------


class TestIsizeMaxOutputLength:
    """Probe OUTPUT buffer length parameters with isize::MAX boundary.

    Complementary to TestIsizeMaxDataLength which tests INPUT data length.
    Kryoptic's check_slice_len<u8>() also guards output/signature buffer
    sizes in sign(), verify(), digest(), sign_final(), verify_final(),
    digest_final().  A claimed output buffer size of isize::MAX (or +1)
    with a small real buffer should be rejected, not cause UB.
    """

    @pytest.mark.parametrize("out_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sign_isize_output(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        out_len: int,
    ) -> None:
        """C_Sign with isize::MAX claimed output buffer length."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_SIGN, CKA_TOKEN, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 32-byte HMAC key via C_CreateObject
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
sign_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

attrs = (CK_ATTRIBUTE * 5)()
attrs[0].type = int(CKA_CLASS)
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = int(CKA_KEY_TYPE)
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = int(CKA_VALUE)
attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = int(CKA_SIGN)
attrs[3].pValue = ctypes.cast(
    ctypes.pointer(sign_true), ctypes.c_void_p,
)
attrs[3].ulValueLen = 1
attrs[4].type = int(CKA_TOKEN)
attrs[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"rv={{rv}}")
    cleanup()
    raise SystemExit(0)

try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        sig_buf = (ctypes.c_ubyte * 64)()
        sig_len = CK_ULONG({out_len})
        rv2 = raw.C_Sign(
            sh, data, 16, sig_buf, ctypes.byref(sig_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(HMAC_SHA256, sig_len={out_len:#x})",
        )

    @pytest.mark.parametrize("out_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_digest_isize_output(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        out_len: int,
    ) -> None:
        """C_Digest with isize::MAX claimed output buffer length."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256, CK_ULONG, CKR_OK,
)

mech = CK_MECHANISM()
mech.mechanism = int(CKM_SHA256)
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
if rv == CKR_OK:
    data = (ctypes.c_ubyte * 16)(*range(16))
    digest_buf = (ctypes.c_ubyte * 64)()
    digest_len = CK_ULONG({out_len})
    rv2 = raw.C_Digest(
        sh, data, 16, digest_buf, ctypes.byref(digest_len),
    )
    print(f"rv={{rv2}}")
else:
    print(f"rv={{rv}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Digest(SHA256, digest_len={out_len:#x})",
        )

    @pytest.mark.parametrize("sig_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_verify_isize_sig_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        sig_len: int,
    ) -> None:
        """C_Verify with isize::MAX claimed signature length."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_VERIFY, CKA_TOKEN, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 32-byte HMAC key via C_CreateObject
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
verify_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

attrs = (CK_ATTRIBUTE * 5)()
attrs[0].type = int(CKA_CLASS)
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = int(CKA_KEY_TYPE)
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = int(CKA_VALUE)
attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = int(CKA_VERIFY)
attrs[3].pValue = ctypes.cast(
    ctypes.pointer(verify_true), ctypes.c_void_p,
)
attrs[3].ulValueLen = 1
attrs[4].type = int(CKA_TOKEN)
attrs[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"rv={{rv}}")
    cleanup()
    raise SystemExit(0)

try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        sig_buf = (ctypes.c_ubyte * 64)()
        rv2 = raw.C_Verify(
            sh, data, 16, sig_buf, {sig_len},
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Verify(HMAC_SHA256, sig_len={sig_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestHkdfNullInfo
# ---------------------------------------------------------------------------


class TestHkdfNullInfo:
    """HKDF derive with pInfo=NULL but ulInfoLen>0.

    Complementary to test_hkdf_null_salt in TestMechanismNullInnerParams
    which tests the NULL salt field.  This tests the other NULL-able
    parameter: the info/context data pointer.
    """

    def test_hkdf_null_info(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """HKDF derive with pInfo=NULL but ulInfoLen=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_HKDF_PARAMS, CK_MECHANISM, CKM_HKDF_DERIVE, CKM_SHA256,
    CKF_HKDF_SALT_NULL,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a generic secret key with CKA_DERIVE=True
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = int(CKA_CLASS)
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = int(CKA_KEY_TYPE)
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = int(CKA_VALUE)
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = int(CKA_DERIVE)
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = int(CKA_TOKEN)
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_HKDF_PARAMS()
    params.bExtract = 1
    params.bExpand = 1
    params.prfHashMechanism = int(CKM_SHA256)
    params.ulSaltType = int(CKF_HKDF_SALT_NULL)
    params.pSalt = None
    params.ulSaltLen = 0
    params.hSaltKey = 0
    params.pInfo = None          # NULL -- crash vector
    params.ulInfoLen = 16        # Non-zero length with NULL pointer
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_HKDF_DERIVE)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(int(CKO_SECRET_KEY))
    d_kt = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = int(CKA_CLASS)
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = int(CKA_KEY_TYPE)
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = int(CKA_VALUE_LEN)
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = int(CKA_TOKEN)
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DeriveKey(HKDF, pInfo=NULL, ulInfoLen=16)",
        )


# ---------------------------------------------------------------------------
# TestEddsaNullContext
# ---------------------------------------------------------------------------


class TestEddsaNullContext:
    """EdDSA with CK_EDDSA_PARAMS having pContextData=NULL but
    ulContextDataLen>0.

    Tests that the module does not dereference the NULL context data
    pointer when building the EdDSA signature context.
    """

    def test_eddsa_null_context_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """EdDSA SignInit with pContextData=NULL, ulContextDataLen=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("EDDSA"):
            pytest.skip("CKM_EDDSA not supported")
        curve_oid = encode_named_curve_parameters("ed25519")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_EDDSA_PARAMS, CK_MECHANISM, CKM_EDDSA,
    CKA_SIGN, CKA_TOKEN,
)
from pkcs11_check.raw.recipes import gen_ec_keypair, destroy_quietly
from pkcs11_check.raw.ec import encode_named_curve_parameters

# Ed25519 OID
curve_oid = encode_named_curve_parameters("ed25519")
pub, priv = gen_ec_keypair(raw, sh, curve_oid,
    private_attrs={CKA_SIGN: True, CKA_TOKEN: False})
try:
    params = CK_EDDSA_PARAMS()
    params.phFlag = 0
    params.ulContextDataLen = 16  # Non-zero
    params.pContextData = None     # NULL -- crash vector
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_EDDSA)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_SignInit(EDDSA, pContextData=NULL, ulContextDataLen=16)"),
        )


# ---------------------------------------------------------------------------
# TestAesCcmNullNonce
# ---------------------------------------------------------------------------


class TestAesCcmNullNonce:
    """AES-CCM with CK_AES_CCM_PARAMS having pNonce=NULL but ulNonceLen>0.

    Separate mechanism from GCM.  Tests that the module does not
    dereference the NULL nonce pointer during C_EncryptInit.
    """

    def test_ccm_null_nonce(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """AES-CCM EncryptInit with pNonce=NULL, ulNonceLen=7."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CCM"):
            pytest.skip("CKM_AES_CCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-CCM NULL-nonce crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_AES_CCM_PARAMS, CK_MECHANISM, CKM_AES_CCM,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    params = CK_AES_CCM_PARAMS()
    params.ulDataLen = 32
    params.pNonce = None         # NULL -- crash vector
    params.ulNonceLen = 7        # Non-zero
    params.pAAD = None
    params.ulAADLen = 0
    params.ulMACLen = 16
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_CCM)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit(AES_CCM, pNonce=NULL, ulNonceLen=7)",
        )


# ---------------------------------------------------------------------------
# TestSimpleKdfNullData
# ---------------------------------------------------------------------------


class TestSimpleKdfNullData:
    """CKM_CONCATENATE_BASE_AND_DATA with CK_KEY_DERIVATION_STRING_DATA
    having pData=NULL but ulLen>0.

    Tests that the module validates the data pointer before
    dereferencing it during key derivation.
    """

    def test_concat_base_data_null(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(CONCATENATE_BASE_AND_DATA) with pData=NULL."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_KEY_DERIVATION_STRING_DATA, CK_MECHANISM,
    CKM_CONCATENATE_BASE_AND_DATA,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a secret key with CKA_DERIVE=True
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = int(CKA_CLASS)
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = int(CKA_KEY_TYPE)
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = int(CKA_VALUE)
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = int(CKA_DERIVE)
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = int(CKA_TOKEN)
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_KEY_DERIVATION_STRING_DATA()
    params.pData = None          # NULL -- crash vector
    params.ulLen = 16            # Non-zero length
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_CONCATENATE_BASE_AND_DATA)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(int(CKO_SECRET_KEY))
    d_kt = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = int(CKA_CLASS)
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = int(CKA_KEY_TYPE)
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = int(CKA_VALUE_LEN)
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = int(CKA_TOKEN)
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(CONCATENATE_BASE_AND_DATA, pData=NULL, ulLen=16)"),
        )


# ---------------------------------------------------------------------------
# TestTlsKdfNullParams
# ---------------------------------------------------------------------------


class TestTlsKdfNullParams:
    """TLS KDF with null inner pointers in CK_TLS_KDF_PARAMS.

    Tests that the module validates the label pointer before
    dereferencing it during TLS key derivation.
    """

    def test_tls_kdf_null_label(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(TLS_KDF) with pLabel=NULL, ulLabelLength=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_TLS_KDF_PARAMS, CK_SSL3_RANDOM_DATA, CK_MECHANISM,
    CKM_TLS_KDF, CKM_SHA256,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 48-byte generic secret key (TLS pre-master secret size)
key_bytes = (ctypes.c_ubyte * 48)(*range(48))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = int(CKA_CLASS)
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = int(CKA_KEY_TYPE)
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = int(CKA_VALUE)
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 48
key_tmpl[3].type = int(CKA_DERIVE)
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = int(CKA_TOKEN)
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    # Build valid random data (32 bytes each)
    client_random = (ctypes.c_ubyte * 32)(*range(32))
    server_random = (ctypes.c_ubyte * 32)(*range(32))
    random_info = CK_SSL3_RANDOM_DATA()
    random_info.pClientRandom = ctypes.cast(
        client_random, ctypes.c_void_p,
    )
    random_info.ulClientRandomLen = 32
    random_info.pServerRandom = ctypes.cast(
        server_random, ctypes.c_void_p,
    )
    random_info.ulServerRandomLen = 32

    params = CK_TLS_KDF_PARAMS()
    params.prfMechanism = int(CKM_SHA256)
    params.pLabel = None             # NULL -- crash vector
    params.ulLabelLength = 16        # Non-zero length
    params.RandomInfo = random_info
    params.pContextData = None
    params.ulContextDataLength = 0
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_TLS_KDF)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(int(CKO_SECRET_KEY))
    d_kt = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = int(CKA_CLASS)
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = int(CKA_KEY_TYPE)
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = int(CKA_VALUE_LEN)
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = int(CKA_TOKEN)
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(TLS_KDF, pLabel=NULL, ulLabelLength=16)"),
        )


# ---------------------------------------------------------------------------
# TestSp800108NullDataParams
# ---------------------------------------------------------------------------


class TestSp800108NullDataParams:
    """SP800-108 Counter KDF with null data params pointer.

    Tests that the module validates pDataParams before dereferencing
    when ulNumberOfDataParams > 0.
    """

    def test_sp800_108_null_data_params(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(SP800_108_COUNTER_KDF) with pDataParams=NULL."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_SP800_108_KDF_PARAMS, CK_MECHANISM,
    CKM_SP800_108_COUNTER_KDF, CKM_SHA256_HMAC,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a generic secret key with CKA_DERIVE=True
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(int(CKO_SECRET_KEY))
kt_val = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = int(CKA_CLASS)
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = int(CKA_KEY_TYPE)
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = int(CKA_VALUE)
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = int(CKA_DERIVE)
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = int(CKA_TOKEN)
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = int(CKM_SHA256_HMAC)
    params.ulNumberOfDataParams = 1   # Non-zero count
    params.pDataParams = None         # NULL -- crash vector
    params.ulAdditionalDerivedKeys = 0
    params.pAdditionalDerivedKeys = None
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SP800_108_COUNTER_KDF)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(int(CKO_SECRET_KEY))
    d_kt = ctypes.c_ulong(int(CKK_GENERIC_SECRET))
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = int(CKA_CLASS)
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = int(CKA_KEY_TYPE)
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = int(CKA_VALUE_LEN)
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = int(CKA_TOKEN)
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(
                "C_DeriveKey(SP800_108_COUNTER_KDF, pDataParams=NULL, ulNumberOfDataParams=1)"
            ),
        )
