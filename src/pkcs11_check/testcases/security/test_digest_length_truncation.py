"""mmap-backed probe for C_Digest / C_Sign (HMAC) 64-bit length truncation.

``C_Digest`` and ``C_Sign`` with an HMAC mechanism must honour the full 64-bit
``ulDataLen`` value.  A module that casts the length to a 32-bit integer
silently truncates it: ``C_Digest(ptr, 0x100000008, ...)`` hashes only the
first 8 bytes (the low-32 value) and returns ``CKR_OK`` -- producing a digest
that matches the digest of 8 zero bytes instead of the digest of 4 GiB of
zeros.  This is a cryptographic-contract violation (CWE-197 / CWE-681).

Safety: the probe uses a ``MAP_PRIVATE | MAP_ANONYMOUS`` demand-zero mapping
for the full 4 GiB+ buffer.  A truncating module touches at most the first 8
bytes; a rejecting module returns an error before touching anything.  Only a
fully-honoring module faults all pages.  No out-of-bounds write occurs in any
case.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.types_std import (
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security._boundary_values import requires_64bit_ck_ulong
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [
    pytest.mark.security,
    pytest.mark.subprocess,
    pytest.mark.slow,
    requires_64bit_ck_ulong,
]

# 0x100000008: low 32 bits == 8, so a (uint32_t)/(word32) cast processes only 8 bytes.
_OVERSIZE_LEN = (1 << 32) + 8

# CKRs that constitute a conformant rejection of an oversized digest input.
_DIGEST_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
)

# Mapping from PKCS#11 mechanism to has_mechanism string and hashlib name.
# The has_mechanism string is the CKM_ name without the leading ``CKM_`` prefix.
_DIGEST_MECHS = [
    (CKM_SHA_1, "sha1"),
    (CKM_SHA224, "sha224"),
    (CKM_SHA256, "sha256"),
    (CKM_SHA384, "sha384"),
    (CKM_SHA512, "sha512"),
]

_DIGEST_MECH_IDS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]

# has_mechanism name for each mech (CKM_ prefix stripped).
_HAS_MECHANISM_NAME = {
    CKM_SHA_1: "SHA_1",
    CKM_SHA224: "SHA224",
    CKM_SHA256: "SHA256",
    CKM_SHA384: "SHA384",
    CKM_SHA512: "SHA512",
}


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-400:]}")


def _parse_prefixed_str_optional(output: str, prefix: str) -> str | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix).strip()
    return None


class TestDigestInputLengthTruncation:
    """C_Digest must not silently truncate a 64-bit input length to 32 bits.

    Probe: request a digest of ``0x100000008`` (4 GiB + 8) bytes from a
    demand-zero mmap region.  A truncating module casts ``ulDataLen`` to a
    32-bit integer, obtains 8, hashes only those 8 bytes, and returns
    ``CKR_OK`` -- producing a digest identical to the digest of 8 zero bytes.
    This is a cryptographic-contract violation.
    """

    @pytest.mark.parametrize(
        "mechanism,hashlib_name",
        _DIGEST_MECHS,
        ids=_DIGEST_MECH_IDS,
    )
    def test_digest_input_length_truncation(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        mechanism: Any,
        hashlib_name: str,
    ) -> None:
        """C_Digest must reject or fully honor a 4 GiB+ input length.

        A 32-bit cast of ``ulDataLen`` silently hashes only the first 8 bytes
        while returning ``CKR_OK``, producing a digest matching the digest of
        8 zero bytes -- a cryptographic-contract violation.
        """
        rs = p11_raw_session
        mech_str = _HAS_MECHANISM_NAME[mechanism]
        if not rs.has_mechanism(mech_str):
            pytest.skip(f"CKM_{mech_str} not advertised")

        body = f"""
import ctypes
import mmap as _mmap

from pkcs11_check.raw.types_std import CK_MECHANISM, CK_ULONG, CKR_OK

LEN = {_OVERSIZE_LEN}  # 0x100000008 -- low 32 bits = 8

mm = _mmap.mmap(
    -1, LEN,
    _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
    _mmap.PROT_READ | _mmap.PROT_WRITE,
)
buf = (ctypes.c_ubyte * LEN).from_buffer(mm)

mech = CK_MECHANISM()
mech.mechanism = {int(mechanism)}
mech.pParameter = None
mech.ulParameterLen = 0

rv = raw.C_DigestInit(sh, ctypes.byref(mech))
if rv == CKR_OK:
    out_buf = (ctypes.c_ubyte * 64)()
    out_len = CK_ULONG(64)
    rv2 = raw.C_Digest(
        sh, ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
        LEN, out_buf, ctypes.byref(out_len),
    )
    print("TARGET_RV:0x%08x" % rv2)
    if rv2 == CKR_OK:
        print("DIGEST_HEX:" + bytes(out_buf[:out_len.value]).hex())
else:
    print("SETUP_XFAIL:C_DigestInit not operational 0x%08x" % rv)

del buf
mm = None
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=180, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Digest({mech_str}, ulDataLen=0x{_OVERSIZE_LEN:x})",
        )

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        digest_hex = _parse_prefixed_str_optional(stdout, "DIGEST_HEX:")

        if rv != 0:
            classify_negative_rv(
                rv,
                _DIGEST_REJECT_RVS,
                label=f"C_Digest({mech_str}) rejects oversized 64-bit input length",
            )
        else:
            # CKR_OK -- check whether the module truncated to the low-32 bytes.
            assert digest_hex is not None, (
                f"TARGET_RV=CKR_OK but DIGEST_HEX line missing: {stdout[-300:]}"
            )
            ref_trunc = hashlib.new(hashlib_name, b"\x00" * (_OVERSIZE_LEN & 0xFFFFFFFF)).digest()
            if bytes.fromhex(digest_hex) == ref_trunc:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=(
                        "C_Digest truncated a 64-bit input length to 32 bits "
                        "(processed only the low-32 bytes)"
                    ),
                    operation="C_Digest",
                    mechanism=hashlib_name,
                    actual="digest of low-32 bytes",
                    expected="digest of full length",
                )
            else:
                note(
                    f"module honored a 4 GiB+ digest input length (no 64->32 truncation)"
                    f" for {hashlib_name}",
                    ComplianceLevel.EXTENDED,
                    reference="PKCS#11 C_Digest length semantics",
                    test_id=("TestDigestInputLengthTruncation.test_digest_input_length_truncation"),
                )


class TestHmacInputLengthTruncation:
    """C_Sign (HMAC) must not silently truncate a 64-bit input length to 32 bits.

    Probe: import a 32-byte generic-secret key and sign ``0x100000008`` bytes
    from a demand-zero mmap.  A truncating module casts ``ulDataLen`` to 32
    bits, signs only the first 8 bytes, and returns ``CKR_OK`` -- producing an
    HMAC matching the HMAC of 8 zero bytes.  This is a cryptographic-contract
    violation.
    """

    def test_hmac_sha256_input_length_truncation(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Sign (CKM_SHA256_HMAC) must reject or fully honor a 4 GiB+ input length.

        A 32-bit cast of ``ulDataLen`` silently signs only the first 8 bytes
        while returning ``CKR_OK``, producing an HMAC matching the HMAC of
        8 zero bytes -- a cryptographic-contract violation.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not advertised")

        body = f"""
import ctypes
import mmap as _mmap

from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

LEN = {_OVERSIZE_LEN}  # 0x100000008 -- low 32 bits = 8

# Import a 32-byte HMAC signing key via C_CreateObject.
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
sign_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

attrs = (CK_ATTRIBUTE * 5)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = CKA_SIGN
attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
attrs[3].ulValueLen = 1
attrs[4].type = CKA_TOKEN
attrs[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
attrs[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 5, ctypes.byref(key),
)
if rv != CKR_OK:
    print("SETUP_XFAIL:HMAC key import rejected 0x%08x" % rv)
    cleanup()
    raise SystemExit(0)

try:
    mm = _mmap.mmap(
        -1, LEN,
        _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
        _mmap.PROT_READ | _mmap.PROT_WRITE,
    )
    buf = (ctypes.c_ubyte * LEN).from_buffer(mm)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0

    rv2 = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    if rv2 == CKR_OK:
        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        rv3 = raw.C_Sign(
            sh, ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
            LEN, out_buf, ctypes.byref(out_len),
        )
        print("TARGET_RV:0x%08x" % rv3)
        if rv3 == CKR_OK:
            print("HMAC_HEX:" + bytes(out_buf[:out_len.value]).hex())
    else:
        print("SETUP_XFAIL:C_SignInit not operational 0x%08x" % rv2)

    del buf
    mm = None
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=180, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(SHA256_HMAC, ulDataLen=0x{_OVERSIZE_LEN:x})",
        )

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        hmac_hex = _parse_prefixed_str_optional(stdout, "HMAC_HEX:")

        if rv != 0:
            classify_negative_rv(
                rv,
                _DIGEST_REJECT_RVS,
                label="C_Sign(SHA256_HMAC) rejects oversized 64-bit input length",
            )
        else:
            assert hmac_hex is not None, (
                f"TARGET_RV=CKR_OK but HMAC_HEX line missing: {stdout[-300:]}"
            )
            key_material = bytes(range(32))
            ref_trunc = hmac.new(
                key_material, b"\x00" * (_OVERSIZE_LEN & 0xFFFFFFFF), hashlib.sha256
            ).digest()
            if bytes.fromhex(hmac_hex) == ref_trunc:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=(
                        "C_Sign (SHA256_HMAC) truncated a 64-bit input length to 32 bits "
                        "(processed only the low-32 bytes)"
                    ),
                    operation="C_Sign",
                    mechanism="sha256_hmac",
                    actual="HMAC of low-32 bytes",
                    expected="HMAC of full length",
                )
            else:
                note(
                    "module honored a 4 GiB+ HMAC-SHA256 input length (no 64->32 truncation)",
                    ComplianceLevel.EXTENDED,
                    reference="PKCS#11 C_Sign length semantics",
                    test_id=(
                        "TestHmacInputLengthTruncation.test_hmac_sha256_input_length_truncation"
                    ),
                )
