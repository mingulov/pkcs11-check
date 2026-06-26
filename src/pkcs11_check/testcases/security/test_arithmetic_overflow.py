"""Integer overflow/underflow probes for user-controlled size fields.

All tests run in subprocess for crash safety. Each test constructs ctypes
structures with near-SIZE_MAX values in length/count fields, then calls C_*
functions to check whether the module wraps around or crashes.

Covers:
- Data length overflow in C_Encrypt / C_Decrypt (ulDataLen near SIZE_MAX)
- Mechanism parameter length overflow (ulParameterLen = ULONG_MAX)
- GCM tag bits overflow ((ulTagBits + 7) / 8 wraps to 0)
- PSS salt length overflow (hash_len + sLen + 2 wraps)
- Template count overflow (count * sizeof(CK_ATTRIBUTE) wraps)
- KEM output-template count overflow in C_EncapsulateKey / C_DecapsulateKey
- Key value length overflow (CKA_VALUE_LEN = ULONG_MAX)
- Attribute value length overflow (ulValueLen = ULONG_MAX)
- GenerateKeyPair template count overflow
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    _CK_ULONG_MAX,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security.conftest import (
    HONEYPOT_MMAP_CODE,
    assert_subprocess_no_crash,
)

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# Literal values for embedding in subprocess script strings.
# Subprocess scripts cannot import _CK_ULONG_MAX so we use plain ints.
_ULONG_MAX = int(_CK_ULONG_MAX)
_ULONG_MAX_MINUS_15 = _ULONG_MAX - 15
_ULONG_HALF = _ULONG_MAX // 2
_ULONG_32BIT_SIGN = 0x80000000
_ULONG_32BIT_MAX = 0xFFFFFFFF
_ULONG_64BIT_SIGN = 0x8000000000000000
_SIZEOF_ATTR_OVERFLOW = _ULONG_MAX // 24 + 1
_ULONG_33BIT = 0x100000000


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


_CHILD_SETUP_REJECT_HELPERS = """
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    is_known_error,
)


def setup_xfail_if_known_ckr(exc, known_ckrs, purpose):
    if is_known_error(exc, known_ckrs):
        rv = getattr(exc, "rv", None)
        detail = ckr_name(rv) if rv is not None else str(exc)
        print(f"SETUP_XFAIL:{purpose}: {detail}")
        cleanup()
        raise SystemExit(0)
    raise exc

"""


# ---------------------------------------------------------------------------
# TestDataLengthOverflow -- 4 lengths x 2 ops = 8 cases
# ---------------------------------------------------------------------------

_DATA_LENGTHS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_ULONG_MAX_MINUS_15, id="ulong_max_minus_15"),
    pytest.param(_ULONG_HALF, id="ulong_half"),
    pytest.param(_ULONG_32BIT_SIGN, id="0x80000000"),
]

_DATA_OPS = [
    pytest.param("C_Encrypt", "C_EncryptInit", id="encrypt"),
    pytest.param("C_Decrypt", "C_DecryptInit", id="decrypt"),
]


class TestDataLengthOverflow:
    """Probe C_Encrypt/C_Decrypt with near-SIZE_MAX ulDataLen.

    After C_EncryptInit / C_DecryptInit with AES-ECB, call the data function
    with a huge ulDataLen.  Modules that compute padded_len =
    block_size * (len / block_size + 1) will wrap near SIZE_MAX.
    """

    @pytest.mark.parametrize("data_len", _DATA_LENGTHS)
    @pytest.mark.parametrize("func,init_func", _DATA_OPS)
    def test_data_length_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        func: str,
        init_func: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{func} data-length overflow crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_ECB
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.{init_func}(sh, ctypes.byref(mech), key)
    if rv == CKR_OK:
        # Small real buffer, but claim huge length
        buf = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.{func}(sh, buf, {data_len}, out_buf, ctypes.byref(out_len))
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{func}(ulDataLen={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestGcmDecryptUpdateAccumulation -- 1 case
# ---------------------------------------------------------------------------

# Reject codes a conformant module may return when ulEncryptedPartLen is
# out of range for the streaming decryption phase.
_DATA_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)


class TestGcmDecryptUpdateAccumulation:
    """AES-GCM C_DecryptUpdate must reject huge length before accumulating.

    A plain 32-bit add for the internal byte accumulator means that feeding
    0xFFFFFFFF first then 2 wraps the accumulator to 1, bypassing the length
    guard and driving an OOB copy.  A conformant module rejects the oversized
    first-update length with ``CKR_DATA_LEN_RANGE`` / ``CKR_ARGUMENTS_BAD`` /
    ``CKR_ENCRYPTED_DATA_LEN_RANGE`` (or another clean code) BEFORE any
    accumulation.
    """

    def test_gcm_decrypt_update_accumulation_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Two-call ``C_DecryptUpdate`` accumulation wrap must be rejected.

        Two ``C_DecryptUpdate`` calls whose lengths sum past the 32-bit boundary
        must not wrap the internal byte accumulator into a small allocation.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        if "C_DecryptUpdate" not in rs.raw.available_function_names():
            pytest.skip("C_DecryptUpdate not available")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM DecryptUpdate accumulation crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS, CK_MECHANISM, CK_ULONG, CKM_AES_GCM, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
{HONEYPOT_MMAP_CODE}
try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    iv = (ctypes.c_ubyte * 12)(*range(12))
    params = CK_AES_GCM_PARAMS()
    params.pIv = ctypes.cast(iv, ctypes.c_void_p)
    params.ulIvLen = 12
    params.ulIvBits = 96
    params.pAAD = None
    params.ulAADLen = 0
    params.ulTagBits = 128
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_GCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv_init = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
    if rv_init != CKR_OK:
        print(f"SETUP_XFAIL:C_DecryptInit rejected: {{rv_init}}")
        cleanup()
        raise SystemExit(0)

    # Honest buffer (docs/probe-soundness.md): the claimed 0xFFFFFFFF bytes are
    # backed by a demand-zero mmap, so a module that honors the length reads real
    # zeroed pages -- any crash that remains (e.g. the word32 encSz accumulator
    # wrapping on the second update -> under-alloc + over-write) is the module's
    # own bug, a real finding, not an over-read of our short buffer.
    out1 = (ctypes.c_ubyte * 32)()
    out1_len = CK_ULONG(32)
    rv1 = raw.C_DecryptUpdate(sh, HONEYPOT_BUF, {_ULONG_32BIT_MAX}, out1, ctypes.byref(out1_len))
    print(f"CKR_UPDATE1:0x{{rv1:08x}}")
    if rv1 == CKR_OK:
        # If the first update was accepted, attempt the wrap-triggering second
        # call only if the module allowed the first; a crash here IS the finding.
        buf2 = (ctypes.c_ubyte * 2)(*[0, 1])
        out2 = (ctypes.c_ubyte * 32)()
        out2_len = CK_ULONG(32)
        rv2 = raw.C_DecryptUpdate(sh, buf2, 2, out2, ctypes.byref(out2_len))
        print(f"CKR_UPDATE2:0x{{rv2:08x}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DecryptUpdate(AES_GCM, ulEncryptedPartLen={_ULONG_32BIT_MAX:#x})",
        )
        # Classify the first-update return value: the module must reject the
        # oversized length before any accumulation.
        rv1_line = next((ln for ln in stdout.splitlines() if ln.startswith("CKR_UPDATE1:")), None)
        if rv1_line is not None:
            rv1 = int(rv1_line.removeprefix("CKR_UPDATE1:"), 0)
            classify_negative_rv(
                rv1,
                _DATA_REJECT_CKRS,
                label=(
                    f"C_DecryptUpdate(AES_GCM, ulEncryptedPartLen={_ULONG_32BIT_MAX:#x}) "
                    "-- must reject before accumulating"
                ),
                allow_ok=True,  # CKR_OK + no crash is tolerable; the two-call crash is the finding
            )


# ---------------------------------------------------------------------------
# TestMechanismParamLengthOverflow -- 2 cases
# ---------------------------------------------------------------------------

_MECH_PARAM_CASES = [
    pytest.param("AES_CBC", "CKM_AES_CBC", 16, id="aes_cbc"),
    pytest.param("AES_GCM", "CKM_AES_GCM", 64, id="aes_gcm"),
]


class TestMechanismParamLengthOverflow:
    """Probe C_EncryptInit with pParameter pointing to a small buffer
    but ulParameterLen = ULONG_MAX.

    Modules that memcpy(ulParameterLen) from the small buffer will read
    past the allocation boundary.
    """

    @pytest.mark.parametrize("mech_check,mech_name,real_size", _MECH_PARAM_CASES)
    def test_mechanism_param_length_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        mech_check: str,
        mech_name: str,
        real_size: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{mech_name} parameter-length overflow crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, {mech_name}
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    param_buf = (ctypes.c_ubyte * {real_size})(*range({real_size}))
    mech = CK_MECHANISM()
    mech.mechanism = {mech_name}
    mech.pParameter = ctypes.cast(param_buf, ctypes.c_void_p)
    mech.ulParameterLen = {_ULONG_MAX}  # Real buffer is only {real_size} bytes!
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(
                f"C_EncryptInit({mech_name}, "
                f"pParameter={real_size}B, ulParameterLen={_ULONG_MAX:#x})"
            ),
        )


# ---------------------------------------------------------------------------
# TestGcmTagBitsOverflow -- 4 cases
# ---------------------------------------------------------------------------

_GCM_TAG_BITS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_ULONG_MAX - 6, id="ulong_max_minus_6"),
    pytest.param(_ULONG_32BIT_MAX, id="0xFFFFFFFF"),
    pytest.param(_ULONG_64BIT_SIGN, id="0x8000000000000000"),
]


class TestGcmTagBitsOverflow:
    """Probe AES-GCM with extreme ulTagBits values.

    Modules compute tag_len = (ulTagBits + 7) / 8 which wraps to 0 near
    SIZE_MAX, causing a buffer underflow when writing the tag.
    """

    @pytest.mark.parametrize("tag_bits", _GCM_TAG_BITS)
    def test_gcm_tag_bits_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        tag_bits: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM tag-bits overflow crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS, CK_MECHANISM, CKM_AES_GCM,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    iv = (ctypes.c_ubyte * 12)(*range(12))
    params = CK_AES_GCM_PARAMS()
    params.pIv = ctypes.cast(iv, ctypes.c_void_p)
    params.ulIvLen = 12
    params.ulIvBits = 96
    params.pAAD = None
    params.ulAADLen = 0
    params.ulTagBits = {tag_bits}
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_GCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_EncryptInit(AES_GCM, ulTagBits={tag_bits:#x})",
        )


# ---------------------------------------------------------------------------
# TestPssSaltLengthOverflow -- 3 cases
# ---------------------------------------------------------------------------

_PSS_SALT_LENGTHS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_ULONG_32BIT_SIGN, id="0x80000000"),
    pytest.param(_ULONG_32BIT_MAX, id="0xFFFFFFFF"),
]


class TestPssSaltLengthOverflow:
    """Probe RSA-PSS with extreme sLen values.

    Modules compute emLen >= hash_len + sLen + 2 which overflows when
    sLen is near SIZE_MAX, bypassing length validation.
    """

    @pytest.mark.parametrize("salt_len", _PSS_SALT_LENGTHS)
    def test_pss_salt_length_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        salt_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("CKM_SHA256_RSA_PKCS_PSS not supported")
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_RSA_PKCS_PSS_PARAMS, CK_MECHANISM, CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA256, CKG_MGF1_SHA256, CKA_SIGN, CKA_TOKEN, CKA_VERIFY,
)
from pkcs11_check.raw.recipes import gen_rsa_keypair, destroy_quietly

try:
    pub, priv = gen_rsa_keypair(raw, sh, 2048,
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
        public_attrs={{CKA_VERIFY: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )
try:
    params = CK_RSA_PKCS_PSS_PARAMS()
    params.hashAlg = CKM_SHA256
    params.mgf = CKG_MGF1_SHA256
    params.sLen = {salt_len}
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_RSA_PKCS_PSS
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_SignInit(SHA256_RSA_PKCS_PSS, sLen={salt_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestTemplateCountOverflow -- 3 counts x 5 ops = 15 cases
# ---------------------------------------------------------------------------

_TEMPLATE_COUNTS = [
    pytest.param(_ULONG_MAX, id="ulong_max"),
    pytest.param(_SIZEOF_ATTR_OVERFLOW, id="sizeof_attr_overflow"),
    pytest.param(_ULONG_33BIT, id="0x100000000"),
]

_TEMPLATE_OPS = [
    pytest.param("C_CreateObject", id="create_object"),
    pytest.param("C_GenerateKey", id="generate_key"),
    pytest.param("C_FindObjectsInit", id="find_objects_init"),
    pytest.param("C_SetAttributeValue", id="set_attribute_value"),
    pytest.param("C_UnwrapKey", id="unwrap_key"),
]


class TestTemplateCountOverflow:
    """Probe template-accepting functions with huge template counts.

    Pass a template with 1 real CK_ATTRIBUTE but claim a count that would
    overflow count * sizeof(CK_ATTRIBUTE), causing the module to iterate
    past the allocation boundary.
    """

    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    @pytest.mark.parametrize("op", _TEMPLATE_OPS)
    def test_template_count_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        count: int,
        op: str,
    ) -> None:
        rs = p11_raw_session
        if op == "C_GenerateKey" and not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if op == "C_UnwrapKey" and not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if op == "C_UnwrapKey":
            setup_key = gen_aes_key_or_xfail(
                rs,
                256,
                purpose="C_UnwrapKey template-count overflow crash probe setup",
            )
            destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)

        if op == "C_CreateObject":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CK_ULONG, CKA_CLASS, CKO_DATA, CK_OBJECT_HANDLE,
)
attr = CK_ATTRIBUTE()
attr.type = CKA_CLASS
cls_val = CK_ULONG(CKO_DATA)
attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attr.ulValueLen = ctypes.sizeof(cls_val)
handle = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(sh, ctypes.byref(attr), {count}, ctypes.byref(handle))
print(f"rv={{rv}}")
cleanup()
"""
        elif op == "C_GenerateKey":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CK_ULONG, CK_MECHANISM, CKM_AES_KEY_GEN,
    CKA_VALUE_LEN, CK_OBJECT_HANDLE,
)
attr = CK_ATTRIBUTE()
attr.type = CKA_VALUE_LEN
vlen = CK_ULONG(32)
attr.pValue = ctypes.cast(ctypes.pointer(vlen), ctypes.c_void_p)
attr.ulValueLen = ctypes.sizeof(vlen)
mech = CK_MECHANISM()
mech.mechanism = CKM_AES_KEY_GEN
mech.pParameter = None
mech.ulParameterLen = 0
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh, ctypes.byref(mech), ctypes.byref(attr), {count}, ctypes.byref(key),
)
print(f"rv={{rv}}")
cleanup()
"""
        elif op == "C_FindObjectsInit":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CK_ULONG, CKA_CLASS, CKO_DATA
attr = CK_ATTRIBUTE()
attr.type = CKA_CLASS
cls_val = CK_ULONG(CKO_DATA)
attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attr.ulValueLen = ctypes.sizeof(cls_val)
rv = raw.C_FindObjectsInit(sh, ctypes.byref(attr), {count})
print(f"rv={{rv}}")
cleanup()
"""
        elif op == "C_SetAttributeValue":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CK_ULONG, CKA_CLASS, CKO_DATA
attr = CK_ATTRIBUTE()
attr.type = CKA_CLASS
cls_val = CK_ULONG(CKO_DATA)
attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attr.ulValueLen = ctypes.sizeof(cls_val)
# Use object handle 0 -- the huge count should be rejected first
rv = raw.C_SetAttributeValue(sh, 0, ctypes.byref(attr), {count})
print(f"rv={{rv}}")
cleanup()
"""
        elif op == "C_UnwrapKey":
            body = f"""
{_CHILD_SETUP_REJECT_HELPERS}
import ctypes
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CK_ULONG, CK_MECHANISM, CKM_AES_ECB,
    CKA_CLASS, CKO_SECRET_KEY, CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    wrap_key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    attr = CK_ATTRIBUTE()
    attr.type = CKA_CLASS
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    attr.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(cls_val)
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_ECB
    mech.pParameter = None
    mech.ulParameterLen = 0
    fake_wrapped = (ctypes.c_ubyte * 32)(*range(32))
    out_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKey(
        sh, ctypes.byref(mech), wrap_key,
        fake_wrapped, 32,
        ctypes.byref(attr), {count},
        ctypes.byref(out_key),
    )
    print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, wrap_key)
cleanup()
"""
        else:
            raise ValueError(f"Unhandled op: {op}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestTemplateCountOverflowValidHandles -- 3 counts x 3 ops = 9 cases
# ---------------------------------------------------------------------------

_VALID_HANDLE_TEMPLATE_OPS = [
    pytest.param("C_GetAttributeValue", id="get_attribute_value"),
    pytest.param("C_SetAttributeValue", id="set_attribute_value"),
    pytest.param("C_CopyObject", id="copy_object"),
]

_IMPORT_DATA_OBJECT_FOR_COUNT_PROBE = """
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CKA_APPLICATION,
    CKA_CLASS,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKO_DATA,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)

value = (ctypes.c_ubyte * 16)(*range(16))
label = (ctypes.c_ubyte * 9)(*b"count-key")
application = (ctypes.c_ubyte * 12)(*b"pkcs11-check")
cls_val = CK_ULONG(CKO_DATA)
token_false = ctypes.c_ubyte(0)

base_tmpl = (CK_ATTRIBUTE * 5)()
base_tmpl[0].type = CKA_CLASS
base_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
base_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
base_tmpl[1].type = CKA_TOKEN
base_tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
base_tmpl[1].ulValueLen = 1
base_tmpl[2].type = CKA_LABEL
base_tmpl[2].pValue = ctypes.cast(label, ctypes.c_void_p)
base_tmpl[2].ulValueLen = len(label)
base_tmpl[3].type = CKA_APPLICATION
base_tmpl[3].pValue = ctypes.cast(application, ctypes.c_void_p)
base_tmpl[3].ulValueLen = len(application)
base_tmpl[4].type = CKA_VALUE
base_tmpl[4].pValue = ctypes.cast(value, ctypes.c_void_p)
base_tmpl[4].ulValueLen = len(value)

base_object = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(base_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_object),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:data-object import rejected: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)
"""


class TestTemplateCountOverflowValidHandles:
    """Template-count overflow probes that reach real object-handle paths."""

    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    @pytest.mark.parametrize("op", _VALID_HANDLE_TEMPLATE_OPS)
    def test_template_count_overflow_with_valid_object_handle(
        self,
        p11_config: Any,
        count: int,
        op: str,
    ) -> None:
        """A huge template count must not walk beyond a one-attribute template."""
        preamble = _preamble(p11_config)

        if op == "C_GetAttributeValue":
            body = (
                _IMPORT_DATA_OBJECT_FOR_COUNT_PROBE
                + f"""
try:
    out_class = CK_ULONG(0)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_CLASS
    attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(out_class)
    rv = raw.C_GetAttributeValue(sh, base_object.value, ctypes.byref(attr), {count})
    print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, base_object.value)
cleanup()
"""
            )
        elif op == "C_SetAttributeValue":
            body = (
                _IMPORT_DATA_OBJECT_FOR_COUNT_PROBE
                + f"""
try:
    label = (ctypes.c_ubyte * 8)(*b"countchk")
    attr = CK_ATTRIBUTE()
    attr.type = CKA_LABEL
    attr.pValue = ctypes.cast(label, ctypes.c_void_p)
    attr.ulValueLen = 8
    rv = raw.C_SetAttributeValue(sh, base_object.value, ctypes.byref(attr), {count})
    print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, base_object.value)
cleanup()
"""
            )
        elif op == "C_CopyObject":
            body = (
                _IMPORT_DATA_OBJECT_FOR_COUNT_PROBE
                + f"""
copy_object = CK_OBJECT_HANDLE(0)
try:
    attr = CK_ATTRIBUTE()
    attr.type = CKA_TOKEN
    attr.pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attr.ulValueLen = 1
    rv = raw.C_CopyObject(
        sh,
        base_object.value,
        ctypes.byref(attr),
        {count},
        ctypes.byref(copy_object),
    )
    print(f"rv={{rv}}")
finally:
    if copy_object.value:
        destroy_quietly(raw, sh, copy_object.value)
    destroy_quietly(raw, sh, base_object.value)
cleanup()
"""
            )
        else:
            raise ValueError(f"Unhandled op: {op}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(valid object, template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestDeriveTemplateCountOverflowValidBase -- 3 cases
# ---------------------------------------------------------------------------


class TestDeriveTemplateCountOverflowValidBase:
    """Template-count overflow probes that reach a valid C_DeriveKey base key path."""

    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    def test_derive_key_template_count_overflow_with_valid_base_key(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        count: int,
    ) -> None:
        """A huge derived-key template count must not walk beyond one attribute."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")

        preamble = _preamble(p11_config)
        body = f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_MECHANISM,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKO_SECRET_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)

base_value = (ctypes.c_ubyte * 32)(*range(32))
cls_val = CK_ULONG(CKO_SECRET_KEY)
kt_val = CK_ULONG(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

base_tmpl = (CK_ATTRIBUTE * 5)()
base_tmpl[0].type = CKA_CLASS
base_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
base_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
base_tmpl[1].type = CKA_KEY_TYPE
base_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
base_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
base_tmpl[2].type = CKA_VALUE
base_tmpl[2].pValue = ctypes.cast(base_value, ctypes.c_void_p)
base_tmpl[2].ulValueLen = len(base_value)
base_tmpl[3].type = CKA_DERIVE
base_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
base_tmpl[3].ulValueLen = 1
base_tmpl[4].type = CKA_TOKEN
base_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
base_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(base_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:derive base-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

derived = CK_OBJECT_HANDLE(0)
try:
    data = (ctypes.c_ubyte * 16)(*range(16))
    params = CK_KEY_DERIVATION_STRING_DATA()
    params.pData = ctypes.cast(data, ctypes.c_void_p)
    params.ulLen = len(data)
    mech = CK_MECHANISM()
    mech.mechanism = CKM_CONCATENATE_BASE_AND_DATA
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    out_class = CK_ULONG(CKO_SECRET_KEY)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_CLASS
    attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(out_class)

    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.byref(attr),
        {count},
        ctypes.byref(derived),
    )
    print(f"rv={{rv}}")
finally:
    if derived.value:
        destroy_quietly(raw, sh, derived.value)
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DeriveKey(valid base, template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestKemTemplateCountOverflow -- 3 counts x 2 ops = 6 cases
# ---------------------------------------------------------------------------

_KEM_TEMPLATE_COUNT_OPS = [
    pytest.param("C_EncapsulateKey", id="encapsulate_key"),
    pytest.param("C_DecapsulateKey", id="decapsulate_key"),
]

_ML_KEM_KEYPAIR_FOR_COUNT_PROBE = """
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CKA_DECAPSULATE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CK_OBJECT_HANDLE,
    CK_MECHANISM,
    CKP_ML_KEM_768,
    CKR_OK,
    CK_ULONG,
)


def _set_bool_attr(attr, attr_type, value_ref):
    attr.type = attr_type
    attr.pValue = ctypes.cast(ctypes.pointer(value_ref), ctypes.c_void_p)
    attr.ulValueLen = 1


def _set_ulong_attr(attr, attr_type, value_ref):
    attr.type = attr_type
    attr.pValue = ctypes.cast(ctypes.pointer(value_ref), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(value_ref)


param_set = CK_ULONG(CKP_ML_KEM_768)
pub_encapsulate = ctypes.c_ubyte(1)
pub_token = ctypes.c_ubyte(0)
priv_decapsulate = ctypes.c_ubyte(1)
priv_token = ctypes.c_ubyte(0)
priv_sensitive = ctypes.c_ubyte(0)
priv_extractable = ctypes.c_ubyte(0)

pub_tmpl = (CK_ATTRIBUTE * 3)()
_set_bool_attr(pub_tmpl[0], CKA_ENCAPSULATE, pub_encapsulate)
_set_ulong_attr(pub_tmpl[1], CKA_PARAMETER_SET, param_set)
_set_bool_attr(pub_tmpl[2], CKA_TOKEN, pub_token)

priv_tmpl = (CK_ATTRIBUTE * 5)()
_set_bool_attr(priv_tmpl[0], CKA_DECAPSULATE, priv_decapsulate)
_set_ulong_attr(priv_tmpl[1], CKA_PARAMETER_SET, param_set)
_set_bool_attr(priv_tmpl[2], CKA_TOKEN, priv_token)
_set_bool_attr(priv_tmpl[3], CKA_SENSITIVE, priv_sensitive)
_set_bool_attr(priv_tmpl[4], CKA_EXTRACTABLE, priv_extractable)

keygen = CK_MECHANISM()
keygen.mechanism = CKM_ML_KEM_KEY_PAIR_GEN
keygen.pParameter = None
keygen.ulParameterLen = 0
pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh,
    ctypes.byref(keygen),
    ctypes.cast(pub_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    3,
    ctypes.cast(priv_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(pub),
    ctypes.byref(priv),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:ML-KEM keypair generation rejected: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)
"""


class TestKemTemplateCountOverflow:
    """Template-count overflow probes for v3.2 KEM output templates."""

    @pytest.mark.needs_function("C_EncapsulateKey")
    @pytest.mark.parametrize("count", _TEMPLATE_COUNTS)
    @pytest.mark.parametrize("op", _KEM_TEMPLATE_COUNT_OPS)
    def test_kem_output_template_count_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        count: int,
        op: str,
    ) -> None:
        """A huge KEM output-template count must not walk beyond one attribute."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("CKM_ML_KEM not supported")
        if "C_EncapsulateKey" not in rs.raw.available_function_names():
            pytest.skip("C_EncapsulateKey not available")
        if op == "C_DecapsulateKey" and "C_DecapsulateKey" not in rs.raw.available_function_names():
            pytest.skip("C_DecapsulateKey not available")

        preamble = _preamble(p11_config)
        if op == "C_EncapsulateKey":
            body = (
                _ML_KEM_KEYPAIR_FOR_COUNT_PROBE
                + f"""
try:
    from pkcs11_check.raw.types_std import (
        CK_ATTRIBUTE,
        CKA_CLASS,
        CKO_SECRET_KEY,
        CKM_ML_KEM,
        CK_OBJECT_HANDLE,
        CK_MECHANISM,
        CK_ULONG,
    )

    out_class = CK_ULONG(CKO_SECRET_KEY)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_CLASS
    attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(out_class)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_ML_KEM
    mech.pParameter = None
    mech.ulParameterLen = 0
    ct_len = CK_ULONG(0)
    secret = CK_OBJECT_HANDLE(0)
    rv = raw.C_EncapsulateKey(
        sh,
        ctypes.byref(mech),
        pub.value,
        ctypes.byref(attr),
        {count},
        None,
        ctypes.byref(ct_len),
        ctypes.byref(secret),
    )
    print(f"rv={{rv}}")
finally:
    if "secret" in locals() and secret.value:
        destroy_quietly(raw, sh, secret.value)
    destroy_quietly(raw, sh, pub.value)
    destroy_quietly(raw, sh, priv.value)
cleanup()
"""
            )
        elif op == "C_DecapsulateKey":
            body = (
                _ML_KEM_KEYPAIR_FOR_COUNT_PROBE
                + f"""
try:
    from pkcs11_check.raw.recipes import encapsulate_key
    from pkcs11_check.raw.types_std import (
        CK_ATTRIBUTE,
        CKA_CLASS,
        CKA_KEY_TYPE,
        CKA_VALUE_LEN,
        CKA_TOKEN,
        CKK_AES,
        CKM_ML_KEM,
        CKO_SECRET_KEY,
        CK_OBJECT_HANDLE,
        CK_MECHANISM,
        CK_ULONG,
    )

    try:
        setup_secret, ciphertext = encapsulate_key(
            raw,
            sh,
            pub.value,
            CKM_ML_KEM,
            attrs={{
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: 32,
                CKA_TOKEN: False,
            }},
        )
    except AssertionError as exc:
        print(f"SETUP_XFAIL:ML-KEM encapsulate rejected: {{exc}}")
        cleanup()
        raise SystemExit(0)

    out_class = CK_ULONG(CKO_SECRET_KEY)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_CLASS
    attr.pValue = ctypes.cast(ctypes.pointer(out_class), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(out_class)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_ML_KEM
    mech.pParameter = None
    mech.ulParameterLen = 0
    ct_buf = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    secret = CK_OBJECT_HANDLE(0)
    rv = raw.C_DecapsulateKey(
        sh,
        ctypes.byref(mech),
        priv.value,
        ctypes.byref(attr),
        {count},
        ct_buf,
        len(ciphertext),
        ctypes.byref(secret),
    )
    print(f"rv={{rv}}")
finally:
    if "secret" in locals() and secret.value:
        destroy_quietly(raw, sh, secret.value)
    if "setup_secret" in locals() and setup_secret:
        destroy_quietly(raw, sh, setup_secret)
    destroy_quietly(raw, sh, pub.value)
    destroy_quietly(raw, sh, priv.value)
cleanup()
"""
            )
        else:
            raise ValueError(f"Unhandled op: {op}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(ML-KEM output template_count={count:#x})",
        )


# ---------------------------------------------------------------------------
# TestKeyValueLenOverflow -- 2 cases
# ---------------------------------------------------------------------------

_KEYGEN_MECHS = [
    pytest.param("AES_KEY_GEN", "CKM_AES_KEY_GEN", id="aes"),
    pytest.param("DES3_KEY_GEN", "CKM_DES3_KEY_GEN", id="des3"),
]


class TestKeyValueLenOverflow:
    """Probe C_GenerateKey with CKA_VALUE_LEN = ULONG_MAX.

    Modules that allocate CKA_VALUE_LEN bytes without validation will
    attempt a near-SIZE_MAX allocation, crashing or hanging.
    """

    @pytest.mark.parametrize("mech_check,mech_name", _KEYGEN_MECHS)
    def test_key_value_len_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        mech_check: str,
        mech_name: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, {mech_name}, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_VALUE_LEN, CKA_TOKEN, CKA_ENCRYPT, CK_ULONG,
)

mech = CK_MECHANISM()
mech.mechanism = {mech_name}
mech.pParameter = None
mech.ulParameterLen = 0

val_len = CK_ULONG({_ULONG_MAX})
token_false = ctypes.c_ubyte(0)
enc_true = ctypes.c_ubyte(1)

attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = CKA_VALUE_LEN
attrs[0].pValue = ctypes.cast(ctypes.pointer(val_len), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(val_len)
attrs[1].type = CKA_TOKEN
attrs[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
attrs[1].ulValueLen = 1
attrs[2].type = CKA_ENCRYPT
attrs[2].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
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
        rc, stdout, stderr = run_with_coverage(script, timeout=5, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKey({mech_name}, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


# ---------------------------------------------------------------------------
# TestAttributeValueLenOverflow -- 3 cases
# ---------------------------------------------------------------------------

_ATTR_VALUE_OPS = [
    pytest.param("C_GetAttributeValue", id="get_attribute_value"),
    pytest.param("C_SetAttributeValue", id="set_attribute_value"),
    pytest.param("C_CreateObject", id="create_object"),
]


class TestAttributeValueLenOverflow:
    """Probe attribute functions with CK_ATTRIBUTE.ulValueLen = ULONG_MAX.

    Pass a CK_ATTRIBUTE whose pValue points to a small buffer but whose
    ulValueLen claims ULONG_MAX bytes.  Modules that memcpy(ulValueLen)
    from pValue will read or write far past the allocation.
    """

    @pytest.mark.parametrize("op", _ATTR_VALUE_OPS)
    def test_attribute_value_len_overflow(
        self,
        p11_config: Any,
        op: str,
    ) -> None:
        preamble = _preamble(p11_config)

        if op == "C_GetAttributeValue":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CKA_CLASS, CK_ULONG
# Small buffer, huge claimed length
buf = (ctypes.c_ubyte * 8)()
attr = CK_ATTRIBUTE()
attr.type = CKA_CLASS
attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
attr.ulValueLen = {_ULONG_MAX}
# Object handle 0 -- module may reject handle before reading attr
rv = raw.C_GetAttributeValue(sh, 0, ctypes.pointer(attr), 1)
print(f"rv={{rv}}")
cleanup()
"""
        elif op == "C_SetAttributeValue":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CKA_TOKEN
buf = (ctypes.c_ubyte * 8)()
attr = CK_ATTRIBUTE()
attr.type = CKA_TOKEN
attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
attr.ulValueLen = {_ULONG_MAX}
rv = raw.C_SetAttributeValue(sh, 0, ctypes.pointer(attr), 1)
print(f"rv={{rv}}")
cleanup()
"""
        elif op == "C_CreateObject":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CKA_CLASS, CK_OBJECT_HANDLE,
)
buf = (ctypes.c_ubyte * 8)()
attr = CK_ATTRIBUTE()
attr.type = CKA_CLASS
attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
attr.ulValueLen = {_ULONG_MAX}
handle = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(sh, ctypes.pointer(attr), 1, ctypes.byref(handle))
print(f"rv={{rv}}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled op: {op}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(ulValueLen={_ULONG_MAX:#x})",
        )


# ---------------------------------------------------------------------------
# TestGenerateKeyPairCountOverflow -- 2 cases
# ---------------------------------------------------------------------------

_KEYPAIR_COUNT_CASES = [
    pytest.param("pub", id="pub_template_overflow"),
    pytest.param("priv", id="priv_template_overflow"),
]


class TestGenerateKeyPairCountOverflow:
    """Probe C_GenerateKeyPair with ULONG_MAX template count.

    Pass one real attribute in the pub/priv template but claim ULONG_MAX
    as the count for one of them.  Modules that iterate
    count * sizeof(CK_ATTRIBUTE) bytes will overflow.
    """

    @pytest.mark.parametrize("which", _KEYPAIR_COUNT_CASES)
    def test_generate_key_pair_count_overflow(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        which: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        preamble = _preamble(p11_config)

        if which == "pub":
            pub_count = _ULONG_MAX
            priv_count = 1
        else:
            pub_count = 1
            priv_count = _ULONG_MAX

        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_TOKEN, CK_ULONG,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
mech.pParameter = None
mech.ulParameterLen = 0

# 1 real attribute in each template
token_false = ctypes.c_ubyte(0)

pub_attr = CK_ATTRIBUTE()
pub_attr.type = CKA_TOKEN
pub_attr.pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
pub_attr.ulValueLen = 1

priv_token = ctypes.c_ubyte(0)
priv_attr = CK_ATTRIBUTE()
priv_attr.type = CKA_TOKEN
priv_attr.pValue = ctypes.cast(ctypes.pointer(priv_token), ctypes.c_void_p)
priv_attr.ulValueLen = 1

pub_h = CK_OBJECT_HANDLE(0)
priv_h = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh, ctypes.byref(mech),
    ctypes.byref(pub_attr), {pub_count},
    ctypes.byref(priv_attr), {priv_count},
    ctypes.byref(pub_h), ctypes.byref(priv_h),
)
print(f"rv={{rv}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"C_GenerateKeyPair(pub_count={pub_count:#x}, priv_count={priv_count:#x})"),
        )
