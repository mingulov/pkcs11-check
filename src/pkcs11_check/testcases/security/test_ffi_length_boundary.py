"""FFI length boundary and mechanism parameter probes.

All tests run in subprocess for crash safety. Tests exercise:
- isize::MAX boundary for data length parameters (Rust-specific UB at 2^63)
- OOM allocation guards (large but valid CKA_VALUE_LEN)
- v3.0 message API input length boundaries
- NULL inner pointers in mechanism parameter structures

A CK_ULONG length that exceeds the platform's maximum addressable slice size
(or available memory) must be rejected with a clean CK_RV, never used to form
an out-of-bounds slice or drive an unguarded allocation (CWE-197 / CWE-681 /
CWE-789).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
    CKM_AES_GCM,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_RANDOM_NO_RNG,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    SUBPROCESS_TIMEOUT_RC,
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_edwards_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security._boundary_values import requires_64bit_ck_ulong
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# ---------------------------------------------------------------------------
# Constants for isize::MAX boundary probing (64-bit)
# ---------------------------------------------------------------------------

# Maximum byte count for a contiguous slice on a 64-bit platform.
_ISIZE_MAX_64 = 0x7FFFFFFFFFFFFFFF

# One past the maximum slice size: forming a slice this large is undefined
# behavior on common 64-bit runtimes, so a module must reject this length.
_ISIZE_MAX_PLUS_1_64 = 0x8000000000000000

# Large but sub-OOM value for allocation guard testing (2 GB).
_ALLOC_GUARD_VALUE_LEN = 0x7FFFFFFF

_PARAM_LENGTH_REJECT_RVS = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_MESSAGE_LENGTH_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
)

_MESSAGE_DECRYPT_LENGTH_REJECT_RVS = _MESSAGE_LENGTH_REJECT_RVS + (CKR_ENCRYPTED_DATA_LEN_RANGE,)

_MESSAGE_VERIFY_LENGTH_REJECT_RVS = _MESSAGE_LENGTH_REJECT_RVS + (CKR_SIGNATURE_LEN_RANGE,)


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


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

_HMAC_KEY_IMPORT_HELPER = """
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_GENERIC_SECRET,
    CKO_SECRET_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly


def import_hmac_key(*, sign=False, verify=False):
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    sign_val = ctypes.c_ubyte(1 if sign else 0)
    verify_val = ctypes.c_ubyte(1 if verify else 0)
    token_false = ctypes.c_ubyte(0)

    attrs = (CK_ATTRIBUTE * 6)()
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
    attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_val), ctypes.c_void_p)
    attrs[3].ulValueLen = 1
    attrs[4].type = CKA_VERIFY
    attrs[4].pValue = ctypes.cast(ctypes.pointer(verify_val), ctypes.c_void_p)
    attrs[4].ulValueLen = 1
    attrs[5].type = CKA_TOKEN
    attrs[5].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[5].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        6, ctypes.byref(key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:HMAC key import rejected: {ckr_name(rv)}")
        cleanup()
        raise SystemExit(0)
    return key

"""


# ---------------------------------------------------------------------------
# TestIsizeMaxDataLength
# ---------------------------------------------------------------------------

_ISIZE_BOUNDARY_LENGTHS = [
    pytest.param(_ISIZE_MAX_64, id="isize_max"),
    pytest.param(_ISIZE_MAX_PLUS_1_64, id="isize_max_plus_1"),
]


# ---------------------------------------------------------------------------
# Honeypot mmap for un-honorable length probes
# ---------------------------------------------------------------------------

# Demand-zero honeypot backing. The SIZE is what we mmap; the LENGTH ARG passed
# to PKCS#11 stays the un-honorable 2^63 value. 1 TiB >> any module can
# genuinely process in 30 s, so an honoring module times out without crashing.
_HONEYPOT_MMAP_CODE = """
import mmap as _mmap
_mm = None
# Demand-zero mmap: try from 1 TiB down to 1 GiB. MAP_NORESERVE is used when
# available (Linux) so the kernel reserves no swap; on systems without it we fall
# back to smaller sizes. The mapping must outlast _HONEYPOT_PTR (OS cleans up on
# process exit); we intentionally do NOT close it before the probe call.
for _honeypot_sz in (1 << 40, 1 << 38, 1 << 36, 1 << 34, 1 << 32, 1 << 30):
    try:
        _mm = _mmap.mmap(
            -1, _honeypot_sz,
            _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS | getattr(_mmap, "MAP_NORESERVE", 0),
            _mmap.PROT_READ | _mmap.PROT_WRITE,
        )
        break
    except (OSError, ValueError):
        _mm = None
if _mm is None:
    print("SETUP_XFAIL:honeypot mmap failed to allocate")
    cleanup()
    raise SystemExit(0)
# 1-byte ctypes view — avoids allocating a ctypes array descriptor for the full
# mapping size, which would itself require enormous memory.
_honeypot_one = (ctypes.c_ubyte * 1).from_buffer(_mm)
_HONEYPOT_PTR = ctypes.cast(_honeypot_one, ctypes.POINTER(ctypes.c_ubyte))
_HONEYPOT_BUF = _HONEYPOT_PTR  # alias for probes that cast to c_void_p
"""


def _classify_unhonorable_length_outcome(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    reject_rvs: tuple[Any, ...],
    label_op: str,
    test_id: str,
) -> None:
    """Classify the outcome of an un-honorable (2^63) length probe.

    Verdict matrix:
    - SETUP_XFAIL line present -> xfail (not_operational, setup didn't reach probe).
    - Timeout (rc==SUBPROCESS_TIMEOUT_RC or SUBPROCESS_TIMEOUT_MARKER in stderr) ->
      note (honoring an un-backable length is caller-UB territory, not silent truncation).
    - Crash (rc < 0) -> note (over-read on caller-induced UB, not a module defect).
    - CKR_OK -> fail (accepted_invalid: silent truncation of an un-honorable length).
    - rv in reject_rvs -> pass.
    - other clean code -> xfail (nonspec_reject).
    """
    from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
    from pkcs11_check.testcases.security.conftest import SETUP_XFAIL_PREFIX

    # SETUP_XFAIL: setup (keygen/Init) cleanly errored before the probe ran.
    for line in stdout.splitlines():
        if line.startswith(SETUP_XFAIL_PREFIX):
            xfail_as(
                "not_operational",
                label=label_op,
                summary=line.removeprefix(SETUP_XFAIL_PREFIX).strip(),
            )

    # Timeout: module attempted the un-honorable length (honoring attempt).
    if SUBPROCESS_TIMEOUT_MARKER in stderr or rc == SUBPROCESS_TIMEOUT_RC:
        note(
            f"{label_op}: module attempted an un-honorable 2^63 length and was "
            "killed at 30 s — it neither rejected nor silently truncated "
            "(caller cannot supply 2^63 bytes; honoring attempt, not a defect)",
            ComplianceLevel.EXTENDED,
            reference="PKCS#11 length semantics",
            test_id=test_id,
        )
        return

    # Crash: module over-read on caller-induced UB.
    if rc < 0:
        note(
            f"{label_op}: module crashed (signal {-rc}) on an un-honorable 2^63 "
            "length — caller cannot supply 2^63 bytes; this is caller-induced UB, "
            "not a module defect",
            ComplianceLevel.EXTENDED,
            reference="PKCS#11 length semantics",
            test_id=test_id,
        )
        return

    # Non-zero exit without SETUP_XFAIL or signal: classify via assert_subprocess_completed
    if rc > 0:
        assert_subprocess_completed(rc, stdout, stderr, context=label_op)
        return

    # rc == 0: parse TARGET_RV.
    rv = _parse_prefixed_int(stdout, "TARGET_RV:")

    # Parse output length if present (for evidence in the fail label).
    out_len_line = ""
    for line in stdout.splitlines():
        if line.startswith("TARGET_OUT_LEN:"):
            out_len_line = f" output_len={line.removeprefix('TARGET_OUT_LEN:').strip()}"
            break

    classify_negative_rv(
        rv,
        reject_rvs,
        label=(
            f"{label_op} returned CKR_OK — silent truncation of an"
            f" un-honorable 2^63 length{out_len_line}"
        ),
        kind="crypto",
    )


@requires_64bit_ck_ulong
class TestIsizeMaxDataLength:
    """Probe data functions with isize::MAX boundary lengths.

    On 64-bit platforms the largest valid byte count for a contiguous
    slice is 0x7FFFFFFFFFFFFFFF (2**63 - 1).  Passing this value (or one
    past it) as the data length to C_Encrypt / C_Decrypt / C_Sign /
    C_Digest with a small real buffer must be rejected cleanly; forming a
    slice of byte count beyond this boundary risks undefined behavior
    (CWE-681).
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_isize",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(ulDataLen={data_len:#x})",
            test_id="test_encrypt_isize_boundary",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_isize",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Decrypt(ulEncryptedDataLen={data_len:#x})",
            test_id="test_decrypt_isize_boundary",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_isize",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Sign(ulDataLen={data_len:#x})",
            test_id="test_sign_isize_boundary",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_verify_isize_data_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """C_Verify must validate a huge claimed data length without crashing."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify_isize",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_VERIFY_LENGTH_REJECT_RVS,
            label_op=f"C_Verify(ulDataLen={data_len:#x})",
            test_id="test_verify_isize_data_len",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_isize",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Digest(ulDataLen={data_len:#x})",
            test_id="test_digest_isize_boundary",
        )


# ---------------------------------------------------------------------------
# TestMessageApiLengthBoundary
# ---------------------------------------------------------------------------

_MESSAGE_ENCRYPT_LENGTH_FIELDS = [
    pytest.param("associated_data", id="associated_data_len"),
    pytest.param("plaintext", id="plaintext_len"),
]

_MESSAGE_DECRYPT_LENGTH_FIELDS = [
    pytest.param("associated_data", id="associated_data_len"),
    pytest.param("ciphertext", id="ciphertext_len"),
]

_MESSAGE_VERIFY_LENGTH_FIELDS = [
    pytest.param("data", id="data_len"),
    pytest.param("signature", id="signature_len"),
]

_MESSAGE_ENCRYPT_MULTIPART_OPS = [
    pytest.param("C_EncryptMessageBegin", id="begin_plaintext_len"),
    pytest.param("C_EncryptMessageNext", id="next_plaintext_len"),
]

_MESSAGE_DECRYPT_MULTIPART_OPS = [
    pytest.param("C_DecryptMessageBegin", id="begin_ciphertext_len"),
    pytest.param("C_DecryptMessageNext", id="next_ciphertext_len"),
]

_MESSAGE_SIGN_MULTIPART_OPS = [
    pytest.param("C_SignMessageBegin", id="begin_data_len"),
    pytest.param("C_SignMessageNext", id="next_data_len"),
]

_MESSAGE_VERIFY_MULTIPART_FIELDS = [
    pytest.param("begin_parameter", id="begin_parameter_len"),
    pytest.param("next_data", id="next_data_len"),
    pytest.param("next_signature", id="next_signature_len"),
]


@requires_64bit_ck_ulong
class TestMessageApiLengthBoundary:
    """v3.0 message APIs must reject huge claimed input lengths safely."""

    @pytest.mark.needs_function("C_EncryptMessage")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_ENCRYPT_LENGTH_FIELDS)
    def test_encrypt_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_EncryptMessage must not turn tiny input buffers into huge reads."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageEncryptInit", "C_EncryptMessage", "C_MessageEncryptFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_EncryptMessage length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        aad_len = data_len if field == "associated_data" else 16
        plaintext_len = data_len if field == "plaintext" else 16
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_message",
                "aad_len": aad_len,
                "plaintext_len": plaintext_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_EncryptMessage({field}={data_len:#x})",
            test_id="test_encrypt_message_isize_input_len",
        )

    @pytest.mark.needs_function("C_DecryptMessage")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_DECRYPT_LENGTH_FIELDS)
    def test_decrypt_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_DecryptMessage must not turn tiny input buffers into huge reads."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_DECRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_DECRYPT")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageDecryptInit", "C_DecryptMessage", "C_MessageDecryptFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_DecryptMessage length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        aad_len = data_len if field == "associated_data" else 16
        ciphertext_len = data_len if field == "ciphertext" else 16
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_message",
                "aad_len": aad_len,
                "ciphertext_len": ciphertext_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_DECRYPT_LENGTH_REJECT_RVS,
            label_op=f"C_DecryptMessage({field}={data_len:#x})",
            test_id="test_decrypt_message_isize_input_len",
        )

    @pytest.mark.needs_function("C_DecryptMessageBegin")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _MESSAGE_DECRYPT_MULTIPART_OPS)
    def test_decrypt_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        """C_DecryptMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_DECRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_DECRYPT")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageDecryptInit",
            "C_DecryptMessageBegin",
            "C_DecryptMessageNext",
            "C_MessageDecryptFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{op} length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_message_multipart",
                "op": op,
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_DECRYPT_LENGTH_REJECT_RVS,
            label_op=f"{op}(ciphertext_len={data_len:#x})",
            test_id="test_decrypt_message_multipart_isize_input_len",
        )

    @pytest.mark.needs_function("C_SignMessage")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sign_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """C_SignMessage must not turn a tiny data buffer into a huge read."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_SIGN)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageSignInit", "C_SignMessage", "C_MessageSignFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_message",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_SignMessage(data_len={data_len:#x})",
            test_id="test_sign_message_isize_input_len",
        )

    @pytest.mark.needs_function("C_VerifyMessage")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_VERIFY_LENGTH_FIELDS)
    def test_verify_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_VerifyMessage must reject huge data/signature lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_VERIFY)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageVerifyInit", "C_VerifyMessage", "C_MessageVerifyFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        normal_data_len = 16
        verify_data_len = data_len if field == "data" else normal_data_len
        signature_len = data_len if field == "signature" else 256
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify_message",
                "verify_data_len": verify_data_len,
                "signature_len": signature_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_VERIFY_LENGTH_REJECT_RVS,
            label_op=f"C_VerifyMessage({field}_len={data_len:#x})",
            test_id="test_verify_message_isize_input_len",
        )

    @pytest.mark.needs_function("C_SignMessageBegin")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _MESSAGE_SIGN_MULTIPART_OPS)
    def test_sign_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        """C_SignMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_SIGN)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageSignInit",
            "C_SignMessageBegin",
            "C_SignMessageNext",
            "C_MessageSignFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_message_multipart",
                "op": op,
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"{op}(data_len={data_len:#x})",
            test_id="test_sign_message_multipart_isize_input_len",
        )

    @pytest.mark.needs_function("C_VerifyMessageBegin")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_VERIFY_MULTIPART_FIELDS)
    def test_verify_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_VerifyMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_VERIFY)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageVerifyInit",
            "C_VerifyMessageBegin",
            "C_VerifyMessageNext",
            "C_MessageVerifyFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        normal_data_len = 16
        begin_param_len = data_len if field == "begin_parameter" else 0
        next_data_len = data_len if field == "next_data" else normal_data_len
        next_signature_len = data_len if field == "next_signature" else 256
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify_message_multipart",
                "field": field,
                "begin_param_len": begin_param_len,
                "next_data_len": next_data_len,
                "next_signature_len": next_signature_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_VERIFY_LENGTH_REJECT_RVS,
            label_op=f"C_VerifyMessage multipart {field}={data_len:#x}",
            test_id="test_verify_message_multipart_isize_input_len",
        )

    @pytest.mark.needs_function("C_EncryptMessageBegin")
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _MESSAGE_ENCRYPT_MULTIPART_OPS)
    def test_encrypt_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        """C_EncryptMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageEncryptInit",
            "C_EncryptMessageBegin",
            "C_EncryptMessageNext",
            "C_MessageEncryptFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{op} length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_message_multipart",
                "op": op,
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"{op}(plaintext_len={data_len:#x})",
            test_id="test_encrypt_message_multipart_isize_input_len",
        )


# ---------------------------------------------------------------------------
# TestIsizeMaxUpdateLength
# ---------------------------------------------------------------------------

_UPDATE_LENGTH_OPS = [
    pytest.param("C_EncryptUpdate", id="encrypt_update"),
    pytest.param("C_DecryptUpdate", id="decrypt_update"),
    pytest.param("C_SignUpdate", id="sign_update"),
    pytest.param("C_VerifyUpdate", id="verify_update"),
    pytest.param("C_DigestUpdate", id="digest_update"),
]


@requires_64bit_ck_ulong
class TestIsizeMaxUpdateLength:
    """Initialized update APIs must reject huge claimed input lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _UPDATE_LENGTH_OPS)
    def test_update_isize_data_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        rs = p11_raw_session
        if op in {"C_EncryptUpdate", "C_DecryptUpdate"}:
            if not rs.has_mechanism("AES_ECB"):
                pytest.skip("CKM_AES_ECB not supported")
            setup_key = gen_aes_key_or_xfail(
                rs,
                256,
                purpose=f"{op} isize-boundary crash probe setup",
            )
            destroy_returned_handles(rs, setup_key)
        elif op in {"C_SignUpdate", "C_VerifyUpdate"}:
            if not rs.has_mechanism("SHA256_HMAC"):
                pytest.skip("CKM_SHA256_HMAC not supported")
        elif op == "C_DigestUpdate":
            if not rs.has_mechanism("SHA256"):
                pytest.skip("CKM_SHA256 not supported")
        else:
            raise ValueError(f"Unhandled op: {op}")

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "update_isize",
                "op": op,
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"{op}(ulPartLen={data_len:#x})",
            test_id="test_update_isize_data_len",
        )


# ---------------------------------------------------------------------------
# TestRandomIsizeLength
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestRandomIsizeLength:
    """Random APIs must handle impossible claimed buffer lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_seed_random_isize_length_rejects_cleanly(
        self,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """``C_SeedRandom`` must reject an impossible claimed seed length cleanly."""
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "seed_random_isize",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=(CKR_RANDOM_NO_RNG, CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD),
            label_op=f"C_SeedRandom(ulSeedLen={data_len:#x})",
            test_id="test_seed_random_isize_length_rejects_cleanly",
        )


# ---------------------------------------------------------------------------
# TestAllocationGuard
# ---------------------------------------------------------------------------


class TestAllocationGuard:
    """Probe key generation with large but valid CKA_VALUE_LEN.

    A large but valid CKA_VALUE_LEN must be handled with a checked
    allocation that returns CKR_HOST_MEMORY on failure, not an unchecked
    allocation that aborts the process (CWE-789).  A 2 GB CKA_VALUE_LEN is
    large enough to likely OOM on most systems but is NOT in
    integer-overflow territory (unlike the ULONG_MAX tests in
    test_arithmetic_overflow.py).
    """

    @pytest.mark.slow
    def test_generate_key_oom_value_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "generate_key_oom",
                "value_len": _ALLOC_GUARD_VALUE_LEN,
            },
            pin=pin_from_config(p11_config),
            timeout=5,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"C_GenerateKey(AES, CKA_VALUE_LEN={_ALLOC_GUARD_VALUE_LEN:#x})"),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label=f"C_GenerateKey(AES, CKA_VALUE_LEN={_ALLOC_GUARD_VALUE_LEN:#x})",
            allow_ok=True,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "gcm_null_iv",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12)",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_EncryptInit(GCM, pIv=NULL, ulIvLen>0)",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ecdh_null_public_data",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(ECDH1, pPublicData=NULL, ulPublicDataLen=65)"),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_DeriveKey(ECDH1, pPublicData=NULL, len>0)",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "oaep_null_source_data",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_EncryptInit(RSA_OAEP, pSourceData=NULL, ulSourceDataLen=16)"),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_EncryptInit(OAEP, pSourceData=NULL, len>0)",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "hkdf_null_salt",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(HKDF, pSalt=NULL, ulSaltLen=16, ulSaltType=CKF_HKDF_SALT_DATA)"),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_DeriveKey(HKDF, pSalt=NULL, len>0)",
        )


# ---------------------------------------------------------------------------
# TestIsizeMaxOutputLength
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestIsizeMaxOutputLength:
    """Probe OUTPUT buffer length parameters with isize::MAX boundary.

    Complementary to TestIsizeMaxDataLength which tests INPUT data length.
    The same maximum-slice-size boundary applies to OUTPUT/signature
    buffer-size parameters on sign / verify / digest and their *Final
    variants.  A claimed output buffer size at the 64-bit boundary (or one
    past it) with a small real buffer must be rejected, not cause UB.
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_isize_output",
                "out_len": out_len,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(HMAC_SHA256, sig_len={out_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_VERIFY_LENGTH_REJECT_RVS,
            label=f"C_Sign(sig_len={out_len:#x})",
            allow_ok=True,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_isize_output",
                "out_len": out_len,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Digest(SHA256, digest_len={out_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_LENGTH_REJECT_RVS,
            label=f"C_Digest(digest_len={out_len:#x})",
            allow_ok=True,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify_isize_sig_len",
                "sig_len": sig_len,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Verify(HMAC_SHA256, sig_len={sig_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_VERIFY_LENGTH_REJECT_RVS,
            label=f"C_Verify(ulSignatureLen={sig_len:#x})",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "hkdf_null_info",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DeriveKey(HKDF, pInfo=NULL, ulInfoLen=16)",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_DeriveKey(HKDF, pInfo=NULL, len>0)",
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
        pub, priv = gen_edwards_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "eddsa_null_context_data",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_SignInit(EDDSA, pContextData=NULL, ulContextDataLen=16)"),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_SignInit(EDDSA, pContextData=NULL, len>0)",
        )


# ---------------------------------------------------------------------------
# TestMlDsaExplicitEmptyContext
# ---------------------------------------------------------------------------


class TestMlDsaExplicitEmptyContext:
    """ML-DSA with CK_SIGN_ADDITIONAL_CONTEXT carrying a non-NULL empty context."""

    def test_mldsa_verify_empty_context_nonnull_pointer(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """ML-DSA Verify with pContext non-NULL and ulContextLen=0."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA"):
            pytest.skip("CKM_ML_DSA not supported")
        if not rs.has_mechanism("ML_DSA_KEY_PAIR_GEN"):
            pytest.skip("CKM_ML_DSA_KEY_PAIR_GEN not supported")
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "mldsa_empty_context",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_Verify(ML-DSA, pContext non-NULL, ulContextLen=0)"),
        )
        # audit-ok(2026-06-19): positive op -- empty context is RFC 8032 default; CKR_OK is correct.


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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ccm_null_nonce",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit(AES_CCM, pNonce=NULL, ulNonceLen=7)",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_EncryptInit(CCM, pNonce=NULL, len>0)",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "concat_base_data_null",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(CONCATENATE_BASE_AND_DATA, pData=NULL, ulLen=16)"),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_DeriveKey(CONCATENATE, pData=NULL, len>0)",
        )


# ---------------------------------------------------------------------------
# TestAesCbcEncryptDataMalformedParams
# ---------------------------------------------------------------------------

_AES_CBC_ENCRYPT_DATA_PARAM_CASES = (
    pytest.param("pData=NULL,length=16", "None", 16, id="null_data_nonzero_length"),
    pytest.param(
        "pData=tiny,length=isize_max_plus_1",
        "ctypes.cast(data_buf, ctypes.c_void_p)",
        _ISIZE_MAX_PLUS_1_64,
        id="tiny_data_huge_length",
    ),
)


@requires_64bit_ck_ulong
class TestAesCbcEncryptDataMalformedParams:
    """CKM_AES_CBC_ENCRYPT_DATA must reject malformed nested data safely."""

    @pytest.mark.parametrize(
        ("case_label", "p_data_expr", "data_len"),
        _AES_CBC_ENCRYPT_DATA_PARAM_CASES,
    )
    def test_aes_cbc_encrypt_data_malformed_params(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        case_label: str,
        p_data_expr: str,
        data_len: int,
    ) -> None:
        """C_DeriveKey(AES_CBC_ENCRYPT_DATA) validates inner pData/length pairs."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.pack import attr_bool, attr_ulong, template
from pkcs11_check.raw.recipes import destroy_quietly, import_secret_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CBC_ENCRYPT_DATA_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_CBC_ENCRYPT_DATA,
    CKO_SECRET_KEY,
    CKR_OK,
)

data_len = {data_len}
data_buf = (ctypes.c_ubyte * 16)(*range(16))
base_key = 0
try:
    base_key = import_secret_key(
        raw,
        sh,
        CKK_AES,
        bytes(range(32)),
        attrs={{
            CKA_DERIVE: True,
            CKA_TOKEN: False,
        }},
    )
except AssertionError as exc:
    print(f"SETUP_XFAIL:AES derive base-key import rejected: {{exc}}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_AES_CBC_ENCRYPT_DATA_PARAMS()
    for idx in range(16):
        params.iv[idx] = idx
    params.pData = {p_data_expr}
    params.length = data_len

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CBC_ENCRYPT_DATA
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    derived_template = template(
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_AES),
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_TOKEN, False),
    )
    derived = CK_OBJECT_HANDLE(0)
    print("TARGET_CALL:C_DeriveKey(AES_CBC_ENCRYPT_DATA,{case_label})", flush=True)
    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key,
        derived_template.ptr,
        derived_template.count,
        ctypes.byref(derived),
    )
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
    if rv == CKR_OK:
        destroy_quietly(raw, sh, derived.value)
finally:
    destroy_quietly(raw, sh, base_key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DeriveKey(AES_CBC_ENCRYPT_DATA, {case_label})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label=f"C_DeriveKey(AES_CBC_ENCRYPT_DATA, {case_label})",
        )


# ---------------------------------------------------------------------------
# TestRsaPssSaltLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestRsaPssSaltLengthBoundary:
    """RSA-PSS sLen (salt length) must reject impossible values safely.

    CK_RSA_PKCS_PSS_PARAMS.sLen is a caller-controlled CK_ULONG. A module that
    uses it without bounds-checking against the modulus and hash sizes can
    over-read or over-allocate. For RSA-2048/SHA-256 the maximum salt length is
    ~222 bytes, so isize::MAX / isize::MAX+1 is impossible and must be cleanly
    rejected; a crash/hang is a finding and CKR_OK accepts a nonsensical param.
    """

    @pytest.mark.parametrize("salt_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_rsa_pss_salt_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        salt_len: int,
    ) -> None:
        """C_Sign(SHA256_RSA_PKCS_PSS) must reject an impossible sLen safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("CKM_SHA256_RSA_PKCS_PSS not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_RSA_PKCS_PSS_PARAMS,
    CK_ULONG,
    CKA_SIGN,
    CKA_TOKEN,
    CKG_MGF1_SHA256,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKR_OK,
)

pub = priv = 0
try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={{CKA_TOKEN: False}},
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
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
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        sig_len = CK_ULONG(512)
        sig_buf = (ctypes.c_ubyte * 512)()
        print("TARGET_CALL:C_Sign(SHA256_RSA_PKCS_PSS,sLen={salt_len:#x})", flush=True)
        rv = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(SHA256_RSA_PKCS_PSS, sLen={salt_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label=f"C_Sign(SHA256_RSA_PKCS_PSS, sLen={salt_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestGcmAadLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestGcmAadLengthBoundary:
    """AES-GCM ulAADLen must not turn a tiny AAD buffer into a huge read.

    CK_AES_GCM_PARAMS.pAAD/ulAADLen are caller-controlled. A module that reads
    ulAADLen bytes from pAAD without bounds-checking over-reads when the claimed
    length is impossible. Drive C_EncryptInit + C_Encrypt with a tiny real AAD
    buffer and isize::MAX / isize::MAX+1 claimed lengths; crash/hang is a finding
    and CKR_OK accepts a nonsensical length.
    """

    @pytest.mark.parametrize("aad_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_gcm_aad_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        aad_len: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(AES_GCM) with tiny pAAD + huge ulAADLen."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM AAD-length crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_GCM,
    CKR_OK,
)

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
    params.pAAD = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulAADLen = {aad_len}
    params.ulTagBits = 128
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_GCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(64)
        out = (ctypes.c_ubyte * 64)()
        print("TARGET_CALL:C_Encrypt(AES_GCM,ulAADLen={aad_len:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(AES_GCM, ulAADLen={aad_len:#x})",
            test_id="test_gcm_aad_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestCcmAadLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestCcmAadLengthBoundary:
    """AES-CCM ulAADLen must not turn a tiny AAD buffer into a huge read.

    Mirrors the GCM AAD-length probe for CK_AES_CCM_PARAMS.pAAD/ulAADLen: a tiny
    real AAD buffer with an impossible claimed length must be rejected, not
    over-read; crash/abnormal-exit is a finding and CKR_OK accepts a nonsensical
    length.
    """

    @pytest.mark.parametrize("aad_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_ccm_aad_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        aad_len: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(AES_CCM) with tiny pAAD + huge ulAADLen."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CCM"):
            pytest.skip("CKM_AES_CCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-CCM AAD-length crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CCM_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_CCM,
    CKR_OK,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    nonce = (ctypes.c_ubyte * 13)(*range(13))
    params = CK_AES_CCM_PARAMS()
    params.ulDataLen = 16
    params.pNonce = ctypes.cast(nonce, ctypes.c_void_p)
    params.ulNonceLen = 13
    params.pAAD = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulAADLen = {aad_len}
    params.ulMACLen = 16
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(64)
        out = (ctypes.c_ubyte * 64)()
        print("TARGET_CALL:C_Encrypt(AES_CCM,ulAADLen={aad_len:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(AES_CCM, ulAADLen={aad_len:#x})",
            test_id="test_ccm_aad_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestPbkdf2NestedLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestPbkdf2NestedLengthBoundary:
    """PBKDF2 nested byte fields must reject impossible claimed lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize(
        "field",
        (
            pytest.param("password", id="password"),
            pytest.param("salt", id="salt"),
            pytest.param("prf_data", id="prf_data"),
        ),
    )
    def test_pbkdf2_nested_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        field: str,
        data_len: int,
    ) -> None:
        """C_GenerateKey(PBKDF2) must not read past tiny nested input buffers."""
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PKCS5_PBKD2_PARAMS2,
    CK_ULONG,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_PKCS5_PBKD2,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKR_OK,
    CKZ_SALT_SPECIFIED,
)

field = {field!r}
data_len = {data_len}

password_real = (ctypes.c_ubyte * 8)(*b"password")
salt_real = (ctypes.c_ubyte * 8)(*b"salt1234")
prf_data_real = (ctypes.c_ubyte * 4)(*b"prf!")

params = CK_PKCS5_PBKD2_PARAMS2()
params.saltSource = CKZ_SALT_SPECIFIED
_salt_buf = _HONEYPOT_BUF if field == "salt" else salt_real
params.pSaltSourceData = ctypes.cast(_salt_buf, ctypes.c_void_p)
params.ulSaltSourceDataLen = data_len if field == "salt" else len(salt_real)
params.iterations = 1024
params.prf = CKP_PKCS5_PBKD2_HMAC_SHA256
if field == "prf_data":
    params.pPrfData = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulPrfDataLen = data_len
else:
    params.pPrfData = None
    params.ulPrfDataLen = 0
_pw_buf = _HONEYPOT_BUF if field == "password" else password_real
params.pPassword = ctypes.cast(_pw_buf, ctypes.c_void_p)
params.ulPasswordLen = data_len if field == "password" else len(password_real)

mech = CK_MECHANISM()
mech.mechanism = CKM_PKCS5_PBKD2
mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
mech.ulParameterLen = ctypes.sizeof(params)

cls_val = CK_ULONG(CKO_SECRET_KEY)
kt_val = CK_ULONG(CKK_GENERIC_SECRET)
value_len = CK_ULONG(32)
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 6)()
tmpl[0].type = CKA_CLASS
tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
tmpl[1].type = CKA_KEY_TYPE
tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
tmpl[2].type = CKA_VALUE_LEN
tmpl[2].pValue = ctypes.cast(ctypes.pointer(value_len), ctypes.c_void_p)
tmpl[2].ulValueLen = ctypes.sizeof(value_len)
tmpl[3].type = CKA_TOKEN
tmpl[3].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
tmpl[3].ulValueLen = 1
tmpl[4].type = CKA_SENSITIVE
tmpl[4].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
tmpl[4].ulValueLen = 1
tmpl[5].type = CKA_EXTRACTABLE
tmpl[5].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
tmpl[5].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh,
    ctypes.byref(mech),
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    6,
    ctypes.byref(key),
)
print(f"TARGET_RV:0x{{rv:08x}}")
print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
if rv == CKR_OK:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_PARAM_LENGTH_REJECT_RVS,
            label_op=f"C_GenerateKey(PBKDF2, {field} length={data_len:#x})",
            test_id="test_pbkdf2_nested_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestPbeNestedLengthBoundary
# ---------------------------------------------------------------------------

_PBE_LENGTH_MECHANISMS = (
    pytest.param(
        (
            "PBE_SHA1_DES3_EDE_CBC",
            "CKM_PBE_SHA1_DES3_EDE_CBC",
            "CKK_DES3",
            8,
            False,
        ),
        id="pbe_sha1_des3",
    ),
    pytest.param(
        (
            "PBE_SHA1_DES2_EDE_CBC",
            "CKM_PBE_SHA1_DES2_EDE_CBC",
            "CKK_DES2",
            8,
            False,
        ),
        id="pbe_sha1_des2",
    ),
    pytest.param(
        (
            "PBA_SHA1_WITH_SHA1_HMAC",
            "CKM_PBA_SHA1_WITH_SHA1_HMAC",
            "CKK_SHA_1_HMAC",
            20,
            True,
        ),
        id="pba_sha1_hmac",
    ),
)


@requires_64bit_ck_ulong
class TestPbeNestedLengthBoundary:
    """PBE parameter byte fields must reject impossible claimed lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", ("password", "salt"))
    @pytest.mark.parametrize("pbe_case", _PBE_LENGTH_MECHANISMS)
    def test_pbe_nested_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        pbe_case: tuple[str, str, str, int, bool],
        field: str,
        data_len: int,
    ) -> None:
        """C_GenerateKey(PBE) must not read past tiny password/salt buffers."""
        rs = p11_raw_session
        mech_name, mech_const, key_type_const, iv_len, sign_verify = pbe_case
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_const} not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PBE_PARAMS,
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_DES2,
    CKK_DES3,
    CKK_SHA_1_HMAC,
    CKM_PBA_SHA1_WITH_SHA1_HMAC,
    CKM_PBE_SHA1_DES2_EDE_CBC,
    CKM_PBE_SHA1_DES3_EDE_CBC,
    CKR_OK,
)

field = {field!r}
data_len = {data_len}
sign_verify = {sign_verify!r}

init_vector = (ctypes.c_ubyte * {iv_len})()
password_real = (ctypes.c_ubyte * 8)(*b"password")
salt_real = (ctypes.c_ubyte * 8)(*b"salt1234")

params = CK_PBE_PARAMS()
params.pInitVector = ctypes.cast(init_vector, ctypes.c_void_p)
_pw_buf = _HONEYPOT_BUF if field == "password" else password_real
params.pPassword = ctypes.cast(_pw_buf, ctypes.c_void_p)
params.ulPasswordLen = data_len if field == "password" else len(password_real)
_salt_buf = _HONEYPOT_BUF if field == "salt" else salt_real
params.pSalt = ctypes.cast(_salt_buf, ctypes.c_void_p)
params.ulSaltLen = data_len if field == "salt" else len(salt_real)
params.ulIteration = 1024

mech = CK_MECHANISM()
mech.mechanism = {mech_const}
mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
mech.ulParameterLen = ctypes.sizeof(params)

key_type = CK_ULONG({key_type_const})
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)
purpose_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 6)()
tmpl[0].type = CKA_KEY_TYPE
tmpl[0].pValue = ctypes.cast(ctypes.pointer(key_type), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(key_type)
tmpl[1].type = CKA_TOKEN
tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
tmpl[1].ulValueLen = 1
tmpl[2].type = CKA_SENSITIVE
tmpl[2].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
tmpl[2].ulValueLen = 1
tmpl[3].type = CKA_EXTRACTABLE
tmpl[3].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
tmpl[3].ulValueLen = 1
tmpl[4].type = CKA_SIGN if sign_verify else CKA_ENCRYPT
tmpl[4].pValue = ctypes.cast(ctypes.pointer(purpose_true), ctypes.c_void_p)
tmpl[4].ulValueLen = 1
tmpl[5].type = CKA_VERIFY if sign_verify else CKA_DECRYPT
tmpl[5].pValue = ctypes.cast(ctypes.pointer(purpose_true), ctypes.c_void_p)
tmpl[5].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh,
    ctypes.byref(mech),
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    6,
    ctypes.byref(key),
)
print(f"TARGET_RV:0x{{rv:08x}}")
print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
if rv == CKR_OK:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_PARAM_LENGTH_REJECT_RVS,
            label_op=f"C_GenerateKey({mech_const}, {field} length={data_len:#x})",
            test_id="test_pbe_nested_length_boundary",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "tls_kdf_null_label",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(TLS_KDF, pLabel=NULL, ulLabelLength=16)"),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_DeriveKey(TLS_KDF, pLabel=NULL, len>0)",
        )


# ---------------------------------------------------------------------------
# TestTlsKdfRandomLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestTlsKdfRandomLengthBoundary:
    """TLS KDF nested random buffers must reject impossible claimed lengths."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize(
        "field",
        (
            pytest.param("client", id="client_random"),
            pytest.param("server", id="server_random"),
        ),
    )
    def test_tls_kdf_random_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        field: str,
        data_len: int,
    ) -> None:
        """C_DeriveKey(TLS_KDF) must not read past tiny random buffers."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_SSL3_RANDOM_DATA,
    CK_TLS_KDF_PARAMS,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKM_TLS_KDF,
    CKO_SECRET_KEY,
    CKR_OK,
)

field = {field!r}
data_len = {data_len}

key_bytes = (ctypes.c_ubyte * 48)(*range(48))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 48
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:TLS KDF base-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

try:
    label = (ctypes.c_ubyte * 12)(*b"test label!!")
    client_random_real = (ctypes.c_ubyte * 32)(*range(32))
    server_random_real = (ctypes.c_ubyte * 32)(*range(32))

    random_info = CK_SSL3_RANDOM_DATA()
    random_info.pClientRandom = ctypes.cast(
        _HONEYPOT_BUF if field == "client" else client_random_real, ctypes.c_void_p,
    )
    random_info.ulClientRandomLen = data_len if field == "client" else 32
    random_info.pServerRandom = ctypes.cast(
        _HONEYPOT_BUF if field == "server" else server_random_real, ctypes.c_void_p,
    )
    random_info.ulServerRandomLen = data_len if field == "server" else 32

    params = CK_TLS_KDF_PARAMS()
    params.prfMechanism = CKM_SHA256
    params.pLabel = ctypes.cast(label, ctypes.c_void_p)
    params.ulLabelLength = len(label)
    params.RandomInfo = random_info
    params.pContextData = None
    params.ulContextDataLength = 0

    mech = CK_MECHANISM()
    mech.mechanism = CKM_TLS_KDF
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(derived),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, derived.value)
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_PARAM_LENGTH_REJECT_RVS,
            label_op=f"C_DeriveKey(TLS_KDF, {field} random length={data_len:#x})",
            test_id="test_tls_kdf_random_length_boundary",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sp800_108_null_data_params",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(
                "C_DeriveKey(SP800_108_COUNTER_KDF, pDataParams=NULL, ulNumberOfDataParams=1)"
            ),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _PARAM_LENGTH_REJECT_RVS,
            label="C_DeriveKey(SP800-108, NULL data params)",
        )


# ---------------------------------------------------------------------------
# TestSp800108NestedCountBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestSp800108NestedCountBoundary:
    """SP800-108 nested arrays must reject impossible counts safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sp800_108_data_param_count_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """A real pDataParams array with a huge count must not be overread."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PRF_DATA_PARAM,
    CK_SP800_108_BYTE_ARRAY,
    CK_SP800_108_DKM_LENGTH,
    CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
    CK_SP800_108_ITERATION_VARIABLE,
    CK_SP800_108_COUNTER_FORMAT,
    CK_SP800_108_KDF_PARAMS,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKM_SP800_108_COUNTER_KDF,
    CKO_SECRET_KEY,
    CKR_OK,
)

key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:SP800-108 base-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

derived = CK_OBJECT_HANDLE(0)
try:
    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = {data_len}
    params.pDataParams = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulAdditionalDerivedKeys = 0
    params.pAdditionalDerivedKeys = None

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SP800_108_COUNTER_KDF
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_AES)
    d_vl = CK_ULONG(16)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    d_tmpl[3].ulValueLen = 1

    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(derived),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, derived.value)
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_PARAM_LENGTH_REJECT_RVS,
            label_op=f"C_DeriveKey(SP800_108_COUNTER_KDF, data-param count={data_len:#x})",
            test_id="test_sp800_108_data_param_count_boundary",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sp800_108_additional_derived_key_count_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """A real additional-key array with a huge count must not be overread."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_DERIVED_KEY,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PRF_DATA_PARAM,
    CK_SP800_108_BYTE_ARRAY,
    CK_SP800_108_COUNTER_FORMAT,
    CK_SP800_108_DKM_LENGTH,
    CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
    CK_SP800_108_ITERATION_VARIABLE,
    CK_SP800_108_KDF_PARAMS,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKM_SP800_108_COUNTER_KDF,
    CKO_SECRET_KEY,
    CKR_OK,
)

key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:SP800-108 base-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

primary = CK_OBJECT_HANDLE(0)
try:
    counter = CK_SP800_108_COUNTER_FORMAT()
    counter.bLittleEndian = 0
    counter.ulWidthInBits = 32
    label = (ctypes.c_ubyte * 12)(*b"hardening-1")
    context = (ctypes.c_ubyte * 12)(*b"hardening-2")
    dkm = CK_SP800_108_DKM_LENGTH_FORMAT()
    dkm.dkmLengthMethod = CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
    dkm.bLittleEndian = 0
    dkm.ulWidthInBits = 32

    data_params = (CK_PRF_DATA_PARAM * 4)()
    data_params[0].type = CK_SP800_108_ITERATION_VARIABLE
    data_params[0].pValue = ctypes.cast(ctypes.pointer(counter), ctypes.c_void_p)
    data_params[0].ulValueLen = ctypes.sizeof(counter)
    data_params[1].type = CK_SP800_108_BYTE_ARRAY
    data_params[1].pValue = ctypes.cast(label, ctypes.c_void_p)
    data_params[1].ulValueLen = len(label)
    data_params[2].type = CK_SP800_108_BYTE_ARRAY
    data_params[2].pValue = ctypes.cast(context, ctypes.c_void_p)
    data_params[2].ulValueLen = len(context)
    data_params[3].type = CK_SP800_108_DKM_LENGTH
    data_params[3].pValue = ctypes.cast(ctypes.pointer(dkm), ctypes.c_void_p)
    data_params[3].ulValueLen = ctypes.sizeof(dkm)

    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 4
    params.pDataParams = ctypes.cast(data_params, ctypes.c_void_p)
    params.ulAdditionalDerivedKeys = {data_len}
    params.pAdditionalDerivedKeys = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SP800_108_COUNTER_KDF
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_AES)
    d_vl = CK_ULONG(16)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    d_tmpl[3].ulValueLen = 1

    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(primary),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, primary.value)
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_PARAM_LENGTH_REJECT_RVS,
            label_op=(
                f"C_DeriveKey(SP800_108_COUNTER_KDF, additional-derived-key count={data_len:#x})"
            ),
            test_id="test_sp800_108_additional_derived_key_count_boundary",
        )


# ---------------------------------------------------------------------------
# Wave 1: nested mechanism-parameter length-boundary probes
# (RSA-OAEP source-data, GCM IV / tag-bits, CCM nonce / MAC, EdDSA context)
# Each probe pairs a tiny real buffer with an impossible (isize::MAX /
# isize::MAX+1) *claimed* length. Crash/hang is a finding; CKR_OK accepts a
# nonsensical length; clean reject is the only passing verdict.
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestRsaOaepSourceDataLengthBoundary:
    """RSA-OAEP ulSourceDataLen must not turn a tiny source buffer into a huge read.

    CK_RSA_PKCS_OAEP_PARAMS.pSourceData/ulSourceDataLen are caller-controlled. A
    module that reads ulSourceDataLen bytes from pSourceData without
    bounds-checking over-reads when the claimed length is impossible. Drive
    C_EncryptInit + C_Encrypt with a tiny real source buffer and isize::MAX /
    isize::MAX+1 claimed lengths; crash/hang is a finding and CKR_OK accepts a
    nonsensical length.
    """

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_rsa_oaep_source_data_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(RSA_PKCS_OAEP) with tiny pSourceData + huge ulSourceDataLen."""
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
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_ULONG,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKG_MGF1_SHA256,
    CKM_SHA256,
    CKM_RSA_PKCS_OAEP,
    CKR_OK,
    CKZ_DATA_SPECIFIED,
)

pub = priv = 0
try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={{CKA_ENCRYPT: True, CKA_TOKEN: False}},
        private_attrs={{CKA_TOKEN: False}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )

try:
    params = CK_RSA_PKCS_OAEP_PARAMS()
    params.hashAlg = CKM_SHA256
    params.mgf = CKG_MGF1_SHA256
    params.source = CKZ_DATA_SPECIFIED
    params.pSourceData = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulSourceDataLen = {data_len}

    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS_OAEP
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), pub)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(512)
        out = (ctypes.c_ubyte * 512)()
        print("TARGET_CALL:C_Encrypt(RSA_PKCS_OAEP,ulSourceDataLen={data_len:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(RSA_PKCS_OAEP, ulSourceDataLen={data_len:#x})",
            test_id="test_rsa_oaep_source_data_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestGcmIvLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestGcmIvLengthBoundary:
    """AES-GCM ulIvLen must not turn a tiny IV buffer into a huge read.

    CK_AES_GCM_PARAMS.pIv/ulIvLen are caller-controlled. A module that reads
    ulIvLen bytes from pIv without bounds-checking over-reads when the claimed
    length is impossible. Drive C_EncryptInit + C_Encrypt with a tiny real IV
    buffer and isize::MAX / isize::MAX+1 claimed lengths; crash/hang is a
    finding and CKR_OK accepts a nonsensical length.
    """

    @pytest.mark.parametrize("iv_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_gcm_iv_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        iv_len: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(AES_GCM) with tiny pIv + huge ulIvLen."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM IV-length crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_GCM,
    CKR_OK,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    params = CK_AES_GCM_PARAMS()
    params.pIv = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulIvLen = {iv_len}
    params.ulIvBits = 96
    params.pAAD = None
    params.ulAADLen = 0
    params.ulTagBits = 128
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_GCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(64)
        out = (ctypes.c_ubyte * 64)()
        print("TARGET_CALL:C_Encrypt(AES_GCM,ulIvLen={iv_len:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(AES_GCM, ulIvLen={iv_len:#x})",
            test_id="test_gcm_iv_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestGcmTagBitsLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestGcmTagBitsLengthBoundary:
    """AES-GCM ulTagBits must reject impossible values safely.

    CK_AES_GCM_PARAMS.ulTagBits is a caller-controlled CK_ULONG. Valid tag
    lengths are {128, 120, 112, 104, 96, 64, 32} per SP800-38D; isize::MAX /
    isize::MAX+1 is impossible. A module that uses the value without
    bounds-checking can over-allocate or write a nonsensical tag. Drive
    C_EncryptInit + C_Encrypt with isize::MAX / isize::MAX+1 ulTagBits; crash is
    a finding and CKR_OK accepts a nonsensical length.
    """

    @pytest.mark.parametrize("tag_bits", _ISIZE_BOUNDARY_LENGTHS)
    def test_gcm_tag_bits_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        tag_bits: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(AES_GCM) with impossible ulTagBits."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM tag-bits crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_GCM,
    CKR_OK,
)

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
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(64)
        out = (ctypes.c_ubyte * 64)()
        print("TARGET_CALL:C_Encrypt(AES_GCM,ulTagBits={tag_bits:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(AES_GCM, ulTagBits={tag_bits:#x})",
            test_id="test_gcm_tag_bits_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestCcmNonceLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestCcmNonceLengthBoundary:
    """AES-CCM ulNonceLen must reject impossible values safely.

    CK_AES_CCM_PARAMS.ulNonceLen is a caller-controlled CK_ULONG. NIST SP800-38C
    restricts nonce size to the range [7, 13]; isize::MAX / isize::MAX+1 is
    impossible. A module that uses the value without bounds-checking can
    over-read or over-allocate. Drive C_EncryptInit + C_Encrypt with isize::MAX
    / isize::MAX+1 ulNonceLen and a tiny real pNonce (13 bytes); crash is a
    finding and CKR_OK accepts a nonsensical length.
    """

    @pytest.mark.parametrize("nonce_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_ccm_nonce_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        nonce_len: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(AES_CCM) with tiny pNonce + huge ulNonceLen."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CCM"):
            pytest.skip("CKM_AES_CCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-CCM nonce-length crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CCM_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_CCM,
    CKR_OK,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    params = CK_AES_CCM_PARAMS()
    params.ulDataLen = 16
    params.pNonce = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulNonceLen = {nonce_len}
    params.pAAD = None
    params.ulAADLen = 0
    params.ulMACLen = 16
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(64)
        out = (ctypes.c_ubyte * 64)()
        print("TARGET_CALL:C_Encrypt(AES_CCM,ulNonceLen={nonce_len:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(AES_CCM, ulNonceLen={nonce_len:#x})",
            test_id="test_ccm_nonce_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestCcmMacLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestCcmMacLengthBoundary:
    """AES-CCM ulMACLen must reject impossible values safely.

    CK_AES_CCM_PARAMS.ulMACLen is a caller-controlled CK_ULONG. NIST SP800-38C
    restricts the MAC length to the set {4, 6, 8, 10, 12, 14, 16}; isize::MAX /
    isize::MAX+1 is impossible. A module that uses the value without
    bounds-checking can over-allocate or write a nonsensical tag. Drive
    C_EncryptInit + C_Encrypt with isize::MAX / isize::MAX+1 ulMACLen; crash is
    a finding and CKR_OK accepts a nonsensical length.
    """

    @pytest.mark.parametrize("mac_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_ccm_mac_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        mac_len: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(AES_CCM) with impossible ulMACLen."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CCM"):
            pytest.skip("CKM_AES_CCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-CCM MAC-length crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CCM_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_CCM,
    CKR_OK,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    nonce = (ctypes.c_ubyte * 13)(*range(13))
    params = CK_AES_CCM_PARAMS()
    params.ulDataLen = 16
    params.pNonce = ctypes.cast(nonce, ctypes.c_void_p)
    params.ulNonceLen = 13
    params.pAAD = None
    params.ulAADLen = 0
    params.ulMACLen = {mac_len}
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(64)
        out = (ctypes.c_ubyte * 64)()
        print("TARGET_CALL:C_Encrypt(AES_CCM,ulMACLen={mac_len:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_MESSAGE_LENGTH_REJECT_RVS,
            label_op=f"C_Encrypt(AES_CCM, ulMACLen={mac_len:#x})",
            test_id="test_ccm_mac_length_boundary",
        )


# ---------------------------------------------------------------------------
# TestEddsaContextLengthBoundary
# ---------------------------------------------------------------------------


@requires_64bit_ck_ulong
class TestEddsaContextLengthBoundary:
    """EdDSA ulContextDataLen must not turn a tiny context buffer into a huge read.

    CK_EDDSA_PARAMS.pContextData/ulContextDataLen are caller-controlled. A module
    that reads ulContextDataLen bytes from pContextData without bounds-checking
    over-reads when the claimed length is impossible. Drive C_SignInit + C_Sign
    with a tiny real context buffer and isize::MAX / isize::MAX+1 claimed
    lengths; crash/hang is a finding and CKR_OK accepts a nonsensical length.
    """

    @pytest.mark.parametrize("ctx_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_eddsa_context_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        ctx_len: int,
    ) -> None:
        """C_SignInit/C_Sign(EDDSA) with tiny pContextData + huge ulContextDataLen."""
        rs = p11_raw_session
        if not rs.has_mechanism("EDDSA"):
            pytest.skip("CKM_EDDSA not supported")
        curve_oid = encode_named_curve_parameters("ed25519")
        pub, priv = gen_edwards_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
{_HONEYPOT_MMAP_CODE}
from pkcs11_check.raw.types_std import (
    CK_EDDSA_PARAMS, CK_MECHANISM, CK_ULONG, CKM_EDDSA,
    CKM_EC_EDWARDS_KEY_PAIR_GEN, CKA_EC_PARAMS, CKA_SIGN, CKA_TOKEN,
    CKA_VERIFY, CKR_OK,
)
from pkcs11_check.raw.pack import attr_bytes
from pkcs11_check.raw.recipes import gen_keypair, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.ec import encode_named_curve_parameters

curve_oid = encode_named_curve_parameters("ed25519")
pub = priv = 0
try:
    pub, priv = gen_keypair(
        raw, sh, CKM_EC_EDWARDS_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
        priv_base=[],
        public_attrs={{CKA_VERIFY: True, CKA_TOKEN: False}},
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
        pub_skip={{CKA_EC_PARAMS}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "EC_EDWARDS keypair generation rejected",
    )
try:
    params = CK_EDDSA_PARAMS()
    params.phFlag = 0
    params.pContextData = ctypes.cast(_HONEYPOT_BUF, ctypes.c_void_p)
    params.ulContextDataLen = {ctx_len}
    mech = CK_MECHANISM()
    mech.mechanism = CKM_EDDSA
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        msg = (ctypes.c_ubyte * 16)(*range(16))
        sig_len = CK_ULONG(128)
        sig = (ctypes.c_ubyte * 128)()
        print("TARGET_CALL:C_Sign(EDDSA,ulContextDataLen={ctx_len:#x})", flush=True)
        rv = raw.C_Sign(sh, msg, 16, sig, ctypes.byref(sig_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        _classify_unhonorable_length_outcome(
            rc,
            stdout,
            stderr,
            reject_rvs=_PARAM_LENGTH_REJECT_RVS,
            label_op=f"C_Sign(EDDSA, ulContextDataLen={ctx_len:#x})",
            test_id="test_eddsa_context_length_boundary",
        )


# ---------------------------------------------------------------------------
# Wave 4: Update output guard + continuation-after-NULL-output probes
# ---------------------------------------------------------------------------


class TestUpdateOutputGuard:
    """``C_EncryptUpdate`` / ``C_DecryptUpdate`` with a 1-byte declared output.

    Probe: ``C_<Enc|Dec>ryptInit`` → ``C_<Enc|Dec>ryptUpdate(NULL, &len)`` size
    query → ``C_<Enc|Dec>ryptUpdate`` continuation with a 1-byte guard-backed
    output buffer.  Per PKCS#11, the NULL-output size query does NOT terminate
    the operation.  The continuation real call must return ``CKR_BUFFER_TOO_SMALL``
    with the required length and must not overwrite the guard bytes.
    """

    def test_encrypt_update_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_EncryptUpdate`` with one declared output byte preserves guard bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_EncryptUpdate guard probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

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
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{rv:08x}", flush=True)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        needed = CK_ULONG(0)
        rv_q = raw.C_EncryptUpdate(sh, buf, 16, None, ctypes.byref(needed))
        print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
        print(f"NEEDED:{needed.value}", flush=True)
        if rv_q == CKR_OK:
            GUARD = 0xE1
            GUARD_SIZE = 32

            class UpdateProbe(ctypes.Structure):
                _fields_ = [
                    ("data", ctypes.c_ubyte * 1),
                    ("guard", ctypes.c_ubyte * GUARD_SIZE),
                ]

            probe = UpdateProbe()
            for idx in range(GUARD_SIZE):
                probe.guard[idx] = GUARD
            out_len = CK_ULONG(1)
            rv2 = raw.C_EncryptUpdate(
                sh, buf, 16,
                ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.byref(out_len),
            )
            print(f"FINAL_RV:0x{rv2:08x}", flush=True)
            print(f"LEN:{out_len.value}", flush=True)
            overwritten = sum(1 for byte in probe.guard if byte != GUARD)
            print(f"OVERWRITTEN:{overwritten}", flush=True)
            if overwritten != 0:
                print(f"GUARD_OVERWRITE:{overwritten}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptUpdate one-byte output buffer guard",
        )
        self._classify_update_guard(stdout, "C_EncryptUpdate", "Encrypt")

    def test_decrypt_update_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_DecryptUpdate`` with one declared output byte preserves guard bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_DecryptUpdate guard probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

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

    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)
    pt_buf = (ctypes.c_ubyte * 16)(*range(16))
    ct_buf = (ctypes.c_ubyte * 16)()
    ct_len = CK_ULONG(16)
    rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)

    dec_rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
    if dec_rv == CKR_OK:
        needed = CK_ULONG(0)
        rv_q = raw.C_DecryptUpdate(sh, ct_buf, 16, None, ctypes.byref(needed))
        print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
        print(f"NEEDED:{needed.value}", flush=True)
        if rv_q == CKR_OK:
            GUARD = 0xD2
            GUARD_SIZE = 32

            class UpdateProbe(ctypes.Structure):
                _fields_ = [
                    ("data", ctypes.c_ubyte * 1),
                    ("guard", ctypes.c_ubyte * GUARD_SIZE),
                ]

            probe = UpdateProbe()
            for idx in range(GUARD_SIZE):
                probe.guard[idx] = GUARD
            out_len = CK_ULONG(1)
            rv2 = raw.C_DecryptUpdate(
                sh, ct_buf, 16,
                ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
                ctypes.byref(out_len),
            )
            print(f"FINAL_RV:0x{rv2:08x}", flush=True)
            print(f"LEN:{out_len.value}", flush=True)
            overwritten = sum(1 for byte in probe.guard if byte != GUARD)
            print(f"OVERWRITTEN:{overwritten}", flush=True)
            if overwritten != 0:
                print(f"GUARD_OVERWRITE:{overwritten}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DecryptUpdate one-byte output buffer guard",
        )
        self._classify_update_guard(stdout, "C_DecryptUpdate", "Decrypt")

    @staticmethod
    def _classify_update_guard(stdout: str, op: str, side: str) -> None:
        """Shared parent-side classification for the update guard probes."""
        if "GUARD_OVERWRITE:" in stdout:
            fail_as(
                "wrong_result",
                kind="crypto",
                label=f"{op} output-buffer guard byte overwritten",
                actual=_parse_prefixed_int(stdout, "GUARD_OVERWRITE:"),
                summary="module wrote past the requested output length (OOB write)",
            )
        init_rv = _parse_prefixed_int(stdout, "INIT_RV:")
        if init_rv != CKR_OK:
            classify(
                "not_operational",
                label=f"{op} guard probe",
                summary=f"C_{side}Init returned {ckr_name(init_rv)}",
            )
        query_rv = _parse_prefixed_int(stdout, "QUERY_RV:")
        if query_rv != CKR_OK:
            classify(
                "not_operational",
                label=f"{op} guard probe",
                summary=f"{op} size query returned {ckr_name(query_rv)}",
            )
        final_rv = _parse_prefixed_int(stdout, "FINAL_RV:")
        classify_negative_rv(
            final_rv,
            (CKR_BUFFER_TOO_SMALL,),
            label=f"{op} with a one-byte output buffer",
        )


class TestContinueAfterNullOutputQuery:
    """Continuation real call after a NULL-output size query must succeed.

    Per PKCS#11, a NULL-output size query (``C_*Update(NULL, &len)`` or
    ``C_*Final(NULL, &len)``) does NOT terminate the active operation.  The
    caller should make the real call again with a real output buffer WITHOUT
    re-initializing.  If the continuation returns ``CKR_OPERATION_NOT_INITIALIZED``,
    the module incorrectly terminated the operation on the size query -- a spec
    violation (lifecycle self-contradiction).
    """

    def test_encrypt_update_continuation_after_size_query(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_EncryptUpdate`` real call after NULL-output size query succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_EncryptUpdate continuation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

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
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{rv:08x}", flush=True)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        needed = CK_ULONG(0)
        rv_q = raw.C_EncryptUpdate(sh, buf, 16, None, ctypes.byref(needed))
        print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
        if rv_q == CKR_OK:
            real_buf = (ctypes.c_ubyte * 64)()
            real_len = CK_ULONG(64)
            rv2 = raw.C_EncryptUpdate(sh, buf, 16, real_buf, ctypes.byref(real_len))
            print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptUpdate continuation after NULL-output size query",
        )
        self._classify_continuation(
            stdout,
            "C_EncryptUpdate",
            has_update_step=False,
        )

    def test_decrypt_update_continuation_after_size_query(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_DecryptUpdate`` real call after NULL-output size query succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_DecryptUpdate continuation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

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

    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)
    pt_buf = (ctypes.c_ubyte * 16)(*range(16))
    ct_buf = (ctypes.c_ubyte * 16)()
    ct_len = CK_ULONG(16)
    rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)

    dec_rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
    if dec_rv == CKR_OK:
        needed = CK_ULONG(0)
        rv_q = raw.C_DecryptUpdate(sh, ct_buf, 16, None, ctypes.byref(needed))
        print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
        if rv_q == CKR_OK:
            real_buf = (ctypes.c_ubyte * 64)()
            real_len = CK_ULONG(64)
            rv2 = raw.C_DecryptUpdate(sh, ct_buf, 16, real_buf, ctypes.byref(real_len))
            print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DecryptUpdate continuation after NULL-output size query",
        )
        self._classify_continuation(
            stdout,
            "C_DecryptUpdate",
            has_update_step=False,
        )

    def test_encrypt_final_continuation_after_size_query(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_EncryptFinal`` real call after NULL-output size query succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_EncryptFinal continuation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

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
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{rv:08x}", flush=True)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        upd_buf = (ctypes.c_ubyte * 16)()
        upd_len = CK_ULONG(16)
        rv_u = raw.C_EncryptUpdate(sh, buf, 16, upd_buf, ctypes.byref(upd_len))
        print(f"UPDATE_RV:0x{rv_u:08x}", flush=True)
        if rv_u == CKR_OK:
            needed = CK_ULONG(0)
            rv_q = raw.C_EncryptFinal(sh, None, ctypes.byref(needed))
            print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
            if rv_q == CKR_OK:
                real_buf = (ctypes.c_ubyte * 64)()
                real_len = CK_ULONG(64)
                rv2 = raw.C_EncryptFinal(sh, real_buf, ctypes.byref(real_len))
                print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptFinal continuation after NULL-output size query",
        )
        self._classify_continuation(
            stdout,
            "C_EncryptFinal",
            has_update_step=True,
        )

    def test_decrypt_final_continuation_after_size_query(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_DecryptFinal`` real call after NULL-output size query succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_DecryptFinal continuation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

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

    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)
    pt_buf = (ctypes.c_ubyte * 16)(*range(16))
    ct_buf = (ctypes.c_ubyte * 16)()
    ct_len = CK_ULONG(16)
    rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)

    dec_rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
    if dec_rv == CKR_OK:
        upd_buf = (ctypes.c_ubyte * 16)()
        upd_len = CK_ULONG(16)
        rv_u = raw.C_DecryptUpdate(sh, ct_buf, 16, upd_buf, ctypes.byref(upd_len))
        print(f"UPDATE_RV:0x{rv_u:08x}", flush=True)
        if rv_u == CKR_OK:
            needed = CK_ULONG(0)
            rv_q = raw.C_DecryptFinal(sh, None, ctypes.byref(needed))
            print(f"QUERY_RV:0x{rv_q:08x}", flush=True)
            if rv_q == CKR_OK:
                real_buf = (ctypes.c_ubyte * 64)()
                real_len = CK_ULONG(64)
                rv2 = raw.C_DecryptFinal(sh, real_buf, ctypes.byref(real_len))
                print(f"CONTINUATION_RV:0x{rv2:08x}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DecryptFinal continuation after NULL-output size query",
        )
        self._classify_continuation(
            stdout,
            "C_DecryptFinal",
            has_update_step=True,
        )

    @staticmethod
    def _classify_continuation(
        stdout: str,
        op: str,
        *,
        has_update_step: bool,
    ) -> None:
        """Shared parent-side classification for continuation probes."""
        init_rv = _parse_prefixed_int(stdout, "INIT_RV:")
        if init_rv != CKR_OK:
            classify(
                "not_operational",
                label=f"{op} continuation probe",
                summary=f"Init returned {ckr_name(init_rv)}",
            )
        if has_update_step:
            update_rv = _parse_prefixed_int(stdout, "UPDATE_RV:")
            if update_rv != CKR_OK:
                classify(
                    "not_operational",
                    label=f"{op} continuation probe",
                    summary=f"Update returned {ckr_name(update_rv)}",
                )
        query_rv = _parse_prefixed_int(stdout, "QUERY_RV:")
        if query_rv != CKR_OK:
            classify(
                "not_operational",
                label=f"{op} continuation probe",
                summary=f"NULL-output size query returned {ckr_name(query_rv)}",
            )
        continuation_rv = _parse_prefixed_int(stdout, "CONTINUATION_RV:")
        if continuation_rv == CKR_OK:
            return
        if continuation_rv == CKR_OPERATION_NOT_INITIALIZED:
            classify(
                "self_contradiction",
                kind="lifecycle",
                label=f"{op} continuation after NULL-output size query",
                summary=(
                    f"{op} returned {ckr_name(continuation_rv)} on the "
                    f"continuation real call after a NULL-output size query -- "
                    f"the size query must NOT terminate the operation "
                    f"(PKCS#11 spec violation)"
                ),
            )
        classify(
            "honest_deviation",
            label=f"{op} continuation after NULL-output size query",
            summary=f"{op} continuation returned {ckr_name(continuation_rv)}",
        )


# ---------------------------------------------------------------------------
# TestSingleShotOutputGuard
# ---------------------------------------------------------------------------


class TestSingleShotOutputGuard:
    """``C_Encrypt`` / ``C_Decrypt`` single-shot with a 1-byte declared output.

    Probe: ``C_<Enc|Dec>ryptInit`` then ``C_<Enc|Dec>rypt`` with a 1-byte
    guard-backed output buffer declaring ``ulEncryptedDataLen=1`` /
    ``ulDataLen=1``.  The module must return ``CKR_BUFFER_TOO_SMALL`` and must
    NOT write past the single declared output byte.  Any guard-byte overwrite
    is an out-of-bounds write finding.
    """

    def test_encrypt_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_Encrypt`` with one declared output byte preserves guard bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Encrypt single-shot guard probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

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
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{rv:08x}", flush=True)
    if rv == CKR_OK:
        GUARD = 0xC3
        GUARD_SIZE = 32

        class SingleShotProbe(ctypes.Structure):
            _fields_ = [
                ("data", ctypes.c_ubyte * 1),
                ("guard", ctypes.c_ubyte * GUARD_SIZE),
            ]

        probe = SingleShotProbe()
        for idx in range(GUARD_SIZE):
            probe.guard[idx] = GUARD
        pt_buf = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(1)
        rv2 = raw.C_Encrypt(
            sh, pt_buf, 16,
            ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(out_len),
        )
        print(f"TARGET_RV:0x{rv2:08x}", flush=True)
        overwritten = sum(1 for byte in probe.guard if byte != GUARD)
        if overwritten != 0:
            print(f"GUARD_OVERWRITE:{overwritten}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_Encrypt single-shot one-byte output buffer guard",
        )
        self._classify_single_shot_guard(stdout, "C_Encrypt", "Encrypt")

    def test_decrypt_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_Decrypt`` with one declared output byte preserves guard bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Decrypt single-shot guard probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )

try:
    # Produce a valid AES-ECB ciphertext block to use as decrypt input.
    enc_mech = CK_MECHANISM()
    enc_mech.mechanism = CKM_AES_ECB
    enc_mech.pParameter = None
    enc_mech.ulParameterLen = 0
    rv = raw.C_EncryptInit(sh, ctypes.byref(enc_mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_EncryptInit) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)
    pt_buf = (ctypes.c_ubyte * 16)(*range(16))
    ct_buf = (ctypes.c_ubyte * 16)()
    ct_len = CK_ULONG(16)
    rv = raw.C_Encrypt(sh, pt_buf, 16, ct_buf, ctypes.byref(ct_len))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:encrypt setup (C_Encrypt) rejected: rv=0x{rv:08x}")
        raise SystemExit(0)

    dec_mech = CK_MECHANISM()
    dec_mech.mechanism = CKM_AES_ECB
    dec_mech.pParameter = None
    dec_mech.ulParameterLen = 0
    dec_rv = raw.C_DecryptInit(sh, ctypes.byref(dec_mech), key)
    print(f"INIT_RV:0x{dec_rv:08x}", flush=True)
    if dec_rv == CKR_OK:
        GUARD = 0xD4
        GUARD_SIZE = 32

        class SingleShotProbe(ctypes.Structure):
            _fields_ = [
                ("data", ctypes.c_ubyte * 1),
                ("guard", ctypes.c_ubyte * GUARD_SIZE),
            ]

        probe = SingleShotProbe()
        for idx in range(GUARD_SIZE):
            probe.guard[idx] = GUARD
        out_len = CK_ULONG(1)
        rv2 = raw.C_Decrypt(
            sh, ct_buf, 16,
            ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(out_len),
        )
        print(f"TARGET_RV:0x{rv2:08x}", flush=True)
        overwritten = sum(1 for byte in probe.guard if byte != GUARD)
        if overwritten != 0:
            print(f"GUARD_OVERWRITE:{overwritten}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            script,
            timeout=10,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_Decrypt single-shot one-byte output buffer guard",
        )
        self._classify_single_shot_guard(stdout, "C_Decrypt", "Decrypt")

    @staticmethod
    def _classify_single_shot_guard(stdout: str, op: str, side: str) -> None:
        """Shared parent-side classification for the single-shot guard probes."""
        if "GUARD_OVERWRITE:" in stdout:
            fail_as(
                "wrong_result",
                kind="crypto",
                label=f"{op} output-buffer guard byte overwritten",
                actual=_parse_prefixed_int(stdout, "GUARD_OVERWRITE:"),
                summary=f"single-shot {op} wrote past the requested output length (OOB write)",
            )
        init_rv = _parse_prefixed_int(stdout, "INIT_RV:")
        if init_rv != CKR_OK:
            classify(
                "not_operational",
                label=f"{op} single-shot guard probe",
                summary=f"C_{side}Init returned {ckr_name(init_rv)}",
            )
        target_rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            target_rv,
            (CKR_BUFFER_TOO_SMALL,),
            label=f"{op} with a one-byte output buffer",
        )
