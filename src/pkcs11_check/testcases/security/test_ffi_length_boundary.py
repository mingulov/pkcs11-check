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
from pkcs11_check.raw import types_std
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
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
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


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


# ---------------------------------------------------------------------------
# TestIsizeMaxDataLength
# ---------------------------------------------------------------------------

_ISIZE_BOUNDARY_LENGTHS = [
    pytest.param(_ISIZE_MAX_64, id="isize_max"),
    pytest.param(_ISIZE_MAX_PLUS_1_64, id="isize_max_plus_1"),
]


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
    - Timeout/crash -> hard crash-class finding. The normal honeypot cannot map 2^63
      bytes, so read-vs-write attribution remains pending an ASAN rerun; lack of that
      evidence must not exonerate a provider crash or hang.
    - SETUP_XFAIL line present -> xfail (not_operational, setup didn't reach probe).
    - CKR_OK -> fail (accepted_invalid: silent truncation of an un-honorable length).
    - rv in reject_rvs -> pass.
    - other clean code -> xfail (nonspec_reject).
    """
    from pkcs11_check.testcases._probes.honeypot import SETUP_XFAIL_PREFIX
    from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

    if rc != 0:
        assert_subprocess_completed(
            rc,
            stdout,
            stderr,
            context=f"{label_op} (near-SIZE_MAX; ASAN read/write classification pending)",
        )
        return

    # SETUP_XFAIL: setup (keygen/Init) cleanly errored before the probe ran.
    for line in stdout.splitlines():
        if line.startswith(SETUP_XFAIL_PREFIX):
            xfail_as(
                "not_operational",
                label=label_op,
                summary=line.removeprefix(SETUP_XFAIL_PREFIX).strip(),
            )

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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "aes_cbc_encrypt_data_malformed",
                "case_label": case_label,
                "null_data": p_data_expr == "None",
                "data_len": data_len,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "rsa_pss_salt_length",
                "salt_len": salt_len,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "gcm_aad_length",
                "aad_len": aad_len,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ccm_aad_length",
                "aad_len": aad_len,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "pbkdf2_nested_length",
                "field": field,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "pbe_nested_length",
                "mechanism": getattr(types_std, mech_const),
                "key_type": getattr(types_std, key_type_const),
                "iv_len": iv_len,
                "sign_verify": sign_verify,
                "field": field,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "tls_kdf_random_length",
                "field": field,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sp800_108_data_param_count",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sp800_108_additional_derived_key_count",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "rsa_oaep_source_data_length",
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "gcm_iv_length",
                "iv_len": iv_len,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "gcm_tag_bits_length",
                "tag_bits": tag_bits,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ccm_nonce_length",
                "nonce_len": nonce_len,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ccm_mac_length",
                "mac_len": mac_len,
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
        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "eddsa_context_length",
                "ctx_len": ctx_len,
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_update_guard",
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_update_guard",
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_update_continuation",
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_update_continuation",
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_final_continuation",
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_final_continuation",
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_single_shot_guard",
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

        result = run_probe(
            "ffi_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_single_shot_guard",
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
