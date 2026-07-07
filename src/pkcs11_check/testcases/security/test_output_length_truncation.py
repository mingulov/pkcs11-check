"""Demand-zero mmap oracle proving 64-bit->32-bit truncation of output writes.

Family B of the WS2 truncation workstream (see ``test_random_length_truncation.py``
for the proven template).  A provider that casts a 64-bit length to 32 bits writes
only the low-32 amount while the caller declared a far larger size -- a silent,
dangerous under-fill.  The ONLY way to PROVE this (vs a clean rejection) is the
demand-zero ``mmap`` oracle: allocate the full 64-bit size as a ``MAP_PRIVATE |
MAP_ANONYMOUS`` (demand-zero, lazy) buffer, run the op, and on ``CKR_OK`` sample
bytes at an offset PAST the 32-bit boundary.  All-zero there means the provider
wrote only the truncated amount -> ``accepted_invalid``.

Oracle precondition -- where this oracle applies (and where it does NOT)
-----------------------------------------------------------------------
The random-length oracle works because for ``C_GenerateRandom`` the *requested*
length IS the *written* length: truncating ``ulRandomLen`` directly shrinks the
write, so a far-offset probe that stays zero proves the under-fill.  Generalising
to other ops requires the same equivalence: there must be a caller-supplied input
length that (a) the caller sets to the oversize 64-bit value and (b) determines
how many output bytes are written.

- ``C_Encrypt`` / ``C_Decrypt`` SATISFY this with a 1:1 (no-padding) stream
  mechanism (AES-CTR): the ciphertext/plaintext length equals the input length,
  so an oversize *input* (``ulDataLen`` / ``ulEncryptedDataLen``) drives an
  oversize *write*.  A truncating provider casts the input length to 32 bits,
  processes only the low-32 amount, and writes only that many output bytes; the
  output probe at 1 MiB stays zero -> truncation proven.  These ARE the
  oracle-amenable output-writing ops, implemented below.

- ``C_WrapKey`` does NOT satisfy it.  Its written length is governed by the size
  of the *key object* being wrapped, not by any caller-supplied input length.
  The only 64-bit caller length is the output *capacity* (``*pulWrappedKeyLen``);
  truncating that to 32 bits makes the wrapped size exceed the (truncated)
  capacity, so the provider returns ``CKR_BUFFER_TOO_SMALL`` and writes nothing --
  a clean return-code signal, never a silent under-fill the demand-zero probe can
  observe.  C_WrapKey is therefore NOT a Family-B target (it belongs with the
  Family-A input-length / capacity-truncation probes); writing a demand-zero
  output probe for it would only false-fail every compliant provider.

- ``C_GenerateKey`` likewise does NOT satisfy it: the key value is written into the
  token, not into a caller output buffer whose fill size the caller can inflate.
  ``CKA_VALUE_LEN`` truncation is covered by the Family-A ``accepted_invalid``
  probe, not by this output oracle.

Safety: the oversize input and output buffers are ``MAP_PRIVATE | MAP_ANONYMOUS``
demand-zero mappings, so the 4 GiB+ allocation is lazy (no physical 4 GiB).  A
rejecting provider touches nothing; a truncating provider touches ~8 input bytes
and writes ~8 output bytes; only a fully-honoring provider faults all pages (and
that is the legitimate "honored" outcome, recorded as a note).  No out-of-bounds
access occurs in any case.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_MEMORY,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
)
from pkcs11_check.testcases.security._boundary_values import (
    OVERSIZE_WRITE_LEN,
    requires_64bit_ck_ulong,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [
    pytest.mark.security,
    pytest.mark.subprocess,
    pytest.mark.slow,
    requires_64bit_ck_ulong,
]

# CKRs that constitute a conformant rejection of an oversized 64-bit data length.
# Memory-pressure codes are included: a provider that *attempts* the full 4 GiB+
# input and runs out of memory rejected honestly (no truncation).
_OUTPUT_LENGTH_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_MEMORY,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_DECRYPT_LENGTH_REJECT_RVS = _OUTPUT_LENGTH_REJECT_RVS + (CKR_ENCRYPTED_DATA_LEN_RANGE,)

# Timeout: a truncating provider finishes near-instantly; a fully-honoring provider
# could spend significant time encrypting/decrypting a 4 GiB+ buffer.  180 s mirrors
# the random-length oracle and keeps slow CI bounded.
_HONORING_TIMEOUT_S = 180


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-400:]}")


def _parse_prefixed_int_optional(output: str, prefix: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


def _classify_oracle(
    stdout: str,
    *,
    reject_rvs: tuple[Any, ...],
    op_name: str,
    test_id: str,
) -> None:
    """Shared oracle verdict: reject -> classify; CKR_OK+all-zero -> accepted_invalid.

    CKR_OK with a non-zero probe means the provider wrote ciphertext spanning past
    the 1 MiB offset -- it honored the full 4 GiB+ length, conformant -> note.
    """
    rv = _parse_prefixed_int(stdout, "TARGET_RV:")
    underfill = _parse_prefixed_int_optional(stdout, "UNDERFILL:")

    assert rv != 0 or underfill is not None, (
        f"{op_name} returned CKR_OK but UNDERFILL line missing: {stdout[-300:]}"
    )

    if rv != 0:
        # Module rejected the oversized length -- classify (pass or xfail).
        classify_negative_rv(
            rv,
            reject_rvs,
            label=f"{op_name} rejects oversized 64-bit data length",
        )
    elif underfill == 1:
        # CKR_OK but only the truncated low-32 bytes written: silent under-fill.
        classify_negative_rv(
            rv,
            reject_rvs,
            label=(
                f"{op_name} 64-bit data length truncated (silent under-fill): "
                "returned CKR_OK but wrote only truncated-low-32 bytes "
                "(output probe past the 32-bit boundary is all-zero)"
            ),
        )
    else:
        # CKR_OK and the probe past the boundary is non-zero: full 4 GiB+ honored.
        note(
            f"{op_name} honored a 4 GiB+ data length (0x{OVERSIZE_WRITE_LEN:x} bytes): "
            "conformant -- no truncation observed (output written past the 32-bit "
            "boundary)",
            ComplianceLevel.EXTENDED,
            reference="PKCS#11 3.1 §5.9 C_Encrypt / C_Decrypt",
            test_id=test_id,
        )


class TestEncryptOutputLengthTruncation:
    """C_Encrypt must not silently truncate a 64-bit input/output length.

    Probe: AES-CTR encrypt a ``0x100000008`` (4 GiB + 8) byte demand-zero input
    into a demand-zero output buffer with ``*pulEncryptedDataLen`` declared at the
    same size.  AES-CTR is a 1:1 stream cipher, so the write length tracks the
    input length.  A truncating provider casts the input length to 32 bits (=8),
    encrypts 8 bytes, writes ~8 output bytes, and returns CKR_OK -- leaving the
    output past offset 8 (and certainly at 1 MiB) zero.  That is a silent
    cryptographic-contract violation -> accepted_invalid.
    """

    def test_encrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Encrypt must reject or fully honor a 4 GiB+ AES-CTR input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Encrypt output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_ctr_encrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Encrypt(AES_CTR, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_OUTPUT_LENGTH_REJECT_RVS,
            op_name="C_Encrypt",
            test_id=(
                "TestEncryptOutputLengthTruncation.test_encrypt_oversized_length_rejects_or_honors"
            ),
        )


class TestDecryptOutputLengthTruncation:
    """C_Decrypt must not silently truncate a 64-bit input/output length.

    Symmetric to the encrypt probe: AES-CTR decrypt of a ``0x100000008`` byte
    demand-zero input into a demand-zero output buffer.  AES-CTR decryption is the
    same 1:1 stream transform, so an oversize input drives an oversize write; a
    truncating provider under-fills the output and the 1 MiB probe stays zero.
    """

    def test_decrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Decrypt must reject or fully honor a 4 GiB+ AES-CTR input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Decrypt output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_ctr_decrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Decrypt(AES_CTR, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_DECRYPT_LENGTH_REJECT_RVS,
            op_name="C_Decrypt",
            test_id=(
                "TestDecryptOutputLengthTruncation.test_decrypt_oversized_length_rejects_or_honors"
            ),
        )


# ---------------------------------------------------------------------------
# AES-OFB -- strictly 1:1 stream mode, 16-byte IV parameter
# ---------------------------------------------------------------------------


class TestAesOFBOutputLengthTruncation:
    """C_Encrypt / C_Decrypt must not silently truncate a 64-bit length for AES-OFB.

    AES-OFB (Output Feedback) is a strictly 1:1 stream mode: output length equals
    input length with no padding.  The mechanism parameter is a raw 16-byte IV.
    The demand-zero mmap oracle applies identically to AES-CTR: an oversize input
    drives an oversize write, and a truncating provider under-fills the output.
    """

    def test_encrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Encrypt must reject or fully honor a 4 GiB+ AES-OFB input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_OFB"):
            pytest.skip("CKM_AES_OFB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Encrypt AES-OFB output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_ofb_encrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Encrypt(AES_OFB, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_OUTPUT_LENGTH_REJECT_RVS,
            op_name="C_Encrypt(AES-OFB)",
            test_id=(
                "TestAesOFBOutputLengthTruncation.test_encrypt_oversized_length_rejects_or_honors"
            ),
        )

    def test_decrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Decrypt must reject or fully honor a 4 GiB+ AES-OFB input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_OFB"):
            pytest.skip("CKM_AES_OFB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Decrypt AES-OFB output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_ofb_decrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Decrypt(AES_OFB, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_DECRYPT_LENGTH_REJECT_RVS,
            op_name="C_Decrypt(AES-OFB)",
            test_id=(
                "TestAesOFBOutputLengthTruncation.test_decrypt_oversized_length_rejects_or_honors"
            ),
        )


# ---------------------------------------------------------------------------
# AES-CFB128 -- strictly 1:1 stream mode, 16-byte IV parameter
# ---------------------------------------------------------------------------


class TestAesCFB128OutputLengthTruncation:
    """C_Encrypt / C_Decrypt must not silently truncate a 64-bit length for AES-CFB128.

    AES-CFB128 (Cipher Feedback, 128-bit segment) is a strictly 1:1 stream mode.
    The mechanism parameter is a raw 16-byte IV.  The demand-zero mmap oracle applies
    identically: an oversize input drives an oversize write.
    """

    def test_encrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Encrypt must reject or fully honor a 4 GiB+ AES-CFB128 input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CFB128"):
            pytest.skip("CKM_AES_CFB128 not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Encrypt AES-CFB128 output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_cfb128_encrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Encrypt(AES_CFB128, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_OUTPUT_LENGTH_REJECT_RVS,
            op_name="C_Encrypt(AES-CFB128)",
            test_id=(
                "TestAesCFB128OutputLengthTruncation"
                ".test_encrypt_oversized_length_rejects_or_honors"
            ),
        )

    def test_decrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Decrypt must reject or fully honor a 4 GiB+ AES-CFB128 input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CFB128"):
            pytest.skip("CKM_AES_CFB128 not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Decrypt AES-CFB128 output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_cfb128_decrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Decrypt(AES_CFB128, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_DECRYPT_LENGTH_REJECT_RVS,
            op_name="C_Decrypt(AES-CFB128)",
            test_id=(
                "TestAesCFB128OutputLengthTruncation"
                ".test_decrypt_oversized_length_rejects_or_honors"
            ),
        )


# ---------------------------------------------------------------------------
# AES-CFB8 -- strictly 1:1 stream mode (8-bit CFB segment), 16-byte IV parameter
# ---------------------------------------------------------------------------


class TestAesCFB8OutputLengthTruncation:
    """C_Encrypt / C_Decrypt must not silently truncate a 64-bit length for AES-CFB8.

    AES-CFB8 (Cipher Feedback, 8-bit segment) produces exactly one byte of output
    per byte of input (1:1).  The mechanism parameter is a raw 16-byte IV.  The
    demand-zero mmap oracle applies identically.
    """

    def test_encrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Encrypt must reject or fully honor a 4 GiB+ AES-CFB8 input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CFB8"):
            pytest.skip("CKM_AES_CFB8 not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Encrypt AES-CFB8 output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_cfb8_encrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Encrypt(AES_CFB8, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_OUTPUT_LENGTH_REJECT_RVS,
            op_name="C_Encrypt(AES-CFB8)",
            test_id=(
                "TestAesCFB8OutputLengthTruncation.test_encrypt_oversized_length_rejects_or_honors"
            ),
        )

    def test_decrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Decrypt must reject or fully honor a 4 GiB+ AES-CFB8 input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CFB8"):
            pytest.skip("CKM_AES_CFB8 not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Decrypt AES-CFB8 output-length truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "aes_cfb8_decrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Decrypt(AES_CFB8, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_DECRYPT_LENGTH_REJECT_RVS,
            op_name="C_Decrypt(AES-CFB8)",
            test_id=(
                "TestAesCFB8OutputLengthTruncation.test_decrypt_oversized_length_rejects_or_honors"
            ),
        )


# ---------------------------------------------------------------------------
# ChaCha20 -- strictly 1:1 stream cipher, CK_CHACHA20_PARAMS parameter
# ---------------------------------------------------------------------------


class TestChaCha20OutputLengthTruncation:
    """C_Encrypt / C_Decrypt must not silently truncate a 64-bit length for ChaCha20.

    ChaCha20 (``CKM_CHACHA20``) is a strictly 1:1 stream cipher: output length
    equals input length.  The mechanism parameter is ``CK_CHACHA20_PARAMS`` (block
    counter + nonce).  The key is generated via ``CKM_CHACHA20_KEY_GEN`` (separate
    from AES key generation).  The demand-zero mmap oracle applies identically.
    """

    def test_encrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Encrypt must reject or fully honor a 4 GiB+ ChaCha20 input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not rs.has_mechanism("CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "chacha20_encrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Encrypt(CHACHA20, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_OUTPUT_LENGTH_REJECT_RVS,
            op_name="C_Encrypt(ChaCha20)",
            test_id=(
                "TestChaCha20OutputLengthTruncation.test_encrypt_oversized_length_rejects_or_honors"
            ),
        )

    def test_decrypt_oversized_length_rejects_or_honors(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Decrypt must reject or fully honor a 4 GiB+ ChaCha20 input length."""
        rs = p11_raw_session
        if not rs.has_mechanism("CHACHA20"):
            pytest.skip("CKM_CHACHA20 not supported")
        if not rs.has_mechanism("CHACHA20_KEY_GEN"):
            pytest.skip("CKM_CHACHA20_KEY_GEN not supported")

        result = run_probe(
            "output_length",
            {
                "module_path": str(p11_config.module),
                "which": "chacha20_decrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=_HONORING_TIMEOUT_S,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Decrypt(CHACHA20, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            result.stdout,
            reject_rvs=_DECRYPT_LENGTH_REJECT_RVS,
            op_name="C_Decrypt(ChaCha20)",
            test_id=(
                "TestChaCha20OutputLengthTruncation.test_decrypt_oversized_length_rejects_or_honors"
            ),
        )
