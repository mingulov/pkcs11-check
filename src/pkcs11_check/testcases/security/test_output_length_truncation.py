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
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
)
from pkcs11_check.testcases.security._boundary_values import (
    OVERSIZE_WRITE_LEN,
    PROBE_OFFSET,
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


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


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


# Setup-reject helper string copied from test_ffi_length_boundary: the child marks a
# known keygen reject as SETUP_XFAIL (-> xfail) instead of a spurious probe failure.
_CHILD_SETUP_REJECT_HELPERS = """
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
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


# Child code: AES-CTR setup (1:1 stream mechanism, no padding constraint) feeding a
# demand-zero oversize input buffer into a demand-zero oversize output buffer, then
# sampling the output at PROBE_OFFSET.  ``{op}`` selects C_EncryptInit/C_Encrypt or
# C_DecryptInit/C_Decrypt; ``{init_fn}``/``{op_fn}`` are interpolated.
_CTR_TRUNCATION_BODY = """
import ctypes
import mmap as _mmap

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CTR_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_CTR,
    CKR_OK,
)

LEN = {oversize_len}        # 0x100000008 -- low 32 bits = 8
PROBE_OFF = {probe_offset}  # 1 MiB, past any 32-bit truncation of LEN

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )

in_mm = None
out_mm = None
in_view = None
out_view = None
try:
    ctr_params = CK_AES_CTR_PARAMS()
    ctr_params.ulCounterBits = 32
    # Counter block: deterministic, non-zero so a correct cipher produces non-zero
    # keystream regardless of the (zero) demand-zero plaintext.
    for _i in range(16):
        ctr_params.cb[_i] = (_i + 1) & 0xFF

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CTR
    mech.pParameter = ctypes.cast(ctypes.pointer(ctr_params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(ctr_params)

    rv = raw.{init_fn}(sh, ctypes.byref(mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:{init_fn} not operational: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    # Oversize demand-zero input + output buffers.  For AES-CTR the output length
    # equals the input length (1:1, no padding): an oversize *input* drives an
    # oversize *write*, restoring the requested==written equivalence the oracle
    # depends on.  A truncating provider casts LEN to 32 bits (=8), processes 8
    # input bytes, writes ~8 output bytes -> output[PROBE_OFF] stays zero.
    in_mm = _mmap.mmap(
        -1, LEN,
        _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
        _mmap.PROT_READ | _mmap.PROT_WRITE,
    )
    out_mm = _mmap.mmap(
        -1, LEN,
        _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
        _mmap.PROT_READ | _mmap.PROT_WRITE,
    )
    in_view = (ctypes.c_ubyte * LEN).from_buffer(in_mm)
    out_view = (ctypes.c_ubyte * LEN).from_buffer(out_mm)
    out_len = CK_ULONG(LEN)

    rv = raw.{op_fn}(
        sh,
        ctypes.cast(in_view, ctypes.POINTER(ctypes.c_ubyte)),
        LEN,
        ctypes.cast(out_view, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.byref(out_len),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        sample = bytes(out_mm[PROBE_OFF : PROBE_OFF + 64])
        underfill = 1 if sample == b"\\x00" * 64 else 0
        print(f"UNDERFILL:{{underfill}}")
        print(f"OUT_LEN:0x{{out_len.value:016x}}")
finally:
    # Release ctypes views before their mmaps; the OS reclaims mappings at exit.
    if in_view is not None:
        del in_view
    if out_view is not None:
        del out_view
    in_mm = None
    out_mm = None
    destroy_quietly(raw, sh, key)
cleanup()
"""


def _build_ctr_script(p11_config: Any, *, init_fn: str, op_fn: str) -> str:
    """Assemble the preamble + setup-reject helpers + AES-CTR truncation body."""
    return (
        _preamble(p11_config)
        + _CHILD_SETUP_REJECT_HELPERS
        + _CTR_TRUNCATION_BODY.format(
            oversize_len=OVERSIZE_WRITE_LEN,
            probe_offset=PROBE_OFFSET,
            init_fn=init_fn,
            op_fn=op_fn,
        )
    )


# ---------------------------------------------------------------------------
# Generalised 1:1 stream-cipher oracle body
#
# ``{key_setup_src}`` is interpolated verbatim; it must assign to ``key`` and
# call ``setup_xfail_if_known_ckr`` on keygen failure (same contract as the
# CTR body).  ``{mech_setup_src}`` must produce a live ``mech`` (CK_MECHANISM)
# with all sub-objects kept alive until the end of the try block.
# ``{init_fn}`` / ``{op_fn}`` select C_EncryptInit/C_Encrypt or the decrypt
# pair.  The AES key import and the mmap oracle logic are identical for all
# strictly-1:1 stream ciphers.
# ---------------------------------------------------------------------------
_STREAM_TRUNCATION_BODY = """
import ctypes
import mmap as _mmap

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKR_OK,
)

LEN = {oversize_len}        # 0x100000008 -- low 32 bits = 8
PROBE_OFF = {probe_offset}  # 1 MiB, past any 32-bit truncation of LEN

{key_setup_src}

in_mm = None
out_mm = None
in_view = None
out_view = None
try:
{mech_setup_src}
    rv = raw.{init_fn}(sh, ctypes.byref(mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:{{init_fn}} not operational: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    # Oversize demand-zero input + output buffers.  For 1:1 stream ciphers the
    # output length equals the input length: an oversize input drives an oversize
    # write.  A truncating provider casts LEN to 32 bits (=8), processes 8 input
    # bytes, writes ~8 output bytes -> output[PROBE_OFF] stays zero.
    in_mm = _mmap.mmap(
        -1, LEN,
        _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
        _mmap.PROT_READ | _mmap.PROT_WRITE,
    )
    out_mm = _mmap.mmap(
        -1, LEN,
        _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
        _mmap.PROT_READ | _mmap.PROT_WRITE,
    )
    in_view = (ctypes.c_ubyte * LEN).from_buffer(in_mm)
    out_view = (ctypes.c_ubyte * LEN).from_buffer(out_mm)
    out_len = CK_ULONG(LEN)

    rv = raw.{op_fn}(
        sh,
        ctypes.cast(in_view, ctypes.POINTER(ctypes.c_ubyte)),
        LEN,
        ctypes.cast(out_view, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.byref(out_len),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        sample = bytes(out_mm[PROBE_OFF : PROBE_OFF + 64])
        underfill = 1 if sample == b"\\x00" * 64 else 0
        print(f"UNDERFILL:{{underfill}}")
        print(f"OUT_LEN:0x{{out_len.value:016x}}")
finally:
    if in_view is not None:
        del in_view
    if out_view is not None:
        del out_view
    in_mm = None
    out_mm = None
    destroy_quietly(raw, sh, key)
cleanup()
"""

# Key-setup snippet reused by AES-OFB, AES-CFB128, and AES-CFB8 (all use AES-256
# session keys; the key type is orthogonal to which stream mode is used).
_AES_KEY_SETUP_SRC = """\
from pkcs11_check.raw.recipes import gen_aes_key

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
"""

# Mechanism-setup snippet for AES modes that take a raw 16-byte IV as parameter
# (OFB, CFB128, CFB8).  ``{mech_const}`` is substituted at build time.
_AES_IV_MECH_SETUP_SRC_TEMPLATE = """\
    from pkcs11_check.raw.types_std import {mech_const}
    iv = (ctypes.c_ubyte * 16)(*range(1, 17))
    mech = CK_MECHANISM()
    mech.mechanism = {mech_const}
    mech.pParameter = ctypes.cast(iv, ctypes.c_void_p)
    mech.ulParameterLen = 16
"""

# Key-setup snippet for ChaCha20 (distinct key type generated via
# CKM_CHACHA20_KEY_GEN; gen_aes_key is reused with a custom mechanism because it
# omits CKA_KEY_TYPE when mechanism != CKM_AES_KEY_GEN, which is exactly what
# CKM_CHACHA20_KEY_GEN requires).
_CHACHA20_KEY_SETUP_SRC = """\
from pkcs11_check.raw.recipes import gen_aes_key
from pkcs11_check.raw.types_std import CKM_CHACHA20_KEY_GEN

try:
    key = gen_aes_key(raw, sh, 256, mechanism=CKM_CHACHA20_KEY_GEN)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "ChaCha20 key generation rejected",
    )
"""

# Mechanism-setup snippet for ChaCha20 (CK_CHACHA20_PARAMS: 16-byte block counter
# at 128 bits + 12-byte nonce at 96 bits).
_CHACHA20_MECH_SETUP_SRC = """\
    from pkcs11_check.raw.types_std import CK_CHACHA20_PARAMS, CKM_CHACHA20
    counter = (ctypes.c_ubyte * 16)()       # all-zero counter at position 0
    nonce = (ctypes.c_ubyte * 12)(*range(12))
    chacha_params = CK_CHACHA20_PARAMS()
    chacha_params.pBlockCounter = ctypes.cast(counter, ctypes.c_void_p)
    chacha_params.blockCounterBits = 128
    chacha_params.pNonce = ctypes.cast(nonce, ctypes.c_void_p)
    chacha_params.ulNonceBits = 96
    mech = CK_MECHANISM()
    mech.mechanism = CKM_CHACHA20
    mech.pParameter = ctypes.cast(ctypes.pointer(chacha_params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(chacha_params)
"""


def _build_stream_script(
    p11_config: Any,
    *,
    key_setup_src: str,
    mech_setup_src: str,
    init_fn: str,
    op_fn: str,
) -> str:
    """Assemble preamble + setup helpers + generalised stream-cipher truncation body.

    ``key_setup_src`` and ``mech_setup_src`` are raw Python source snippets
    (already dedented to their intended indentation level in the child); the CKM
    constant is embedded in ``mech_setup_src``.
    """
    return (
        _preamble(p11_config)
        + _CHILD_SETUP_REJECT_HELPERS
        + _STREAM_TRUNCATION_BODY.format(
            oversize_len=OVERSIZE_WRITE_LEN,
            probe_offset=PROBE_OFFSET,
            key_setup_src=key_setup_src,
            mech_setup_src=mech_setup_src,
            init_fn=init_fn,
            op_fn=op_fn,
        )
    )


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

        script = _build_ctr_script(p11_config, init_fn="C_EncryptInit", op_fn="C_Encrypt")
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(AES_CTR, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_ctr_script(p11_config, init_fn="C_DecryptInit", op_fn="C_Decrypt")
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Decrypt(AES_CTR, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_AES_KEY_SETUP_SRC,
            mech_setup_src=_AES_IV_MECH_SETUP_SRC_TEMPLATE.format(mech_const="CKM_AES_OFB"),
            init_fn="C_EncryptInit",
            op_fn="C_Encrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(AES_OFB, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_AES_KEY_SETUP_SRC,
            mech_setup_src=_AES_IV_MECH_SETUP_SRC_TEMPLATE.format(mech_const="CKM_AES_OFB"),
            init_fn="C_DecryptInit",
            op_fn="C_Decrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Decrypt(AES_OFB, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_AES_KEY_SETUP_SRC,
            mech_setup_src=_AES_IV_MECH_SETUP_SRC_TEMPLATE.format(mech_const="CKM_AES_CFB128"),
            init_fn="C_EncryptInit",
            op_fn="C_Encrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(AES_CFB128, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_AES_KEY_SETUP_SRC,
            mech_setup_src=_AES_IV_MECH_SETUP_SRC_TEMPLATE.format(mech_const="CKM_AES_CFB128"),
            init_fn="C_DecryptInit",
            op_fn="C_Decrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Decrypt(AES_CFB128, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_AES_KEY_SETUP_SRC,
            mech_setup_src=_AES_IV_MECH_SETUP_SRC_TEMPLATE.format(mech_const="CKM_AES_CFB8"),
            init_fn="C_EncryptInit",
            op_fn="C_Encrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(AES_CFB8, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_AES_KEY_SETUP_SRC,
            mech_setup_src=_AES_IV_MECH_SETUP_SRC_TEMPLATE.format(mech_const="CKM_AES_CFB8"),
            init_fn="C_DecryptInit",
            op_fn="C_Decrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Decrypt(AES_CFB8, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_CHACHA20_KEY_SETUP_SRC,
            mech_setup_src=_CHACHA20_MECH_SETUP_SRC,
            init_fn="C_EncryptInit",
            op_fn="C_Encrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(CHACHA20, ulDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
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

        script = _build_stream_script(
            p11_config,
            key_setup_src=_CHACHA20_KEY_SETUP_SRC,
            mech_setup_src=_CHACHA20_MECH_SETUP_SRC,
            init_fn="C_DecryptInit",
            op_fn="C_Decrypt",
        )
        rc, stdout, stderr = run_with_coverage(
            script, timeout=_HONORING_TIMEOUT_S, pin=pin_from_config(p11_config)
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Decrypt(CHACHA20, ulEncryptedDataLen=0x{OVERSIZE_WRITE_LEN:x})",
        )
        _classify_oracle(
            stdout,
            reject_rvs=_DECRYPT_LENGTH_REJECT_RVS,
            op_name="C_Decrypt(ChaCha20)",
            test_id=(
                "TestChaCha20OutputLengthTruncation.test_decrypt_oversized_length_rejects_or_honors"
            ),
        )
