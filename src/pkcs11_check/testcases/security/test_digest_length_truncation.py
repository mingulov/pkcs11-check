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
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
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

        result = run_probe(
            "digest_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "digest",
                "mech_id": int(mechanism),
            },
            pin=pin_from_config(p11_config),
            timeout=180,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Digest({mech_str}, ulDataLen=0x{_OVERSIZE_LEN:x})",
        )

        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
        digest_hex = _parse_prefixed_str_optional(result.stdout, "DIGEST_HEX:")

        if rv != 0:
            classify_negative_rv(
                rv,
                _DIGEST_REJECT_RVS,
                label=f"C_Digest({mech_str}) rejects oversized 64-bit input length",
            )
        else:
            # CKR_OK -- check whether the module truncated to the low-32 bytes.
            assert digest_hex is not None, (
                f"TARGET_RV=CKR_OK but DIGEST_HEX line missing: {result.stdout[-300:]}"
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

        result = run_probe(
            "digest_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "hmac_sha256",
            },
            pin=pin_from_config(p11_config),
            timeout=180,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_Sign(SHA256_HMAC, ulDataLen=0x{_OVERSIZE_LEN:x})",
        )

        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
        hmac_hex = _parse_prefixed_str_optional(result.stdout, "HMAC_HEX:")

        if rv != 0:
            classify_negative_rv(
                rv,
                _DIGEST_REJECT_RVS,
                label="C_Sign(SHA256_HMAC) rejects oversized 64-bit input length",
            )
        else:
            assert hmac_hex is not None, (
                f"TARGET_RV=CKR_OK but HMAC_HEX line missing: {result.stdout[-300:]}"
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
