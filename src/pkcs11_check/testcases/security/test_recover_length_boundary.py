"""Crash-safe length-boundary probes for sign/verify-recover APIs."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import compliance
from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.types_std import (
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security._boundary_values import requires_64bit_ck_ulong
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [
    pytest.mark.security,
    pytest.mark.subprocess,
    requires_64bit_ck_ulong,
]

_ISIZE_MAX_64 = 0x7FFFFFFFFFFFFFFF
_ISIZE_MAX_PLUS_1_64 = 0x8000000000000000
# Oversized output-length: low 32 bits = 256 (matches a 256-byte output buffer),
# high 32 bits set.  A module that writes only the low 32 bits of *pulDataLen
# leaves the high half intact, producing a huge value that drives an OOB copy.
_R6_INFLATED_PULDATALEN = (1 << 32) + 256

_BOUNDARY_LENGTHS = [
    pytest.param(_ISIZE_MAX_64, id="isize_max"),
    pytest.param(_ISIZE_MAX_PLUS_1_64, id="isize_max_plus_1"),
]


def _parse_output_value(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


class TestRecoverInputLengthBoundary:
    """Recover APIs must reject impossible claimed input lengths without crashing."""

    @pytest.mark.parametrize("data_len", _BOUNDARY_LENGTHS)
    def test_sign_recover_huge_data_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """``C_SignRecover`` with a tiny real buffer and huge ``ulDataLen``."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        result = run_probe(
            "recover_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "sign_huge_data_len",
                "data_len": data_len,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_SignRecover(ulDataLen={data_len:#x})",
        )
        rv = _parse_output_value(result.stdout, "CKR:")
        classify_negative_rv(
            rv,
            (CKR_DATA_LEN_RANGE,),
            label=f"C_SignRecover with ulDataLen={data_len:#x}",
        )

    @pytest.mark.parametrize("sig_len", _BOUNDARY_LENGTHS)
    def test_verify_recover_huge_signature_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        sig_len: int,
    ) -> None:
        """``C_VerifyRecover`` with a tiny real signature and huge ``ulSignatureLen``."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        result = run_probe(
            "recover_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "verify_huge_sig_len",
                "sig_len": sig_len,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_VerifyRecover(ulSignatureLen={sig_len:#x})",
        )
        rv = _parse_output_value(result.stdout, "CKR:")
        classify_negative_rv(
            rv,
            (CKR_SIGNATURE_LEN_RANGE,),
            label=f"C_VerifyRecover with ulSignatureLen={sig_len:#x}",
        )


class TestRecoverOutputLengthBoundary:
    """Recover output buffers must not be overrun on valid operations."""

    def test_verify_recover_inflated_pul_data_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_VerifyRecover`` with ``*pulDataLen`` high 32 bits set must not crash.

        The output-length pointer value exceeds 32 bits: low 32 bits = 256
        (the actual output buffer size), high 32 bits set.  A module that writes
        only the low 32 bits of ``*pulDataLen`` leaves the high half intact;
        the surviving large value then drives an oversized output copy (OOB).
        A conformant module treats ``*pulDataLen`` as a capacity and writes only
        the actual recovered length (≤256); the high bits are irrelevant to a
        correct implementation.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        result = run_probe(
            "recover_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "verify_inflated_out_len",
            },
            pin=pin_from_config(p11_config),
            timeout=20,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_VerifyRecover(*pulDataLen={_R6_INFLATED_PULDATALEN:#x})",
        )
        rv = _parse_output_value(result.stdout, "CKR:")
        classify_negative_rv(
            rv,
            (CKR_BUFFER_TOO_SMALL,),
            label=(
                f"C_VerifyRecover with *pulDataLen={_R6_INFLATED_PULDATALEN:#x} (high 32 bits set)"
            ),
            allow_ok=True,
        )

    def test_verify_recover_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_VerifyRecover`` with one declared output byte preserves guard bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        result = run_probe(
            "recover_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "verify_one_byte_guard",
            },
            pin=pin_from_config(p11_config),
            timeout=20,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_VerifyRecover one-byte output buffer guard",
        )
        rv = _parse_output_value(result.stdout, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            needed = _parse_output_value(result.stdout, "NEEDED:")
            out_len = _parse_output_value(result.stdout, "LEN:")
            # PKCS#11 v3.2 §5.2: both the NULL-size-query length and the
            # CKR_BUFFER_TOO_SMALL *pulBufLen may over-estimate, so they need not be
            # equal. Only a length that does not exceed the 1-byte probe buffer is a
            # self-contradiction (module said "too small" yet needs <= 1 byte).
            if out_len <= 1:
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label="C_VerifyRecover one-byte output buffer length",
                    actual=out_len,
                    summary=f"CKR_BUFFER_TOO_SMALL but reported needed length {out_len} <= 1",
                )
            elif out_len != needed:
                compliance.note(
                    "C_VerifyRecover size-query length "
                    f"{needed} != BUFFER_TOO_SMALL length {out_len} "
                    "(both spec-legal over-estimates)",
                    ComplianceLevel.EXTENDED,
                )
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_VerifyRecover with a one-byte output buffer",
            )

    def test_sign_recover_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_SignRecover`` with one declared output byte preserves guard bytes.

        Mirrors the verify-recover guard probe on the sign side: ``C_SignRecoverInit``
        -> NULL-output size query -> real call with a 1-byte guard-backed output
        buffer (NO re-Init -- the size query does not terminate the operation).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        result = run_probe(
            "recover_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "sign_one_byte_guard",
            },
            pin=pin_from_config(p11_config),
            timeout=20,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_SignRecover one-byte output buffer guard",
        )
        rv = _parse_output_value(result.stdout, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            needed = _parse_output_value(result.stdout, "NEEDED:")
            out_len = _parse_output_value(result.stdout, "LEN:")
            # PKCS#11 v3.2 §5.2: both the NULL-size-query length and the
            # CKR_BUFFER_TOO_SMALL *pulBufLen may over-estimate, so they need not be
            # equal. Only a length that does not exceed the 1-byte probe buffer is a
            # self-contradiction (module said "too small" yet needs <= 1 byte).
            if out_len <= 1:
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label="C_SignRecover one-byte output buffer length",
                    actual=out_len,
                    summary=f"CKR_BUFFER_TOO_SMALL but reported needed length {out_len} <= 1",
                )
            elif out_len != needed:
                compliance.note(
                    "C_SignRecover size-query length "
                    f"{needed} != BUFFER_TOO_SMALL length {out_len} "
                    "(both spec-legal over-estimates)",
                    ComplianceLevel.EXTENDED,
                )
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_SignRecover with a one-byte output buffer",
            )
