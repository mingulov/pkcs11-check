"""Tests for C_SignRecoverInit / C_SignRecover and C_VerifyRecoverInit / C_VerifyRecover.

Happy-path functional tests exercising sign-recover and verify-recover operations.

Source: PKCS#11 v3.2 (C_SignRecoverInit, C_SignRecover,
        C_VerifyRecoverInit, C_VerifyRecover).

C_SignRecover produces a signature from which the original data can be recovered.
C_VerifyRecover takes a signature and recovers the original data (and verifies it).
The primary mechanism is CKM_RSA_X_509 (raw RSA, no padding).

For RSA X.509, the input data must be padded to exactly the modulus size (2048
bits -> 256 bytes).  The token performs raw modular exponentiation; the caller is
responsible for any padding.  CKM_RSA_X_509 is widely supported in hardware and
software tokens as the recovery-capable RSA mechanism.

These operations are only accessible via the raw C API - python-pkcs11 does not
expose high-level sign_recover() / verify_recover() methods on Key or Session
objects.  Tests use a ctypes subprocess in the same pattern as test_operation_state.py.

CK_FUNCTION_LIST indices (0-based, after the CK_VERSION field):
  C_SignRecoverInit = 45
  C_SignRecover     = 46
  C_VerifyRecoverInit = 51
  C_VerifyRecover     = 52
  C_GenerateKeyPair   = 59
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_recover_single,
    verify_recover_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKM_RSA_X_509, CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import KEYPAIR_RUNTIME_REJECT_RVS, assert_correct

pytestmark = pytest.mark.full


def _handle_subprocess_failure(returncode: int, stdout: str, stderr: str) -> None:
    """Fail or xfail a raw subprocess result after checking setup-reject fatals."""
    if returncode == 0:
        return

    fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
    if fatals:
        detail = fatals[0]
        _, _, payload = detail.partition(":")
        label, _, rv_text = payload.partition(":")
        if label == "GenerateKeyPair":
            try:
                rv = int(rv_text, 16)
            except ValueError:
                rv = None
            if rv is not None and rv in KEYPAIR_RUNTIME_REJECT_RVS:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="RSA_PKCS_KEY_PAIR_GEN:keypair setup",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    actual=rv,
                    summary=f"RSA_PKCS_KEY_PAIR_GEN keypair setup rejected: {ckr_name(rv)}",
                )
    else:
        detail = f"stdout={stdout!r} stderr={stderr!r}"

    classify(
        "crash",
        label="sign-recover subprocess",
        summary=f"Subprocess failed: {detail}",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestSignRecover:
    """C_SignRecover / C_VerifyRecover functional tests using CKM_RSA_X_509.

    C_SignRecover (Sec.5.10.6): Signs data with a private key using a mechanism
    that allows the original data to be recovered from the signature.

    C_VerifyRecover (Sec.5.11.6): Verifies a signature and recovers the original
    data from the signature using the corresponding public key.

    CKM_RSA_X_509 (raw RSA) is the standard mechanism for these operations.
    The input must be padded to the modulus size (2048 bits -> 256 bytes).
    """

    def test_sign_recover_produces_output(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with RSA X.509 produces a 256-byte signature block.

        Steps:
        1. Generate RSA-2048 key pair with CKA_SIGN_RECOVER / CKA_VERIFY_RECOVER.
        2. C_SignRecoverInit(CKM_RSA_X_509, privateKey).
        3. C_SignRecover(padded_data) -> signature.
        4. Verify signature length equals modulus size (256 bytes).

        Source: PKCS#11 v3.2.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        result = run_probe(
            "sign_recover",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_recover_produces_output",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover: {lines_map['SKIP']}")

        _handle_subprocess_failure(returncode, stdout, stderr)

        assert "SIG_LEN" in lines_map, f"Missing SIG_LEN in output: {stdout!r}"
        assert "SIG" in lines_map, f"Missing SIG in output: {stdout!r}"

        sig_len = int(lines_map["SIG_LEN"])
        assert sig_len == 256, f"RSA-2048 sign-recover output must be 256 bytes, got {sig_len}"

    def test_verify_recover_round_trip(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover then C_VerifyRecover recovers the original padded data.

        Steps:
        1. Generate RSA-2048 key pair.
        2. C_SignRecoverInit -> C_SignRecover(padded_data) -> signature.
        3. C_VerifyRecoverInit -> C_VerifyRecover(signature) -> recovered_data.
        4. Assert recovered_data == padded_data.

        Source: PKCS#11 v3.2.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        result = run_probe(
            "sign_recover",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify_recover_round_trip",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign/verify-recover: {lines_map['SKIP']}")

        _handle_subprocess_failure(returncode, stdout, stderr)

        assert "ORIGINAL" in lines_map, f"Missing ORIGINAL in output: {stdout!r}"
        assert "RECOVERED" in lines_map, f"Missing RECOVERED in output: {stdout!r}"

        original = lines_map["ORIGINAL"]
        recovered = lines_map["RECOVERED"]
        assert_correct(
            actual=recovered,
            expected=original,
            label="CKM_RSA_X_509:Sign/VerifyRecover round-trip",
            operation="C_VerifyRecover",
            mechanism="CKM_RSA_X_509",
        )

    def test_sign_recover_wrong_data_length(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with wrong-length data returns a PKCS#11 error (not crash).

        For CKM_RSA_X_509 with a 2048-bit key, input must be exactly 256 bytes.
        Passing shorter data must return CKR_DATA_LEN_RANGE or CKR_ARGUMENTS_BAD
        (or similar), not crash or silently succeed.

        Source: PKCS#11 v3.2 error table.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        result = run_probe(
            "sign_recover",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_recover_wrong_data_length",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover error test: {lines_map['SKIP']}")

        _handle_subprocess_failure(returncode, stdout, stderr)

        assert "RESULT" in lines_map, f"Missing RESULT in output: {stdout!r}"

        # The module should not silently accept wrong-length data.
        # Some modules pad internally and accept any length - this is non-standard
        # for CKM_RSA_X_509 but we don't fail on it; we just note it.
        result_line = lines_map["RESULT"]
        if result_line == "ACCEPTED_SHORT_DATA":
            classify(
                "honest_deviation",
                kind="crypto",
                label="CKM_RSA_X_509:C_SignRecover short data",
                operation="C_SignRecover",
                mechanism="CKM_RSA_X_509",
                summary=(
                    "Module accepted short data for CKM_RSA_X_509 C_SignRecover - "
                    "non-standard behaviour (spec requires CKR_DATA_LEN_RANGE)"
                ),
            )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _has_rsa_x509(p11_module: Any) -> bool:
    """Return True if the module's first token supports CKM_RSA_X_509."""
    slots = list(p11_module.get_slots(token_present=True))
    if not slots:
        return False

    mechs = {getattr(m, "name", str(m)) for m in slots[0].get_mechanisms()}
    return "RSA_X_509" in mechs


class TestSignRecoverRecipes:
    """In-process tests exercising sign_recover_single / verify_recover_single recipes."""

    @staticmethod
    def _check_sign_recover(rs: Any) -> None:
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        try:
            mech = mech_simple(CKM_RSA_X_509)
            rv = rs.raw.C_SignRecoverInit(rs.sh, mech.byref(), 0)
        except (AttributeError, TypeError):
            pytest.skip("C_SignRecoverInit not available")
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            pytest.skip("C_SignRecover not supported by module")

    @staticmethod
    def _gen_recover_key(rs: Any) -> tuple[int, int]:
        TestSignRecoverRecipes._check_sign_recover(rs)
        return gen_rsa_keypair(rs.raw, rs.sh, 2048)

    def test_sign_recover_single_returns_signature(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254
            sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            assert isinstance(sig, bytes)
            assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_recover_round_trip(self, p11_raw_session: Any) -> None:
        """C_VerifyRecover should recover the original data from a valid signature.

        Some modules recover wrong/unexpected data on CKM_RSA_X_509 --
        the recovered bytes do not match the original padded input.
        """
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254
            sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            valid, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, sig)
            assert valid is True
            # Raw RSA (CKM_RSA_X_509) VerifyRecover returns sig^e mod n, i.e. the signed
            # value AS AN INTEGER. Compare as integers so a benign leading-zero / length
            # representation difference is not mis-flagged. A genuine integer mismatch IS a
            # crypto-correctness break (the module recovered the wrong value) -> wrong_result
            # (crypto fail), not a tolerable deviation. (Any documented per-module bug is
            # cross-referenced as KNOWN_ISSUE at the report layer, not hidden here.)
            recovered_int = int.from_bytes(recovered, "big") if recovered else -1
            if recovered_int != int.from_bytes(data, "big"):
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_RSA_X_509:C_VerifyRecover recovered data",
                    operation="C_VerifyRecover",
                    mechanism="CKM_RSA_X_509",
                    summary=(
                        "C_VerifyRecover recovered the wrong value for CKM_RSA_X_509 "
                        "(recovered integer != signed integer) -- crypto-correctness break"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_recover_invalid_signature(self, p11_raw_session: Any) -> None:
        """C_VerifyRecover should reject an invalid signature.

        Some modules return valid=True and non-empty recovered data for an
        invalid (all-zero) signature block, failing to detect the invalid input.
        """
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            bad_sig = b"\x00" * 256
            valid, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, bad_sig)
            if valid is True or recovered != b"":
                classify(
                    "honest_deviation",
                    kind="crypto",
                    label="CKM_RSA_X_509:C_VerifyRecover invalid signature",
                    operation="C_VerifyRecover",
                    mechanism="CKM_RSA_X_509",
                    summary=(
                        f"Module C_VerifyRecover accepted invalid all-zero signature: "
                        f"valid={valid}, recovered={recovered!r} -- "
                        f"the signature block is not validated in C_VerifyRecover"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
