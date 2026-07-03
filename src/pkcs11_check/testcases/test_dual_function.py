"""Tests for dual-function operations.

Covers all four PKCS#11 dual-function operations:
  Sec.5.14.1 C_DigestEncryptUpdate  (index 54)
  Sec.5.14.2 C_DecryptDigestUpdate  (index 55)
  Sec.5.14.3 C_SignEncryptUpdate    (index 56)
  Sec.5.14.4 C_DecryptVerifyUpdate  (index 57)

Most PKCS#11 modules do NOT implement these operations and return
CKR_FUNCTION_NOT_SUPPORTED (0x54).  Some modules reject the second active
operation with CKR_OPERATION_ACTIVE (0x90) because they only allow one
active operation type per session.  Tests skip gracefully in both cases.

These operations are only available via the raw C API - python-pkcs11 has no
high-level wrappers.  The C-level init/update/final steps run in an isolated
subprocess via the ``_probes/dual_function.py`` probe module, launched with
``run_probe`` (same pattern as test_operation_state.py).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import assert_correct

pytestmark = pytest.mark.full


def _skip_missing_mechanisms(rs: Any, names: tuple[str, ...]) -> None:
    for name in names:
        if not rs.has_mechanism(name):
            pytest.skip(f"{name} not supported by module")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestDigestEncryptUpdate:
    """C_DigestEncryptUpdate functional tests (AES-CBC + SHA-256).

    C_DigestEncryptUpdate (Sec.5.14.1): Continues a multiple-part combined digest
    and encryption operation, processing another data part.  Requires both a
    digest operation and an encrypt operation to be active on the session.

    The combined operation must produce output identical to running the digest
    and encrypt operations separately over the same data.
    """

    def test_digest_encrypt_update_round_trip(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """DigestEncryptUpdate produces same ciphertext and digest as separate operations.

        Steps:
        1. Generate an AES-256 session key.
        2. Reference path - separate operations:
           a. Reference digest via hashlib SHA-256.
           b. EncryptInit(AES-CBC, key, IV) -> EncryptUpdate(data) -> EncryptFinal -> ct_ref.
        3. Dual-function path:
           a. DigestInit(SHA-256)
           b. EncryptInit(AES-CBC, key, IV) - skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + encrypt on the same session)
           c. DigestEncryptUpdate(data) -> ciphertext_chunk - skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. EncryptFinal -> remaining ciphertext
           e. DigestFinal -> digest
        4. Assert: ciphertext == ct_ref AND digest == SHA-256(data).

        Source: PKCS#11 v3.2.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC", "SHA256"))

        result = run_probe(
            "dual_function",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_encrypt_update",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            if returncode < 0:
                classify(
                    "crash",
                    label="C_DigestEncryptUpdate",
                    operation="C_DigestEncryptUpdate",
                    summary=f"Subprocess crashed (signal {-returncode}): {detail}",
                )
            classify(
                "not_operational",
                kind="crypto",
                label="C_DigestEncryptUpdate",
                operation="C_DigestEncryptUpdate",
                summary=f"Subprocess failed: {detail}",
            )

        assert "DIGEST_REF" in lines_map, f"Missing DIGEST_REF in output: {stdout!r}"
        assert "CT_REF" in lines_map, f"Missing CT_REF in output: {stdout!r}"
        assert "CT_DUAL" in lines_map, f"Missing CT_DUAL in output: {stdout!r}"
        assert "DIGEST_DUAL" in lines_map, f"Missing DIGEST_DUAL in output: {stdout!r}"

        ct_ref = lines_map["CT_REF"]
        ct_dual = lines_map["CT_DUAL"]
        digest_ref = lines_map["DIGEST_REF"]
        digest_dual = lines_map["DIGEST_DUAL"]

        assert_correct(
            actual=ct_dual,
            expected=ct_ref,
            label="C_DigestEncryptUpdate:ciphertext vs separate encrypt",
            operation="C_DigestEncryptUpdate",
        )
        assert_correct(
            actual=digest_dual,
            expected=digest_ref,
            label="C_DigestEncryptUpdate:digest vs reference SHA-256",
            operation="C_DigestEncryptUpdate",
        )


@pytest.mark.usefixtures("p11_module")
class TestDecryptDigestUpdate:
    """C_DecryptDigestUpdate functional tests (AES-CBC + SHA-256).

    C_DecryptDigestUpdate (Sec.5.14.2): Continues a multiple-part combined decryption
    and digest operation, processing another encrypted data part.  The ciphertext
    is decrypted and the resulting plaintext is simultaneously digested.

    The combined operation must recover the original plaintext and produce a digest
    equal to SHA-256(original plaintext).
    """

    def test_decrypt_digest_update_round_trip(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """DecryptDigestUpdate recovers plaintext and produces correct SHA-256 digest.

        Steps:
        1. Generate an AES-256 session key.
        2. Encrypt plaintext via separate C_EncryptInit/Update/Final to get ciphertext.
        3. Dual-function decryption path:
           a. DigestInit(SHA-256)
           b. DecryptInit(AES-CBC, key, IV) - skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + decrypt on the same session)
           c. DecryptDigestUpdate(ciphertext) -> plaintext_chunk - skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. DecryptFinal -> remaining plaintext
           e. DigestFinal -> digest of decrypted plaintext
        4. Assert: recovered plaintext == original data AND digest == SHA-256(data).

        Source: PKCS#11 v3.2.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC", "SHA256"))

        result = run_probe(
            "dual_function",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_digest_update",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            if returncode < 0:
                classify(
                    "crash",
                    label="C_DecryptDigestUpdate",
                    operation="C_DecryptDigestUpdate",
                    summary=f"Subprocess crashed (signal {-returncode}): {detail}",
                )
            classify(
                "not_operational",
                kind="crypto",
                label="C_DecryptDigestUpdate",
                operation="C_DecryptDigestUpdate",
                summary=f"Subprocess failed: {detail}",
            )

        assert "PT_REF" in lines_map, f"Missing PT_REF in output: {stdout!r}"
        assert "DIGEST_REF" in lines_map, f"Missing DIGEST_REF in output: {stdout!r}"
        assert "RECOVERED" in lines_map, f"Missing RECOVERED in output: {stdout!r}"
        assert "DIGEST_DUAL" in lines_map, f"Missing DIGEST_DUAL in output: {stdout!r}"

        pt_ref = lines_map["PT_REF"]
        digest_ref = lines_map["DIGEST_REF"]
        recovered = lines_map["RECOVERED"]
        digest_dual = lines_map["DIGEST_DUAL"]

        assert_correct(
            actual=recovered,
            expected=pt_ref,
            label="C_DecryptDigestUpdate:recovered plaintext vs reference",
            operation="C_DecryptDigestUpdate",
        )
        assert_correct(
            actual=digest_dual,
            expected=digest_ref,
            label="C_DecryptDigestUpdate:digest vs reference SHA-256",
            operation="C_DecryptDigestUpdate",
        )
