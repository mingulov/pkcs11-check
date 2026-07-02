"""CKR multipart operation error tests via raw ctypes calls.

Tests CKR conditions that python-pkcs11 wrapper prevents:
- C_EncryptUpdate/Final without C_EncryptInit
- C_DecryptUpdate/Final without C_DecryptInit
- C_SignUpdate/Final without C_SignInit
- C_DigestUpdate/Final without C_DigestInit
- C_DigestUpdate after a successful C_DigestFinal (operation-terminated state)

Each test launches the ``ckr_raw_multipart`` probe module (``_probes/ckr_raw_multipart.py``)
via ``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a PIN is
configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN`` env var
(never embedded in source or params -- Invariant I3).  This CLOSES the legacy leak that
formatted the PIN literal into the generated child-script source.  The probe drives the
per-test multipart call and prints the resulting ``CKR:0x...`` line for the parent-side
``_classify_multipart_ckr`` classifier.  Raw calls run in the subprocess for crash survival.

Requires: pkcs11.raw.RawPKCS11
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_OPERATION_NOT_INITIALIZED
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _classify_multipart_ckr(out: str, *, label: str) -> None:
    """Parent-side 3-way classifier over a child script's ``CKR:0x...`` line.

    A C_*Update/Final without the matching C_*Init must reject with
    CKR_OPERATION_NOT_INITIALIZED. Classification happens here (not via an
    in-child ``assert``) so a non-spec clean reject becomes ``xfail`` instead of
    crashing the child and being mislabeled as a crash:

    - ``CKR_OK`` (the multipart op ran without init) -> ``fail``,
    - ``CKR_OPERATION_NOT_INITIALIZED`` (spec) -> ``pass``,
    - any other clean reject code -> ``xfail``.
    """
    rv: int | None = None
    for line in out.splitlines():
        if line.startswith("CKR:0x"):
            rv = int(line.removeprefix("CKR:"), 16)
            break
    assert rv is not None, f"{label}: no CKR line in child output: {out!r}"
    classify_negative_rv(rv, (CKR_OPERATION_NOT_INITIALIZED,), label=label)


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    """Launch the ``ckr_raw_multipart`` probe (Level.LOGIN) and return (rc, out, err)."""
    result = run_probe(
        "ckr_raw_multipart",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


class TestMultipartNotInitialized:
    """C_*Update/Final without Init -> CKR_OPERATION_NOT_INITIALIZED."""

    def test_encrypt_update_no_init(self, p11_config: Any) -> None:
        """C_EncryptUpdate without C_EncryptInit."""
        rc, out, err = _run_probe(p11_config, "encrypt_update")
        assert_ckr_subprocess_ok(rc, out, err, context="C_EncryptUpdate without init")
        _classify_multipart_ckr(out, label="C_EncryptUpdate without C_EncryptInit")

    def test_encrypt_final_no_init(self, p11_config: Any) -> None:
        """C_EncryptFinal without C_EncryptInit."""
        rc, out, err = _run_probe(p11_config, "encrypt_final")
        assert_ckr_subprocess_ok(rc, out, err, context="C_EncryptFinal without init")
        _classify_multipart_ckr(out, label="C_EncryptFinal without C_EncryptInit")

    def test_decrypt_update_no_init(self, p11_config: Any) -> None:
        """C_DecryptUpdate without C_DecryptInit."""
        rc, out, err = _run_probe(p11_config, "decrypt_update")
        assert_ckr_subprocess_ok(rc, out, err, context="C_DecryptUpdate without init")
        _classify_multipart_ckr(out, label="C_DecryptUpdate without C_DecryptInit")

    def test_sign_update_no_init(self, p11_config: Any) -> None:
        """C_SignUpdate without C_SignInit."""
        rc, out, err = _run_probe(p11_config, "sign_update")
        assert_ckr_subprocess_ok(rc, out, err, context="C_SignUpdate without init")
        _classify_multipart_ckr(out, label="C_SignUpdate without C_SignInit")

    def test_digest_update_no_init(self, p11_config: Any) -> None:
        """C_DigestUpdate without C_DigestInit."""
        rc, out, err = _run_probe(p11_config, "digest_update")
        assert_ckr_subprocess_ok(rc, out, err, context="C_DigestUpdate without init")
        _classify_multipart_ckr(out, label="C_DigestUpdate without C_DigestInit")

    def test_digest_final_no_init(self, p11_config: Any) -> None:
        """C_DigestFinal without C_DigestInit."""
        rc, out, err = _run_probe(p11_config, "digest_final")
        assert_ckr_subprocess_ok(rc, out, err, context="C_DigestFinal without init")
        _classify_multipart_ckr(out, label="C_DigestFinal without C_DigestInit")

    def test_decrypt_final_no_init(self, p11_config: Any) -> None:
        """C_DecryptFinal without C_DecryptInit."""
        rc, out, err = _run_probe(p11_config, "decrypt_final")
        assert_ckr_subprocess_ok(rc, out, err, context="C_DecryptFinal without init")
        _classify_multipart_ckr(out, label="C_DecryptFinal without C_DecryptInit")

    def test_sign_final_no_init(self, p11_config: Any) -> None:
        """C_SignFinal without C_SignInit."""
        rc, out, err = _run_probe(p11_config, "sign_final")
        assert_ckr_subprocess_ok(rc, out, err, context="C_SignFinal without init")
        _classify_multipart_ckr(out, label="C_SignFinal without C_SignInit")

    def test_verify_update_no_init(self, p11_config: Any) -> None:
        """C_VerifyUpdate without C_VerifyInit."""
        rc, out, err = _run_probe(p11_config, "verify_update")
        assert_ckr_subprocess_ok(rc, out, err, context="C_VerifyUpdate without init")
        _classify_multipart_ckr(out, label="C_VerifyUpdate without C_VerifyInit")

    def test_verify_final_no_init(self, p11_config: Any) -> None:
        """C_VerifyFinal without C_VerifyInit."""
        rc, out, err = _run_probe(p11_config, "verify_final")
        assert_ckr_subprocess_ok(rc, out, err, context="C_VerifyFinal without init")
        _classify_multipart_ckr(out, label="C_VerifyFinal without C_VerifyInit")


class TestUpdateAfterFinal:
    """C_*Update after a successfully completed C_*Final -> CKR_OPERATION_NOT_INITIALIZED.

    PKCS#11 v3.2 §5.2 specifies that a C_*Final call terminates the active
    multipart operation.  After termination the operation state is cleared;
    any subsequent C_*Update call must return CKR_OPERATION_NOT_INITIALIZED
    because there is no active operation to continue.

    Two probe variants are covered:
    - Digest (CKM_SHA_256): stateless, no key required — widest module support.
    - Encrypt (CKM_AES_ECB): requires a setup key; skips if AES_KEY_GEN or
      CKM_AES_ECB are not operational on this module.

    CKR_OK from C_*Update after C_*Final means the module continued an already-
    completed operation — a lifecycle self-contradiction (accepted_invalid).
    """

    def test_digest_update_after_final(self, p11_config: Any) -> None:
        """C_DigestUpdate after C_DigestFinal must return CKR_OPERATION_NOT_INITIALIZED.

        PKCS#11 v3.2 §5.2: C_DigestFinal terminates the active digest operation.
        Calling C_DigestUpdate on a terminated operation must be rejected.
        CKR_OK here means the module accepted data into a finished digest (lifecycle
        self-contradiction: accepted_invalid).
        """
        rc, out, err = _run_probe(p11_config, "digest_update_after_final")
        assert_ckr_subprocess_ok(rc, out, err, context="C_DigestUpdate after C_DigestFinal")
        _classify_multipart_ckr(out, label="C_DigestUpdate after C_DigestFinal")

    def test_encrypt_update_after_final(self, p11_config: Any) -> None:
        """C_EncryptUpdate after C_EncryptFinal must return CKR_OPERATION_NOT_INITIALIZED.

        PKCS#11 v3.2 §5.2: C_EncryptFinal terminates the active encryption operation.
        Calling C_EncryptUpdate on a terminated operation must be rejected.
        CKR_OK here means the module accepted plaintext into a finished encryption (lifecycle
        self-contradiction: accepted_invalid).
        """
        rc, out, err = _run_probe(p11_config, "encrypt_update_after_final")
        assert_ckr_subprocess_ok(rc, out, err, context="C_EncryptUpdate after C_EncryptFinal")
        _classify_multipart_ckr(out, label="C_EncryptUpdate after C_EncryptFinal")
