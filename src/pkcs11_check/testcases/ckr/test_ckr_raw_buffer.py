"""CKR buffer sizing tests via raw ctypes calls.

Tests CKR_BUFFER_TOO_SMALL: output functions with undersized buffers.
Uses pkcs11_check.raw.RawPKCS11 - wrapper handles buffer sizing internally.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.types_std import CKR_BUFFER_TOO_SMALL, CKR_OK
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    """Launch the ``ckr_raw_buffer`` probe (Level.LOGIN) and return (rc, out, err).

    The PIN travels solely through ``_P11CHECK_PIN`` (via ``pin_from_config`` ->
    ``run_probe``); it is never embedded in the probe source or params (Invariant I3).
    """
    result = run_probe(
        "ckr_raw_buffer",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


def _parse_output_value(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


def classify_undersized_digest_outcome(overwritten: int, ckr_ok: bool) -> None:
    """Classify C_Digest's response to an undersized (1-byte) output buffer.

    The probe over-allocates the real buffer but declares ``*pulDigestLen = 1``
    and counts how many bytes were written past that declared boundary, so the
    return code and an actual out-of-bounds write are SEPARATE signals:

    - ``overwritten > 0`` -> the module wrote past the declared buffer: a real
      OOB write (would corrupt a genuinely 1-byte caller buffer) -> ``fail``,
      regardless of the return code.
    - ``CKR_OK`` with ``overwritten == 0`` -> the module returned success but did
      NOT overflow: a clean PKCS#11 §5.10.2 return-code deviation (it should have
      returned ``CKR_BUFFER_TOO_SMALL``) with no security impact -> ``xfail``,
      recorded not hidden. (Every probed provider takes this path; the original
      "SECURITY" hard-fail conflated a benign return-code deviation with a buffer
      overflow.)
    - otherwise (CKR_BUFFER_TOO_SMALL, no overwrite) -> returns; the caller runs
      the size-query retry checks.
    """
    if overwritten > 0:
        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            f"C_Digest wrote {overwritten} bytes past a declared 1-byte output buffer.",
            ComplianceLevel.CRITICAL,
            reference="PKCS#11 v3.2",
        )
        # A real out-of-bounds write past the declared output buffer: the module
        # ignored the declared size it was given -> self-contradiction.
        classify(
            "self_contradiction",
            kind="policy",
            label="C_Digest:undersized-output-buffer",
            operation="C_Digest",
            spec_ref="PKCS#11 v3.2",
            summary=(
                f"SECURITY: C_Digest wrote {overwritten} bytes past a declared 1-byte output "
                f"buffer (out-of-bounds write)"
            ),
        )
    if ckr_ok:
        # CKR_OK with no overflow: a benign return-code deviation (should have
        # returned CKR_BUFFER_TOO_SMALL) with no security impact -> xfail.
        classify(
            "honest_deviation",
            label="C_Digest:undersized-output-buffer",
            operation="C_Digest",
            spec_ref="PKCS#11 v3.2",
            summary=(
                "C_Digest returned CKR_OK for a 1-byte output buffer without writing past it "
                "(PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, "
                "no buffer overflow)"
            ),
        )


class TestBufferTooSmall:
    """Output operations with undersized buffers."""

    def test_digest_buffer_too_small(self, p11_config: Any) -> None:
        """C_Digest with 1-byte output -> CKR_BUFFER_TOO_SMALL.

        PKCS#11 v3.2: C_Digest with undersized output buffer MUST return
        CKR_BUFFER_TOO_SMALL and update *pulDigestLen with the required size.

        Uses a 64-byte buffer filled with guard bytes (0xAA) and passes out_len=1.
        After the call, checks how many guard bytes were overwritten to confirm
        whether the module actually wrote past the declared buffer boundary.
        """
        rc, out, err = _run_probe(p11_config, "digest_buffer_too_small")
        assert_ckr_subprocess_ok(rc, out, err, context="C_Digest undersized buffer")
        # Parse overflow evidence from subprocess output
        overwritten = 0
        for line in out.splitlines():
            if line.startswith("OVERWRITTEN:"):
                overwritten = int(line.split(":")[1])
        classify_undersized_digest_outcome(overwritten, ckr_ok="CKR:0x00000000" in out)
        if "CKR:0x00000150" in out:
            retry_rv = _parse_output_value(out, "RETRY_CKR:")
            retry_len = _parse_output_value(out, "RETRY_LEN:")
            retry_match = _parse_output_value(out, "RETRY_MATCH:")
            assert retry_rv == CKR_OK, (
                "C_Digest was not retryable after CKR_BUFFER_TOO_SMALL; "
                f"retry returned 0x{retry_rv:08x}"
            )
            assert retry_len == 32, f"C_Digest retry length {retry_len}, expected 32"
            assert retry_match == 1, "C_Digest retry returned the wrong digest"

    def test_encrypt_buffer_too_small(self, p11_config: Any) -> None:
        """C_Encrypt AES-ECB with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_probe(p11_config, "encrypt_buffer_too_small")
        assert_ckr_subprocess_ok(rc, out, err, context="C_Encrypt undersized buffer")

    def test_sign_buffer_too_small(self, p11_config: Any) -> None:
        """C_Sign with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_probe(p11_config, "sign_buffer_too_small")
        assert_ckr_subprocess_ok(rc, out, err, context="C_Sign undersized buffer")
        retry_rv = _parse_output_value(out, "RETRY_CKR:")
        retry_len = _parse_output_value(out, "RETRY_LEN:")
        assert retry_rv == CKR_OK, (
            f"C_Sign was not retryable after CKR_BUFFER_TOO_SMALL; retry returned 0x{retry_rv:08x}"
        )
        assert retry_len == 256, f"C_Sign retry length {retry_len}, expected 256"


class TestListBufferTooSmallGuards:
    """List-returning APIs must not write past the declared output count."""

    def test_get_slot_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetSlotList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_slot_list_guard")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_GetSlotList undersized list buffer guard",
        )

    def test_get_mechanism_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetMechanismList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_mechanism_list_guard")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_GetMechanismList undersized list buffer guard",
        )

    def test_get_interface_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetInterfaceList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_interface_list_guard")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_GetInterfaceList undersized list buffer guard",
        )


class TestSearchOutputGuards:
    """Search APIs must not write past the declared object-handle count."""

    def test_find_objects_max_count_one_preserves_guard(self, p11_config: Any) -> None:
        """C_FindObjects must return at most ulMaxObjectCount handles."""
        rc, out, err = _run_probe(p11_config, "find_objects_max_count_one_guard")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_FindObjects one-handle output guard",
        )


class TestAttributeBufferTooSmallGuards:
    """C_GetAttributeValue must preserve caller buffers and size state."""

    def test_get_attribute_value_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_GetAttributeValue must not write past an undersized attribute buffer."""
        rc, out, err = _run_probe(p11_config, "get_attribute_value_guard")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_GetAttributeValue undersized attribute buffer guard",
        )


class TestDecryptBufferTooSmallGuards:
    """Decrypt output APIs must preserve state after CKR_BUFFER_TOO_SMALL."""

    def test_aes_cbc_pad_decrypt_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_Decrypt(CKM_AES_CBC_PAD) must be retryable after an undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_buffer_too_small")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_Decrypt AES-CBC-PAD undersized output buffer guard",
        )

    def test_aes_cbc_pad_decrypt_update_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_DecryptUpdate(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_update_buffer_too_small")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_DecryptUpdate AES-CBC-PAD undersized output buffer guard",
        )
        rv = _parse_output_value(out, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            retry_usable = _parse_output_value(out, "RETRY_USABLE:")
            if retry_usable == 0:
                # Reported CKR_BUFFER_TOO_SMALL but no usable retry length: a clean
                # sizing-contract deviation, no break -> xfail.
                classify(
                    "honest_deviation",
                    label="C_DecryptUpdate:undersized-output-buffer",
                    operation="C_DecryptUpdate",
                    summary=(
                        "C_DecryptUpdate returned CKR_BUFFER_TOO_SMALL but did not report "
                        "a usable retry length"
                    ),
                )
            retry_rv = _parse_output_value(out, "RETRY_CKR:")
            final_rv = _parse_output_value(out, "FINAL_CKR:")
            retry_match = _parse_output_value(out, "RETRY_MATCH:")
            assert retry_rv == CKR_OK, (
                "C_DecryptUpdate was not retryable after CKR_BUFFER_TOO_SMALL; "
                f"retry returned 0x{retry_rv:08x}"
            )
            assert final_rv == CKR_OK, (
                f"C_DecryptFinal after C_DecryptUpdate retry failed; returned 0x{final_rv:08x}"
            )
            assert retry_match == 1, "C_DecryptUpdate retry returned wrong plaintext"
        elif rv == CKR_OK:
            final_rv = _parse_output_value(out, "FINAL_CKR:")
            match = _parse_output_value(out, "MATCH:")
            assert final_rv == CKR_OK, (
                f"C_DecryptFinal after CKR_OK C_DecryptUpdate failed; returned 0x{final_rv:08x}"
            )
            assert match == 1, "C_DecryptUpdate/Final returned wrong plaintext"
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_DecryptUpdate with a one-byte output buffer",
            )

    def test_aes_cbc_pad_encrypt_final_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_EncryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_encrypt_final_buffer_too_small")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_EncryptFinal AES-CBC-PAD undersized output buffer guard",
        )
        rv = _parse_output_value(out, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            retry_usable = _parse_output_value(out, "RETRY_USABLE:")
            if retry_usable == 0:
                # Reported CKR_BUFFER_TOO_SMALL but no usable retry length: a clean
                # sizing-contract deviation, no break -> xfail.
                classify(
                    "honest_deviation",
                    label="C_EncryptFinal:undersized-output-buffer",
                    operation="C_EncryptFinal",
                    summary=(
                        "C_EncryptFinal returned CKR_BUFFER_TOO_SMALL but did not report "
                        "a usable retry length"
                    ),
                )
            retry_rv = _parse_output_value(out, "RETRY_CKR:")
            retry_match = _parse_output_value(out, "RETRY_MATCH:")
            assert retry_rv == CKR_OK, (
                "C_EncryptFinal was not retryable after CKR_BUFFER_TOO_SMALL; "
                f"retry returned 0x{retry_rv:08x}"
            )
            assert retry_match == 1, "C_EncryptFinal retry returned wrong ciphertext"
        elif rv != CKR_OK:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_EncryptFinal with a one-byte output buffer",
            )

    def test_aes_cbc_pad_decrypt_final_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_DecryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_final_buffer_too_small")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_DecryptFinal AES-CBC-PAD undersized output buffer guard",
        )
        rv = _parse_output_value(out, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            retry_rv = _parse_output_value(out, "RETRY_CKR:")
            retry_match = _parse_output_value(out, "RETRY_MATCH:")
            assert retry_rv == CKR_OK, (
                "C_DecryptFinal was not retryable after CKR_BUFFER_TOO_SMALL; "
                f"retry returned 0x{retry_rv:08x}"
            )
            assert retry_match == 1, "C_DecryptFinal retry returned wrong plaintext"
        elif rv != CKR_OK:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_DecryptFinal with a one-byte output buffer",
            )


class TestByteOutputBufferTooSmallGuards:
    """Byte-output APIs must not write past the declared output length."""

    def test_wrap_key_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_WrapKey with one declared byte must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "wrap_key_buffer_too_small")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_WrapKey undersized output buffer guard",
        )
        rv = _parse_output_value(out, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            needed = _parse_output_value(out, "NEEDED:")
            out_len = _parse_output_value(out, "LEN:")
            assert out_len == needed, (
                f"C_WrapKey reported required length {out_len}, expected {needed}"
            )
            retry_rv = _parse_output_value(out, "RETRY_CKR:")
            retry_len = _parse_output_value(out, "RETRY_LEN:")
            assert retry_rv == CKR_OK, (
                "C_WrapKey was not retryable after CKR_BUFFER_TOO_SMALL; "
                f"retry returned 0x{retry_rv:08x}"
            )
            assert retry_len == needed, (
                f"C_WrapKey retry produced length {retry_len}, expected {needed}"
            )
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_WrapKey with a one-byte output buffer",
            )

    def test_ecdh_aes_wrap_compressed_public_key_buffer_too_small_preserves_guard(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """ECDH-AES C_WrapKey with compressed EC public key must size safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH_AES_KEY_WRAP"):
            pytest.skip("CKM_ECDH_AES_KEY_WRAP not supported")
        if not (rs.has_mechanism("EC_KEY_PAIR_GEN") or rs.has_mechanism("ECDSA_KEY_PAIR_GEN")):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        rc, out, err = _run_probe(
            p11_config, "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        )
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="ECDH-AES C_WrapKey compressed public key undersized output buffer guard",
        )
        rv = _parse_output_value(out, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            needed = _parse_output_value(out, "NEEDED:")
            out_len = _parse_output_value(out, "LEN:")
            assert out_len == needed, (
                f"ECDH-AES C_WrapKey reported required length {out_len}, expected {needed}"
            )
            retry_rv = _parse_output_value(out, "RETRY_CKR:")
            retry_len = _parse_output_value(out, "RETRY_LEN:")
            assert retry_rv == CKR_OK, (
                "ECDH-AES C_WrapKey was not retryable after CKR_BUFFER_TOO_SMALL; "
                f"retry returned 0x{retry_rv:08x}"
            )
            assert retry_len == needed, (
                f"ECDH-AES C_WrapKey retry produced length {retry_len}, expected {needed}"
            )
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="ECDH-AES C_WrapKey with a one-byte output buffer",
            )

    def test_get_operation_state_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetOperationState with one declared byte must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_operation_state_buffer_too_small")
        assert_ckr_subprocess_ok(
            rc,
            out,
            err,
            context="C_GetOperationState undersized output buffer guard",
        )
        rv = _parse_output_value(out, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            needed = _parse_output_value(out, "NEEDED:")
            out_len = _parse_output_value(out, "LEN:")
            assert out_len == needed, (
                f"C_GetOperationState reported required length {out_len}, expected {needed}"
            )
            retry_rv = _parse_output_value(out, "RETRY_CKR:")
            retry_len = _parse_output_value(out, "RETRY_LEN:")
            assert retry_rv == CKR_OK, (
                "C_GetOperationState was not retryable after CKR_BUFFER_TOO_SMALL; "
                f"retry returned 0x{retry_rv:08x}"
            )
            assert retry_len == needed, (
                f"C_GetOperationState retry produced length {retry_len}, expected {needed}"
            )
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_GetOperationState with a one-byte output buffer",
            )
