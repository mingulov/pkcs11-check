"""FFI pointer-alignment hardening probes and aligned controls.

The ``TestMisaligned*`` tests exercise caller buffers whose bytes encode valid
PKCS#11 structs or scalar values but whose pointers are intentionally
1-byte-misaligned. A typed C structure pointer that is not correctly aligned
has undefined behavior on dereference, and unaligned ``CK_VOID_PTR`` scalar
storage carries no cited PKCS #11 acceptance obligation -- so whatever the
provider does with such input is a non-normative hostile-caller robustness
observation (P11C-0198-013), never a conformance or memory-safety finding.

The ``TestAligned*`` controls prove the valid-input baseline in-process with
valid typed storage: same operations, correctly aligned pointers, ``CKR_OK``
plus a verified effect. A failure here is a genuine provider finding.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.core.crash_codes import crash_detail_name, is_crash_returncode
from pkcs11_check.raw.recipes import decrypt_single, encrypt_single
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKA_TOKEN, CKM_AES_ECB
from pkcs11_check.testcases._probes.ffi_alignment import HOSTILE_CALLER_PREFIX
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    pin_from_config,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    assert_correct,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# CPython traceback header (same line `runner._PYTHON_TRACEBACK` matches): a
# hostile-path child exit carrying one is a probe bug, not provider behavior.
_TRACEBACK_LINE = "Traceback (most recent call last)"

# One AES block; the control roundtrips need no padding under AES-ECB.
_CONTROL_PLAINTEXT = b"align-ctl-block1"


def _is_hostile_caller(stdout: str) -> bool:
    """Whether the child executed the provider call with misaligned pointers."""
    return any(line.startswith(HOSTILE_CALLER_PREFIX) for line in stdout.splitlines())


def _observe_hostile_caller_robustness(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
    input_desc: str,
    test_id: str,
) -> None:
    """Record a non-normative hostile-caller robustness observation; never fail.

    The child passed 1-byte-misaligned caller pointers: a typed struct pointer
    has undefined behavior on dereference, and unaligned ``CK_VOID_PTR``
    scalar storage has no cited acceptance obligation. Whatever the provider
    did -- crash, hang, reject, or accept -- the caller owns the fault, so the
    outcome is an ``EXTENDED`` compliance note, never a conformance or
    security finding. The only loud path is a Python-traceback child exit,
    which is a probe bug.
    """
    if is_crash_returncode(rc):
        note(
            f"hostile-caller robustness observation (non-normative): {context} "
            f"with {input_desc} terminated the child "
            f"({crash_detail_name(rc)}); out-of-contract caller input -- the caller "
            "owns the fault, not the provider; not a conformance or security finding",
            ComplianceLevel.EXTENDED,
            reference="P11C-0198-013",
            test_id=test_id,
        )
        return
    if SUBPROCESS_TIMEOUT_MARKER in stderr:
        note(
            f"hostile-caller robustness observation (non-normative): {context} "
            f"with {input_desc} timed out without returning; out-of-contract "
            "caller input -- the caller owns the fault, not the provider; not a "
            "conformance or security finding",
            ComplianceLevel.EXTENDED,
            reference="P11C-0198-013",
            test_id=test_id,
        )
        return
    if rc == 0:
        rv: int | None = None
        for line in stdout.splitlines():
            if line.startswith("TARGET_RV:"):
                try:
                    rv = int(line.rsplit(":", 1)[1], 0)
                except ValueError:
                    rv = None
                break
        outcome = f"returned {ckr_name(rv)}" if rv is not None else "completed"
        note(
            f"hostile-caller robustness observation (non-normative): {context} "
            f"with {input_desc} {outcome}; out-of-contract caller input -- the "
            "caller owns the fault, not the provider; not a conformance or "
            "security finding",
            ComplianceLevel.EXTENDED,
            reference="P11C-0198-013",
            test_id=test_id,
        )
        return
    if _TRACEBACK_LINE in stderr:
        # Our probe code raised after printing the marker: a probe bug, loud
        # (AssertionError, like protocol-marker parse failures).
        raise AssertionError(
            f"{context}: hostile-path probe bug -- child exited {rc} with a "
            f"Python traceback after printing the {HOSTILE_CALLER_PREFIX} marker; "
            f"not provider behavior:\n{stderr[-1500:]}"
        )
    note(
        f"hostile-caller robustness observation (non-normative): {context} "
        f"with {input_desc} ended with exit code {rc} and no Python traceback; "
        "out-of-contract caller input -- the caller owns the fault, not the "
        "provider; not a conformance or security finding",
        ComplianceLevel.EXTENDED,
        reference="P11C-0198-013",
        test_id=test_id,
    )


class TestMisalignedAttributeValues:
    """CK_ATTRIBUTE.pValue points to unaligned scalar storage (hostile-caller)."""

    def test_generate_key_with_misaligned_scalar_attribute_values(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKey with unaligned scalar pValue pointers: observe, never fail."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        result = run_probe(
            "ffi_alignment",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "misaligned_scalar_attrs",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
            interface=getattr(p11_config, "interface", "auto"),
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        context = "C_GenerateKey with misaligned CK_ATTRIBUTE.pValue scalars"
        if _is_hostile_caller(stdout):
            _observe_hostile_caller_robustness(
                rc,
                stdout,
                stderr,
                context=context,
                input_desc="1-byte-misaligned CK_ATTRIBUTE.pValue scalar storage "
                "(CK_VOID_PTR, ambiguous contract)",
                test_id="TestMisalignedAttributeValues."
                "test_generate_key_with_misaligned_scalar_attribute_values",
            )
            return
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=context,
        )


class TestMisalignedMechanismPointer:
    """CK_MECHANISM_PTR itself points to unaligned struct storage (hostile-caller)."""

    def test_encrypt_init_with_misaligned_mechanism_pointer(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_EncryptInit with an unaligned CK_MECHANISM_PTR: observe, never fail."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        result = run_probe(
            "ffi_alignment",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "misaligned_mechanism_ptr",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
            interface=getattr(p11_config, "interface", "auto"),
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        context = "C_EncryptInit with misaligned CK_MECHANISM_PTR"
        if _is_hostile_caller(stdout):
            _observe_hostile_caller_robustness(
                rc,
                stdout,
                stderr,
                context=context,
                input_desc="1-byte-misaligned typed CK_MECHANISM_PTR "
                "(undefined behavior on dereference)",
                test_id="TestMisalignedMechanismPointer."
                "test_encrypt_init_with_misaligned_mechanism_pointer",
            )
            return
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=context,
        )


class TestAlignedAttributeValues:
    """Aligned control: the scalar template via valid typed storage must work."""

    def test_generate_key_with_aligned_scalar_attribute_values(
        self,
        p11_raw_session: Any,
    ) -> None:
        """C_GenerateKey with aligned scalar pValue storage creates a working key."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_TOKEN: False},
            purpose="aligned scalar-attribute control",
        )
        try:
            try:
                ciphertext = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, _CONTROL_PLAINTEXT)
                recovered = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ciphertext)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    CIPHER_OP_RUNTIME_REJECT_RVS,
                    "AES_ECB advertised but the aligned-control roundtrip is not operational",
                )
                raise
        finally:
            destroy_returned_handles(rs, key)
        assert_correct(
            actual=recovered,
            expected=_CONTROL_PLAINTEXT,
            label="C_GenerateKey with aligned scalar attribute values: AES-ECB roundtrip",
            operation="C_Decrypt",
            mechanism="CKM_AES_ECB",
        )


class TestAlignedMechanismPointer:
    """Aligned control: C_EncryptInit via valid typed storage must work."""

    def test_encrypt_init_with_aligned_mechanism_pointer(
        self,
        p11_raw_session: Any,
    ) -> None:
        """C_EncryptInit with an aligned CK_MECHANISM_PTR encrypts correctly."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        key = gen_aes_key_or_xfail(
            rs,
            128,
            purpose="aligned mechanism-pointer control setup",
        )
        try:
            try:
                ciphertext = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, _CONTROL_PLAINTEXT)
                recovered = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ciphertext)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    CIPHER_OP_RUNTIME_REJECT_RVS,
                    "AES_ECB advertised but aligned C_EncryptInit/C_Encrypt is not operational",
                )
                raise
        finally:
            destroy_returned_handles(rs, key)
        assert_correct(
            actual=recovered,
            expected=_CONTROL_PLAINTEXT,
            label="C_EncryptInit with aligned CK_MECHANISM_PTR: AES-ECB roundtrip",
            operation="C_Decrypt",
            mechanism="CKM_AES_ECB",
        )
