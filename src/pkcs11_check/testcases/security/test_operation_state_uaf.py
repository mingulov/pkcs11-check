"""Operation-state use-after-free: ``C_DestroyObject`` mid-operation.

After ``C_DestroyObject`` on a key with an active operation, the operation's
stored key reference may point to freed memory if the module holds a raw pointer
rather than copying key material at ``*Init`` time.  The next completion call
then dereferences freed memory → heap-use-after-free.

Conformant behaviour: either the destroy is refused while the operation is
active, OR the completion call returns a clean error, OR (for snapshot-based
implementations) the operation completes with ``CKR_OK`` because key material
was copied at ``*Init`` time.  The **one** hard requirement is no crash.

Fifteen probes (single-threaded, no race required):

- Sign (HMAC)             — ``CKM_SHA256_HMAC`` key destroyed between
  ``C_SignInit`` and ``C_Sign``.
- Encrypt/Decrypt (AES)   — parametrized family over ECB / CBC / CTR / GCM
  (8 test cases): AES key destroyed between ``C_EncryptInit``/``C_DecryptInit``
  and the completion call.  Encrypt cases additionally carry a wrong-output
  oracle: the expected ciphertext is captured with the live key before the
  destroy; if the post-destroy encrypt also completes the outputs are compared
  for a crypto self-contradiction.
- Digest                  — ``C_DigestInit(CKM_SHA256)`` then ``C_DigestKey``
  on the already-destroyed key handle.
- Verify                  — ``CKM_SHA256_HMAC`` key destroyed between
  ``C_VerifyInit`` and ``C_Verify``.
- Derive                  — EC private key destroyed before ``C_DeriveKey``; the
  module must reject the stale handle cleanly, not dereference freed memory.
- Cross-session           — token HMAC key sign-inited from session A, destroyed
  from session B, then ``C_Sign`` completed in session A; CWE-416 across session
  boundaries. (Token object cleaned up; test skips if token creation fails.)
- Sign (ECDSA)            — EC private key destroyed between
  ``C_SignInit(CKM_ECDSA)`` and ``C_Sign``; asymmetric scalar operation on
  possibly-freed key material.
- Decrypt (RSA)           — RSA private key destroyed between
  ``C_DecryptInit(CKM_RSA_PKCS)`` and ``C_Decrypt``; invalid ciphertext (zero
  bytes) so a clean decrypt error is also acceptable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.raw.types_std import (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# CKRs accepted as a "clean" completion after the key handle was destroyed.
# allow_ok=True is also passed so snapshot-based modules (which copied key
# material at *Init time) can return CKR_OK without being flagged.
_COMPLETION_REJECT_RVS = (
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_KEY_HANDLE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)

# For the RSA decrypt probe the ciphertext is intentionally invalid (256 zero
# bytes), so a snapshot-based module that copied the key at *Init time may
# proceed to decrypt and then reject the bad ciphertext with one of these
# spec-defined codes — both are conformant, not findings.
_RSA_DECRYPT_REJECT_RVS = _COMPLETION_REJECT_RVS + (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)

# For the AES-GCM decrypt probe the 16-byte input is a 0-byte ciphertext plus
# a 16-byte authentication tag.  A conformant module that copied the key at
# *Init time may proceed to decrypt and reject the bad tag with one of these
# spec-defined codes — both are conformant, not findings.  (ECB/CBC/CTR are
# unaffected: they complete with CKR_OK on the valid 16-byte block.)
_AES_DECRYPT_REJECT_RVS = _COMPLETION_REJECT_RVS + (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)


def _parse_rv(output: str, prefix: str) -> int | None:
    """Return the integer rv printed as ``<prefix>0x…`` or ``None`` if absent."""
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


def _parse_line(output: str, prefix: str) -> str | None:
    """Return the value printed as ``<prefix><value>`` or ``None`` if absent."""
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    return None


# ---------------------------------------------------------------------------
# Sign probe (CKM_SHA256_HMAC)
# ---------------------------------------------------------------------------


class TestSignOperationStateUAF:
    """``C_Sign`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the HMAC key mid-sign must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  A conformant module either refuses
        the destroy while the operation is active, invalidates the operation so
        ``C_Sign`` returns a clean error, or (snapshot-based) completes normally.
        A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign after C_DestroyObject (operation-state UAF)",
        )
        sign_rv = _parse_rv(out, "SIGN_RV:")
        if sign_rv is not None:
            classify_negative_rv(
                sign_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign after destroy of active HMAC key",
                allow_ok=True,
            )
        sign_rv2 = _parse_rv(out, "SIGN_RV2:")
        if sign_rv2 is not None:
            classify_negative_rv(
                sign_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(2nd pass) after destroy of active HMAC key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# AES destroy-mid-operation UAF (ECB / CBC / CTR / GCM) — parametrized family
# ---------------------------------------------------------------------------

# (label, has_mechanism_name, ckm_const_name)
_AES_UAF_CASES = [
    ("AES-ECB", "AES_ECB", "CKM_AES_ECB"),
    ("AES-CBC", "AES_CBC", "CKM_AES_CBC"),
    ("AES-CTR", "AES_CTR", "CKM_AES_CTR"),
    ("AES-GCM", "AES_GCM", "CKM_AES_GCM"),
]


@pytest.mark.parametrize("label,mech_name,ckm", _AES_UAF_CASES)
class TestAesEncryptDestroyUAF:
    """Parametrized AES ``C_Encrypt`` after ``C_DestroyObject`` — ECB/CBC/CTR/GCM."""

    def test_encrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        label: str,
        mech_name: str,
        ckm: str,
    ) -> None:
        """Destroying the AES key mid-encrypt must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  The probe covers ECB, CBC, CTR, and
        GCM mechanism variants to exercise different parameter-carrying code paths.
        An encrypt oracle captures the expected ciphertext before the destroy; if the
        post-destroy ``C_Encrypt`` also completes, the outputs are compared for a
        crypto self-contradiction (use-after-free corrupting the key material).
        A crash is the primary finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "aes_encrypt",
                "ckm": ckm,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context=f"C_Encrypt({ckm}) after C_DestroyObject (operation-state UAF)",
        )
        enc_rv = _parse_rv(out, "ENCRYPT_RV:")
        if enc_rv is not None:
            classify_negative_rv(
                enc_rv,
                _COMPLETION_REJECT_RVS,
                label=f"C_Encrypt({label}) after destroy of active AES key",
                allow_ok=True,
            )
        enc_rv2 = _parse_rv(out, "ENCRYPT_RV2:")
        if enc_rv2 is not None:
            classify_negative_rv(
                enc_rv2,
                _COMPLETION_REJECT_RVS,
                label=f"C_Encrypt({label}, 2nd pass) after destroy of active AES key",
                allow_ok=True,
            )
        # Oracle: if both the live-key reference encrypt and the post-destroy encrypt
        # completed, compare ciphertexts — a mismatch is a crypto self-contradiction.
        expected_hex = _parse_line(out, "EXPECTED:")
        ct_hex = _parse_line(out, "ENCRYPT_CT:")
        if expected_hex is not None and ct_hex is not None and expected_hex != ct_hex:
            fail_as(
                "self_contradiction",
                kind="crypto",
                label=(
                    f"{label} C_Encrypt after C_DestroyObject produced output differing"
                    " from the live-key encryption (use-after-free corrupted the key)"
                ),
            )


@pytest.mark.parametrize("label,mech_name,ckm", _AES_UAF_CASES)
class TestAesDecryptDestroyUAF:
    """Parametrized AES ``C_Decrypt`` after ``C_DestroyObject`` — ECB/CBC/CTR/GCM."""

    def test_decrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        label: str,
        mech_name: str,
        ckm: str,
    ) -> None:
        """Destroying the AES key mid-decrypt must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  The probe covers ECB, CBC, CTR, and
        GCM mechanism variants.  A crash is the primary finding; a clean error or
        (snapshot-based) success are both conformant.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "aes_decrypt",
                "ckm": ckm,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context=f"C_Decrypt({ckm}) after C_DestroyObject (operation-state UAF)",
        )
        dec_rv = _parse_rv(out, "DECRYPT_RV:")
        if dec_rv is not None:
            classify_negative_rv(
                dec_rv,
                _AES_DECRYPT_REJECT_RVS,
                label=f"C_Decrypt({label}) after destroy of active AES key",
                allow_ok=True,
            )
        dec_rv2 = _parse_rv(out, "DECRYPT_RV2:")
        if dec_rv2 is not None:
            classify_negative_rv(
                dec_rv2,
                _AES_DECRYPT_REJECT_RVS,
                label=f"C_Decrypt({label}, 2nd pass) after destroy of active AES key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Digest probe (CKM_SHA256 + C_DigestKey on destroyed handle)
# ---------------------------------------------------------------------------


class TestDigestOperationStateUAF:
    """``C_DigestKey`` on a destroyed handle must not cause a use-after-free crash."""

    def test_digest_key_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Using a destroyed key handle in ``C_DigestKey`` must not UAF.

        After ``C_DestroyObject`` on the key, ``C_DigestKey`` may dereference
        the operation's stored key reference, which now points to freed memory.
        A crash is the finding.  A conformant module either refuses the destroy
        while the digest is active, returns a clean error from ``C_DigestKey``,
        or (if it snapshotted the key value at import) succeeds.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_DigestKey after C_DestroyObject (operation-state UAF)",
        )
        digest_key_rv = _parse_rv(out, "DIGEST_KEY_RV:")
        if digest_key_rv is not None:
            classify_negative_rv(
                digest_key_rv,
                _COMPLETION_REJECT_RVS,
                label="C_DigestKey on destroyed key handle",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Verify probe (CKM_SHA256_HMAC)
# ---------------------------------------------------------------------------


class TestVerifyOperationStateUAF:
    """``C_Verify`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_verify_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the HMAC key mid-verify must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, ``C_Verify`` may dereference
        the operation's stored key reference, which now points to freed memory
        (CWE-416).  A conformant module either refuses the destroy while the
        operation is active, invalidates the operation so ``C_Verify`` returns a
        clean error, or (snapshot-based) completes normally.  A crash is the
        finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Verify after C_DestroyObject (operation-state UAF)",
        )
        verify_rv = _parse_rv(out, "VERIFY_RV:")
        if verify_rv is not None:
            classify_negative_rv(
                verify_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Verify after destroy of active HMAC verify key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Derive probe (CKM_ECDH1_DERIVE — use-after-destroy of the base private key)
# ---------------------------------------------------------------------------
#
# C_DeriveKey is atomic (no Init/complete split), so the UAF pattern is
# modelled as a use-after-destroy of the base key handle: generate an EC
# keypair, destroy the private key, then call C_DeriveKey with the stale
# handle.  A conformant module must reject the stale handle with a clean
# CKR (e.g. CKR_KEY_HANDLE_INVALID / CKR_OBJECT_HANDLE_INVALID) without
# dereferencing freed memory.


class TestDeriveOperationStateUAF:
    """``C_DeriveKey`` with a destroyed base-key handle must not cause a UAF crash."""

    def test_derive_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Using a destroyed private-key handle in ``C_DeriveKey`` must not UAF.

        ``C_DeriveKey`` is atomic (no Init/complete split), so the use-after-free
        pattern is modelled as a use-after-destroy of the base key: the EC private
        key is destroyed immediately before ``C_DeriveKey`` is called with the stale
        handle.  A conformant module must reject the stale handle with a clean error
        (CWE-416) rather than dereferencing freed memory.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "derive",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_DeriveKey with destroyed base-key handle (use-after-destroy)",
        )
        derive_rv = _parse_rv(out, "DERIVE_RV:")
        if derive_rv is not None:
            classify_negative_rv(
                derive_rv,
                _COMPLETION_REJECT_RVS,
                label="C_DeriveKey with destroyed EC private key handle",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Cross-session probe: token key sign-inited in session A, destroyed from B
# ---------------------------------------------------------------------------
#
# Token objects are shared across sessions on the same slot.  If the module
# tracks the key reference by raw pointer and a second session frees the
# object store entry, the first session's pending C_Sign may dereference freed
# memory.  The probe exercises this path single-threadedly, sequentially:
#   Session A: C_SignInit(token_key)
#   Session B: C_DestroyObject(token_key)
#   Session A: C_Sign(...)
# A crash is the only finding; completion and clean rejection are both
# conformant (CWE-416, PKCS#11 object-lifecycle / session-sharing semantics).


class TestCrossSessionOperationStateUAF:
    """Cross-session UAF: token key destroyed from session B during active sign in A."""

    def test_cross_session_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying a token key from session B while session A has it sign-inited.

        Token objects are visible across all sessions on the same slot.  If the
        module tracks the active operation's key by raw pointer and another session
        frees the backing object, the pending ``C_Sign`` in session A may dereference
        freed memory (CWE-416).  Conformant outcomes: the destroy is refused while
        the operation is active, the operation is invalidated so ``C_Sign`` returns a
        clean error, or (snapshot-based) the sign completes normally.  A crash is the
        finding.  The token object is cleaned up before the probe exits so no
        persistent mutation is left on the token.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "cross_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign in session A after C_DestroyObject from session B (cross-session UAF)",
        )
        xsession_rv = _parse_rv(out, "XSESSION_SIGN_RV:")
        if xsession_rv is not None:
            classify_negative_rv(
                xsession_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(session A) after cross-session destroy of active token key",
                allow_ok=True,
            )
        xsession_rv2 = _parse_rv(out, "XSESSION_SIGN_RV2:")
        if xsession_rv2 is not None:
            classify_negative_rv(
                xsession_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(session A, 2nd pass) after cross-session destroy of active token key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# ECDSA sign probe — asymmetric destroy-mid-sign
# ---------------------------------------------------------------------------
#
# C_SignInit(CKM_ECDSA, priv) → C_DestroyObject(priv) → C_Sign on the stale
# operation state.  ECDSA modular arithmetic dereferences the private-key scalar;
# if the module holds a raw pointer to the key's CKA_VALUE field and the object
# store entry is freed by C_DestroyObject, the subsequent C_Sign walks freed
# memory (CWE-416).  The probe is single-threaded and sequential.


class TestSignEcdsaOperationStateUAF:
    """``C_Sign`` (ECDSA) after ``C_DestroyObject`` on the private key must not crash."""

    def test_ecdsa_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the EC private key mid-ECDSA-sign must not cause a UAF crash.

        After ``C_DestroyObject`` on the active EC private key, the operation's stored
        key reference may point to freed memory (CWE-416).  A conformant module either
        refuses the destroy while the operation is active, invalidates the operation so
        ``C_Sign`` returns a clean error, or (snapshot-based) completes normally.  A
        crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ecdsa_sign",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign(ECDSA) after C_DestroyObject (operation-state UAF)",
        )
        sign_rv = _parse_rv(out, "SIGN_RV:")
        if sign_rv is not None:
            classify_negative_rv(
                sign_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(ECDSA) after destroy of active EC private key",
                allow_ok=True,
            )
        sign_rv2 = _parse_rv(out, "SIGN_RV2:")
        if sign_rv2 is not None:
            classify_negative_rv(
                sign_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(ECDSA, 2nd pass) after destroy of active EC private key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# RSA decrypt probe — asymmetric destroy-mid-decrypt
# ---------------------------------------------------------------------------
#
# C_DecryptInit(CKM_RSA_PKCS, priv) → C_DestroyObject(priv) → C_Decrypt on
# a modulus-sized zero buffer.  RSA PKCS#1 v1.5 decryption performs private-key
# scalar operations that dereference the CRT key material; if the module holds
# raw pointers into the object store entry freed by C_DestroyObject, the
# subsequent C_Decrypt walks freed memory (CWE-416).  The ciphertext is
# intentionally invalid (256 zero bytes) so a clean decrypt error is acceptable;
# the only hard requirement is no crash.


class TestDecryptRsaOperationStateUAF:
    """``C_Decrypt`` (RSA_PKCS) after ``C_DestroyObject`` on the active key must not crash."""

    def test_rsa_decrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the RSA private key mid-decrypt must not cause a UAF crash.

        After ``C_DestroyObject`` on the active RSA private key, the operation's stored
        key reference may point to freed memory (CWE-416).  A conformant module either
        refuses the destroy while the operation is active, invalidates the operation so
        ``C_Decrypt`` returns a clean error, or (snapshot-based) proceeds to a clean
        error on the invalid ciphertext.  A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "rsa_decrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Decrypt(RSA_PKCS) after C_DestroyObject (operation-state UAF)",
        )
        dec_rv = _parse_rv(out, "DECRYPT_RV:")
        if dec_rv is not None:
            classify_negative_rv(
                dec_rv,
                _RSA_DECRYPT_REJECT_RVS,
                label="C_Decrypt(RSA_PKCS) after destroy of active RSA private key",
                allow_ok=True,
            )
        dec_rv2 = _parse_rv(out, "DECRYPT_RV2:")
        if dec_rv2 is not None:
            classify_negative_rv(
                dec_rv2,
                _RSA_DECRYPT_REJECT_RVS,
                label="C_Decrypt(RSA_PKCS, 2nd pass) after destroy of active RSA private key",
                allow_ok=True,
            )
