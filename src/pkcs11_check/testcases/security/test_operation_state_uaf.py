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
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
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


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


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

_DERIVE_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack_mechanisms import mech_ecdh
from pkcs11_check.raw.recipes import gen_ec_keypair, read_attributes
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKD_NULL,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKM_EC_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""

_DERIVE_UAF_BODY = """
# --- generate two EC keypairs on P-256 ---
curve_oid = encode_named_curve_parameters("secp256r1")

pub_a = CK_OBJECT_HANDLE(0)
priv_a = CK_OBJECT_HANDLE(0)

# Build the key pair template manually to keep the child script self-contained.
try:
    pub_a_h, priv_a_h = gen_ec_keypair(
        raw,
        sh,
        curve_oid,
        public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
        private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
    )
except AssertionError as exc:
    print(f"SETUP_XFAIL:EC keypair generation rejected: {exc}")
    cleanup()
    raise SystemExit(0)

try:
    pub_b_h, priv_b_h = gen_ec_keypair(
        raw,
        sh,
        curve_oid,
        public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
        private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
    )
except AssertionError as exc:
    print(f"SETUP_XFAIL:EC keypair (peer) generation rejected: {exc}")
    raw.C_DestroyObject(sh, pub_a_h)
    raw.C_DestroyObject(sh, priv_a_h)
    cleanup()
    raise SystemExit(0)

# --- read the peer public-key EC point ---
try:
    attrs_b = read_attributes(raw, sh, pub_b_h, [CKA_EC_POINT])
    ec_point_b = bytes(attrs_b[CKA_EC_POINT])
except AssertionError as exc:
    print(f"SETUP_XFAIL:Could not read peer EC point: {exc}")
    for h in (pub_a_h, priv_a_h, pub_b_h, priv_b_h):
        raw.C_DestroyObject(sh, h)
    cleanup()
    raise SystemExit(0)

# Destroy peer keypair — only the peer's public point is needed hereafter.
raw.C_DestroyObject(sh, pub_b_h)
raw.C_DestroyObject(sh, priv_b_h)

# --- destroy the *base* private key before C_DeriveKey ---
destroy_rv = raw.C_DestroyObject(sh, priv_a_h)
print(f"DESTROY_RV:0x{destroy_rv:08x}")
raw.C_DestroyObject(sh, pub_a_h)

# --- derive template: a 32-byte generic-secret ---
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
val_len_val = CK_ULONG(32)
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)

derive_tmpl = (CK_ATTRIBUTE * 5)()
derive_tmpl[0].type = CKA_CLASS
derive_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
derive_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
derive_tmpl[1].type = CKA_KEY_TYPE
derive_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
derive_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
derive_tmpl[2].type = CKA_TOKEN
derive_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
derive_tmpl[2].ulValueLen = 1
derive_tmpl[3].type = CKA_SENSITIVE
derive_tmpl[3].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
derive_tmpl[3].ulValueLen = 1
derive_tmpl[4].type = CKA_EXTRACTABLE
derive_tmpl[4].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
derive_tmpl[4].ulValueLen = 1

packed_mech = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=ec_point_b)
derived_key = CK_OBJECT_HANDLE(0)

# --- C_DeriveKey with the already-destroyed private key handle ---
derive_rv = raw.C_DeriveKey(
    sh,
    packed_mech.byref(),
    priv_a_h,
    ctypes.cast(derive_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(derived_key),
)
print(f"DERIVE_RV:0x{derive_rv:08x}")

if derive_rv == CKR_OK and derived_key.value != 0:
    raw.C_DestroyObject(sh, derived_key.value)

cleanup()
"""


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

        body = _DERIVE_UAF_IMPORTS + _DERIVE_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
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

_XSESSION_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_NOTIFY,
    CK_OBJECT_HANDLE,
    CK_SESSION_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_OK,
)
"""

_XSESSION_UAF_BODY = """
# --- create a TOKEN sign key on session A (sh) ---
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
token_true = ctypes.c_ubyte(1)
sign_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 5)()
tmpl[0].type = CKA_CLASS
tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
tmpl[1].type = CKA_KEY_TYPE
tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
tmpl[2].type = CKA_TOKEN
tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_true), ctypes.c_void_p)
tmpl[2].ulValueLen = 1
tmpl[3].type = CKA_VALUE
tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
tmpl[3].ulValueLen = 32
tmpl[4].type = CKA_SIGN
tmpl[4].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
tmpl[4].ulValueLen = 1

token_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(token_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:TOKEN HMAC key creation not operational: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)

# --- open session B on the same slot ---
sh_b = CK_SESSION_HANDLE(0)
rv_b = raw.C_OpenSession(
    slot_id,
    CKF_SERIAL_SESSION | CKF_RW_SESSION,
    None,
    CK_NOTIFY(),
    ctypes.byref(sh_b),
)
if rv_b != CKR_OK:
    print(f"SETUP_XFAIL:C_OpenSession(session B) failed: {ckr_name(rv_b)}")
    raw.C_DestroyObject(sh, token_key.value)
    cleanup()
    raise SystemExit(0)

# --- C_SignInit in session A with the token key ---
mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256_HMAC
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_SignInit(sh, ctypes.byref(mech), token_key.value)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_SignInit(CKM_SHA256_HMAC) in session A failed: {ckr_name(rv)}")
    raw.C_DestroyObject(sh, token_key.value)
    raw.C_CloseSession(sh_b.value)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject from session B ---
destroy_rv = raw.C_DestroyObject(sh_b.value, token_key.value)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Sign in session A (operation may reference freed/invalid key) ---
data = (ctypes.c_ubyte * 16)(*range(16))
sig_len = CK_ULONG(0)
xsession_rv = raw.C_Sign(sh, data, 16, None, ctypes.byref(sig_len))
print(f"XSESSION_SIGN_RV:0x{xsession_rv:08x}")
if xsession_rv == CKR_OK:
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    xsession_rv2 = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
    print(f"XSESSION_SIGN_RV2:0x{xsession_rv2:08x}")

# --- clean up session B and token object (best-effort; may already be gone) ---
raw.C_DestroyObject(sh_b.value, token_key.value)
raw.C_CloseSession(sh_b.value)

cleanup()
"""


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

        body = _XSESSION_UAF_IMPORTS + _XSESSION_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
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

_ECDSA_SIGN_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import gen_ec_keypair
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_ECDSA,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import KEYPAIR_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""

_ECDSA_SIGN_UAF_BODY = """
# --- generate a session P-256 EC keypair (CKA_SIGN on private) ---
curve_oid = encode_named_curve_parameters("secp256r1")
try:
    pub_h, priv_h = gen_ec_keypair(
        raw,
        sh,
        curve_oid,
        public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
    )
except AssertionError as exc:
    if child_setup_reject_known(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "EC keypair generation rejected"
    ):
        cleanup()
        raise SystemExit(0)
    raise

raw.C_DestroyObject(sh, pub_h)

# --- C_SignInit with CKM_ECDSA ---
mech = CK_MECHANISM()
mech.mechanism = CKM_ECDSA
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_SignInit(sh, ctypes.byref(mech), priv_h)
if rv != CKR_OK:
    from pkcs11_check.raw.rv import ckr_name as _cn
    print(f"SETUP_XFAIL:C_SignInit(CKM_ECDSA) failed: {_cn(rv)}")
    raw.C_DestroyObject(sh, priv_h)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject on the private key while sign operation is active ---
destroy_rv = raw.C_DestroyObject(sh, priv_h)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Sign on possibly-freed key reference (two-pass) ---
data = (ctypes.c_ubyte * 32)(*range(32))
sig_len = CK_ULONG(0)
sign_rv = raw.C_Sign(sh, data, 32, None, ctypes.byref(sig_len))
print(f"SIGN_RV:0x{sign_rv:08x}")
if sign_rv == CKR_OK and sig_len.value > 0:
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    sign_rv2 = raw.C_Sign(sh, data, 32, sig_buf, ctypes.byref(sig_len))
    print(f"SIGN_RV2:0x{sign_rv2:08x}")

cleanup()
"""


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

        body = _ECDSA_SIGN_UAF_IMPORTS + _ECDSA_SIGN_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
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

_RSA_DECRYPT_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.recipes import RSAUsage, gen_rsa_keypair
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKM_RSA_PKCS,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import KEYPAIR_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""

_RSA_DECRYPT_UAF_BODY = """
# --- generate a session RSA-2048 keypair (CKA_DECRYPT on private) ---
try:
    pub_h, priv_h = gen_rsa_keypair(raw, sh, 2048, usage=RSAUsage.DECRYPT)
except AssertionError as exc:
    if child_setup_reject_known(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected"
    ):
        cleanup()
        raise SystemExit(0)
    raise

raw.C_DestroyObject(sh, pub_h)

# --- C_DecryptInit with CKM_RSA_PKCS ---
mech = CK_MECHANISM()
mech.mechanism = CKM_RSA_PKCS
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv_h)
if rv != CKR_OK:
    from pkcs11_check.raw.rv import ckr_name as _cn
    print(f"SETUP_XFAIL:C_DecryptInit(CKM_RSA_PKCS) failed: {_cn(rv)}")
    raw.C_DestroyObject(sh, priv_h)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject on the private key while decrypt operation is active ---
destroy_rv = raw.C_DestroyObject(sh, priv_h)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Decrypt on possibly-freed key reference (two-pass, modulus-sized zero input) ---
# 256 zero bytes is an invalid RSA-PKCS#1 v1.5 ciphertext; a clean decrypt error
# (e.g. CKR_FUNCTION_FAILED, CKR_ENCRYPTED_DATA_INVALID) is acceptable.  No crash is the
# only hard requirement.
ciphertext = (ctypes.c_ubyte * 256)(0)
dec_len = CK_ULONG(0)
dec_rv = raw.C_Decrypt(sh, ciphertext, 256, None, ctypes.byref(dec_len))
print(f"DECRYPT_RV:0x{dec_rv:08x}")
if dec_rv == CKR_OK and dec_len.value > 0:
    dec_buf = (ctypes.c_ubyte * dec_len.value)()
    dec_rv2 = raw.C_Decrypt(sh, ciphertext, 256, dec_buf, ctypes.byref(dec_len))
    print(f"DECRYPT_RV2:0x{dec_rv2:08x}")

cleanup()
"""


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

        body = _RSA_DECRYPT_UAF_IMPORTS + _RSA_DECRYPT_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=30,
            pin=pin_from_config(p11_config),
        )
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
