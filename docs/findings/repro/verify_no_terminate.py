#!/usr/bin/env python3
"""Minimal reproduction: C_Verify does not terminate the operation on a rejected
signature (CKR_SIGNATURE_INVALID), leaving the session with a dangling active
verify operation so the *next* C_VerifyInit returns CKR_OPERATION_ACTIVE.

PKCS#11 v3.0/v3.1, "Functions for verifying signatures and MACs", C_Verify:

    "The verification operation MUST have been initialized with C_VerifyInit. A
     call to C_Verify always terminates the active verification operation."
    "A successful call to C_Verify should return either the value CKR_OK ... or
     CKR_SIGNATURE_INVALID ... In any of these cases, the active verification
     operation is terminated."

So CKR_SIGNATURE_INVALID is an EXPLICITLY terminal outcome. A provider that
leaves the operation active afterwards violates the spec.

Run inside a provider container (module + PIN come from the env the test
harness already sets):

    docker compose -f docker/docker-compose.test.yml run --rm \
        test-kryoptic uv run --no-sync python /app/docs/findings/repro/verify_no_terminate.py

No project test infrastructure is used beyond the raw ctypes binding + a couple
of one-line key/sign helpers, so a provider author can read it top-to-bottom.
"""

from __future__ import annotations

import os
import sys

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import gen_rsa_keypair, sign_single, to_ubyte_buf
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_VERIFY,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKU_USER,
)


def _rv_name(rv: int) -> str:
    from pkcs11_check.raw import types_std

    for name in dir(types_std):
        if name.startswith("CKR_") and getattr(types_std, name) == rv:
            return name
    return f"0x{rv:08x}"


def _verify_init(raw: RawPKCS11, sh: int, key: int) -> int:
    """C_VerifyInit(SHA256-RSA-PKCS). Returns the raw CK_RV (does not raise)."""
    mech = mech_simple(CKM_SHA256_RSA_PKCS)
    return int(raw.C_VerifyInit(sh, mech.byref(), key))


def _verify(raw: RawPKCS11, sh: int, data: bytes, sig: bytes) -> int:
    """C_Verify. Returns the raw CK_RV (does not raise)."""
    return int(raw.C_Verify(sh, to_ubyte_buf(data), len(data), to_ubyte_buf(sig), len(sig)))


def main() -> int:
    module = os.environ.get("PKCS11_CHECK_MODULE") or os.environ.get("P11TEST_MODULE")
    pin = os.environ.get("PKCS11_CHECK_PIN") or os.environ.get("P11TEST_PIN")
    if not module:
        print("set PKCS11_CHECK_MODULE", file=sys.stderr)
        return 2

    raw = RawPKCS11(lib_path=module)
    print(f"module           : {module}")
    print(f"interface version: {raw.interface_version}")
    raw.C_Initialize(None)
    try:
        slot = get_slot_ids(raw)[0]
        sh = open_session(raw, slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        if pin:
            login_user(raw, sh, CKU_USER, pin.encode())

        pub, priv = gen_rsa_keypair(raw, sh, 2048)
        msg = b"pkcs11-check reproduction message"
        good_sig = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, msg)
        # A wrong-LENGTH signature (one byte short of the 256-byte RSA-2048 block):
        # the spec says the provider "can [see it] to be invalid purely on the basis
        # of its length" -> CKR_SIGNATURE_LEN_RANGE, "in any of these cases the active
        # verification operation is terminated." This is the same terminal outcome the
        # Wycheproof rsa_signature_2048_sha224 tc242 vector produces on kryoptic.
        bad_sig = good_sig[:-1]

        # ---- Control: a VALID verify (CKR_OK) must leave a clean session ------
        assert _verify_init(raw, sh, pub) == CKR_OK
        rv_good = _verify(raw, sh, msg, good_sig)
        rv_reinit_after_good = _verify_init(raw, sh, pub)
        # tidy up the (correctly) re-initialized op so it doesn't pollute the next step
        _verify(raw, sh, msg, good_sig)

        # ---- Bug probe: a REJECTED verify (CKR_SIGNATURE_INVALID) -------------
        assert _verify_init(raw, sh, pub) == CKR_OK
        rv_bad = _verify(raw, sh, msg, bad_sig)
        rv_reinit_after_bad = _verify_init(raw, sh, pub)

        # ---- Recovery probe: does C_SessionCancel clear the dangling op? ------
        rv_cancel = -1
        rv_reinit_after_cancel = -1
        try:
            rv_cancel = int(raw.C_SessionCancel(sh, CKF_VERIFY))
            rv_reinit_after_cancel = _verify_init(raw, sh, pub)
        except AttributeError:
            print("  (module has no C_SessionCancel -- pre-v3.0)")

        print()
        print(f"  control  C_Verify(valid)                 -> {_rv_name(rv_good)}")
        print(f"  control  C_VerifyInit after valid verify -> {_rv_name(rv_reinit_after_good)}")
        print(f"  probe    C_Verify(invalid)               -> {_rv_name(rv_bad)}")
        print(f"  probe    C_VerifyInit after invalid      -> {_rv_name(rv_reinit_after_bad)}")
        print(f"  recover  C_SessionCancel(CKF_VERIFY)     -> {_rv_name(rv_cancel)}")
        print(f"  recover  C_VerifyInit after cancel       -> {_rv_name(rv_reinit_after_cancel)}")
        print()

        spec_ok = rv_reinit_after_bad == CKR_OK
        cascade = rv_reinit_after_bad == CKR_OPERATION_ACTIVE
        if rv_bad not in (CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE):
            print(
                f"INCONCLUSIVE: rejected sig did not return a terminal "
                f"CKR_SIGNATURE_* code (got {_rv_name(rv_bad)})"
            )
            return 3
        if spec_ok:
            print(
                "PASS: C_Verify terminated the operation on CKR_SIGNATURE_INVALID (spec-compliant)."
            )
            return 0
        if cascade:
            print(
                f"BUG REPRODUCED: C_Verify left the verify operation ACTIVE after "
                f"{_rv_name(rv_bad)}."
            )
            print(
                "   The next C_VerifyInit returns CKR_OPERATION_ACTIVE -- spec violation "
                "(C_Verify MUST terminate the op)."
            )
            if rv_reinit_after_cancel == CKR_OK:
                print(
                    "   C_SessionCancel(CKF_VERIFY) clears the dangling op (recovery path works)."
                )
            return 1
        print(f"UNEXPECTED: C_VerifyInit after invalid verify -> {_rv_name(rv_reinit_after_bad)}")
        return 4
    finally:
        raw.C_Finalize(None)


if __name__ == "__main__":
    sys.exit(main())
