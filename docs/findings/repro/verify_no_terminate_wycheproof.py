#!/usr/bin/env python3
"""Reproduction using a real Wycheproof vector: replays rsa_signature_2048_sha224
verify vectors in order and reports the first one whose CKR_SIGNATURE_INVALID
result leaves the verify operation ACTIVE (next C_VerifyInit -> CKR_OPERATION_ACTIVE).

This is the exact sequence the pkcs11-check suite hit on kryoptic v1.5.0
(test_wycheproof_rsa, rsa_signature_2048_sha224 tc242 -> tc243 cascade).

    docker compose -f docker/docker-compose.test.yml run --rm \
        test-kryoptic uv run --no-sync python \
        /app/docs/findings/repro/verify_no_terminate_wycheproof.py
"""

from __future__ import annotations

import json
import os
import sys

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    _VERIFY_FAIL_RVS,
    destroy_quietly,
    import_rsa_public_key,
    to_ubyte_buf,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_VERIFY,
    CKM_SHA224_RSA_PKCS,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKU_USER,
)
from pkcs11_check.testcases.data import WYCHEPROOF_DIR
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex


def main() -> int:
    module = os.environ.get("PKCS11_CHECK_MODULE") or os.environ.get("P11TEST_MODULE")
    pin = os.environ.get("PKCS11_CHECK_PIN") or os.environ.get("P11TEST_PIN")
    path = WYCHEPROOF_DIR / "rsa_signature_2048_sha224_test.json"
    data = json.loads(path.read_text())

    raw = RawPKCS11(lib_path=module)
    print(f"module: {module}  interface: {raw.interface_version}")
    raw.C_Initialize(None)
    try:
        slot = get_slot_ids(raw)[0]
        sh = open_session(raw, slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        if pin:
            login_user(raw, sh, CKU_USER, pin.encode())

        mech = mech_simple(CKM_SHA224_RSA_PKCS)
        checked = 0
        for group in data["testGroups"]:
            pk = group.get("publicKey", {})
            n = pkcs11_bigint_from_hex(pk.get("modulus", ""))
            e = pkcs11_bigint_from_hex(pk.get("publicExponent", ""))
            pub = import_rsa_public_key(raw, sh, n=n, e=e, attrs={CKA_VERIFY: True})
            try:
                for test in group["tests"]:
                    msg = bytes.fromhex(test["msg"])
                    sig = bytes.fromhex(test["sig"])
                    rv = int(raw.C_VerifyInit(sh, mech.byref(), pub))
                    if rv != CKR_OK:
                        print(
                            f"  tc{test['tcId']}: C_VerifyInit -> {ckr_name(rv)} "
                            f"(operation from a PRIOR vector is still active!)"
                        )
                        return 1
                    rv = int(
                        raw.C_Verify(sh, to_ubyte_buf(msg), len(msg), to_ubyte_buf(sig), len(sig))
                    )
                    checked += 1
                    if rv in _VERIFY_FAIL_RVS:
                        # Spec: C_Verify ALWAYS terminates the op here. Probe it.
                        rv2 = int(raw.C_VerifyInit(sh, mech.byref(), pub))
                        if rv2 == CKR_OPERATION_ACTIVE:
                            print(
                                f"\nBUG REPRODUCED at tc{test['tcId']} "
                                f"({test['result']}, {checked} vectors in):"
                            )
                            print(f"  C_Verify        -> {ckr_name(rv)}  (correctly rejected)")
                            print(
                                f"  C_VerifyInit    -> {ckr_name(rv2)}  "
                                f"(op was NOT terminated -- spec violation)"
                            )
                            rvc = int(raw.C_SessionCancel(sh, CKF_VERIFY))
                            rv3 = int(raw.C_VerifyInit(sh, mech.byref(), pub))
                            print(f"  C_SessionCancel -> {ckr_name(rvc)}")
                            print(f"  C_VerifyInit    -> {ckr_name(rv3)}  (recovered after cancel)")
                            return 1
                        # spec-compliant: terminate the probe op we just opened
                        raw.C_Verify(sh, to_ubyte_buf(msg), len(msg), to_ubyte_buf(sig), len(sig))
            finally:
                destroy_quietly(raw, sh, pub)
        print(
            f"PASS: checked {checked} vectors; every CKR_SIGNATURE_INVALID "
            f"terminated the op (spec-compliant)."
        )
        return 0
    finally:
        raw.C_Finalize(None)


if __name__ == "__main__":
    sys.exit(main())
