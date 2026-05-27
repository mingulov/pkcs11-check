#!/usr/bin/env python3
"""Standalone reproducer: SoftHSM2 Ed25519 CKA_EC_POINT encoding.

PKCS#11 v3.0 Current Mechanisms Errata 01, sec. 2.1 (EdDSA public key object):
    CKA_EC_POINT = "Public key bytes in little endian order as defined in
    RFC 8032"  -- i.e. the RAW 32-byte Ed25519 public key, NOT a DER OCTET
    STRING (unlike Weierstrass CKK_EC, whose CKA_EC_POINT is a DER-encoded
    ANSI X9.62 point).

This script imports the RFC 8032 sec. 7.1 Ed25519 test-1 public key two ways and
verifies the known-good signature with CKM_EDDSA:

  1. raw  CKA_EC_POINT = <32 pubkey bytes>            (the PKCS#11 form)
  2. DER  CKA_EC_POINT = 04 20 <32 pubkey bytes>      (OCTET STRING wrapper)

Observed on SoftHSM2 2.7.0: (1) returns CKR_SIGNATURE_INVALID, (2) returns
CKR_OK -- so SoftHSM2 only accepts the non-spec DER-wrapped form.

Usage:
    python3 softhsm2-eddsa-ecpoint-repro.py [/path/to/libsofthsm2.so]

Needs: python3, softhsm2-util on PATH, a libsofthsm2.so built --with-eddsa.
Creates a throwaway token in a temp dir; touches nothing else.
"""
# ruff: noqa: N801, N812  -- CK_* and ctypes-as-C are intentional PKCS#11 binding names
from __future__ import annotations

import ctypes as C
import os
import subprocess
import sys
import tempfile

# --- PKCS#11 types ----------------------------------------------------------
CK_ULONG = C.c_ulong
CK_BYTE = C.c_ubyte


class CK_ATTRIBUTE(C.Structure):
    _fields_ = [("type", CK_ULONG), ("pValue", C.c_void_p), ("ulValueLen", CK_ULONG)]


class CK_MECHANISM(C.Structure):
    _fields_ = [("mechanism", CK_ULONG), ("pParameter", C.c_void_p), ("ulParameterLen", CK_ULONG)]


# --- PKCS#11 constants ------------------------------------------------------
CKR_OK = 0x00000000
CKR_SIGNATURE_INVALID = 0x000000C0
CKF_SERIAL_SESSION, CKF_RW_SESSION = 0x4, 0x2
CKO_PUBLIC_KEY = 0x02
CKK_EC_EDWARDS = 0x40
CKA_CLASS, CKA_TOKEN, CKA_KEY_TYPE = 0x0, 0x1, 0x100
CKA_VERIFY, CKA_EC_PARAMS, CKA_EC_POINT = 0x10A, 0x180, 0x181
CKM_EDDSA = 0x00001057

# --- RFC 8032 sec. 7.1, Ed25519 test 1 (empty message) ----------------------
EC_PARAMS = bytes.fromhex("06032b6570")  # OID id-Ed25519 (1.3.101.112)
PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
MSG = b""
SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
    "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
RAW_POINT = PUB
DER_POINT = bytes.fromhex("0420") + PUB  # DER OCTET STRING (tag 04, len 0x20)


def ckr(rv: int) -> str:
    return {CKR_OK: "CKR_OK", CKR_SIGNATURE_INVALID: "CKR_SIGNATURE_INVALID"}.get(rv, f"0x{rv:08X}")


def build_template(items: list[tuple[int, int | bool | bytes]]) -> tuple[C.Array, list]:
    keep: list = []
    arr = (CK_ATTRIBUTE * len(items))()
    for i, (t, val) in enumerate(items):
        if isinstance(val, bool):
            buf, ln = (CK_BYTE * 1)(1 if val else 0), 1
        elif isinstance(val, int):
            buf, ln = CK_ULONG(val), C.sizeof(CK_ULONG)
        else:
            vb = bytes(val)
            buf, ln = (CK_BYTE * len(vb)).from_buffer_copy(vb), len(vb)
        keep.append(buf)
        arr[i].type, arr[i].pValue, arr[i].ulValueLen = t, C.addressof(buf), ln
    return arr, keep


def verify_with_point(lib: C.CDLL, session: CK_ULONG, point: bytes) -> int:
    """Import an Ed25519 public key with the given CKA_EC_POINT, verify SIG."""
    tmpl, _keep = build_template([
        (CKA_CLASS, CKO_PUBLIC_KEY),
        (CKA_KEY_TYPE, CKK_EC_EDWARDS),
        (CKA_TOKEN, False),
        (CKA_VERIFY, True),
        (CKA_EC_PARAMS, EC_PARAMS),
        (CKA_EC_POINT, point),
    ])
    h = CK_ULONG(0)
    rv = lib.C_CreateObject(session, tmpl, len(tmpl), C.byref(h))
    if rv != CKR_OK:
        return rv  # import itself rejected
    try:
        mech = CK_MECHANISM(CKM_EDDSA, None, 0)
        rv = lib.C_VerifyInit(session, C.byref(mech), h)
        if rv != CKR_OK:
            return rv
        data = (CK_BYTE * (len(MSG) or 1)).from_buffer_copy(MSG or b"\x00")
        sig = (CK_BYTE * len(SIG)).from_buffer_copy(SIG)
        return int(lib.C_Verify(session, data, len(MSG), sig, len(SIG)))
    finally:
        lib.C_DestroyObject(session, h)


def main() -> int:
    mod = sys.argv[1] if len(sys.argv) > 1 else "/usr/lib/softhsm/libsofthsm2.so"
    if not os.path.exists(mod):
        sys.exit(f"module not found: {mod} (pass the path as arg 1)")

    tmp = tempfile.mkdtemp(prefix="sh2-eddsa-")
    tokens = os.path.join(tmp, "tokens")
    os.makedirs(tokens)
    conf = os.path.join(tmp, "softhsm2.conf")
    with open(conf, "w") as f:
        f.write(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = conf

    subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", "eddsa-repro",
         "--pin", "1234", "--so-pin", "5678"],
        check=True, stdout=subprocess.DEVNULL,
    )

    lib = C.CDLL(mod)
    for name in ("C_Initialize", "C_Finalize", "C_GetSlotList", "C_OpenSession",
                 "C_CloseSession", "C_CreateObject", "C_VerifyInit", "C_Verify", "C_DestroyObject"):
        getattr(lib, name).restype = CK_ULONG

    assert lib.C_Initialize(None) == CKR_OK
    try:
        count = CK_ULONG(0)
        assert lib.C_GetSlotList(1, None, C.byref(count)) == CKR_OK and count.value
        slots = (CK_ULONG * count.value)()
        assert lib.C_GetSlotList(1, slots, C.byref(count)) == CKR_OK
        session = CK_ULONG(0)
        assert lib.C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 None, None, C.byref(session)) == CKR_OK

        raw_rv = verify_with_point(lib, session, RAW_POINT)
        der_rv = verify_with_point(lib, session, DER_POINT)
    finally:
        lib.C_Finalize(None)

    print(f"module : {mod}")
    print("vector : RFC 8032 Ed25519 test 1 (empty message)")
    print(f"  raw  CKA_EC_POINT ({len(RAW_POINT)}B)            -> C_Verify = {ckr(raw_rv)}")
    print(f"  DER  CKA_EC_POINT (04 20 ..., {len(DER_POINT)}B) -> C_Verify = {ckr(der_rv)}")
    print()
    if raw_rv != CKR_OK and der_rv == CKR_OK:
        print("REPRODUCED: only the non-spec DER OCTET STRING form verifies; the raw")
        print("RFC 8032 form (required by PKCS#11 v3.0-curr errata01 sec.2.1) is rejected.")
        return 0
    if raw_rv == CKR_OK:
        print("NOT reproduced: raw CKA_EC_POINT verifies (spec-conformant on this build).")
        return 0
    print("INCONCLUSIVE: neither form verified; check the build / vector.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
