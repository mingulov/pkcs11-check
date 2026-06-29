"""Provision a SoftHSM2 token via the PKCS#11 C_* exports directly.

Used by the Windows CI (and reusable elsewhere): softhsm2-util's DLL search is
unreliable on Windows, so this drives the provider's own C_* exports with pure
ctypes -- no framework imports, no cryptography. Requires SOFTHSM2_CONF to point
at a conf whose tokendir exists.

Usage: python scripts/init_softhsm2_token.py <module-path> [label] [user-pin] [so-pin]
"""

from __future__ import annotations

import ctypes
import sys

module = sys.argv[1]
label = (sys.argv[2] if len(sys.argv) > 2 else "pkcs11-check").encode().ljust(32)
user_pin = (sys.argv[3] if len(sys.argv) > 3 else "1234").encode()
so_pin = (sys.argv[4] if len(sys.argv) > 4 else "1234").encode()

CKR_OK = 0
CKU_SO = 0
CKF_SERIAL_SESSION = 0x02
CKF_RW_SESSION = 0x04

dll = ctypes.CDLL(module)


def call(name: str, *args: object) -> None:
    fn = getattr(dll, name)
    fn.restype = ctypes.c_ulong
    rv = fn(*args)
    if rv != CKR_OK:
        raise SystemExit(f"{name} failed: 0x{rv:08x}")


call("C_Initialize", None)
count = ctypes.c_ulong(0)
call("C_GetSlotList", 0, None, ctypes.byref(count))  # tokenPresent=False
slots = (ctypes.c_ulong * count.value)()
call("C_GetSlotList", 0, slots, ctypes.byref(count))
slot = ctypes.c_ulong(slots[0])

call("C_InitToken", slot, so_pin, ctypes.c_ulong(len(so_pin)), label)
sess = ctypes.c_ulong(0)
call(
    "C_OpenSession",
    slot,
    ctypes.c_ulong(CKF_SERIAL_SESSION | CKF_RW_SESSION),
    None,
    None,
    ctypes.byref(sess),
)
call("C_Login", sess, ctypes.c_ulong(CKU_SO), so_pin, ctypes.c_ulong(len(so_pin)))
call("C_InitPIN", sess, user_pin, ctypes.c_ulong(len(user_pin)))
call("C_Logout", sess)
call("C_CloseSession", sess)
call("C_Finalize", None)
print(f"TOKEN_INIT_OK slot={slots[0]}")
