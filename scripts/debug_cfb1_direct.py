#!/usr/bin/env python3
"""Debug script to understand CFB1 behavior in Kryoptic."""

import os
import sys

# Set up environment for Kryoptic
os.environ["PKCS11_CHECK_MODULE"] = (
    "/home/user/src/m/pkcs11-check/local-builds/kryoptic/lib/libkryoptic_pkcs11.so"
)
os.environ["PKCS11_CHECK_PIN"] = "1234"

sys.path.insert(0, "/home/user/src/m/pkcs11-check/src")

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.types_std import (
    CKM_AES_CFB1,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKA_CLASS,
    CKO_SECRET_KEY,
    CKA_KEY_TYPE,
    CKK_AES,
    CKA_VALUE_LEN,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKR_OK,
    CK_MECHANISM,
    CK_AES_PARAMS,
)
from pkcs11_check.raw.pack import mech_bytes

# ACVP Test Vector tc5:
# Key: 00000000000000000000000000000000
# IV:  B26AEB1874E47CA8358FF22378F09144
# PT:  00 (1 bit)
# Expected CT: 00
# Kryoptic got: 76

key = bytes.fromhex("00000000000000000000000000000000")
iv = bytes.fromhex("B26AEB1874E47CA8358FF22378F09144")
pt = bytes.fromhex("00")
expected_ct = bytes.fromhex("00")

print("=" * 70)
print("Direct CFB1 Test via Kryoptic")
print("=" * 70)
print(f"Key: {key.hex()}")
print(f"IV:  {iv.hex()}")
print(f"PT:  {pt.hex()}")
print(f"Expected CT: {expected_ct.hex()}")
print()

# Load module
raw = RawPKCS11.from_lib(os.environ["PKCS11_CHECK_MODULE"])

# Initialize
rv = raw.C_Initialize(None)
print(f"C_Initialize: {rv}")

# Get slot list
slot_count = raw.CK_ULONG()
rv = raw.C_GetSlotList(1, None, raw.byref(slot_count))
print(f"C_GetSlotList (count): rv={rv}, count={slot_count.value}")

# For now, just show the test parameters
print()
print("Test parameters prepared. The issue is:")
print("- ACVP expects CFB1 output with only MSB set (00 or 80)")
print("- Kryoptic/OpenSSL returns full 8-bit result (76)")
print()
print("My patch masks the output to only keep MSB:")
print("  cipher[i] &= 0x80")
print()
print("So 0x76 & 0x80 should produce 0x00 or 0x80")
print(f"  0x76 & 0x80 = {0x76 & 0x80:02x}")
print(f"  0x97 & 0x80 = {0x97 & 0x80:02x}")
print()
print("The patch should work! Let me check if it's being applied...")
