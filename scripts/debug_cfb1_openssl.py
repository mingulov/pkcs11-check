#!/usr/bin/env python3
"""
Test script to understand OpenSSL CFB1 bit ordering.
Uses ctypes to call OpenSSL directly.
"""

import ctypes
import sys
from ctypes import CDLL, c_char_p, c_int, c_void_p, POINTER, c_ubyte

# Load OpenSSL
try:
    libssl = CDLL("libssl.so.3")
    libcrypto = CDLL("libcrypto.so.3")
except OSError:
    try:
        libssl = CDLL("libssl.so")
        libcrypto = CDLL("libcrypto.so")
    except OSError:
        print("Could not load OpenSSL libraries")
        sys.exit(1)

# Define constants
EVP_CIPH_CFB_MODE = 3
EVP_CIPH_FLAG_LENGTH_BITS = 0x2000

# Function prototypes
libcrypto.EVP_CIPHER_fetch.argtypes = [c_void_p, c_char_p, c_char_p]
libcrypto.EVP_CIPHER_fetch.restype = c_void_p

libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p

libcrypto.EVP_CIPHER_CTX_free.argtypes = [c_void_p]

libcrypto.EVP_CipherInit_ex2.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_int, c_void_p]
libcrypto.EVP_CipherInit_ex2.restype = c_int

libcrypto.EVP_CipherUpdate.argtypes = [
    c_void_p,
    POINTER(c_ubyte),
    POINTER(c_int),
    POINTER(c_ubyte),
    c_int,
]
libcrypto.EVP_CipherUpdate.restype = c_int

libcrypto.EVP_CipherFinal_ex.argtypes = [c_void_p, POINTER(c_ubyte), POINTER(c_int)]
libcrypto.EVP_CipherFinal_ex.restype = c_int

libcrypto.OSSL_LIB_CTX_get0_global_default.argtypes = []
libcrypto.OSSL_LIB_CTX_get0_global_default.restype = c_void_p

# ACVP test vector tc1
key = bytes.fromhex("00000000000000000000000000000000")
iv = bytes.fromhex("F34481EC3CC627BACD5DC3FB08F273E6")
pt = bytes.fromhex("00")  # 1 byte with 1 bit of data (payloadLen=1)
expected_ct = bytes.fromhex("00")

print("=" * 60)
print("ACVP Test Vector tc1:")
print(f"  Key: {key.hex()}")
print(f"  IV:  {iv.hex()}")
print(f"  PT:  {pt.hex()} (1 bit of data, payloadLen=1)")
print(f"  Expected CT: {expected_ct.hex()}")
print("=" * 60)
print()

# Get OpenSSL context
ctx = libcrypto.OSSL_LIB_CTX_get0_global_default()

# Fetch AES-128-CFB1 cipher
cipher_name = b"AES-128-CFB1"
cipher = libcrypto.EVP_CIPHER_fetch(ctx, cipher_name, None)
if not cipher:
    print(f"Failed to fetch cipher {cipher_name}")
    sys.exit(1)

print(f"Successfully fetched cipher: {cipher_name.decode()}")

# Create context
ctx = libcrypto.EVP_CIPHER_CTX_new()
if not ctx:
    print("Failed to create context")
    sys.exit(1)

# Initialize for encryption
key_arr = (c_ubyte * len(key)).from_buffer_copy(key)
iv_arr = (c_ubyte * len(iv)).from_buffer_copy(iv)

ret = libcrypto.EVP_CipherInit_ex2(
    ctx, cipher, None, key_arr, iv_arr, c_int(1), None
)  # 1 = encrypt
if ret != 1:
    print(f"EVP_CipherInit_ex2 failed: {ret}")
    sys.exit(1)

print("Context initialized for encryption")

# Encrypt
pt_arr = (c_ubyte * len(pt)).from_buffer_copy(pt)
ct_buf = (c_ubyte * 16)()  # Output buffer
out_len = c_int()

# Try encrypting with length=1 (1 bit)
ret = libcrypto.EVP_CipherUpdate(ctx, ct_buf, ctypes.byref(out_len), pt_arr, 1)
if ret != 1:
    print(f"EVP_CipherUpdate failed: {ret}")
    sys.exit(1)

print(f"EVP_CipherUpdate: out_len = {out_len.value}")
print(f"Output buffer: {bytes(ct_buf).hex()}")

# Finalize
final_buf = (c_ubyte * 16)()
final_len = c_int()
ret = libcrypto.EVP_CipherFinal_ex(ctx, final_buf, ctypes.byref(final_len))
if ret != 1:
    print(f"EVP_CipherFinal_ex failed: {ret}")
    sys.exit(1)

print(f"EVP_CipherFinal_ex: final_len = {final_len.value}")

# Cleanup
libcrypto.EVP_CIPHER_CTX_free(ctx)

# Show results
actual_ct = bytes(ct_buf[: out_len.value])
print()
print("=" * 60)
print("RESULTS:")
print(f"  Input:         {pt.hex()} (1 byte, {len(pt) * 8} bits)")
print(f"  Output:        {actual_ct.hex()} ({len(actual_ct)} bytes)")
print(f"  Expected:      {expected_ct.hex()}")
print(f"  Match:         {actual_ct == expected_ct}")
print("=" * 60)

# Try with different interpretations
print()
print("Testing different bit positions:")
for i in range(8):
    # Create plaintext with bit at position i
    test_pt = bytes([1 << (7 - i)])  # MSB first
    print(f"  Bit at pos {i} (MSB-first): pt={test_pt.hex()} -> ", end="")

    ctx = libcrypto.EVP_CIPHER_CTX_new()
    libcrypto.EVP_CipherInit_ex2(ctx, cipher, None, key_arr, iv_arr, 1, None)

    pt_arr = (c_ubyte * len(test_pt)).from_buffer_copy(test_pt)
    ct_buf = (c_ubyte * 16)()
    out_len = c_int()

    ret = libcrypto.EVP_CipherUpdate(ctx, ct_buf, ctypes.byref(out_len), pt_arr, 1)
    result = bytes(ct_buf[: out_len.value])
    print(f"ct={result.hex()}")

    libcrypto.EVP_CIPHER_CTX_free(ctx)

print()
print("Note: In CFB1, each bit of input produces 1 bit of output.")
print("OpenSSL's CFB1 processes all 8 bits of each input byte.")
print("The output shows which bit positions carry the encrypted data.")
