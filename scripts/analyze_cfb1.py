#!/usr/bin/env python3
"""
Test to understand OpenSSL CFB1 behavior using cryptography library.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import AES


def aes_ecb_encrypt(key, data):
    """Encrypt using AES-ECB."""
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def cfb1_manual(key, iv, pt_bits):
    """Manual CFB1 implementation following NIST spec."""
    # CFB1 processes one bit at a time
    # Each step:
    # 1. Encrypt the shift register (IV for first block)
    # 2. Take MSB of output as keystream bit
    # 3. XOR with plaintext bit to get ciphertext bit
    # 4. Shift register left by 1, add ciphertext bit as LSB

    sr = bytearray(iv)  # Shift register (16 bytes for AES)
    ct_bits = []

    for pt_bit in pt_bits:
        # Encrypt shift register
        output = aes_ecb_encrypt(key, bytes(sr))
        # Take MSB of first byte as keystream bit
        ks_bit = (output[0] >> 7) & 1
        # XOR with plaintext bit
        ct_bit = ks_bit ^ pt_bit
        ct_bits.append(ct_bit)
        # Shift register left by 1, add ct_bit as LSB
        # This means shifting all bytes left
        carry = ct_bit
        for i in range(len(sr) - 1, -1, -1):
            new_carry = (sr[i] >> 7) & 1
            sr[i] = ((sr[i] << 1) | carry) & 0xFF
            carry = new_carry

    return ct_bits


# ACVP Test Vector tc1:
# Key: 00000000000000000000000000000000
# IV:  F34481EC3CC627BACD5DC3FB08F273E6
# PT:   00 (1 bit of 0) - but which bit position?
# Expected CT: 00 (MSB is 0)

key = bytes.fromhex("00000000000000000000000000000000")
iv = bytes.fromhex("F34481EC3CC627BACD5DC3FB08F273E6")

# The ACVP vector says payloadLen=1, meaning 1 bit
# PT=00 means the byte 0x00, but which bit is the actual data?
# In CFB1, we process bit by bit

print("=" * 70)
print("ACVP AES-CFB1 Test Vector tc1 Analysis")
print("=" * 70)
print(f"Key: {key.hex()}")
print(f"IV:  {iv.hex()}")
print(f"PT:  00 (1 bit, payloadLen=1)")
print(f"Expected CT: 00")
print()

# Test manual CFB1 with different bit positions
print("Testing manual CFB1 with bit at different positions:")
for bit_pos in range(8):
    # PT bit at position bit_pos (0=MSB, 7=LSB)
    pt_byte = 0x00  # All zeros
    pt_bit = (pt_byte >> (7 - bit_pos)) & 1  # Extract bit at position
    ct_bits = cfb1_manual(key, iv, [pt_bit])
    ct_byte = ct_bits[0] << 7  # Place result in MSB position
    print(f"  Bit at pos {bit_pos} (value={pt_bit}): CT bit={ct_bits[0]}, CT byte={ct_byte:02x}")

print()
print("ACVP expects CT=00, meaning the ciphertext bit should be 0 in MSB")
print()

# Now test with OpenSSL's CFB1 via python-cryptography
# Note: python-cryptography doesn't expose CFB1 directly, but we can test with CFB8
print("Testing with OpenSSL via cryptography library:")

# Test regular CFB (which defaults to CFB128 for AES)
cipher = Cipher(AES(key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
pt = bytes.fromhex("00")
ct = encryptor.update(pt) + encryptor.finalize()
print(f"  AES-CFB (128-bit feedback): pt=00 -> ct={ct.hex()}")

# The issue is that CFB1 is not directly exposed in the cryptography library
# But we know Kryoptic uses OpenSSL's EVP interface directly

print()
print("=" * 70)
print("ANALYSIS:")
print("=" * 70)
print("""
The ACVP test vectors for CFB1 have payloadLen=1, meaning 1 bit of data.
The PT is '00' (a byte), but only 1 bit matters.

ACVP expects the CT to have the result in the MSB position:
- CT='00' means the ciphertext bit is 0
- CT='80' means the ciphertext bit is 1 (MSB set)

OpenSSL's AES-CFB1 cipher processes bytes bit-by-bit. When you pass 1 byte
to OpenSSL CFB1, it processes all 8 bits, producing 8 bits of output.

The issue is the mismatch between:
1. ACVP format: 1 bit of data, result in MSB
2. OpenSSL CFB1: processes all 8 bits of each input byte

For CFB1 with payloadLen=1, Kryoptic needs to:
1. Determine which bit of the input byte contains the actual data
2. Extract the corresponding bit from OpenSSL's output
3. Place that bit in the MSB position of the output byte

The most likely interpretation is:
- Input: MSB contains the data bit (bit 0 of the byte)
- Output: MSB should contain the result bit

Kryoptic needs special handling for CFB1 to:
1. Pass the full byte to OpenSSL (which processes all 8 bits)
2. Extract the MSB of the first output byte
3. Return a single byte with that bit in the MSB position
""")
