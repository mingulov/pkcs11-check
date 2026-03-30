#!/usr/bin/env python3
"""
Detailed analysis of CFB1 bit positions.
"""

# ACVP Test Vector tc5 (which shows clear mismatch):
# Key: 00000000000000000000000000000000
# IV:  B26AEB1874E47CA8358FF22378F09144
# PT:  00 (1 bit)
# Expected CT: 00
# Kryoptic got: 76

# Let's trace through CFB1 manually


def aes_encrypt(key, data):
    """Simulate AES encryption."""
    # For all-zero key, AES encryption is deterministic
    # We'll compute this using a simple approach
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# Test vector tc5
key = bytes.fromhex("00000000000000000000000000000000")
iv = bytes.fromhex("B26AEB1874E47CA8358FF22378F09144")

# First, encrypt IV to get output block
output = aes_encrypt(key, iv)
print(f"AES(IV) = {output.hex()}")
print(f"First byte: {output[0]:02x} = {output[0]:08b}")
print(f"MSB of first byte: {(output[0] >> 7) & 1}")
print()

# For CFB1:
# - Input is 1 bit (from PT=00, bit value = 0)
# - Keystream bit is MSB of AES(IV)
# - CT bit = PT bit XOR keystream bit
pt_bit = 0  # From PT=00, assuming MSB
ks_bit = (output[0] >> 7) & 1
ct_bit = pt_bit ^ ks_bit

print(f"PT bit: {pt_bit}")
print(f"Keystream bit (MSB of AES(IV)): {ks_bit}")
print(f"CT bit = PT XOR KS = {pt_bit} XOR {ks_bit} = {ct_bit}")
print(f"Expected CT byte with bit in MSB: {ct_bit << 7:02x}")
print()

# Now, what does OpenSSL produce for the same input?
# When you call CFB1 with 1 byte of input, it processes all 8 bits
# Let's see what the full 8-bit encryption would produce

print("Full 8-bit CFB1 encryption:")
pt_byte = 0x00
iv_copy = bytearray(iv)
ct_byte = 0

for bit_pos in range(8):
    # Encrypt current IV
    output = aes_encrypt(key, bytes(iv_copy))
    ks_bit = (output[0] >> 7) & 1

    # Get PT bit at this position (MSB first)
    pt_bit = (pt_byte >> (7 - bit_pos)) & 1

    # Compute CT bit
    ct_bit = pt_bit ^ ks_bit

    # Place CT bit in output
    ct_byte |= ct_bit << (7 - bit_pos)

    # Update IV: shift left by 1, add ct_bit as LSB
    for i in range(len(iv_copy) - 1, -1, -1):
        new_carry = (iv_copy[i] >> 7) & 1
        iv_copy[i] = ((iv_copy[i] << 1) | (ct_bit if i == len(iv_copy) - 1 else carry)) & 0xFF
        carry = new_carry

    print(f"  Bit {bit_pos}: pt={pt_bit}, ks={ks_bit}, ct={ct_bit}")

print(f"Full CT byte: {ct_byte:02x} = {ct_byte:08b}")
print()

# Compare with what Kryoptic produced
kryoptic_ct = 0x76
print(f"Kryoptic produced: {kryoptic_ct:02x} = {kryoptic_ct:08b}")
print()

# Analysis
print("ANALYSIS:")
print("-" * 50)
print(f"Expected CT (ACVP): 00 (bit in MSB position)")
print(f"Kryoptic got:       {kryoptic_ct:02x} ({kryoptic_ct:08b})")
print(f"Manual full-byte:   {ct_byte:02x} ({ct_byte:08b})")
print()

# Check which bit of Kryoptic output matches expected
for i in range(8):
    bit_val = (kryoptic_ct >> (7 - i)) & 1
    if ct_bit == bit_val:
        print(
            f"Bit {i} (MSB-first) of Kryoptic output = {bit_val} (matches expected CT bit {ct_bit})"
        )

print()
print("The issue is clear: Kryoptic returns the full 8-bit result from OpenSSL,")
print("but ACVP expects only the first encrypted bit in the MSB position.")
print()
print("FIX: In CFB1 mode, Kryoptic should:")
print("  1. Pass data to OpenSSL as normal (it processes bit-by-bit internally)")
print("  2. BUT only return the first N bits (where N = payload length in bits)")
print("  3. Place those bits in the MSB positions of output bytes")
