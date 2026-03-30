#!/usr/bin/env python3
"""
Test script to understand OpenSSL CFB1 bit ordering.
This helps determine the root cause of ACVP CFB1 test failures.
"""

import subprocess
import sys

# ACVP test vector tc1:
# key = 00000000000000000000000000000000
# iv = F34481EC3CC627BACD5DC3FB08F273E6
# pt = 00 (1 bit of 0)
# Expected ct = 00 (1 bit result in MSB position)

# Let's test what OpenSSL produces
test_script = '''
import os
import sys

# Check if cryptography library is available
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ACVP test vector tc1
key = bytes.fromhex('00000000000000000000000000000000')
iv = bytes.fromhex('F34481EC3CC627BACD5DC3FB08F273E6')
pt = bytes.fromhex('00')  # 1 byte with 1 bit of data
expected_ct = bytes.fromhex('00')

print("ACVP Test Vector tc1:")
print(f"  Key: {key.hex()}")
print(f"  IV:  {iv.hex()}")
print(f"  PT:  {pt.hex()} (1 bit of 0)")
print(f"  Expected CT: {expected_ct.hex()}")
print()

if HAS_CRYPTOGRAPHY:
    # Cryptography library uses OpenSSL under the hood
    try:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()
        print(f"Cryptography CFB (128-bit): ct = {ct.hex()}")
    except Exception as e:
        print(f"Cryptography CFB failed: {e}")

# Let's manually compute what CFB1 should produce using the AES encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_encrypt_block(key, block):
    """Encrypt a single 16-byte block with AES-ECB."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

# CFB1 process:
# 1. Encrypt IV to get output block
# 2. Take MSB of output block (1 bit)
# 3. XOR with plaintext bit
# 4. Shift IV left by 1 bit, append ciphertext bit
# 5. Repeat

output_block = aes_encrypt_block(key, iv)
print(f"AES(IV) = {output_block.hex()}")
print(f"First byte of AES(IV) = {output_block[0]:02x} = {output_block[0]:08b}")

# In CFB1, we take the MSB of the output and XOR with plaintext bit
msb = (output_block[0] >> 7) & 1
pt_bit = (pt[0] >> 7) & 1  # Assuming MSB contains the plaintext bit
ct_bit = msb ^ pt_bit

print(f"MSB of AES(IV) = {msb}")
print(f"PT bit (MSB) = {pt_bit}")
print(f"CT bit = MSB XOR PT = {msb} XOR {pt_bit} = {ct_bit}")

# ACVP expects result in MSB position
expected_output = ct_bit << 7
print(f"Expected ACVP output: {expected_output:02x} = {expected_output:08b}")
'''

# Write and run the test
with open("/tmp/cfb1_test.py", "w") as f:
    f.write(test_script)

result = subprocess.run([sys.executable, "/tmp/cfb1_test.py"], capture_output=True, text=True)
print("STDOUT:")
print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)
