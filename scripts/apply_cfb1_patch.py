#!/usr/bin/env python3
"""Script to apply CFB1 patch to Kryoptic aes.rs"""

import re

# Read the file
with open("/home/user/src/m/pkcs11-check-ws/kryoptic/src/ossl/aes.rs", "r") as f:
    content = f.read()

# Find and replace in encrypt_update function
# Add is_cfb1 check after the finalized check in encrypt_update
encrypt_update_pattern = r"(    fn encrypt_update\([^)]+\)[^{]+{[^}]+if self\.finalized \{[^}]+return Err\(CKR_OPERATION_NOT_INITIALIZED\)\?;[^}]+\})(\s+self\.in_use = true;)"
encrypt_update_replacement = r"""\1

        // Check if this is CFB1 mode for special handling
        let is_cfb1 = self.mech == CKM_AES_CFB1;
\2"""

content = re.sub(encrypt_update_pattern, encrypt_update_replacement, content, count=1)

# Add masking after cipher_offset += outlen in encrypt_update
cipher_mask_pattern = (
    r'(            cipher_offset \+= outlen;\s+\})(\s+#\[cfg\(feature = "fips"\)\])'
)
cipher_mask_replacement = r"""\1

        // For CFB1, mask output to only keep MSB of each byte
        if is_cfb1 {
            for i in 0..cipher_offset {
                cipher[i] &= 0x80;
            }
        }
\2"""

content = re.sub(cipher_mask_pattern, cipher_mask_replacement, content, count=1)

# Find and replace in decrypt_update function
# Add is_cfb1 check after the finalized check in decrypt_update
decrypt_update_pattern = r"(    fn decrypt_update\([^)]+\)[^{]+{[^}]+if self\.finalized \{[^}]+return Err\(CKR_OPERATION_NOT_INITIALIZED\)\?;[^}]+\})(\s+match self\.mech \{)"
decrypt_update_replacement = r"""\1

        // Check if this is CFB1 mode for special handling
        let is_cfb1 = self.mech == CKM_AES_CFB1;

\2"""

content = re.sub(decrypt_update_pattern, decrypt_update_replacement, content, count=1)

# Add masking after plain_offset += outlen in decrypt_update
plain_mask_pattern = r'(            plain_offset \+= outlen;\s+\})(\s+#\[cfg\(feature = "fips"\)\])'
plain_mask_replacement = r"""\1

        // For CFB1, mask output to only keep MSB of each byte
        if is_cfb1 {
            for i in 0..plain_offset {
                plain[i] &= 0x80;
            }
        }
\2"""

content = re.sub(plain_mask_pattern, plain_mask_replacement, content, count=1)

# Write the file back
with open("/home/user/src/m/pkcs11-check-ws/kryoptic/src/ossl/aes.rs", "w") as f:
    f.write(content)

print("Patch applied successfully!")
