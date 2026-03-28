"""Mechanism-driven encrypt/decrypt tests.

Parametrized by mech_encrypt_entry — tests every encrypt mechanism advertised
by the module that also has a registry config.

Key types covered:
- AES block modes (ECB, CBC, CBC-PAD, OFB, CFB*, CTS): 32-byte plaintext, block-aligned where needed
- AES stream modes (CTR): any-length plaintext, CK_AES_CTR_PARAMS
- AES-AEAD (GCM, CCM): 32-byte plaintext, random IV, auth tag included in ciphertext
- AES-XTS: 32-byte plaintext, IV param required
- RSA-PKCS / RSA-OAEP: small plaintext (< modulus), asymmetric keypair
- DES/DES3/SEED/Camellia/ARIA/etc.: follow AES block/stream patterns via registry config

Mechanisms not yet parameterised (complex wraps, SSL3/TLS key-mat, etc.) are
skipped with a clear message.
"""
from __future__ import annotations

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.recipes import decrypt_single, destroy_quietly, encrypt_single
from pkcs11_check.raw.types_std import (
    CKM,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    generate_key_for_encrypt,
    make_mech_param_or_skip,
    test_plaintext_bytes,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.encrypt]


class TestMechEncryptRoundtrip:
    """Encrypt then decrypt roundtrip for every advertised encrypt mechanism."""

    def test_roundtrip(self, p11_raw_session: RawSession, mech_encrypt_entry: MechEntry) -> None:
        """Encrypt then decrypt, verify recovered plaintext matches original."""
        rs = p11_raw_session
        entry = mech_encrypt_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        # Key-wrap only mechanisms — not testing data encrypt here
        if config.input_constraint == "none":
            pytest.skip(f"{entry.mech_name}: wrap-only mechanism, no data encrypt test")

        enc_key, dec_key = generate_key_for_encrypt(rs, entry, config)
        dec_key_handle = dec_key if dec_key is not None else enc_key

        try:
            plaintext = test_plaintext_bytes()
            mech_param = make_mech_param_or_skip(entry)

            overhead = 16 if config.auth_tag_included else 0
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                enc_key,
                CKM(entry.mech_id),
                plaintext,
                mech_param=mech_param,
                output_overhead=overhead,
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                dec_key_handle,
                CKM(entry.mech_id),
                ct,
                mech_param=mech_param,
            )
            assert pt == plaintext, (
                f"Decrypt mismatch for {entry.mech_name}: "
                f"expected {plaintext.hex()!r}, got {pt.hex()!r}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, enc_key)
            if dec_key is not None:
                destroy_quietly(rs.raw, rs.sh, dec_key)
