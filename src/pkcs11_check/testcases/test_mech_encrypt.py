"""Mechanism-driven encrypt/decrypt tests.

Parametrized by mech_encrypt_entry -- tests every encrypt mechanism advertised
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
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKK,
    CKM,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    build_params_from_vector,
    generate_key_for_encrypt,
    get_test_plaintext_bytes,
    make_mech_param_or_skip,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.encrypt]

_ENCRYPT_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


class TestMechEncryptRoundtrip:
    """Encrypt then decrypt roundtrip for every advertised encrypt mechanism."""

    def test_roundtrip(self, p11_raw_session: RawSession, mech_encrypt_entry: MechEntry) -> None:
        """Encrypt then decrypt, verify recovered plaintext matches original."""
        rs = p11_raw_session
        entry = mech_encrypt_entry
        config = entry.config
        assert config is not None

        enc_key, dec_key = generate_key_for_encrypt(rs, entry, config)
        dec_key_handle = dec_key if dec_key is not None else enc_key

        try:
            plaintext = get_test_plaintext_bytes()
            mech_param = make_mech_param_or_skip(entry)

            overhead = 16 if config.auth_tag_included else 0
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    enc_key,
                    CKM(entry.mech_id),
                    plaintext,
                    mech_param=mech_param,
                    output_overhead=overhead,
                    retry_on_buffer_too_small=config.auth_tag_included,
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _ENCRYPT_RUNTIME_REJECT_RVS,
                    f"{entry.mech_name} advertised but encrypt is not operational",
                )
            try:
                pt = decrypt_single(
                    rs.raw,
                    rs.sh,
                    dec_key_handle,
                    CKM(entry.mech_id),
                    ct,
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _ENCRYPT_RUNTIME_REJECT_RVS,
                    f"{entry.mech_name} advertised but decrypt is not operational",
                )
            if config.input_constraint == "raw_block":
                expected = plaintext.lstrip(b"\x00")
                actual = pt.lstrip(b"\x00")
            else:
                expected = plaintext
                actual = pt
            assert actual == expected, (
                f"Decrypt mismatch for {entry.mech_name}: "
                f"expected {expected.hex()!r}, got {actual.hex()!r}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, enc_key)
            if dec_key is not None:
                destroy_quietly(rs.raw, rs.sh, dec_key)


class TestMechEncryptKAT:
    """Known-answer encryption tests from pre-generated vectors."""

    def test_kat_vector(self, p11_raw_session: RawSession, mech_encrypt_entry: MechEntry) -> None:
        """Encrypt known plaintext with known key -- verify ciphertext matches vector."""
        rs = p11_raw_session
        entry = mech_encrypt_entry
        config = entry.config
        if config is None or not config.vector_file:
            pytest.skip("No KAT vectors for this mechanism")

        from pkcs11_check.testcases.mechanism_vectors import load_positive_vectors

        vectors = load_positive_vectors(config.vector_file)
        if not vectors:
            pytest.skip(f"No positive vectors in {config.vector_file}")

        for vec in vectors:
            key_hex = vec.get("key_hex")
            if not key_hex:
                continue
            key_bytes = bytes.fromhex(key_hex)
            if config.key_type is None:
                continue
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK(int(config.key_type)),
                key_bytes,
                attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
            )
            try:
                params = build_params_from_vector(entry.mech_id, config.param_recipe, vec)
                if params == "SKIP":
                    continue
                try:
                    overhead = 16 if config.auth_tag_included else 0
                    ct = encrypt_single(
                        rs.raw,
                        rs.sh,
                        key,
                        CKM(entry.mech_id),
                        bytes.fromhex(vec["plaintext_hex"]),
                        mech_param=params,
                        output_overhead=overhead,
                        retry_on_buffer_too_small=config.auth_tag_included,
                    )
                except AssertionError as exc:
                    xfail_if_known_ckr(
                        exc,
                        _ENCRYPT_RUNTIME_REJECT_RVS,
                        f"{entry.mech_name} advertised but KAT encrypt is not operational",
                    )
                expected_ct = bytes.fromhex(vec["ciphertext_hex"])
                tag_hex = vec.get("tag_hex", "")
                if tag_hex:
                    expected_ct += bytes.fromhex(tag_hex)
                assert ct == expected_ct, (
                    f"KAT ciphertext mismatch for {vec.get('id', '?')}: "
                    f"got {ct.hex()!r}, expected {expected_ct.hex()!r}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
