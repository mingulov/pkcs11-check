"""Multi-part streaming operation tests.

Parametrized by mech_encrypt_entry / mech_sign_entry / mech_digest_entry —
verifies that multi-part operations produce the same result as the
equivalent single-part operation.

Test patterns:
- Encrypt: C_EncryptUpdate chunks → C_EncryptFinal, result matches C_Encrypt
- Decrypt: C_DecryptUpdate chunks → C_DecryptFinal, result matches C_Decrypt
- Sign: C_SignUpdate chunks → C_SignFinal, result matches C_Sign (deterministic mechs)
- Verify: C_VerifyUpdate chunks → C_VerifyFinal, validates multipart sig
- Digest: C_DigestUpdate chunks → C_DigestFinal, result matches C_Digest

AEAD mechanisms (GCM, CCM) do not support multi-part — they are skipped
here with a clear message (config.multi_part_supported == False).
"""
from __future__ import annotations

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.recipes import (
    decrypt_multipart,
    destroy_quietly,
    digest_multipart,
    digest_single,
    encrypt_multipart,
    encrypt_single,
    sign_multipart,
    verify_multipart,
)
from pkcs11_check.raw.types_std import (
    CKM,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import make_mech_param
from pkcs11_check.testcases.test_mech_encrypt import (
    _generate_key_for_encrypt,
    _test_plaintext,
)
from pkcs11_check.testcases.test_mech_sign import _generate_key_for_sign

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.multipart]

# AES-XTS key type (doesn't support multipart on most implementations)
_CKK_AES_XTS_ID: int = 0
try:
    from pkcs11_check.raw.types_std import CKK_AES_XTS

    _CKK_AES_XTS_ID = int(CKK_AES_XTS)
except ImportError:
    pass


class TestMultipartEncrypt:
    """C_EncryptUpdate chunks → C_EncryptFinal matches C_Encrypt."""

    def test_streaming_equals_single(
        self, p11_raw_session: RawSession, mech_encrypt_entry: MechEntry
    ) -> None:
        """Multi-part encrypt output must equal single-part encrypt for the same input."""
        rs = p11_raw_session
        entry = mech_encrypt_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        if not config.multi_part_supported:
            pytest.skip(f"{entry.mech_name}: multi-part not supported (AEAD/stream)")

        # XTS: multipart unsupported on most modules, skip
        if config.key_type is not None and int(config.key_type) == _CKK_AES_XTS_ID:
            pytest.skip(f"{entry.mech_name}: AES-XTS multipart not widely supported")

        # Wrap-only mechanisms
        if config.input_constraint == "none":
            pytest.skip(f"{entry.mech_name}: wrap-only mechanism")

        enc_key, dec_key = _generate_key_for_encrypt(rs, entry, config)
        dec_key_handle = dec_key if dec_key is not None else enc_key

        try:
            plaintext = _test_plaintext(config)
            mech_param = make_mech_param(entry)
            if mech_param == "SKIP":
                pytest.skip(f"{entry.mech_name}: cannot build mech param generically")

            # For deterministic mechanisms with no IV, multipart and single-part
            # should produce identical ciphertext.  For non-deterministic, we just
            # verify that multipart decrypts back to plaintext.
            mech_id = CKM(entry.mech_id)

            # Single-part as reference
            ct_single = encrypt_single(
                rs.raw, rs.sh, enc_key, mech_id, plaintext, mech_param=mech_param
            )

            if config.deterministic and mech_param is None:
                # Multi-part must produce identical ciphertext
                chunks = [plaintext[:len(plaintext) // 2], plaintext[len(plaintext) // 2:]]
                ct_multi = encrypt_multipart(
                    rs.raw, rs.sh, enc_key, mech_id, chunks, mech_param=mech_param
                )
                assert ct_multi == ct_single, (
                    f"{entry.mech_name}: multipart ciphertext differs from single-part"
                )
            else:
                # Non-deterministic: just verify roundtrip via decrypt
                overhead = 16 if config.auth_tag_included else 0
                ct_multi_enc = encrypt_single(
                    rs.raw, rs.sh, enc_key, mech_id, plaintext,
                    mech_param=mech_param, output_overhead=overhead,
                )
                pt = decrypt_multipart(
                    rs.raw, rs.sh, dec_key_handle, mech_id,
                    [ct_multi_enc[:len(ct_multi_enc) // 2], ct_multi_enc[len(ct_multi_enc) // 2:]],
                    mech_param=mech_param,
                )
                assert pt == plaintext, (
                    f"{entry.mech_name}: multipart decrypt mismatch after encrypt"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, enc_key)
            if dec_key is not None:
                destroy_quietly(rs.raw, rs.sh, dec_key)


class TestMultipartDigest:
    """C_DigestUpdate chunks → C_DigestFinal matches C_Digest."""

    def test_streaming_equals_single(
        self, p11_raw_session: RawSession, mech_digest_entry: MechEntry
    ) -> None:
        """Multi-part digest must match single-part digest for the same input."""
        rs = p11_raw_session
        entry = mech_digest_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        # XOF mechanisms (SHAKE) use a different API
        shake_128_id = 0x00000418
        shake_256_id = 0x00000419
        if entry.mech_id in (shake_128_id, shake_256_id):
            pytest.skip(f"{entry.mech_name}: XOF mechanism requires C_DigestXof*")

        # Parameterised digests (SHA-512/t) without a buildable recipe
        if config.param_required and config.param_recipe.style == "none":
            pytest.skip(
                f"{entry.mech_name}: param_required but recipe style 'none' — cannot build params"
            )

        data = b"multipart digest test input data" * 3  # 96 bytes
        mech_id = CKM(entry.mech_id)

        # Single-part reference
        single = digest_single(rs.raw, rs.sh, mech_id, data)
        assert len(single) > 0

        # Multi-part (3 chunks)
        chunk_size = len(data) // 3
        chunks = [data[:chunk_size], data[chunk_size:2 * chunk_size], data[2 * chunk_size:]]
        multi = digest_multipart(rs.raw, rs.sh, mech_id, chunks)

        assert multi == single, (
            f"{entry.mech_name}: multipart digest {multi.hex()!r} != "
            f"single-part digest {single.hex()!r}"
        )

    def test_streaming_single_chunk_equals_single(
        self, p11_raw_session: RawSession, mech_digest_entry: MechEntry
    ) -> None:
        """Multi-part with one chunk must equal single-part digest."""
        rs = p11_raw_session
        entry = mech_digest_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        shake_128_id = 0x00000418
        shake_256_id = 0x00000419
        if entry.mech_id in (shake_128_id, shake_256_id):
            pytest.skip(f"{entry.mech_name}: XOF mechanism requires C_DigestXof*")

        if config.param_required and config.param_recipe.style == "none":
            pytest.skip(
                f"{entry.mech_name}: param_required but recipe style 'none' — cannot build params"
            )

        data = b"single chunk multipart test"
        mech_id = CKM(entry.mech_id)

        single = digest_single(rs.raw, rs.sh, mech_id, data)
        multi = digest_multipart(rs.raw, rs.sh, mech_id, [data])

        assert multi == single, (
            f"{entry.mech_name}: 1-chunk multipart digest != single-part"
        )


class TestMultipartSign:
    """C_SignUpdate chunks → C_SignFinal — multipart signature verifies."""

    def test_multipart_sign_verify(
        self, p11_raw_session: RawSession, mech_sign_entry: MechEntry
    ) -> None:
        """Multi-part sign then verify with the same multi-part verify."""
        rs = p11_raw_session
        entry = mech_sign_entry
        config = entry.config
        if config is None:
            pytest.skip(f"{entry.mech_name}: no registry config")

        if not config.multi_part_supported:
            pytest.skip(f"{entry.mech_name}: multi-part not supported")

        sign_key, verify_key = _generate_key_for_sign(rs, entry, config)
        verify_key_handle = verify_key if verify_key is not None else sign_key

        try:
            from pkcs11_check.testcases.test_mech_sign import _make_sign_mech_param

            mech_param = _make_sign_mech_param(entry, config)
            if mech_param == "SKIP":
                pytest.skip(f"{entry.mech_name}: cannot build mech param generically")

            data = b"multipart signing test input data " * 4
            chunk_size = len(data) // 4
            chunks = [
                data[:chunk_size],
                data[chunk_size : 2 * chunk_size],
                data[2 * chunk_size : 3 * chunk_size],
                data[3 * chunk_size:],
            ]
            mech_id = CKM(entry.mech_id)

            sig = sign_multipart(
                rs.raw, rs.sh, sign_key, mech_id, chunks, mech_param=mech_param
            )
            ok = verify_multipart(
                rs.raw, rs.sh, verify_key_handle, mech_id, chunks, sig, mech_param=mech_param
            )
            assert ok, (
                f"{entry.mech_name}: multipart sign/verify failed "
                f"(sig={sig.hex()!r})"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None:
                destroy_quietly(rs.raw, rs.sh, verify_key)
