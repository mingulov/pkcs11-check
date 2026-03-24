"""Tests for raw recipe helpers."""
from __future__ import annotations

from pkcs11_check.raw.recipes import (
    quick_session, gen_aes_key, gen_rsa_keypair, gen_ec_keypair,
    import_secret_key, destroy_quietly, encrypt_single, sign_single,
)


class TestRecipeSignatures:
    def test_quick_session_callable(self):
        assert callable(quick_session)

    def test_gen_aes_key_callable(self):
        assert callable(gen_aes_key)

    def test_gen_rsa_keypair_callable(self):
        assert callable(gen_rsa_keypair)

    def test_gen_ec_keypair_callable(self):
        assert callable(gen_ec_keypair)

    def test_import_secret_key_callable(self):
        assert callable(import_secret_key)

    def test_destroy_quietly_callable(self):
        assert callable(destroy_quietly)

    def test_encrypt_single_callable(self):
        assert callable(encrypt_single)

    def test_sign_single_callable(self):
        assert callable(sign_single)
