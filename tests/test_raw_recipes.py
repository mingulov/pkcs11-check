"""Tests for raw recipe helpers."""
from __future__ import annotations

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    get_object_size,
    import_secret_key,
    quick_session,
    read_attributes,
    sign_single,
    verify_single,
)


class TestEcCurveEncoding:
    def test_p256_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("secp256r1")
        assert isinstance(result, bytes)
        assert len(result) == 10  # OID 1.2.840.10045.3.1.7 DER-encoded
        assert result[0] == 0x06  # ASN.1 OID tag

    def test_p384_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("secp384r1")
        assert isinstance(result, bytes)
        assert result[0] == 0x06

    def test_p521_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("secp521r1")
        assert isinstance(result, bytes)
        assert result[0] == 0x06

    def test_ed25519_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("ed25519")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x70])

    def test_ed448_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("ed448")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x71])

    def test_x25519_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("x25519")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])

    def test_x448_returns_der_oid(self) -> None:
        result = encode_named_curve_parameters("x448")
        assert result == bytes([0x06, 0x03, 0x2B, 0x65, 0x6F])

    def test_alias_prime256v1(self) -> None:
        p256 = encode_named_curve_parameters("secp256r1")
        assert encode_named_curve_parameters("prime256v1") == p256

    def test_alias_p256(self) -> None:
        assert encode_named_curve_parameters("P-256") == encode_named_curve_parameters("secp256r1")

    def test_unknown_curve_raises(self) -> None:
        import pytest
        with pytest.raises(ValueError, match="Unknown curve"):
            encode_named_curve_parameters("not-a-real-curve")


class TestRawFixtureSignatures:
    def test_raw_has_mechanism_callable(self) -> None:
        from pkcs11_check.raw_fixtures import raw_has_mechanism
        assert callable(raw_has_mechanism)

    def test_raw_session_fixture_exists(self) -> None:
        from pkcs11_check.raw_fixtures import raw_session
        assert callable(raw_session)

    def test_raw_pkcs11_fixture_exists(self) -> None:
        from pkcs11_check.raw_fixtures import raw_pkcs11
        assert callable(raw_pkcs11)


class TestRecipeSignatures:
    def test_quick_session_callable(self) -> None:
        assert callable(quick_session)

    def test_gen_aes_key_callable(self) -> None:
        assert callable(gen_aes_key)

    def test_gen_rsa_keypair_callable(self) -> None:
        assert callable(gen_rsa_keypair)

    def test_gen_ec_keypair_callable(self) -> None:
        assert callable(gen_ec_keypair)

    def test_import_secret_key_callable(self) -> None:
        assert callable(import_secret_key)

    def test_destroy_quietly_callable(self) -> None:
        assert callable(destroy_quietly)

    def test_encrypt_single_callable(self) -> None:
        assert callable(encrypt_single)

    def test_sign_single_callable(self) -> None:
        assert callable(sign_single)

    def test_decrypt_single_callable(self) -> None:
        assert callable(decrypt_single)

    def test_verify_single_callable(self) -> None:
        assert callable(verify_single)

    def test_digest_single_callable(self) -> None:
        assert callable(digest_single)

    def test_read_attributes_callable(self) -> None:
        assert callable(read_attributes)

    def test_get_object_size_callable(self) -> None:
        assert callable(get_object_size)

    def test_find_objects_callable(self) -> None:
        assert callable(find_objects)
