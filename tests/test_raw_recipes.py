"""Tests for raw recipe helpers."""

from __future__ import annotations

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    copy_object,
    decapsulate_key,
    decrypt_multipart,
    decrypt_single,
    derive_key,
    destroy_quietly,
    digest_multipart,
    digest_single,
    encapsulate_key,
    encrypt_multipart,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    generate_random,
    get_object_size,
    import_secret_key,
    init_pin,
    init_token,
    message_decrypt,
    message_encrypt,
    quick_session,
    read_attributes,
    restore_operation_state,
    save_operation_state,
    seed_random,
    set_attributes,
    set_pin,
    sign_multipart,
    sign_single,
    unwrap_key,
    unwrap_key_authenticated,
    verify_multipart,
    verify_recover_single,
    verify_single,
    wrap_key,
    wrap_key_authenticated,
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

    def test_wrap_key_callable(self) -> None:
        assert callable(wrap_key)

    def test_unwrap_key_callable(self) -> None:
        assert callable(unwrap_key)

    def test_derive_key_callable(self) -> None:
        assert callable(derive_key)

    def test_generate_random_callable(self) -> None:
        assert callable(generate_random)

    def test_copy_object_callable(self) -> None:
        assert callable(copy_object)

    def test_set_attributes_callable(self) -> None:
        assert callable(set_attributes)

    def test_encrypt_multipart_callable(self) -> None:
        assert callable(encrypt_multipart)

    def test_decrypt_multipart_callable(self) -> None:
        assert callable(decrypt_multipart)

    def test_sign_multipart_callable(self) -> None:
        assert callable(sign_multipart)

    def test_verify_multipart_callable(self) -> None:
        assert callable(verify_multipart)

    def test_digest_multipart_callable(self) -> None:
        assert callable(digest_multipart)

    def test_save_operation_state_callable(self) -> None:
        assert callable(save_operation_state)

    def test_restore_operation_state_callable(self) -> None:
        assert callable(restore_operation_state)

    def test_init_token_callable(self) -> None:
        assert callable(init_token)

    def test_init_pin_callable(self) -> None:
        assert callable(init_pin)

    def test_set_pin_callable(self) -> None:
        assert callable(set_pin)

    def test_seed_random_callable(self) -> None:
        assert callable(seed_random)

    def test_message_encrypt_callable(self) -> None:
        assert callable(message_encrypt)

    def test_message_decrypt_callable(self) -> None:
        assert callable(message_decrypt)

    def test_encapsulate_key_callable(self) -> None:
        assert callable(encapsulate_key)

    def test_decapsulate_key_callable(self) -> None:
        assert callable(decapsulate_key)

    def test_wrap_key_authenticated_callable(self) -> None:
        assert callable(wrap_key_authenticated)

    def test_unwrap_key_authenticated_callable(self) -> None:
        assert callable(unwrap_key_authenticated)


def test_get_session_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_session_info
    from pkcs11_check.raw.types_std import CKR_OK

    class FakeRaw:
        def C_GetSessionInfo(self, session: int, info) -> int:  # noqa: N802
            info._obj.slotID = 42
            info._obj.state = 1
            info._obj.flags = 0x04
            info._obj.ulDeviceError = 0
            return CKR_OK

    result = get_session_info(FakeRaw(), 1)
    assert result == {"slot_id": 42, "state": 1, "flags": 0x04, "device_error": 0}


def test_get_mechanism_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_mechanism_info
    from pkcs11_check.raw.types_std import CKR_OK

    class FakeRaw:
        def C_GetMechanismInfo(self, slot_id: int, mech: int, info) -> int:  # noqa: N802
            info._obj.ulMinKeySize = 128
            info._obj.ulMaxKeySize = 256
            info._obj.flags = 0x01
            return CKR_OK

    result = get_mechanism_info(FakeRaw(), 0, 0x01)
    assert result == {"min_key_size": 128, "max_key_size": 256, "flags": 0x01}


def test_get_slot_info_returns_struct_fields() -> None:
    from pkcs11_check.raw.recipes import get_slot_info
    from pkcs11_check.raw.types_std import CK_VERSION, CKR_OK

    class FakeRaw:
        def C_GetSlotInfo(self, slot_id: int, info) -> int:  # noqa: N802
            info._obj.flags = 0x03
            info._obj.hardwareVersion = CK_VERSION(2, 1)
            info._obj.firmwareVersion = CK_VERSION(1, 0)
            return CKR_OK

    result = get_slot_info(FakeRaw(), 0)
    assert result["flags"] == 0x03
    assert result["hardware_version"] == (2, 1)
    assert result["firmware_version"] == (1, 0)


def test_digest_single_with_key_calls_init_key_final() -> None:
    from pkcs11_check.raw.recipes import digest_single_with_key
    from pkcs11_check.raw.types_std import CKM_SHA224, CKR_OK

    calls: list[str] = []

    class FakeRaw:
        def C_DigestInit(self, session, mech) -> int:  # noqa: N802
            calls.append("init")
            return CKR_OK

        def C_DigestKey(self, session, key) -> int:  # noqa: N802
            calls.append("key")
            return CKR_OK

        def C_DigestFinal(self, session, out, out_len):  # noqa: N802
            calls.append("final")
            if out is None:
                out_len._obj.value = 4
                return CKR_OK
            out[0] = 0x01
            out[1] = 0x02
            out[2] = 0x03
            out[3] = 0x04
            out_len._obj.value = 4
            return CKR_OK

    result = digest_single_with_key(FakeRaw(), 1, CKM_SHA224, 99)
    assert calls == ["init", "key", "final", "final"]
    assert result == b"\x01\x02\x03\x04"


def test_verify_recover_single_returns_false_on_invalid_sig() -> None:
    from pkcs11_check.raw.types_std import CKM_RSA_PKCS, CKR_OK, CKR_SIGNATURE_INVALID

    class FakeRaw:
        def C_VerifyRecoverInit(self, session, mech, key) -> int:  # noqa: N802
            return CKR_OK

        def C_VerifyRecover(self, session, sig, sig_len, out, out_len) -> int:  # noqa: N802
            return CKR_SIGNATURE_INVALID

    valid, data = verify_recover_single(FakeRaw(), 1, 1, CKM_RSA_PKCS, b"x" * 8)
    assert valid is False
    assert data == b""


def test_expect_rv_context_in_error_message() -> None:
    from pkcs11_check.raw.rv import expect_rv
    from pkcs11_check.raw.types_std import CKR_OK

    try:
        expect_rv(999, CKR_OK, context="C_EncryptInit")
        assert False, "Should have raised"
    except AssertionError as e:
        assert "C_EncryptInit" in str(e)
