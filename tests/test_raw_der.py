"""Tests for minimal DER/ASN.1 encoding utilities in pkcs11_check.raw.der."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.der import (
    decode_ec_point,
    decode_rsa_public_key_der,
    ecdsa_sig_der_to_p1363,
    ecdsa_sig_from_der,
    ecdsa_sig_p1363_to_der,
    ecdsa_sig_to_der,
    encode_ec_point,
    encode_rsa_public_key_der,
)

# ---------------------------------------------------------------------------
# ECDSA signature encode/decode round-trips
# ---------------------------------------------------------------------------


class TestEcdsaSigToDer:
    def test_encodes_small_r_and_s(self) -> None:
        der = ecdsa_sig_to_der(1, 1)
        # SEQUENCE tag + length, two INTEGER(1) = 0x02 0x01 0x01 each
        assert der[0] == 0x30
        assert der[2] == 0x02  # INTEGER tag for r

    def test_round_trip_small_values(self) -> None:
        r, s = ecdsa_sig_from_der(ecdsa_sig_to_der(1, 1))
        assert r == 1
        assert s == 1

    def test_round_trip_p256_sized_values(self) -> None:
        # Typical P-256 r and s values (32-byte range)
        r = 0xDEADBEEFCAFEBABE001122334455667788990AABBCCDDEEFF0123456789ABCDEF
        s = 0x0123456789ABCDEFDEADBEEFCAFEBABE00112233445566778899AABBCCDDEEFF
        der = ecdsa_sig_to_der(r, s)
        r2, s2 = ecdsa_sig_from_der(der)
        assert r2 == r
        assert s2 == s

    def test_high_bit_set_adds_zero_padding(self) -> None:
        # r = 0x80 has the high bit set — DER INTEGER must prepend 0x00
        der = ecdsa_sig_to_der(0x80, 1)
        r, s = ecdsa_sig_from_der(der)
        assert r == 0x80
        assert s == 1

    def test_zero_value_encodes_as_single_zero_byte(self) -> None:
        der = ecdsa_sig_to_der(0, 0)
        r, s = ecdsa_sig_from_der(der)
        assert r == 0
        assert s == 0

    def test_large_values_round_trip(self) -> None:
        r = 2**255 - 19  # large prime (Ed25519 field prime)
        s = 2**256 - 1
        r2, s2 = ecdsa_sig_from_der(ecdsa_sig_to_der(r, s))
        assert r2 == r
        assert s2 == s

    def test_from_der_rejects_wrong_outer_tag(self) -> None:
        with pytest.raises(ValueError, match="SEQUENCE"):
            ecdsa_sig_from_der(b"\x02\x04\x02\x01\x01\x02\x01\x01")

    def test_from_der_rejects_wrong_integer_tag(self) -> None:
        # Manually craft SEQUENCE with wrong inner tag
        inner = b"\x03\x01\x01\x02\x01\x01"  # 0x03 instead of 0x02
        bad_der = b"\x30" + bytes([len(inner)]) + inner
        with pytest.raises(ValueError, match="INTEGER"):
            ecdsa_sig_from_der(bad_der)


class TestEcdsaKnownVector:
    """Verify encoding against a hand-computed known DER byte sequence."""

    # r=1, s=1 → each INTEGER is: 02 01 01
    # SEQUENCE body = 02 01 01 02 01 01 → 6 bytes
    # Full DER: 30 06 02 01 01 02 01 01
    KNOWN_DER = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])

    def test_encode_matches_known_vector(self) -> None:
        assert ecdsa_sig_to_der(1, 1) == self.KNOWN_DER

    def test_decode_matches_known_vector(self) -> None:
        r, s = ecdsa_sig_from_der(self.KNOWN_DER)
        assert r == 1
        assert s == 1


# ---------------------------------------------------------------------------
# P1363 <-> DER conversion
# ---------------------------------------------------------------------------


class TestP1363Conversion:
    def test_p1363_to_der_round_trip(self) -> None:
        # 64-byte P1363 signature (P-256 key_size=32)
        r_bytes = b"\x01" * 32
        s_bytes = b"\x02" * 32
        p1363 = r_bytes + s_bytes
        der = ecdsa_sig_p1363_to_der(p1363)
        recovered = ecdsa_sig_der_to_p1363(der, key_size=32)
        assert recovered == p1363

    def test_der_to_p1363_round_trip(self) -> None:
        r = 0xDEADBEEF
        s = 0xCAFEBABE
        der = ecdsa_sig_to_der(r, s)
        p1363 = ecdsa_sig_der_to_p1363(der, key_size=32)
        assert len(p1363) == 64
        r_bytes, s_bytes = p1363[:32], p1363[32:]
        assert int.from_bytes(r_bytes, "big") == r
        assert int.from_bytes(s_bytes, "big") == s

    def test_p384_key_size(self) -> None:
        r_bytes = b"\xAB" * 48
        s_bytes = b"\xCD" * 48
        p1363 = r_bytes + s_bytes
        der = ecdsa_sig_p1363_to_der(p1363)
        recovered = ecdsa_sig_der_to_p1363(der, key_size=48)
        assert recovered == p1363

    def test_p521_key_size(self) -> None:
        # P-521 key_size=66
        r_bytes = b"\x01" + b"\x00" * 65
        s_bytes = b"\x02" + b"\x00" * 65
        p1363 = r_bytes + s_bytes
        der = ecdsa_sig_p1363_to_der(p1363)
        recovered = ecdsa_sig_der_to_p1363(der, key_size=66)
        assert recovered == p1363

    def test_p1363_to_der_rejects_odd_length(self) -> None:
        with pytest.raises(ValueError, match="even"):
            ecdsa_sig_p1363_to_der(b"\x01" * 63)

    def test_der_to_p1363_pads_small_values_to_key_size(self) -> None:
        # r=1, s=1 with key_size=32 — both must be zero-padded to 32 bytes
        der = ecdsa_sig_to_der(1, 1)
        p1363 = ecdsa_sig_der_to_p1363(der, key_size=32)
        assert len(p1363) == 64
        assert p1363[:31] == b"\x00" * 31
        assert p1363[31] == 1
        assert p1363[32:63] == b"\x00" * 31
        assert p1363[63] == 1


# ---------------------------------------------------------------------------
# EC point encoding/decoding
# ---------------------------------------------------------------------------


class TestEcPointEncoding:
    # Minimal P-256 point coordinates (not a real point, just for encoding tests)
    X = int.from_bytes(b"\x01" * 32, "big")
    Y = int.from_bytes(b"\x02" * 32, "big")
    KEY_SIZE = 32

    def test_encode_produces_der_octet_string(self) -> None:
        der = encode_ec_point(self.X, self.Y, self.KEY_SIZE)
        assert der[0] == 0x04  # OCTET STRING tag
        assert der[1] == 65  # length: 1 (0x04 prefix) + 32 + 32
        assert der[2] == 0x04  # uncompressed point prefix

    def test_round_trip(self) -> None:
        der = encode_ec_point(self.X, self.Y, self.KEY_SIZE)
        point = decode_ec_point(der)
        assert point[0] == 0x04
        assert len(point) == 1 + 2 * self.KEY_SIZE
        x_recovered = int.from_bytes(point[1:33], "big")
        y_recovered = int.from_bytes(point[33:65], "big")
        assert x_recovered == self.X
        assert y_recovered == self.Y

    def test_decode_p384(self) -> None:
        x = int.from_bytes(b"\xAB" * 48, "big")
        y = int.from_bytes(b"\xCD" * 48, "big")
        der = encode_ec_point(x, y, key_size=48)
        point = decode_ec_point(der)
        assert len(point) == 1 + 2 * 48
        assert int.from_bytes(point[1:49], "big") == x
        assert int.from_bytes(point[49:97], "big") == y

    def test_decode_rejects_wrong_outer_tag(self) -> None:
        with pytest.raises(ValueError, match="OCTET STRING"):
            decode_ec_point(b"\x30\x03\x04\x01\x01")

    def test_known_short_length_encoding(self) -> None:
        # P-256 point body = 65 bytes < 128, so single-byte length
        der = encode_ec_point(self.X, self.Y, self.KEY_SIZE)
        assert der[1] < 128  # short-form length

    def test_long_form_length_for_p521(self) -> None:
        # P-521: point body = 1 + 2*66 = 133 bytes >= 128 → long-form length
        x = int.from_bytes(b"\x01" * 66, "big")
        y = int.from_bytes(b"\x02" * 66, "big")
        der = encode_ec_point(x, y, key_size=66)
        # long-form: first byte 0x81, next byte is actual length
        assert der[1] == 0x81
        assert der[2] == 133
        point = decode_ec_point(der)
        assert len(point) == 133


# ---------------------------------------------------------------------------
# RSA public key encoding/decoding
# ---------------------------------------------------------------------------


class TestRsaPublicKeyEncoding:
    MODULUS = b"\xc4\x1a\x4b\x32\x7d\x11\x89\xef"  # 8-byte fake modulus
    EXPONENT = b"\x01\x00\x01"  # 65537

    def test_encode_produces_sequence(self) -> None:
        der = encode_rsa_public_key_der(self.MODULUS, self.EXPONENT)
        assert der[0] == 0x30  # SEQUENCE tag

    def test_round_trip(self) -> None:
        der = encode_rsa_public_key_der(self.MODULUS, self.EXPONENT)
        modulus, exponent = decode_rsa_public_key_der(der)
        assert modulus == self.MODULUS
        assert exponent == self.EXPONENT

    def test_exponent_65537(self) -> None:
        der = encode_rsa_public_key_der(self.MODULUS, self.EXPONENT)
        _modulus, exponent = decode_rsa_public_key_der(der)
        assert int.from_bytes(exponent, "big") == 65537

    def test_large_modulus_round_trip(self) -> None:
        # 256-byte (2048-bit) modulus
        modulus = bytes(range(256))
        exponent = b"\x01\x00\x01"
        der = encode_rsa_public_key_der(modulus, exponent)
        mod2, exp2 = decode_rsa_public_key_der(der)
        # Leading zero bytes are stripped in canonical form
        assert int.from_bytes(mod2, "big") == int.from_bytes(modulus, "big")
        assert int.from_bytes(exp2, "big") == 65537

    def test_decode_rejects_wrong_tag(self) -> None:
        with pytest.raises(ValueError, match="SEQUENCE"):
            decode_rsa_public_key_der(b"\x02\x04\x01\x02\x03\x04")

    def test_high_bit_modulus_gets_zero_padded(self) -> None:
        # Modulus starting with 0x80 — DER INTEGER must prepend 0x00
        modulus = b"\x80" + b"\x01" * 31
        exponent = b"\x03"
        der = encode_rsa_public_key_der(modulus, exponent)
        mod2, exp2 = decode_rsa_public_key_der(der)
        assert int.from_bytes(mod2, "big") == int.from_bytes(modulus, "big")
        assert exp2 == exponent
