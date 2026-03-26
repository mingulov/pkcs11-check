"""Tests for typed CK_CONSTANT families in types_std."""

from __future__ import annotations

import copy
import ctypes


class TestCKConstantBase:
    """Core CK_CONSTANT int-subclass behavior."""

    def test_is_int(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        assert isinstance(CKA(1), int)

    def test_is_ck_constant(self) -> None:
        from pkcs11_check.raw.types_std import CK_CONSTANT, CKA

        assert isinstance(CKA(1), CK_CONSTANT)

    def test_is_own_type(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        assert isinstance(CKA(1), CKA)

    def test_not_other_type(self) -> None:
        from pkcs11_check.raw.types_std import CKA, CKM

        assert not isinstance(CKA(1), CKM)

    def test_equality_with_int(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        assert CKA(1) == 1
        assert 1 == CKA(1)

    def test_hash_matches_int(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        assert hash(CKA(1)) == hash(1)

    def test_ctypes_compat(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        val = ctypes.c_ulong(CKA(0x0001))
        assert val.value == 1

    def test_repr_named(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        r = repr(CKA(1, "CKA_TOKEN"))
        assert "CKA_TOKEN" in r
        assert "0x00000001" in r

    def test_repr_unnamed(self) -> None:
        from pkcs11_check.raw.types_std import CKM

        r = repr(CKM(0x80010001))
        assert "CKM" in r
        assert "0x80010001" in r

    def test_str_named(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        assert str(CKA(1, "CKA_TOKEN")) == "CKA_TOKEN"

    def test_str_unnamed(self) -> None:
        from pkcs11_check.raw.types_std import CKM

        s = str(CKM(0x80010001))
        assert "0x80010001" in s

    def test_getnewargs_and_copy(self) -> None:
        from pkcs11_check.raw.types_std import CKA

        original = CKA(1, "CKA_TOKEN")
        args = original.__getnewargs__()
        assert args == (1, "CKA_TOKEN")

        copied = copy.copy(original)
        assert copied == original
        assert repr(copied) == repr(original)
        assert isinstance(copied, CKA)


class TestCKFBitwise:
    """CKF flag bitwise operations."""

    def test_or_returns_ckf(self) -> None:
        from pkcs11_check.raw.types_std import CKF

        result = CKF(0x02) | CKF(0x04)
        assert isinstance(result, CKF)
        assert result == 0x06

    def test_ror_returns_ckf(self) -> None:
        from pkcs11_check.raw.types_std import CKF

        result = 0x100 | CKF(0x02)
        assert isinstance(result, CKF)

    def test_and_returns_ckf(self) -> None:
        from pkcs11_check.raw.types_std import CKF

        result = CKF(0x06) & CKF(0x04)
        assert isinstance(result, CKF)
        assert result == 0x04

    def test_rand_returns_ckf(self) -> None:
        from pkcs11_check.raw.types_std import CKF

        result = 0x06 & CKF(0x04)
        assert isinstance(result, CKF)
        assert result == 0x04

    def test_invert_returns_ckf_no_negative_sign(self) -> None:
        from pkcs11_check.raw.types_std import CKF

        result = ~CKF(0x02)
        assert isinstance(result, CKF)
        # repr should use hex mask, not show negative sign
        assert "-" not in repr(result)


class TestCKPOverlap:
    """CKP values can overlap across parameter sets."""

    def test_ckp_same_value_distinct_repr(self) -> None:
        from pkcs11_check.raw.types_std import CKP

        a = CKP(1, "CKP_ML_DSA_44")
        b = CKP(1, "CKP_ML_KEM_512")
        assert a == b  # same int value
        assert repr(a) != repr(b)  # distinct repr


class TestVendorConstants:
    """Vendor-defined constants."""

    def test_vendor_mechanism_is_ckm(self) -> None:
        from pkcs11_check.raw.types_std import CKM

        v = CKM(0x80010001)
        assert isinstance(v, CKM)
        assert isinstance(v, int)


class TestGeneratedConstants:
    """Verify that generated constants in types_std have correct types."""

    def test_cka_token_is_cka(self) -> None:
        from pkcs11_check.raw.types_std import CKA, CKA_TOKEN

        assert isinstance(CKA_TOKEN, CKA)

    def test_ckm_aes_key_gen_is_ckm(self) -> None:
        from pkcs11_check.raw.types_std import CKM, CKM_AES_KEY_GEN

        assert isinstance(CKM_AES_KEY_GEN, CKM)

    def test_ckr_ok_is_ckr(self) -> None:
        from pkcs11_check.raw.types_std import CKR, CKR_OK

        assert isinstance(CKR_OK, CKR)

    def test_ckf_rw_session_is_ckf(self) -> None:
        from pkcs11_check.raw.types_std import CKF, CKF_RW_SESSION

        assert isinstance(CKF_RW_SESSION, CKF)

    def test_combined_flags_is_ckf(self) -> None:
        from pkcs11_check.raw.types_std import CKF, CKF_RW_SESSION, CKF_SERIAL_SESSION

        combined = CKF_RW_SESSION | CKF_SERIAL_SESSION
        assert isinstance(combined, CKF)

    def test_generated_constants_have_names(self) -> None:
        from pkcs11_check.raw.types_std import CKA_TOKEN, CKM_AES_KEY_GEN, CKR_OK

        assert str(CKA_TOKEN) == "CKA_TOKEN"
        assert str(CKM_AES_KEY_GEN) == "CKM_AES_KEY_GEN"
        assert str(CKR_OK) == "CKR_OK"

    def test_generated_constants_repr(self) -> None:
        from pkcs11_check.raw.types_std import CKA_TOKEN

        r = repr(CKA_TOKEN)
        assert "CKA_TOKEN" in r
        assert "0x00000001" in r

    def test_generated_constants_equal_raw_int(self) -> None:
        from pkcs11_check.raw.types_std import CKA_TOKEN, CKM_AES_KEY_GEN, CKR_OK

        assert CKA_TOKEN == 0x1
        assert CKM_AES_KEY_GEN == 0x1080
        assert CKR_OK == 0x0

    def test_generated_constants_hash_matches(self) -> None:
        from pkcs11_check.raw.types_std import CKR_OK

        assert hash(CKR_OK) == hash(0)

    def test_generated_constants_usable_in_dict(self) -> None:
        from pkcs11_check.raw.types_std import CKR_OK

        d = {CKR_OK: "success"}
        assert d[0] == "success"
        assert d[CKR_OK] == "success"

    def test_generated_constants_usable_in_ctypes(self) -> None:
        from pkcs11_check.raw.types_std import CKF_RW_SESSION

        val = ctypes.c_ulong(CKF_RW_SESSION)
        assert val.value == CKF_RW_SESSION


class TestPlatformDependentConstants:
    """CK_UNAVAILABLE_INFORMATION must match the platform CK_ULONG width."""

    def test_ck_unavailable_information_matches_ulong_max(self) -> None:
        from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION

        ulong_max = (1 << (ctypes.sizeof(ctypes.c_ulong) * 8)) - 1
        assert CK_UNAVAILABLE_INFORMATION == ulong_max

    def test_ck_unavailable_information_fits_in_c_ulong(self) -> None:
        from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION

        val = ctypes.c_ulong(CK_UNAVAILABLE_INFORMATION)
        assert val.value == CK_UNAVAILABLE_INFORMATION

    def test_ck_unavailable_information_is_all_bits_set(self) -> None:
        from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION

        # On any platform, all bits of CK_ULONG must be set
        ulong_bits = ctypes.sizeof(ctypes.c_ulong) * 8
        assert CK_UNAVAILABLE_INFORMATION == (1 << ulong_bits) - 1

    def test_ck_unavailable_information_not_hardcoded_64bit(self) -> None:
        from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION

        # Must NOT be hardcoded to 0xFFFFFFFFFFFFFFFF on 32-bit platforms
        ulong_bytes = ctypes.sizeof(ctypes.c_ulong)
        if ulong_bytes == 4:
            assert CK_UNAVAILABLE_INFORMATION == 0xFFFFFFFF
        elif ulong_bytes == 8:
            assert CK_UNAVAILABLE_INFORMATION == 0xFFFFFFFFFFFFFFFF

    def test_ck_effectively_infinite_is_zero(self) -> None:
        from pkcs11_check.raw.types_std import CK_EFFECTIVELY_INFINITE

        assert CK_EFFECTIVELY_INFINITE == 0
