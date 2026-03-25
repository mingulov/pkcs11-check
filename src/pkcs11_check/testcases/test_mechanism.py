"""Tests for PKCS#11 mechanism discovery and info retrieval."""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.recipes import get_mechanism_list
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_MECHANISM_INFO,
    CKM_AES_CBC,
    CKM_RSA_PKCS,
    CKR_OK,
)

pytestmark = pytest.mark.mechflags


def _mech_name(m: int) -> str:
    """Return mechanism name from int."""
    return MECHANISM_NAMES.get(m, f"0x{m:08x}")


class TestMechanismInfo:
    def test_mechanism_info_has_key_sizes(self, p11_raw_session: Any) -> None:
        """Mechanism info reports min/max key sizes."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        assert len(mechanisms) > 0
        for mech in mechanisms:
            info = CK_MECHANISM_INFO()
            rv = rs.raw.C_GetMechanismInfo(rs.slot_id, mech, byref(info))
            expect_rv(int(rv), CKR_OK)
            assert info.ulMinKeySize >= 0
            assert info.ulMaxKeySize >= info.ulMinKeySize
            break

    def test_all_mechanisms_have_info(self, p11_raw_session: Any) -> None:
        """Every reported mechanism returns valid info."""
        rs = p11_raw_session
        for mech in get_mechanism_list(rs.raw, rs.slot_id):
            info = CK_MECHANISM_INFO()
            rv = rs.raw.C_GetMechanismInfo(rs.slot_id, mech, byref(info))
            expect_rv(int(rv), CKR_OK)

    def test_aes_key_sizes(self, p11_raw_session: Any) -> None:
        """AES mechanism reports correct key size range."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        if int(CKM_AES_CBC) not in mechanisms:
            pytest.skip("AES_CBC not supported")
        info = CK_MECHANISM_INFO()
        rv = rs.raw.C_GetMechanismInfo(rs.slot_id, int(CKM_AES_CBC), byref(info))
        expect_rv(int(rv), CKR_OK)
        assert info.ulMinKeySize <= 16  # 128 bits = 16 bytes
        assert info.ulMaxKeySize >= 32  # 256 bits = 32 bytes

    def test_rsa_key_sizes(self, p11_raw_session: Any) -> None:
        """RSA mechanism reports reasonable key size range."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        if int(CKM_RSA_PKCS) not in mechanisms:
            pytest.skip("RSA_PKCS not supported")
        info = CK_MECHANISM_INFO()
        rv = rs.raw.C_GetMechanismInfo(rs.slot_id, int(CKM_RSA_PKCS), byref(info))
        expect_rv(int(rv), CKR_OK)
        assert info.ulMinKeySize <= 2048
        assert info.ulMaxKeySize >= 2048


class TestMechanismCategories:
    def test_has_symmetric_mechanisms(self, p11_raw_session: Any) -> None:
        """Module supports at least one symmetric cipher."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        symmetric = [m for m in mechanisms if "AES" in _mech_name(m) or "DES" in _mech_name(m)]
        assert len(symmetric) > 0

    def test_has_hash_mechanisms(self, p11_raw_session: Any) -> None:
        """Module supports at least one hash mechanism."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        hashes = [m for m in mechanisms if "SHA" in _mech_name(m)]
        assert len(hashes) > 0

    def test_has_asymmetric_mechanisms(self, p11_raw_session: Any) -> None:
        """Module supports at least one asymmetric mechanism."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        asymmetric = [m for m in mechanisms if "RSA" in _mech_name(m) or "EC" in _mech_name(m)]
        assert len(asymmetric) > 0

    def test_mechanism_count_reasonable(self, p11_raw_session: Any) -> None:
        """Module reports a reasonable number of mechanisms (>10)."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        assert len(mechanisms) > 10
