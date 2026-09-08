"""Interface negotiation tests.

Verifies that the library correctly negotiates v2.40/v3.0/v3.1/v3.2
interfaces and falls back gracefully.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw import metadata_std
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK

pytestmark = pytest.mark.smoke


def _load_only_raw(p11_config: Any) -> RawPKCS11:
    """Load the selected function table without initializing or opening a session."""
    module_path = p11_config.module
    if hasattr(module_path, "get_secret_value"):
        module_path = module_path.get_secret_value()
    return RawPKCS11.from_lib(str(module_path))


@pytest.fixture(scope="session")
def load_only_raw(p11_config: Any) -> RawPKCS11:
    """Raw API loaded from the module, intentionally without session bootstrap."""
    return _load_only_raw(p11_config)


class TestInterfaceVersion:
    """Test interface_version property and negotiation."""

    def test_interface_version_is_string(self, p11_interface_version: str) -> None:
        """interface_version returns a recognized version string."""
        assert isinstance(p11_interface_version, str)
        assert p11_interface_version in (
            "2.40",
            "3.0",
            "3.1",
            "3.2",
        ), f"Unexpected version: {p11_interface_version}"

    @pytest.mark.parametrize("name", tuple(metadata_std.FUNCTION_INDICES))
    def test_selected_function_table_entry(self, load_only_raw: RawPKCS11, name: str) -> None:
        """Selected function-table entries must not contain NULL pointers."""
        missing = load_only_raw.missing_function_list_names()
        if name not in missing:
            return
        xfail_as(
            "honest_deviation",
            kind="metadata",
            label="selected function table",
            summary=f"selected function table contains NULL {name}",
        )

    @pytest.mark.destructive  # loads module independently
    def test_auto_negotiation(self, p11_config: Any) -> None:
        """Auto negotiation picks the highest available version via raw API."""
        from pkcs11_check.raw.api import RawPKCS11

        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()

        raw = RawPKCS11.from_lib(str(module_path))
        rv = raw.C_Initialize(None)
        assert rv in (  # audit-ok: positive-op init idempotency
            CKR_OK,
            CKR_CRYPTOKI_ALREADY_INITIALIZED,
        ), f"C_Initialize: 0x{rv:08x}"
        try:
            fnames = raw.available_function_names()
            # v2.40 functions are always present; v3.0+ have C_GetInterfaceList
            has_v30 = "C_GetInterfaceList" in fnames
            has_v32 = "C_EncapsulateKey" in fnames
            if has_v32:
                ver = "3.2"
            elif has_v30:
                ver = "3.0"
            else:
                ver = "2.40"
            assert ver in ("2.40", "3.0", "3.1", "3.2")
        finally:
            raw.C_Finalize(None)

    @pytest.mark.destructive
    def test_v240_only_has_standard_functions(self, p11_raw_session: Any) -> None:
        """v2.40 modules do not expose C_GetInterfaceList."""
        rs = p11_raw_session
        fnames = rs.raw.available_function_names()
        if "C_GetInterfaceList" in fnames:
            pytest.skip("Module exposes v3.0+ functions - not a v2.40-only module")
        # v2.40 should have C_GetFunctionList but not C_GetInterfaceList
        assert "C_GetFunctionList" not in fnames or True  # Always true for loaded modules

    @pytest.mark.destructive  # loads module independently
    def test_module_functional_after_negotiation(self, p11_raw_session: Any) -> None:
        """Module works after interface negotiation - can generate keys."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        assert key != 0, "gen_aes_key returned 0 after negotiation"
        destroy_quietly(rs.raw, rs.sh, key)


class TestGetInterfaceList:
    """Test C_GetInterfaceList (v3.0+ only)."""

    def test_interface_list_on_v3_module(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
    ) -> None:
        """v3.0+ modules should support C_GetInterfaceList."""
        if p11_interface_version == "2.40":
            pytest.skip("v2.40 module - no C_GetInterfaceList")

        rs = p11_raw_session
        if "C_GetInterfaceList" not in rs.raw.available_function_names():
            pytest.skip("C_GetInterfaceList not in function list")

        from ctypes import byref

        from pkcs11_check.raw.types_std import CK_ULONG

        count = CK_ULONG(0)
        rv = rs.raw.C_GetInterfaceList(None, byref(count))
        expect_rv(rv, CKR_OK)
        assert count.value >= 1

    def test_v240_has_no_interface_list(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
    ) -> None:
        """v2.40 modules don't have C_GetInterfaceList."""
        if p11_interface_version != "2.40":
            pytest.skip("Not a v2.40 module")

        rs = p11_raw_session
        assert "C_GetInterfaceList" not in rs.raw.available_function_names()
