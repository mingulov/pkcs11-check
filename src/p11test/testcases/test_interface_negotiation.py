"""Interface negotiation tests.

Verifies that the library correctly negotiates v2.40/v3.0/v3.1/v3.2
interfaces and falls back gracefully.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest

pytestmark = pytest.mark.smoke


class TestInterfaceVersion:
    """Test interface_version property and negotiation."""

    def test_interface_version_is_string(self, p11_module: Any) -> None:
        """interface_version returns a recognized version string."""
        ver = p11_module.interface_version
        assert isinstance(ver, str)
        assert ver in ("2.40", "3.0", "3.1", "3.2"), f"Unexpected version: {ver}"

    @pytest.mark.destructive  # calls lib.finalize() which breaks shared session
    def test_auto_negotiation(self, p11_config: Any) -> None:
        """interface='auto' picks the highest available version."""
        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()

        lib = pkcs11.lib(str(module_path), interface="auto")
        lib.initialize()
        try:
            ver = lib.interface_version
            assert ver in ("2.40", "3.0", "3.1", "3.2")
        finally:
            lib.finalize()

    @pytest.mark.destructive  # calls lib.finalize()
    def test_explicit_v240_fallback(self, p11_config: Any) -> None:
        """interface='2.40' forces v2.40 even if module supports v3.x."""
        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()

        try:
            lib = pkcs11.lib(str(module_path), interface="2.40")
        except RuntimeError:
            pytest.skip("Module already loaded with different interface")

        lib.initialize()
        try:
            assert lib.interface_version == "2.40"
        finally:
            lib.finalize()

    @pytest.mark.destructive  # calls lib.finalize()
    def test_module_functional_after_negotiation(self, p11_config: Any) -> None:
        """Module works after interface negotiation — can generate keys."""
        module_path = p11_config.module
        if hasattr(module_path, "get_secret_value"):
            module_path = module_path.get_secret_value()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        lib = pkcs11.lib(str(module_path))
        lib.initialize()
        try:
            token = lib.get_token(token_label="p11test")
            with token.open(rw=True, user_pin=pin_str) as session:
                key = session.generate_key(pkcs11.KeyType.AES, 256)
                assert key is not None
        finally:
            lib.finalize()


class TestGetInterfaceList:
    """Test get_interface_list() (v3.0+ only)."""

    def test_interface_list_on_v3_module(self, p11_module: Any) -> None:
        """v3.0+ modules should support get_interface_list."""
        if p11_module.interface_version == "2.40":
            pytest.skip("v2.40 module — no C_GetInterfaceList")

        if not hasattr(p11_module, "get_interface_list"):
            pytest.skip("get_interface_list not exposed on wrapper")

        ifaces = p11_module.get_interface_list()
        assert isinstance(ifaces, list)
        assert len(ifaces) >= 1

    def test_v240_has_no_interface_list(self, p11_module: Any) -> None:
        """v2.40 modules don't have C_GetInterfaceList."""
        if p11_module.interface_version != "2.40":
            pytest.skip("Not a v2.40 module")

        if hasattr(p11_module, "get_interface_list"):
            ifaces = p11_module.get_interface_list()
            assert ifaces == []
