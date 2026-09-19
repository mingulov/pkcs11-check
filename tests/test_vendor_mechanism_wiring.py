"""Tests for --p11-vendor-mechanism / --vendor-mechanism wiring (audit F3)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import pkcs11_check.plugin as plugin_mod
from pkcs11_check.cli.test_cmd import _build_pytest_args

_MODULE = Path("/tmp/test.so")


def _default_args(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "module": _MODULE,
        "interface": "auto",
        "timeout": 180,
        "category": None,
        "match": None,
        "marker": None,
        "include_pin_arg": False,
        "pin": None,
        "so_pin": None,
        "slot": 0,
        "destructive": False,
        "rv_trace": False,
        "rv_trace_compact": None,
        "output": "rich",
        "output_file": None,
        "include_machine_report_args": False,
        "verbose": False,
        "key_inject": "off",
        "wrap_key_source": "bootstrap",
        "wrap_key_label": None,
        "wrap_key_handle": None,
        "wrap_mech": None,
        "wrap_rsa_bits": 2048,
        "wrap_oaep_hash": "auto",
        "allow_external_provision": False,
        "external_provision_cmd": None,
        "vendor_mechanism": None,
    }
    defaults.update(overrides)
    return defaults


def _registered_options() -> list[str]:
    registered: list[str] = []

    class FakeGroup:
        def addoption(self, *option_strings: str, **_kw: object) -> None:
            registered.extend(option_strings)

    class FakeParser:
        def getgroup(self, name: str, description: str = "") -> FakeGroup:
            return FakeGroup()

    plugin_mod.pytest_addoption(FakeParser())  # type: ignore[arg-type]
    return registered


def _fake_config(**options: Any) -> SimpleNamespace:
    def _getoption(name: str, default: Any = None) -> Any:
        return options.get(name, default)

    return SimpleNamespace(
        getoption=_getoption,
        addinivalue_line=lambda *a: None,
        stash={},
        option=SimpleNamespace(),
    )


class TestVendorMechanismOptionRegistered:
    def test_both_spellings_registered(self) -> None:
        registered = _registered_options()
        assert "--p11-vendor-mechanism" in registered
        assert "--vendor-mechanism" in registered


class TestParseVendorMechanismSpecs:
    def test_none_and_empty_yield_empty_mapping(self) -> None:
        assert plugin_mod.parse_vendor_mechanism_specs(None) == {}
        assert plugin_mod.parse_vendor_mechanism_specs([]) == {}

    def test_names_normalize_to_ckm_form(self) -> None:
        assert plugin_mod.parse_vendor_mechanism_specs(["KMAC_128=0x80001234"]) == {
            0x80001234: "CKM_KMAC_128"
        }
        assert plugin_mod.parse_vendor_mechanism_specs(["CKM_KMAC_128=0x80001234"]) == {
            0x80001234: "CKM_KMAC_128"
        }

    def test_decimal_ids_accepted(self) -> None:
        assert plugin_mod.parse_vendor_mechanism_specs(["FOO=2147483649"]) == {
            2147483649: "CKM_FOO"
        }

    @pytest.mark.parametrize(
        "spec",
        ["KMAC_128", "=0x80001234", "KMAC_128=xyz", "KMAC_128=-1", "  =  "],
    )
    def test_malformed_specs_raise_value_error(self, spec: str) -> None:
        with pytest.raises(ValueError, match="malformed --p11-vendor-mechanism spec"):
            plugin_mod.parse_vendor_mechanism_specs([spec])

    def test_conflicting_names_for_one_id_raise(self) -> None:
        with pytest.raises(ValueError, match="conflicting"):
            plugin_mod.parse_vendor_mechanism_specs(["KMAC_128=0x80001234", "OTHER=0x80001234"])

    def test_duplicate_spec_is_idempotent(self) -> None:
        assert plugin_mod.parse_vendor_mechanism_specs(
            ["KMAC_128=0x80001234", "KMAC_128=0x80001234"]
        ) == {0x80001234: "CKM_KMAC_128"}


class TestRegisterCliVendorMechanisms:
    def test_registration_feeds_reverse_lookup(self) -> None:
        from pkcs11_check.raw.extensions import (
            clear_extensions,
            lookup_mechanism_id,
            lookup_symbol_name,
        )

        clear_extensions("cli")
        try:
            mapping = plugin_mod.register_cli_vendor_mechanisms(["KMAC_128=0x80001234"])
            assert mapping == {0x80001234: "CKM_KMAC_128"}
            assert lookup_mechanism_id("KMAC_128") == 0x80001234
            assert lookup_symbol_name("mechanisms", 0x80001234) == "CKM_KMAC_128"
        finally:
            clear_extensions("cli")

    def test_empty_specs_do_not_create_namespace(self) -> None:
        from pkcs11_check.raw import extensions

        extensions.clear_extensions("cli")
        assert plugin_mod.register_cli_vendor_mechanisms(None) == {}
        assert extensions._vendor_or_none("cli") is None

    def test_standard_id_rejected(self) -> None:
        from pkcs11_check.raw.extensions import clear_extensions

        clear_extensions("cli")
        try:
            with pytest.raises(ValueError, match="standard mechanism ids"):
                plugin_mod.register_cli_vendor_mechanisms(["FOO=0x00001082"])
        finally:
            clear_extensions("cli")

    def test_standard_name_rejected(self) -> None:
        from pkcs11_check.raw.extensions import clear_extensions

        clear_extensions("cli")
        try:
            with pytest.raises(ValueError, match="standard mechanism names"):
                plugin_mod.register_cli_vendor_mechanisms(["AES_ECB=0x80001235"])
        finally:
            clear_extensions("cli")


class TestPytestConfigureRegistersVendorMechanisms:
    def test_configure_registers_specs(self) -> None:
        from pkcs11_check.raw.extensions import clear_extensions, lookup_mechanism_id

        clear_extensions("cli")
        try:
            config = _fake_config(
                p11_vendor_mechanism=["KMAC_128=0x80001234"],
                p11_module=None,
            )
            plugin_mod.pytest_configure(config)  # type: ignore[arg-type]
            assert lookup_mechanism_id("KMAC_128") == 0x80001234
        finally:
            clear_extensions("cli")

    def test_configure_absent_specs_is_noop(self) -> None:
        from pkcs11_check.raw import extensions

        extensions.clear_extensions("cli")
        config = _fake_config(p11_vendor_mechanism=None, p11_module=None)
        plugin_mod.pytest_configure(config)  # type: ignore[arg-type]
        assert extensions._vendor_or_none("cli") is None

    def test_configure_malformed_spec_is_usage_error(self) -> None:
        config = _fake_config(
            p11_vendor_mechanism=["KMAC_128"],
            p11_module=None,
        )
        with pytest.raises(pytest.UsageError, match="malformed"):
            plugin_mod.pytest_configure(config)  # type: ignore[arg-type]


class TestBuildPytestArgsForwardsVendorMechanism:
    def test_each_spec_forwarded_as_own_flag(self) -> None:
        args = _build_pytest_args(  # type: ignore[arg-type]
            **_default_args(vendor_mechanism=["KMAC_128=0x80001234", "KMAC_256=0x80005678"])
        )
        assert args.count("--p11-vendor-mechanism") == 2
        first = args.index("--p11-vendor-mechanism")
        assert args[first + 1] == "KMAC_128=0x80001234"
        second = args.index("--p11-vendor-mechanism", first + 1)
        assert args[second + 1] == "KMAC_256=0x80005678"

    def test_default_omits_flag(self) -> None:
        args = _build_pytest_args(**_default_args())  # type: ignore[arg-type]
        assert "--p11-vendor-mechanism" not in args
