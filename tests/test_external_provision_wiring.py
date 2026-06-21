"""Tests for --allow-external-provision / --external-provision-cmd end-to-end wiring.

Covers:
- _build_pytest_args emits both flags when enabled.
- _build_pytest_args omits both flags at their defaults.
- pytest_addoption registers both --p11-allow-external-provision and
  --p11-external-provision-cmd.
"""

from __future__ import annotations

from pathlib import Path

import pkcs11_check.plugin as plugin_mod
from pkcs11_check.cli.test_cmd import _build_pytest_args

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MODULE = Path("/tmp/test.so")


def _default_args(**overrides: object) -> dict[str, object]:
    """Return a full kwargs dict for _build_pytest_args with sane defaults."""
    defaults: dict[str, object] = {
        "module": _MODULE,
        "interface": "auto",
        "timeout": 180,
        "category": None,
        "match": None,
        "marker": None,
        "include_pin_arg": False,
        "pin": None,
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
        "wrap_key_value": None,
        "wrap_mech": None,
        "wrap_rsa_bits": 2048,
        "wrap_oaep_hash": "auto",
        "allow_external_provision": False,
        "external_provision_cmd": None,
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# _build_pytest_args tests
# ---------------------------------------------------------------------------


class TestBuildPytestArgsExternalProvision:
    def test_both_flags_emitted_when_enabled(self) -> None:
        """When allow_external_provision=True and a cmd is set, both flags appear."""
        args = _build_pytest_args(  # type: ignore[arg-type]
            **_default_args(
                allow_external_provision=True,
                external_provision_cmd="load {keyfile}",
            )
        )
        assert "--p11-allow-external-provision" in args
        assert "--p11-external-provision-cmd" in args
        idx = args.index("--p11-external-provision-cmd")
        assert args[idx + 1] == "load {keyfile}"

    def test_allow_flag_emitted_alone(self) -> None:
        """allow_external_provision=True without a cmd emits the flag but not the cmd."""
        args = _build_pytest_args(  # type: ignore[arg-type]
            **_default_args(allow_external_provision=True, external_provision_cmd=None)
        )
        assert "--p11-allow-external-provision" in args
        assert "--p11-external-provision-cmd" not in args

    def test_cmd_flag_emitted_without_allow(self) -> None:
        """external_provision_cmd set without allow_external_provision still emits the cmd flag."""
        args = _build_pytest_args(  # type: ignore[arg-type]
            **_default_args(
                allow_external_provision=False,
                external_provision_cmd="load {keyfile}",
            )
        )
        assert "--p11-allow-external-provision" not in args
        assert "--p11-external-provision-cmd" in args
        idx = args.index("--p11-external-provision-cmd")
        assert args[idx + 1] == "load {keyfile}"

    def test_defaults_emit_neither_flag(self) -> None:
        """With defaults (False / None), neither flag appears in the output."""
        args = _build_pytest_args(**_default_args())  # type: ignore[arg-type]
        assert "--p11-allow-external-provision" not in args
        assert "--p11-external-provision-cmd" not in args


# ---------------------------------------------------------------------------
# Plugin option registration test
# ---------------------------------------------------------------------------


class TestPluginRegistersExternalProvisionOptions:
    def _collect_registered(self) -> list[str]:
        registered: list[str] = []

        class FakeGroup:
            def addoption(self, *option_strings: str, **kw: object) -> None:
                registered.extend(option_strings)

        class FakeParser:
            def getgroup(self, name: str, description: str = "") -> FakeGroup:
                return FakeGroup()

        plugin_mod.pytest_addoption(FakeParser())
        return registered

    def test_allow_external_provision_registered(self) -> None:
        """pytest_addoption must register --p11-allow-external-provision."""
        assert "--p11-allow-external-provision" in self._collect_registered()

    def test_external_provision_cmd_registered(self) -> None:
        """pytest_addoption must register --p11-external-provision-cmd."""
        assert "--p11-external-provision-cmd" in self._collect_registered()

    def test_both_options_registered(self) -> None:
        """Both new options are registered in a single pytest_addoption call."""
        registered = set(self._collect_registered())
        missing = {"--p11-allow-external-provision", "--p11-external-provision-cmd"} - registered
        assert not missing, f"Options not registered: {missing}"
