"""Tests for --ckr-strict wiring through the CLI and the pytest plugin."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.cli.test_cmd import _build_pytest_args

pytest_plugins = ["pytester"]

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
        "so_pin": None,
        "slot": 0,
        "destructive": False,
        "ckr_strict": False,
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


class TestBuildPytestArgsCkrStrict:
    def test_enabled_emits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(ckr_strict=True))  # type: ignore[arg-type]
        assert "--ckr-strict" in args

    def test_disabled_omits_flag(self) -> None:
        args = _build_pytest_args(**_default_args())  # type: ignore[arg-type]
        assert "--ckr-strict" not in args


def test_ckr_strict_parses_without_ckr_conftest(pytester: pytest.Pytester) -> None:
    # The CLI passes --ckr-strict for any selection, so the flag must
    # parse without the CKR conftest loaded (it used to be registered
    # there; a non-CKR run would die with exit 4, unrecognized
    # argument). A bare directory exercises exactly that: no
    # conftest, no CKR tests, flag accepted.
    pytester.makepyfile("def test_trivial(): assert True")
    result = pytester.runpytest_subprocess("--ckr-strict", "-q")
    result.assert_outcomes(passed=1)
