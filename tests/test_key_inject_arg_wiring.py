"""Tests for key-inject / wrap-* option wiring through _build_pytest_args and pytest plugin."""

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
        # provisioning defaults (new params)
        "key_inject": "off",
        "wrap_key_source": "bootstrap",
        "wrap_key_label": None,
        "wrap_key_handle": None,
        "wrap_key_value": None,
        "wrap_mech": None,
        "wrap_rsa_bits": 2048,
        "wrap_oaep_hash": "auto",
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# _build_pytest_args tests
# ---------------------------------------------------------------------------


class TestBuildPytestArgsKeyInject:
    def test_force_unwrap_emits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(key_inject="force-unwrap"))  # type: ignore[arg-type]
        idx = args.index("--p11-key-inject")
        assert args[idx + 1] == "force-unwrap"

    def test_unwrap_emits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(key_inject="unwrap"))  # type: ignore[arg-type]
        assert "--p11-key-inject" in args
        idx = args.index("--p11-key-inject")
        assert args[idx + 1] == "unwrap"

    def test_off_default_omits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(key_inject="off"))  # type: ignore[arg-type]
        assert "--p11-key-inject" not in args

    def test_default_omits_flag(self) -> None:
        """Default kwargs (key_inject='off') must not emit --p11-key-inject."""
        args = _build_pytest_args(**_default_args())  # type: ignore[arg-type]
        assert "--p11-key-inject" not in args


class TestBuildPytestArgsWrapRsaBits:
    def test_4096_emits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_rsa_bits=4096))  # type: ignore[arg-type]
        assert "--p11-wrap-rsa-bits" in args
        idx = args.index("--p11-wrap-rsa-bits")
        assert args[idx + 1] == "4096"

    def test_default_2048_omits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_rsa_bits=2048))  # type: ignore[arg-type]
        assert "--p11-wrap-rsa-bits" not in args


class TestBuildPytestArgsWrapOaepHash:
    def test_sha1_emits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_oaep_hash="sha1"))  # type: ignore[arg-type]
        assert "--p11-wrap-oaep-hash" in args
        idx = args.index("--p11-wrap-oaep-hash")
        assert args[idx + 1] == "sha1"

    def test_auto_default_omits_flag(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_oaep_hash="auto"))  # type: ignore[arg-type]
        assert "--p11-wrap-oaep-hash" not in args


class TestBuildPytestArgsNoneDefaults:
    def test_wrap_key_label_emits_when_set(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_key_label="my-kek"))  # type: ignore[arg-type]
        assert "--p11-wrap-key-label" in args
        idx = args.index("--p11-wrap-key-label")
        assert args[idx + 1] == "my-kek"

    def test_wrap_key_label_absent_when_none(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_key_label=None))  # type: ignore[arg-type]
        assert "--p11-wrap-key-label" not in args

    def test_wrap_key_handle_emits_when_set(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_key_handle=7))  # type: ignore[arg-type]
        assert "--p11-wrap-key-handle" in args
        idx = args.index("--p11-wrap-key-handle")
        assert args[idx + 1] == "7"

    def test_wrap_key_value_emits_when_set(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_key_value="deadbeef"))  # type: ignore[arg-type]
        assert "--p11-wrap-key-value" in args
        idx = args.index("--p11-wrap-key-value")
        assert args[idx + 1] == "deadbeef"

    def test_wrap_mech_emits_when_set(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_mech="CKM_RSA_AES_KEY_WRAP"))  # type: ignore[arg-type]
        assert "--p11-wrap-mech" in args
        idx = args.index("--p11-wrap-mech")
        assert args[idx + 1] == "CKM_RSA_AES_KEY_WRAP"

    def test_wrap_key_source_emits_when_not_bootstrap(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_key_source="configured"))  # type: ignore[arg-type]
        assert "--p11-wrap-key-source" in args
        idx = args.index("--p11-wrap-key-source")
        assert args[idx + 1] == "configured"

    def test_wrap_key_source_absent_when_bootstrap(self) -> None:
        args = _build_pytest_args(**_default_args(wrap_key_source="bootstrap"))  # type: ignore[arg-type]
        assert "--p11-wrap-key-source" not in args


# ---------------------------------------------------------------------------
# Plugin option registration test
# ---------------------------------------------------------------------------


class TestPluginRegistersKeyInjectOption:
    def test_p11_key_inject_registered(self) -> None:
        """pytest_addoption must register --p11-key-inject.

        We verify by feeding a fake parser that collects all registered option strings
        and asserting --p11-key-inject is among them.  This is cleaner than exercising
        the full fixture (which requires live pytest internals / a real module path).
        """
        registered: list[str] = []

        class FakeOption:
            def __init__(self, *option_strings: str, **_kw: object) -> None:
                registered.extend(option_strings)

        class FakeGroup:
            def addoption(self, *option_strings: str, **kw: object) -> None:
                registered.extend(option_strings)

        class FakeParser:
            def getgroup(self, name: str, description: str = "") -> FakeGroup:
                return FakeGroup()

        plugin_mod.pytest_addoption(FakeParser())

        assert "--p11-key-inject" in registered

    def test_all_wrap_options_registered(self) -> None:
        """All 8 new options are registered in pytest_addoption."""
        registered: list[str] = []

        class FakeGroup:
            def addoption(self, *option_strings: str, **kw: object) -> None:
                registered.extend(option_strings)

        class FakeParser:
            def getgroup(self, name: str, description: str = "") -> FakeGroup:
                return FakeGroup()

        plugin_mod.pytest_addoption(FakeParser())

        expected = {
            "--p11-key-inject",
            "--p11-wrap-key-source",
            "--p11-wrap-key-label",
            "--p11-wrap-key-handle",
            "--p11-wrap-key-value",
            "--p11-wrap-mech",
            "--p11-wrap-rsa-bits",
            "--p11-wrap-oaep-hash",
        }
        missing = expected - set(registered)
        assert not missing, f"Options not registered: {missing}"
