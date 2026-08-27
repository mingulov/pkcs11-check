"""The per-test timeout must stop a hang inside native code, and say so.

Two separate problems, both real, both verified against a real hanging module:

1. pytest-timeout's default `signal` method cannot interrupt a thread blocked in an
   FFI call. SIGALRM is delivered, the C trampoline consumes it, and the Python-level
   handler never runs because the thread never returns to bytecode. Measured: a 5s
   per-test timeout did not stop a native spin at all.

2. pytest-timeout's `thread` method DOES stop it, but exits via os._exit(1) - pytest's
   ordinary "tests failed" code. The runner classifies 1 as `failed`, so a provider
   deadlock would be recorded as ordinary assertion failures with no failing test.

The framework already classifies _TIMEOUT_RETURN_CODE (124) as `timeout` and already
preserves a unit's partial report records on that path, so owning the timer and exiting
124 is the whole fix. pytest-timeout declares pytest_timeout_set_timer as a
firstresult=True hookspec and implements it `trylast`, so an implementation here wins
while pytest-timeout keeps doing settings resolution, marker precedence and cancellation.

In-process runs (`--isolation none`) must NOT self-exit: pytest.main() runs inside the
CLI, so os._exit would skip results.json assembly entirely. There the hook delegates.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pkcs11_check.plugin as plugin_mod
from pkcs11_check.cli.test_cmd import _build_pytest_args
from pkcs11_check.core.file_runner import _TIMEOUT_RETURN_CODE

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
        "wrap_key_value": None,
        "wrap_mech": None,
        "wrap_rsa_bits": 2048,
        "wrap_oaep_hash": "auto",
        "allow_external_provision": False,
        "external_provision_cmd": None,
    }
    defaults.update(overrides)
    return defaults


class _FakeSettings:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self.func_only = False


class _FakeItem:
    nodeid = "test_x.py::test_hangs"


class TestOwnedTimeoutTimer:
    def test_plugin_implements_the_timer_hook(self) -> None:
        """Without this hook pytest-timeout owns the exit code and uses 1."""
        assert hasattr(plugin_mod, "pytest_timeout_set_timer")
        assert hasattr(plugin_mod, "pytest_timeout_cancel_timer")

    def test_child_unit_timeout_exits_with_the_timeout_return_code(self, monkeypatch: Any) -> None:
        """Firing in a child unit must exit 124, which the runner maps to `timeout`."""
        monkeypatch.setenv(plugin_mod.UNIT_CHILD_ENV, "1")
        exits: list[int] = []
        monkeypatch.setattr(plugin_mod.os, "_exit", lambda code: exits.append(code))

        plugin_mod._on_timeout_expired(_FakeItem())  # type: ignore[attr-defined]

        assert exits == [_TIMEOUT_RETURN_CODE], (
            "a child-reported timeout must use 124; exiting 1 makes a native deadlock "
            "indistinguishable from ordinary test failures"
        )

    def test_in_process_run_delegates_instead_of_self_exiting(self, monkeypatch: Any) -> None:
        """--isolation none runs pytest in-process; os._exit there loses results.json."""
        monkeypatch.delenv(plugin_mod.UNIT_CHILD_ENV, raising=False)
        armed = plugin_mod.pytest_timeout_set_timer(_FakeItem(), _FakeSettings(30))
        assert armed is None, (
            "in-process runs must fall through to pytest-timeout rather than arm a "
            "self-exiting timer that would kill the CLI before results are written"
        )


class TestTimeoutDiagnosticsReachTheLog:
    def test_capture_is_suspended_before_dumping(self, monkeypatch: Any) -> None:
        """Without suspending capture the stack dump is swallowed by pytest.

        pytest captures stdout/stderr at the fd level and os._exit discards the capture
        buffer, so a dump written while capture is active never reaches the unit log.
        Verified against a real native hang: the timeout fired and exited 124 correctly,
        but the diagnostic was invisible - leaving "a timeout happened" with no clue as
        to WHERE, which is most of the value of catching it.
        """
        suspended: list[bool] = []

        class _Capman:
            # Signature matches _pytest.capture.CaptureManager exactly: (in_=False),
            # with NO item argument. An earlier version of this mock accepted an item,
            # so the test passed while production raised TypeError and the stack dump
            # was silently lost. A mock whose signature is wrong tests nothing.
            def suspend_global_capture(self, in_: bool = False) -> None:
                suspended.append(in_)

        class _PM:
            def getplugin(self, name: str) -> Any:
                return _Capman() if name == "capturemanager" else None

        class _Config:
            pluginmanager = _PM()

        class _Item:
            nodeid = "test_x.py::test_hangs"
            config = _Config()

        monkeypatch.setenv(plugin_mod.UNIT_CHILD_ENV, "1")
        monkeypatch.setattr(plugin_mod.os, "_exit", lambda code: None)

        plugin_mod._on_timeout_expired(_Item())  # type: ignore[attr-defined]

        assert suspended == [True], (
            "capture must be suspended before the stack dump, with in_=True so stdin is "
            "restored too; the call must match CaptureManager's real (in_) signature"
        )


class TestTimeoutMethodNotForced:
    def test_thread_method_is_not_passed(self) -> None:
        """The owned hook wins regardless of method, and forcing `thread` would make
        pytest-timeout os._exit(1) during in-process runs."""
        args = _build_pytest_args(**_default_args())  # type: ignore[arg-type]
        assert "--timeout-method" not in args

    def test_timeout_value_still_passed(self) -> None:
        args = _build_pytest_args(**_default_args(timeout=42))  # type: ignore[arg-type]
        assert args[args.index("--timeout") + 1] == "42"
