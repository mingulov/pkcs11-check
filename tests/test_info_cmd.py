"""Tests for ``pkcs11-check info`` isolation (F-019) and success path (F-040).

F-019 -- the module query runs in a spawned child so a crashing module
cannot take down ``info`` itself: the parent reports the crash and exits 3.
F-040 -- success-path coverage against a real module (SoftHSM when present).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.cli import info_cmd
from pkcs11_check.cli.app import app
from tests._plain_cli_runner import PlainCliRunner

runner = PlainCliRunner()


def _probe_add(a: int, b: int) -> int:
    return a + b


def _probe_boom() -> None:
    raise ValueError("boom-marker")


def _probe_segfault() -> None:
    import ctypes
    import sys

    if sys.platform == "win32":
        # A null dereference never kills the child on Windows: SEH
        # translates it into a catchable OSError, so the child would answer
        # instead of dying. Terminate with the AV status code -- the same
        # shape as the crashing-child probes elsewhere -- to exercise the
        # died-without-answering path. (os._exit cannot carry this code:
        # CPython parses the status as a C int and raises OverflowError.)
        kernel = ctypes.windll.kernel32
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel.TerminateProcess(kernel.GetCurrentProcess(), 0xC0000005)
    ctypes.string_at(0)


def _probe_sleep() -> None:
    import time

    time.sleep(30)


_LARGE_PAYLOAD = b"large-response-marker:" * 8192  # ~168 KiB pickled


def _probe_large_payload() -> bytes:
    return _LARGE_PAYLOAD


def test_isolated_call_returns_result() -> None:
    assert info_cmd._run_isolated(_probe_add, 2, 3) == 5


def test_isolated_call_propagates_child_error() -> None:
    with pytest.raises(info_cmd.InfoQueryError, match="boom-marker"):
        info_cmd._run_isolated(_probe_boom)


def test_isolated_call_survives_child_segfault() -> None:
    """F-019: a native crash in the child is a clean parent-side error."""
    with pytest.raises(info_cmd.InfoQueryCrashError) as ei:
        info_cmd._run_isolated(_probe_segfault)
    assert ei.value.exitcode is not None and ei.value.exitcode != 0
    assert "crash" in str(ei.value).lower()


def test_isolated_call_times_out_hung_child() -> None:
    """F-019: a hung query cannot hang ``info`` forever."""
    with pytest.raises(info_cmd.InfoQueryError, match="timed out"):
        info_cmd._run_isolated(_probe_sleep, timeout=2)


def test_isolated_call_large_response() -> None:
    """A large child payload must not deadlock the parent (drain-before-join).

    RED proof: the pre-fix ``join``-before-``get`` ordering leaves the child
    unable to hand over a >pipe-buffer payload, surfacing as a timeout.
    """
    payload = info_cmd._run_isolated(_probe_large_payload, timeout=30)
    assert payload == _LARGE_PAYLOAD


def _find_softhsm() -> Path | None:
    for candidate in (
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
    ):
        if Path(candidate).exists():
            return Path(candidate)
    return None


def test_info_success_against_softhsm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """F-040: success-path coverage for ``info`` (skipped without SoftHSM).

    Provisions a hermetic token dir so the test never depends on ambient
    SoftHSM state.
    """
    import shutil
    import subprocess

    module = _find_softhsm()
    if module is None or shutil.which("softhsm2-util") is None:
        pytest.skip("SoftHSM not installed")
    tokens = tmp_path / "tokens"
    tokens.mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(
        f"directories.tokendir = {tokens}\nobjectstore.backend = file\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    init = subprocess.run(
        [
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            "info-test",
            "--so-pin",
            "12345678",
            "--pin",
            "1234",
        ],
        capture_output=True,
        timeout=60,
    )
    if init.returncode != 0:
        pytest.skip(f"cannot init SoftHSM token: {init.stderr.decode()[:200]}")
    result = runner.invoke(app, ["info", "--module", str(module)])
    assert result.exit_code == 0, result.output
    assert "Module:" in result.output
    assert "Slots with tokens:" in result.output
    assert "Mechanism" in result.output


def _fake_module(slots: list[tuple[str, int]]) -> object:
    """Fake loader module: (label, flags) per token-present slot."""

    class _Token:
        def __init__(self, label: str, flags: int) -> None:
            self.label = label
            self.manufacturer_id = "FakeHSM"
            self.model = "Fake v1"
            self.flags = flags

    class _Slot:
        def __init__(self, label: str, flags: int) -> None:
            self._token = _Token(label, flags)
            self.queries = 0

        def get_token(self) -> _Token:
            return self._token

        def get_mechanisms(self) -> list[int]:
            self.queries += 1
            return [0x1082] if self._token.label else []

        def get_mechanism_info(self, mech: int) -> object:
            from types import SimpleNamespace

            return SimpleNamespace(min_key_length=16, max_key_length=32)

    class _Module:
        path = "fake.so"
        interface_version = "3.0"

        def __init__(self) -> None:
            self._slots = [_Slot(label, flags) for label, flags in slots]

        def get_interface_list(self) -> list[tuple[str, int, int]]:
            return []

        def get_slots(self, token_present: bool = True) -> list[_Slot]:
            assert token_present
            return self._slots

    return _Module()


def test_collect_marks_uninitialized_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U9: collection records per-slot initialized state from token flags."""
    from pkcs11_check.raw.types_std import CKF_TOKEN_INITIALIZED

    fake = _fake_module([("demo", int(CKF_TOKEN_INITIALIZED)), ("", 0)])
    monkeypatch.setattr(info_cmd, "load_module", lambda *a, **k: fake)
    info = info_cmd._collect_module_info("fake.so", "auto")
    assert [slot.initialized for slot in info.slots] == [True, False]
    # N7: mechanism queries run only for the initialized slot.
    assert [slot.queries for slot in fake._slots] == [1, 0]


def test_render_names_usable_slot_and_skips_uninitialized_table(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """U9: exactly one usable slot named; no duplicated table for the other."""
    info = info_cmd.ModuleInfo(
        path="fake.so",
        interface_version="3.0",
        interfaces=(),
        slots=(
            info_cmd.SlotInfo(
                index=0,
                label="demo",
                manufacturer_id="FakeHSM",
                model="Fake v1",
                mechanisms=(("AES_CBC", "16", "32"),),
                initialized=True,
            ),
            info_cmd.SlotInfo(
                index=1,
                label="",
                manufacturer_id="FakeHSM",
                model="Fake v1",
                mechanisms=(("AES_CBC", "16", "32"),),
                initialized=False,
            ),
        ),
    )
    info_cmd._render_module_info(info)
    out = capsys.readouterr().out
    assert "(1 initialized)" in out
    assert "Slot 0:" in out
    assert "not initialized" in out
    assert out.count("Mechanisms (") == 1
