"""Meta-test: external_provision — module-free unit tests.

All tests use monkeypatched subprocess.run and find_objects; no real PKCS#11
module or filesystem operations on real keys are required.

Covers:
  (a) both flags set + fake command succeeds + find returns a handle → returns
      the handle, records (obj_class, "ran_via_external"), temp file deleted.
  (b) allow_external_provision=False (or cmd None) → returns None immediately;
      subprocess.run NOT called.
  (c) returncode != 0 → None.
  (d) find_objects returns [] → None.
  (e) subprocess.run raises TimeoutExpired → None (no exception escapes).
  (f) temp file passed to fake command was mode 0600 while it existed (stat
      inside the fake subprocess.run via the {keyfile} arg).
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.testcases._provisioning import (
    ProvisioningEvent,
    clear_provisioning_events,
    external_provision,
    get_provisioning_events,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MATERIAL = b"\x01\x02\x03\x04" * 8  # 32 bytes of fake key material


def _make_rs(sh: int = 1) -> Any:
    """Synthetic RS stub — no real PKCS#11 module needed."""
    return type(
        "FakeRS",
        (),
        {
            "raw": object(),
            "sh": sh,
        },
    )()


def _make_cfg(
    *,
    allow_external: bool = True,
    cmd: str | None = "load-key {keyfile} {label} {key_type} {key_class}",
) -> Any:
    """Synthetic config stub."""
    return type(
        "FakeCfg",
        (),
        {
            "allow_external_provision": allow_external,
            "external_provision_cmd": cmd,
        },
    )()


# ---------------------------------------------------------------------------
# (a) Happy path: command succeeds, find returns a handle
# ---------------------------------------------------------------------------


def test_happy_path_returns_handle_and_records_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both flags set + command succeeds + find returns [42] → handle 42, event recorded."""
    clear_provisioning_events()

    fake_proc = MagicMock()
    fake_proc.returncode = 0

    run_called: list[bool] = []

    def fake_run(args: Any, **kwargs: Any) -> Any:
        run_called.append(True)
        return fake_proc

    def fake_find(raw: Any, sh: Any, tmpl: Any = None, **kwargs: Any) -> list[int]:
        return [42]

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find)

    rs = _make_rs(sh=1)
    cfg = _make_cfg()
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="mykey", key_type=3, obj_class="secret"
    )

    assert result == 42
    assert run_called, "subprocess.run should have been called"

    events = get_provisioning_events()
    assert ProvisioningEvent("secret", "ran_via_external") in events, (
        f"expected ran_via_external event in {events}"
    )


def test_find_objects_access_violation_is_not_an_unavailable_strategy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_proc = MagicMock(returncode=0)
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: fake_proc)
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.find_objects",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("exception: access violation reading 0x0")),
    )

    with pytest.raises(OSError, match="access violation"):
        external_provision(
            _make_rs(),
            _make_cfg(),
            material=_MATERIAL,
            label="mykey",
            key_type=3,
            obj_class="secret",
        )


@pytest.mark.parametrize(
    "error",
    [
        CkrAssertionError("undefined provider return", 0x12345678),
        AssertionError("binding bug"),
    ],
)
def test_find_objects_error_is_not_an_unavailable_strategy(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: MagicMock(returncode=0))
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.find_objects",
        lambda *_a, **_k: (_ for _ in ()).throw(error),
    )

    with pytest.raises(type(error)) as caught:
        external_provision(
            _make_rs(),
            _make_cfg(),
            material=_MATERIAL,
            label="mykey",
            key_type=3,
            obj_class="secret",
        )

    assert caught.value is error


def test_happy_path_temp_file_deleted_after_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After the call the temp file must no longer exist on the filesystem."""
    clear_provisioning_events()

    captured_path: list[str] = []

    def fake_run(args: list[str], **kwargs: Any) -> Any:
        # The keyfile is the first positional argument after the command name.
        # Template: "load-key {keyfile} {label} {key_type} {key_class}"
        # args = ["load-key", "<path>", "mykey", "3", "secret"]
        captured_path.append(args[1])
        proc = MagicMock()
        proc.returncode = 0
        return proc

    def fake_find(raw: Any, sh: Any, tmpl: Any = None, **kwargs: Any) -> list[int]:
        return [42]

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find)

    rs = _make_rs()
    cfg = _make_cfg()
    external_provision(rs, cfg, material=_MATERIAL, label="mykey", key_type=3, obj_class="secret")

    assert captured_path, "subprocess.run must have been called and captured the path"
    assert not os.path.exists(captured_path[0]), (
        f"temp file {captured_path[0]} should have been deleted"
    )


# ---------------------------------------------------------------------------
# (b) Gate: flags unset → returns None; subprocess.run NOT called
# ---------------------------------------------------------------------------


def test_gate_allow_false_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """allow_external_provision=False → None; subprocess.run must NOT be called."""
    run_called: list[bool] = []

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        run_called.append(True)
        return MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    rs = _make_rs()
    cfg = _make_cfg(allow_external=False)
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
    )

    assert result is None
    assert not run_called, "subprocess.run must NOT be called when gate is closed"


def test_gate_cmd_none_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """external_provision_cmd=None → None; subprocess.run must NOT be called."""
    run_called: list[bool] = []

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        run_called.append(True)
        return MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    rs = _make_rs()
    cfg = _make_cfg(cmd=None)
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
    )

    assert result is None
    assert not run_called, "subprocess.run must NOT be called when cmd is None"


def test_gate_cmd_empty_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """external_provision_cmd="" → None; subprocess.run must NOT be called."""
    run_called: list[bool] = []

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        run_called.append(True)
        return MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    rs = _make_rs()
    cfg = _make_cfg(cmd="")
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
    )

    assert result is None
    assert not run_called, "subprocess.run must NOT be called when cmd is empty"


# ---------------------------------------------------------------------------
# (c) Non-zero returncode → None
# ---------------------------------------------------------------------------


def test_nonzero_returncode_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Command exits with non-zero → None."""

    def fake_run(args: Any, **kwargs: Any) -> Any:
        proc = MagicMock()
        proc.returncode = 1
        return proc

    monkeypatch.setattr(subprocess, "run", fake_run)

    rs = _make_rs()
    cfg = _make_cfg()
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
    )
    assert result is None


# ---------------------------------------------------------------------------
# (d) find_objects returns [] → None
# ---------------------------------------------------------------------------


def test_find_objects_empty_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Command succeeds (returncode=0) but find_objects returns [] → None."""

    def fake_run(args: Any, **kwargs: Any) -> Any:
        proc = MagicMock()
        proc.returncode = 0
        return proc

    def fake_find(raw: Any, sh: Any, tmpl: Any = None, **kwargs: Any) -> list[int]:
        return []

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find)

    rs = _make_rs()
    cfg = _make_cfg()
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
    )
    assert result is None


# ---------------------------------------------------------------------------
# (e) subprocess.run raises TimeoutExpired → None (no exception escapes)
# ---------------------------------------------------------------------------


def test_timeout_expired_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """TimeoutExpired from subprocess.run → None; must not propagate."""

    def fake_run(args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=args, timeout=120)

    monkeypatch.setattr(subprocess, "run", fake_run)

    rs = _make_rs()
    cfg = _make_cfg()
    try:
        result = external_provision(
            rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
        )
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"external_provision raised unexpectedly: {exc}")
    else:
        assert result is None


# ---------------------------------------------------------------------------
# (f) Temp file has mode 0600 while it exists (stat inside fake subprocess.run)
# ---------------------------------------------------------------------------


def test_record_provisioning_event_raises_still_returns_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """record_provisioning_event raising must not prevent external_provision returning the handle.

    Pins the never-raises contract: even if event recording explodes, the function
    must still return the provisioned handle (not raise).
    """
    clear_provisioning_events()

    def fake_run(args: Any, **kwargs: Any) -> Any:
        proc = MagicMock()
        proc.returncode = 0
        return proc

    def fake_find(raw: Any, sh: Any, tmpl: Any = None, **kwargs: Any) -> list[int]:
        return [42]

    def exploding_record(obj_class: str, method: str) -> None:
        raise RuntimeError("event recording exploded")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find)
    monkeypatch.setattr(
        "pkcs11_check.testcases._provisioning.record_provisioning_event",
        exploding_record,
    )

    rs = _make_rs()
    cfg = _make_cfg()
    try:
        result = external_provision(
            rs, cfg, material=_MATERIAL, label="mykey", key_type=3, obj_class="secret"
        )
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"external_provision raised unexpectedly: {exc}")
    else:
        assert result == 42, f"expected handle 42, got {result!r}"


def test_temp_file_mode_0600_while_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    """The key file must be owner-only while the operator command can see it.

    The guarantee is one thing; its mechanism is platform-specific, so assert whichever
    one actually applies:

    * POSIX -- ``os.fchmod(fd, 0o600)``, checked as mode bits.
    * Windows -- ``os.fchmod`` does not exist, so the file keeps the default 0o666 and the
      protection is instead that ``tempfile`` places it in the per-user ``%TEMP%`` under
      the profile directory, whose NTFS ACL excludes other users. Asserting 0o600 there
      asserted a POSIX API that is simply absent.

    Mode bits are NOT merely skipped on Windows: the containment that replaces them is
    asserted, so the platform's real boundary stays covered.
    """
    observed_mode: list[int] = []
    observed_path: list[str] = []

    def fake_run(args: list[str], **kwargs: Any) -> Any:
        # args[1] is the keyfile path (template: "load-key {keyfile} {label} ...")
        keyfile = args[1]
        st = os.stat(keyfile)
        observed_mode.append(stat.S_IMODE(st.st_mode))
        observed_path.append(keyfile)
        proc = MagicMock()
        proc.returncode = 0
        return proc

    def fake_find(raw: Any, sh: Any, tmpl: Any = None, **kwargs: Any) -> list[int]:
        return [99]

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find)

    rs = _make_rs()
    cfg = _make_cfg()
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
    )

    assert result == 99
    assert observed_mode, "fake_run must have been called and observed the file mode"

    # Gate on the PLATFORM, not on hasattr(os, "fchmod"): Python 3.13 added os.fchmod on
    # Windows, where it SUCCEEDS and yet leaves the mode 0o666, because NTFS cannot express
    # POSIX owner-only bits. A capability check therefore takes the POSIX branch on Windows
    # and asserts a guarantee the OS never made.
    if sys.platform != "win32":
        assert observed_mode[0] == 0o600, f"expected mode 0600, got {oct(observed_mode[0])}"
    else:
        # Windows: assert the containment that replaces the mode bits.
        keyfile = Path(observed_path[0]).resolve()
        assert Path(tempfile.gettempdir()).resolve() in keyfile.parents, (
            f"key file {keyfile} must live in the per-user temp dir, which is what "
            "protects it when fchmod is unavailable"
        )


def test_write_failure_still_removes_temp_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failure during write-prep (os.write raises, e.g. ENOSPC) must still unlink the
    temp file — the finally covers it from mkstemp onward, so no key material is left on
    disk. Regression for the Phase-6 final-review security fix."""
    import os
    import tempfile

    clear_provisioning_events()
    captured: list[str] = []
    _real_mkstemp = tempfile.mkstemp

    def spy_mkstemp(*a: Any, **k: Any) -> Any:
        fd, path = _real_mkstemp(*a, **k)
        captured.append(path)
        return fd, path

    def boom_write(fd: int, data: Any) -> int:
        raise OSError("ENOSPC simulated")

    monkeypatch.setattr(tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(os, "write", boom_write)

    rs = _make_rs()
    cfg = _make_cfg()
    result = external_provision(
        rs, cfg, material=_MATERIAL, label="k", key_type=3, obj_class="secret"
    )

    assert result is None
    assert captured, "mkstemp should have been called"
    assert not os.path.exists(captured[0]), (
        f"temp file {captured[0]} must be removed even when write fails"
    )
