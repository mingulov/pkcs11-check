"""Meta-tests for _probes/session.py: the RawPKCS11 child entry point.

The test drives probe_main end-to-end via a real subprocess so that the
session-setup path (load -> C_Initialize -> C_OpenSession -> C_Login) is exercised
against a real PKCS#11 shared library, not a Python mock.

Mock module requirements: pkcs11-mock (https://github.com/Pkcs11Interop/pkcs11-mock)
is a minimal C stub that returns CKR_OK for all operations and accepts any PIN.
Build from upstream (https://github.com/Pkcs11Interop/pkcs11-mock) and set
P11TEST_MOCK_MODULE=/path/to/pkcs11-mock.so.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_PIN_LOCKED,
    CKR_SLOT_ID_INVALID,
)
from pkcs11_check.testcases._probes import session


@pytest.fixture(autouse=True)
def _probe_params_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    """Direct probe calls must not depend on pytest's own command-line arguments."""
    monkeypatch.setattr(sys, "argv", ["session-probe", "params.json"])


def _write_probe(tmp_path: Path) -> Path:
    """Write a tiny child module that calls probe_main and reports session state."""
    probe = tmp_path / "probe_under_test.py"
    probe.write_text(
        textwrap.dedent(
            """
            from pkcs11_check.testcases._probes.session import probe_main, ProbeContext

            def run(ctx: ProbeContext, extra: dict) -> None:
                print("SESSION_OK:" + str(ctx.sh is not None))

            if __name__ == "__main__":
                probe_main(run)
            """
        ),
        encoding="utf-8",
    )
    return probe


def test_session_probe_opens_session_and_runs(tmp_path: Path, mock_module_path: str) -> None:
    """probe_main at Level.LOGIN opens a session and delivers a non-None sh to run_fn."""
    params = tmp_path / "params.json"
    # Do NOT hard-code slot_id: pkcs11-mock exposes slot 1, not 0. Omitting lets
    # probe_main discover the first available slot via get_slot_ids().
    params.write_text(json.dumps({"module_path": mock_module_path}), encoding="utf-8")

    probe = _write_probe(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "_P11CHECK_PIN": "1234"},  # PIN only via env (I3)
        timeout=30,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr
    assert "SESSION_OK:True" in proc.stdout


def test_session_probe_writes_coverage(tmp_path: Path, mock_module_path: str) -> None:
    """I6 round-trip: _P11CHECK_SUBPROCESS_COVERAGE produces a parseable JSON file.

    The call_log must contain "C_Initialize" (probe_main always calls it at Level.LOGIN).
    A future rename of call_log / mechanism_counts fields would be caught here.
    """
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"module_path": mock_module_path}), encoding="utf-8")

    probe = _write_probe(tmp_path)
    cov_path = tmp_path / "cov.json"

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "_P11CHECK_PIN": "1234", "_P11CHECK_SUBPROCESS_COVERAGE": str(cov_path)},
        timeout=30,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr

    assert cov_path.exists(), "coverage file was not written"
    data = json.loads(cov_path.read_text(encoding="utf-8"))

    assert "call_log" in data, f"missing 'call_log' key; got: {list(data)}"
    assert "mechanism_counts" in data, f"missing 'mechanism_counts' key; got: {list(data)}"

    call_log = data["call_log"]
    assert isinstance(call_log, dict) and call_log, f"call_log is empty or not a dict: {call_log!r}"
    # C_Initialize is always called by probe_main at Level.LOGIN — assert the real key.
    assert "C_Initialize" in call_log, (
        f"expected 'C_Initialize' in call_log; got keys: {list(call_log)}"
    )


def test_session_probe_emits_rv_trace(tmp_path: Path, mock_module_path: str) -> None:
    """I7 round-trip: PKCS11_CHECK_RV_TRACE=1 causes P11_RV_TRACE_JSON: to appear in stdout."""
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"module_path": mock_module_path}), encoding="utf-8")

    probe = _write_probe(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(probe), str(params)],
        capture_output=True,
        text=True,
        env={"PATH": "", "_P11CHECK_PIN": "1234", "PKCS11_CHECK_RV_TRACE": "1"},
        timeout=30,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr

    marker = "P11_RV_TRACE_JSON:"
    assert marker in proc.stdout, f"marker {marker!r} not found in stdout: {proc.stdout!r}"

    # Extract the JSON after the LAST occurrence of the marker on its line.
    last_json_str = next(
        line.split(marker, 1)[1] for line in reversed(proc.stdout.splitlines()) if marker in line
    )
    trace = json.loads(last_json_str)
    assert isinstance(trace, list), f"rv_trace is not a list: {trace!r}"


def test_probe_teardown_runs_at_most_once(monkeypatch: object) -> None:
    """_ProbeTeardown is registered via atexit AND exposed as ctx.cleanup, so a probe that calls
    ctx.cleanup() plus the atexit firing must not double-finalize. Guards the run-once contract
    directly (previously only exercised end-to-end)."""
    import pkcs11_check.testcases._probes.session as session

    calls = {"coverage": 0, "close": 0, "finalize": 0}
    monkeypatch.setattr(
        session, "_write_coverage", lambda raw: calls.__setitem__("coverage", calls["coverage"] + 1)
    )  # type: ignore[attr-defined]
    monkeypatch.setattr(
        session,
        "close_session_quietly",
        lambda raw, sh: calls.__setitem__("close", calls["close"] + 1),
    )  # type: ignore[attr-defined]

    class _FakeRaw:
        def C_Finalize(self, _reserved: object) -> int:  # noqa: N802  # PKCS#11 API name
            calls["finalize"] += 1
            return 0

    teardown = session._ProbeTeardown(_FakeRaw())  # type: ignore[arg-type]
    teardown.sh = 7
    teardown.initialized = True

    teardown()
    teardown()  # second invocation must be a no-op

    assert calls == {"coverage": 1, "close": 1, "finalize": 1}


def test_probe_main_passes_requested_interface_to_raw_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _Raw:
        pass

    def _from_lib(path: str, *, interface: str = "auto") -> _Raw:
        captured.update(path=path, interface=interface)
        return _Raw()

    monkeypatch.setattr(
        session.ProbeParams,
        "load",
        lambda _path: SimpleNamespace(
            module_path="provider.so", slot_id=None, interface="3.1", extra={}
        ),
    )
    monkeypatch.setattr(session.RawPKCS11, "from_lib", _from_lib)
    monkeypatch.setattr(session, "_ProbeTeardown", _NoopTeardown)
    monkeypatch.setattr(session.atexit, "register", lambda *_a, **_k: None)

    session.probe_main(lambda _ctx, _extra: None, level=session.Level.LOAD)

    assert captured == {"path": "provider.so", "interface": "3.1"}


class _NoopTeardown:
    def __init__(self, _raw: object) -> None:
        self.sh: int | None = None
        self.initialized = False

    def __call__(self) -> None:
        return


def _session_params() -> SimpleNamespace:
    return SimpleNamespace(module_path="provider.so", slot_id=None, extra={})


def test_session_clean_initialize_reject_is_terminal_setup_evidence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A clean C_Initialize CKR is preserved and the target probe is not run."""

    class _Raw:
        def C_Initialize(self, _reserved: object) -> int:  # noqa: N802
            return int(CKR_GENERAL_ERROR)

    monkeypatch.setattr(session.ProbeParams, "load", lambda _path: _session_params())
    monkeypatch.setattr(session.RawPKCS11, "from_lib", lambda _path, **_kwargs: _Raw())
    monkeypatch.setattr(session, "_ProbeTeardown", _NoopTeardown)
    monkeypatch.setattr(session.atexit, "register", lambda *_a, **_k: None)
    monkeypatch.setattr(session, "rv_trace_enabled", lambda: False)

    session.probe_main(
        lambda _ctx, _extra: pytest.fail("probe must not run"),
        level=session.Level.INIT,
    )

    assert "SETUP_XFAIL:C_Initialize rejected with CKR_GENERAL_ERROR" in capsys.readouterr().out


def test_session_python_initialize_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only provider CKR assertions are converted to setup evidence."""

    class _Raw:
        def C_Initialize(self, _reserved: object) -> int:  # noqa: N802
            raise RuntimeError("bootstrap bug")

    monkeypatch.setattr(session.ProbeParams, "load", lambda _path: _session_params())
    monkeypatch.setattr(session.RawPKCS11, "from_lib", lambda _path, **_kwargs: _Raw())
    monkeypatch.setattr(session, "_ProbeTeardown", _NoopTeardown)
    monkeypatch.setattr(session.atexit, "register", lambda *_a, **_k: None)
    monkeypatch.setattr(session, "rv_trace_enabled", lambda: False)

    with pytest.raises(RuntimeError, match="bootstrap bug"):
        session.probe_main(lambda _ctx, _extra: None, level=session.Level.INIT)


def test_probe_main_announces_spawn_before_module_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#88R23-1: the spawn record lands before the module even loads."""
    from pkcs11_check.core import _counters_durability as durability
    from pkcs11_check.core import call_counters

    counters = tmp_path / "counters"
    counters.mkdir()
    monkeypatch.setenv(durability.PROBE_SIDECAR_ENV, str(counters / "probe-aaaaaaaa-5-bead01.json"))
    monkeypatch.setenv(durability.PROBE_SEQ_ENV, "5")
    monkeypatch.setenv(durability.PROBE_PARENT_ENV, "a" * 32)
    order: list[str] = []
    real_note = call_counters.note_own_probe_spawn

    def _note() -> object:
        order.append("spawn")
        return real_note()

    def _from_lib(path: str, **kwargs: object) -> object:
        order.append("load")
        return SimpleNamespace()

    monkeypatch.setattr(session.ProbeParams, "load", lambda _path: _session_params())
    monkeypatch.setattr(session.RawPKCS11, "from_lib", _from_lib)
    monkeypatch.setattr(session, "_ProbeTeardown", _NoopTeardown)
    monkeypatch.setattr(session.atexit, "register", lambda *_a, **_k: None)
    monkeypatch.setattr(session, "note_own_probe_spawn", _note, raising=False)
    session.probe_main(lambda _ctx, _extra: None, level=session.Level.LOAD)
    assert order == ["spawn", "load"]
    assert len(list(counters.glob("spawn-*.json"))) == 1


def _drive_login_setup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    open_rv: int | None = None,
    login_rv: int | None = None,
) -> None:
    """Run probe_main at LOGIN with scripted setup failures (B5a harness)."""

    class _Raw:
        def C_Initialize(self, _reserved: object) -> int:  # noqa: N802
            return int(CKR_OK)

    def _open(_raw: object, _slot: int, _flags: int) -> int:
        if open_rv is not None:
            raise CkrAssertionError(f"C_OpenSession -> {ckr_name(open_rv)}", open_rv)
        return 99

    def _login(_raw: object, _sh: int, _user: int, _pin: bytes) -> None:
        if login_rv is not None:
            raise CkrAssertionError(f"C_Login -> {ckr_name(login_rv)}", login_rv)

    monkeypatch.setattr(session.ProbeParams, "load", lambda _path: _session_params())
    monkeypatch.setattr(session.RawPKCS11, "from_lib", lambda _path, **_kwargs: _Raw())
    monkeypatch.setattr(session, "_ProbeTeardown", _NoopTeardown)
    monkeypatch.setattr(session.atexit, "register", lambda *_a, **_k: None)
    monkeypatch.setattr(session, "rv_trace_enabled", lambda: False)
    monkeypatch.setattr(session, "get_slot_ids", lambda _raw: [7])
    monkeypatch.setattr(session, "resolve_slot_id", lambda _slots, _idx: 7)
    monkeypatch.setattr(session, "open_session", _open)
    monkeypatch.setattr(session, "login_user", _login)
    monkeypatch.setenv("_P11CHECK_PIN", "1234")
    session.probe_main(
        lambda _ctx, _extra: pytest.fail("probe must not run"),
        level=session.Level.LOGIN,
    )


def test_session_login_pin_incorrect_is_harness_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """B5a: a rejected configured PIN is never not_operational.

    R1-F3: the nonzero exit is load-bearing -- the parent raises a
    single harness_error fail for rc != 0, while exit 0 would
    record-then-continue into a probe_incomplete follow-on.
    """
    with pytest.raises(SystemExit) as exit_info:
        _drive_login_setup(monkeypatch, login_rv=int(CKR_PIN_INCORRECT))
    assert exit_info.value.code == 1
    out = capsys.readouterr().out
    assert "HARNESS_ERROR:" in out
    assert "SETUP_XFAIL" not in out


def test_session_open_invalid_slot_id_stays_setup_xfail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R1-F4: a rejected self-resolved id may be a yanked token, not our bug."""
    _drive_login_setup(monkeypatch, open_rv=int(CKR_SLOT_ID_INVALID))
    out = capsys.readouterr().out
    assert "SETUP_XFAIL:C_OpenSession rejected with CKR_SLOT_ID_INVALID" in out
    assert "HARNESS_ERROR" not in out


def test_session_open_device_error_stays_setup_xfail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """B5a control: ambiguous provider setup faults keep the xfail bucket."""
    _drive_login_setup(monkeypatch, open_rv=int(CKR_DEVICE_ERROR))
    out = capsys.readouterr().out
    assert "SETUP_XFAIL:C_OpenSession rejected with CKR_DEVICE_ERROR" in out
    assert "HARNESS_ERROR" not in out


def test_session_login_pin_locked_stays_setup_xfail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """B5a control: a locked PIN is token state, not operator config."""
    _drive_login_setup(monkeypatch, login_rv=int(CKR_PIN_LOCKED))
    out = capsys.readouterr().out
    assert "SETUP_XFAIL:C_Login rejected with CKR_PIN_LOCKED" in out
    assert "HARNESS_ERROR" not in out
