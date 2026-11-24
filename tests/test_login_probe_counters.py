"""Login-probe counter engagement: the U1 test-path probe joins the session.

The pre-suite login probe (``pkcs11-check test --pin ...``) runs in a child
that makes real PKCS#11 calls (~8: initialize, slot/token reads, open,
login, logout, close, finalize). Engaged (``counters=...``), the child
records under the preflight unit / attempt 1 and the parent retains its
evidence exactly like the manifest preflight (attempt 0); disengaged
(``counters=None``, the ``doctor`` command) nothing is recorded and the
child env is scrubbed. Collection never alters the verdict and never
raises: evidence failures warn.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.cli import test_cmd
from pkcs11_check.cli.app import app
from pkcs11_check.core import counters_schema as schema
from pkcs11_check.core._counters_durability import (
    COUNTERS_ATTEMPT_ENV,
    COUNTERS_DIR_ENV,
    COUNTERS_ROLE_ENV,
    COUNTERS_UNIT_ENV,
)
from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl
from pkcs11_check.core.call_counters import RUN_ID_ENV
from pkcs11_check.core.doctor_probe import LoginProbe, run_login_probe_subprocess
from pkcs11_check.core.preflight import (
    PREFLIGHT_UNIT,
    CapabilityManifest,
    PreflightCounters,
)
from tests._plain_cli_runner import PlainCliRunner

_RUN = "20261116T120000000000Z-p100-a1b2c3d4"
_UUID_PROBE = "c" * 32
_UUID_CENSUS = "d" * 32
_MODULE = "/usr/lib/softhsm/libsofthsm2.so"

# The login probe's 8 calls, bucketed like the census planter: loader
# traffic under module_init, the login exchange under session_provisioning.
_LOGIN_PLAN: tuple[tuple[str, str], ...] = (
    ("module_init", "C_Initialize"),
    ("module_init", "C_GetSlotList"),
    ("session_provisioning", "C_GetTokenInfo"),
    ("session_provisioning", "C_OpenSession"),
    ("session_provisioning", "C_Login"),
    ("session_provisioning", "C_Logout"),
    ("session_provisioning", "C_CloseSession"),
    ("module_init", "C_Finalize"),
)
assert len(_LOGIN_PLAN) == 8

runner = PlainCliRunner()


def _login_block() -> dict[str, Any]:
    buckets: dict[str, Any] = {}
    for bucket, fn in _LOGIN_PLAN:
        bucket_block = buckets.setdefault(bucket, {"calls": 0, "by_fn": {}})
        bucket_block["calls"] += 1
        bucket_block["by_fn"][fn] = {"calls": 1, "by_rv": {"0": {"name": "CKR_OK", "count": 1}}}
    block = {"total_calls": 8, "by_module": {_MODULE: {"calls": 8, "buckets": buckets}}}
    assert schema.is_module_first_block(block)
    return block


def _plant_attempt(
    counters_dir: Path,
    *,
    attempt: int,
    uuid: str,
    pid: int = 4242,
    block: dict[str, Any] | None = None,
) -> None:
    reg_dir = counters_dir / "registrations"
    reg_dir.mkdir(parents=True, exist_ok=True)
    sidecar = counters_dir / f"{uuid}-abcd1234.partial.json"
    content = {
        "worker_uuid": uuid,
        "run_id": _RUN,
        "unit": PREFLIGHT_UNIT,
        "attempt": attempt,
        "pid": pid,
        "role": "preflight",
        "timestamp": 0.0,
        "sidecar": str(sidecar),
        "birth_token": 0,
        "isolation": "none",
    }
    assert schema.is_registry_content(content)
    (reg_dir / f"{uuid}.json").write_text(json.dumps(content), encoding="utf-8")
    payload = {
        "worker_uuid": uuid,
        "run_id": _RUN,
        "unit": PREFLIGHT_UNIT,
        "attempt": attempt,
        "pid": pid,
        "journal_seq": 0,
        "in_progress": block if block is not None else _login_block(),
        "receipts": [],
    }
    sidecar.write_text(json.dumps(payload), encoding="utf-8")


def _counters(tmp_path: Path, *, attempt: int = 1) -> PreflightCounters:
    return PreflightCounters(
        counters_dir=tmp_path / "counters",
        run_id=_RUN,
        unit=PREFLIGHT_UNIT,
        attempt=attempt,
        evidence_path=tmp_path / "preflight-counters.jsonl",
    )


class _FakeProbeChild:
    """A stubbed login-probe child: scripted pipes, fixed pid."""

    def __init__(
        self,
        *,
        pid: int = 4242,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        hang: bool = False,
        interrupt: bool = False,
        seen: dict[str, Any] | None = None,
    ) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self.killed = False
        self.waited = False
        self._stdout = stdout
        self._stderr = stderr
        self._returncode = returncode
        self._hang = hang
        self._interrupt = interrupt
        self._seen = seen

    def __call__(self, cmd: Any, **kwargs: Any) -> _FakeProbeChild:
        if self._seen is not None:
            self._seen["cmd"] = cmd
            self._seen["env"] = kwargs.get("env")
        return self

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        if self._interrupt:
            raise KeyboardInterrupt
        if self._hang:
            raise subprocess.TimeoutExpired(cmd="probe", timeout=timeout or 0)
        self.returncode = self._returncode
        return (self._stdout, self._stderr)

    def kill(self) -> None:
        self.killed = True

    def wait(self) -> int:
        self.waited = True
        self.returncode = -9
        return -9


def _patch_child(monkeypatch: pytest.MonkeyPatch, fake: _FakeProbeChild) -> None:
    monkeypatch.setattr(subprocess, "Popen", fake)


def _extracted_total(evidence: Path) -> int:
    payload = extract_call_counters_from_jsonl(evidence)
    assert payload is not None
    return int(payload["total_calls"])


class TestEngagedProbe:
    def test_ok_probe_folds_8_calls_and_consumes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        seen: dict[str, Any] = {}
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b'{"status": "ok"}\n', seen=seen),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert (probe.status, probe.detail) == ("ok", "")
        assert probe.returncode == 0
        assert _extracted_total(counters.evidence_path) == 8
        # Commit consumed the producer files; nothing left for a later pass.
        assert list((counters.counters_dir / "registrations").glob("*.json")) == []
        assert list(counters.counters_dir.glob("*.partial.json")) == []
        # The child ran as the doctor-probe module with attempt-1 identity.
        assert seen["cmd"][1:3] == ["-m", "pkcs11_check.core.doctor_probe"]
        assert seen["env"][COUNTERS_ATTEMPT_ENV] == "1"
        assert seen["env"][COUNTERS_UNIT_ENV] == PREFLIGHT_UNIT
        assert seen["env"][COUNTERS_ROLE_ENV] == PREFLIGHT_UNIT
        assert seen["env"][RUN_ID_ENV] == _RUN
        assert seen["env"]["P11TEST_PIN"] == "1234"

    def test_attempt_isolation_leaves_census_files_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=0, uuid=_UUID_CENSUS)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(monkeypatch, _FakeProbeChild(stdout=b'{"status": "ok"}\n'))
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "ok"
        assert _extracted_total(counters.evidence_path) == 8
        reg_dir = counters.counters_dir / "registrations"
        assert (reg_dir / f"{_UUID_CENSUS}.json").exists()
        assert not (reg_dir / f"{_UUID_PROBE}.json").exists()

    def test_crashed_probe_retains_loss_and_consumes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(monkeypatch, _FakeProbeChild(returncode=-11))
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "crashed"
        assert "crashed" in probe.detail
        assert probe.returncode == -11
        assert counters.evidence_path.read_bytes().strip() != b""
        assert list((counters.counters_dir / "registrations").glob("*.json")) == []

    def test_timeout_kills_without_drain_and_retains(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        fake = _FakeProbeChild(hang=True)
        _patch_child(monkeypatch, fake)
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "timeout"
        assert fake.killed is True
        assert counters.evidence_path.read_bytes().strip() != b""

    def test_error_tail_still_retains_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b"not json\n", stderr=b"boom\nline2\n", returncode=1),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "error"
        assert probe.detail == "boom\nline2"
        assert counters.evidence_path.read_bytes().strip() != b""

    def test_interrupt_kills_child_and_propagates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R19-5: Ctrl-C kills the probe child (run() parity), no verdict."""
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        fake = _FakeProbeChild(interrupt=True)
        _patch_child(monkeypatch, fake)
        with pytest.raises(KeyboardInterrupt):
            run_login_probe_subprocess(
                tmp_path / "module.so",
                interface="auto",
                slot=0,
                pin=b"1234",
                timeout=5,
                counters=counters,
            )
        assert fake.killed is True
        assert fake.waited is True

    def test_error_detail_scrubs_pin_from_verdict_and_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R20-1: child stderr echoing the PIN is redacted everywhere."""
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b"not json\n", stderr=b"provider said 1234 loudly\n"),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "error"
        assert "1234" not in probe.detail
        assert "[redacted]" in probe.detail
        blob = counters.evidence_path.read_bytes().decode("utf-8")
        assert "1234" not in blob
        assert "[redacted]" in blob

    def test_error_detail_straddling_pin_scrubs_before_truncate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R21-1: a PIN split by the 200-char cutoff leaks no suffix."""
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b"not json\n", stderr=b"A" * 8 + b"1234" + b"B" * 198 + b"\n"),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "error"
        assert "1234" not in probe.detail
        assert "34" not in probe.detail
        blob = counters.evidence_path.read_bytes().decode("utf-8")
        assert "1234" not in blob
        assert "34" not in blob

    def test_error_detail_space_padded_pin_scrubs_before_strip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R22-1: a space-padded PIN echo is redacted, not trimmed-then-leaked."""
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b"not json\n", stderr=b"  1234  \n"),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"  1234  ",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "error"
        assert probe.detail == "[redacted]"
        blob = counters.evidence_path.read_bytes().decode("utf-8")
        assert "1234" not in blob

    def test_scrub_pin_ignores_empty_and_blank_pins(self) -> None:
        """R22-1: empty/blank PINs scrub nothing (never corrupt the bytes)."""
        from pkcs11_check.core.doctor_probe import _scrub_pin

        assert _scrub_pin(b"provider said boom", b"") == b"provider said boom"
        assert _scrub_pin(b"a b c", b" ") == b"a b c"
        assert _scrub_pin(b"used 1234 here", b"1234") == b"used [redacted] here"
        assert _scrub_pin(b"pin ab\rcd x", b"ab\rcd") == b"pin [redacted] x"

    def test_error_detail_cr_pin_scrubs_before_decoding(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R24-2: binary pipes preserve the CR so an embedded-CR PIN matches
        exactly (no newline translation before the scrubber)."""
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b"not json\n", stderr=b"pin ab\rcd leaked\n"),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"ab\rcd",
            timeout=5,
            counters=counters,
        )
        assert probe.status == "error"
        assert probe.detail == "pin [redacted] leaked"
        blob = counters.evidence_path.read_bytes().decode("utf-8")
        assert "ab\rcd" not in blob
        assert "ab" not in blob.replace("[redacted]", "X")

    def test_error_detail_invalid_byte_pin_scrubs_before_decoding(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R24-2: a PIN with invalid UTF-8 bytes redacts fully; decoding
        cannot fragment it past the scrubber."""
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        pin = b"ab\xffcd"
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b"not json\n", stderr=b"pin " + pin + b" leaked\n"),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=pin,
            timeout=5,
            counters=counters,
        )
        assert probe.status == "error"
        assert probe.detail == "pin [redacted] leaked"
        blob = counters.evidence_path.read_bytes().decode("utf-8")
        assert "ab" not in blob.replace("[redacted]", "X")
        assert "cd leaked" not in blob

    def test_json_detail_scrubs_pin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """R20-1: child JSON details are scrubbed like stderr tails."""
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b'{"status": "ok", "detail": "used 1234"}\n'),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert (probe.status, probe.detail) == ("ok", "used [redacted]")

    def test_login_status_passes_through_while_counts_fold(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b'{"status": "pin_incorrect", "detail": "nope"}\n'),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so",
            interface="auto",
            slot=0,
            pin=b"1234",
            timeout=5,
            counters=counters,
        )
        assert (probe.status, probe.detail) == ("pin_incorrect", "nope")
        assert _extracted_total(counters.evidence_path) == 8


class TestDisengagedProbe:
    def test_counts_nothing_and_scrubs_child_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(COUNTERS_DIR_ENV, "/tmp/stale-counters")
        monkeypatch.setenv(COUNTERS_UNIT_ENV, "stale.py")
        monkeypatch.setenv(COUNTERS_ATTEMPT_ENV, "7")
        monkeypatch.setenv(COUNTERS_ROLE_ENV, "worker")
        monkeypatch.setenv(RUN_ID_ENV, "stale-run")
        seen: dict[str, Any] = {}
        _patch_child(
            monkeypatch,
            _FakeProbeChild(stdout=b'{"status": "ok"}\n', seen=seen),
        )
        probe = run_login_probe_subprocess(
            tmp_path / "module.so", interface="auto", slot=0, pin=b"1234", timeout=5
        )
        assert probe.status == "ok"
        assert not (tmp_path / "preflight-counters.jsonl").exists()
        for key in (
            COUNTERS_DIR_ENV,
            COUNTERS_UNIT_ENV,
            COUNTERS_ATTEMPT_ENV,
            COUNTERS_ROLE_ENV,
            RUN_ID_ENV,
        ):
            assert key not in seen["env"]
        assert seen["env"]["P11TEST_PIN"] == "1234"


class TestEvidenceFailureIsWarning:
    def test_collect_failure_warns_and_keeps_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pkcs11_check.core.doctor_probe as doctor_probe_mod

        counters = _counters(tmp_path)
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(monkeypatch, _FakeProbeChild(stdout=b'{"status": "ok"}\n'))

        def _boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("torn registry")

        monkeypatch.setattr(doctor_probe_mod, "collect_preflight_counters", _boom)
        with pytest.warns(UserWarning, match="counter evidence not collected"):
            probe = run_login_probe_subprocess(
                tmp_path / "module.so",
                interface="auto",
                slot=0,
                pin=b"1234",
                timeout=5,
                counters=counters,
            )
        assert probe.status == "ok"
        assert not counters.evidence_path.exists()

    def test_append_failure_warns_and_skips_commit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir", encoding="utf-8")
        counters = PreflightCounters(
            counters_dir=tmp_path / "counters",
            run_id=_RUN,
            unit=PREFLIGHT_UNIT,
            attempt=1,
            evidence_path=blocker / "preflight-counters.jsonl",
        )
        _plant_attempt(counters.counters_dir, attempt=1, uuid=_UUID_PROBE)
        _patch_child(monkeypatch, _FakeProbeChild(stdout=b'{"status": "ok"}\n'))
        with pytest.warns(UserWarning, match="counter evidence not retained"):
            probe = run_login_probe_subprocess(
                tmp_path / "module.so",
                interface="auto",
                slot=0,
                pin=b"1234",
                timeout=5,
                counters=counters,
            )
        assert probe.status == "ok"
        # No commit: the producer files stay for a later pass.
        reg_dir = counters.counters_dir / "registrations"
        assert (reg_dir / f"{_UUID_PROBE}.json").exists()


def _ok_preflight(
    module: Path,
    *,
    interface: str,
    slot: int,
    timeout: int,
    output_path: Path,
    counters: object = None,
) -> CapabilityManifest:
    del module, interface, slot, timeout, counters
    output_path.write_text("{}", encoding="utf-8")
    return CapabilityManifest(
        status="ok",
        module_path="dummy.so",
        requested_interface="auto",
        interface_version="3.2",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_AES_CBC"],
    )


class TestU1Threading:
    def test_test_path_probe_engages_attempt_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The test-path U1 probe passes attempt-1 preflight counters."""
        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        seen: dict[str, Any] = {}

        def capturing_probe(*args: Any, **kwargs: Any) -> LoginProbe:
            seen["counters"] = kwargs.get("counters")
            return LoginProbe("ok")

        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", lambda *a, **k: 0)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _ok_preflight)
        monkeypatch.setattr(test_cmd, "run_login_probe_subprocess", capturing_probe)
        monkeypatch.setattr(
            test_cmd,
            "discover_pytest_units",
            lambda targets, default_root, *, granularity, pytest_args: [],
        )
        result = runner.invoke(
            app,
            ["test", "--module", str(module), "--pin", "1234", "--isolation", "file"],
        )
        assert result.exit_code == 0, result.output
        engaged = seen["counters"]
        assert isinstance(engaged, PreflightCounters)
        assert engaged.unit == PREFLIGHT_UNIT
        assert engaged.attempt == 1
