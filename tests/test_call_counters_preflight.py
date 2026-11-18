"""Task-4 preflight counting: census + recovery sidecars, synth records, retention.

Step-1 RED tests for the rc2 preflight plan (v8 Task 4): every behavior below
failed before the implementation (no ``PreflightCounters`` surface, no role
rows, no evidence retention) and goes green with it. Real files + real JSONL
only -- subprocesses are faked at the ``Popen`` boundary (except the
disengaged-scrub proof, which runs the real child), never the extractor.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from pkcs11_check.core import counters_schema as schema
from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl
from pkcs11_check.core.call_counters import RUN_ID_ENV, CounterPersistenceError
from pkcs11_check.core.preflight import (
    PREFLIGHT_EVIDENCE_ENV,
    PREFLIGHT_UNIT,
    CapabilityManifest,
    PreflightCounters,
    append_preflight_evidence,
    collect_preflight_counters,
    preflight_child_env,
    probe_capabilities,
    rebucket_to_preflight,
    run_preflight_subprocess,
    save_manifest,
)

_RUN = "20261116T120000000000Z-p100-a1b2c3d4"
_UUID_A = "a" * 32
_UUID_B = "b" * 32
_MODULE = "/usr/lib/softhsm/libsofthsm2.so"

# An 85-call SoftHSM-shaped census: loader traffic under module_init, the
# slot/token/mechanism census under session_provisioning (the child's default
# phase). Counts sum to exactly 85.
_SOFTHSM_PLAN: tuple[tuple[str, str, int], ...] = (
    ("module_init", "C_GetFunctionList", 1),
    ("module_init", "C_GetInterface", 2),
    ("module_init", "C_Initialize", 1),
    ("session_provisioning", "C_GetSlotList", 2),
    ("session_provisioning", "C_GetSlotInfo", 4),
    ("session_provisioning", "C_GetTokenInfo", 4),
    ("session_provisioning", "C_GetMechanismList", 2),
    ("session_provisioning", "C_GetMechanismInfo", 68),
    ("session_provisioning", "C_Finalize", 1),
)
assert sum(calls for _, _, calls in _SOFTHSM_PLAN) == 85

needs_posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")


def _softhsm_block() -> dict[str, Any]:
    """The 85-call census as a valid module-first block (natural buckets)."""
    buckets: dict[str, Any] = {}
    for bucket, fn, calls in _SOFTHSM_PLAN:
        bucket_block = buckets.setdefault(bucket, {"calls": 0, "by_fn": {}})
        bucket_block["calls"] += calls
        bucket_block["by_fn"][fn] = {
            "calls": calls,
            "by_rv": {"0": {"name": "CKR_OK", "count": calls}},
        }
    block = {"total_calls": 85, "by_module": {_MODULE: {"calls": 85, "buckets": buckets}}}
    assert schema.is_module_first_block(block)
    return block


def _plant_producer(
    counters_dir: Path,
    *,
    run_id: str = _RUN,
    unit: str = PREFLIGHT_UNIT,
    attempt: int = 0,
    pid: int = 4242,
    block: dict[str, Any] | None = None,
    uuid: str = _UUID_A,
) -> str:
    """Plant one preflight producer's registry + sidecar; return its uuid."""
    reg_dir = counters_dir / "registrations"
    reg_dir.mkdir(parents=True, exist_ok=True)
    sidecar = counters_dir / f"{uuid}-abcd1234.partial.json"
    content = {
        "worker_uuid": uuid,
        "run_id": run_id,
        "unit": unit,
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
        "run_id": run_id,
        "unit": unit,
        "attempt": attempt,
        "pid": pid,
        "journal_seq": 0,
        "in_progress": block if block is not None else _softhsm_block(),
        "receipts": [],
    }
    sidecar.write_text(json.dumps(payload), encoding="utf-8")
    return uuid


def _counters(tmp_path: Path, *, unit: str = PREFLIGHT_UNIT, attempt: int = 0) -> PreflightCounters:
    return PreflightCounters(
        counters_dir=tmp_path / "counters",
        run_id=_RUN,
        unit=unit,
        attempt=attempt,
        evidence_path=tmp_path / "preflight-counters.jsonl",
    )


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def _ok_manifest() -> CapabilityManifest:
    return CapabilityManifest(
        status="ok",
        module_path="m.so",
        requested_interface="auto",
        interface_version="3.2",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_AES_CBC"],
    )


class _FakePopen:
    """A stubbed preflight child: scripted wait results, fixed pid."""

    def __init__(
        self,
        *,
        pid: int = 4242,
        wait_results: int | list[Any] = 0,
    ) -> None:
        self.pid = pid
        self.killed = False
        self._wait_results = wait_results if isinstance(wait_results, list) else [wait_results]

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        result = self._wait_results.pop(0) if len(self._wait_results) > 1 else self._wait_results[0]
        if isinstance(result, BaseException):
            raise result
        return int(result)

    def kill(self) -> None:
        self.killed = True


def _patch_popen(
    monkeypatch: pytest.MonkeyPatch, fake: _FakePopen, seen: dict[str, Any] | None = None
) -> None:
    def _popen(cmd: Any, **kwargs: Any) -> _FakePopen:
        if seen is not None:
            seen["cmd"] = cmd
            seen["env"] = kwargs.get("env")
        return fake

    monkeypatch.setattr(subprocess, "Popen", _popen)


class TestCensusSidecarFold:
    def test_census_sidecar_folds_exact_85_softhsm_shaped(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        records, _commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        assert len(records) == 1
        (synth,) = records
        assert schema.is_preflight_synth_record(synth) is True
        assert synth["total_calls"] == 85
        assert synth["pid"] == 4242
        assert synth["worker_uuid"] == _UUID_A
        assert synth["run_id"] == _RUN
        assert synth["role"] == "preflight"
        assert synth["isolation"] == "none"
        assert synth["probes_lost"] == 0
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, synth, {"$report_type": "SessionFinish"}],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True
        assert payload["by_process"] == [
            {
                "pid": 4242,
                "isolation": "none",
                "total_calls": 85,
                "complete": True,
                "worker_uuid": _UUID_A,
                "role": "preflight",
            }
        ]
        assert list(payload["by_round"]) == [_RUN]

    def test_collect_commit_collect_second_is_loud(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        first, commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        assert len(first) == 1
        # Collection alone is read-only: the commit (after the JSONL
        # evidence is appended and closed) consumes the producer files.
        assert list((counters.counters_dir / "registrations").glob("*.json")) != []
        assert list(counters.counters_dir.glob("*.partial.json")) != []
        commit()
        leftovers = list(counters.counters_dir.rglob("*"))
        assert [path for path in leftovers if path.is_file()] == []
        # A second collection is a caller bug (no evidence remains): loud
        # unknown loss, never a double count and never silence.
        second, _ = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        assert len(second) == 2  # note + lost
        assert second[0]["$report_type"] == "PreflightNote"
        assert second[1]["$report_type"] == "CallCountersLost"
        assert second[1]["end_state"] == "unknown"

    def test_rebucket_merges_buckets_preserving_totals(self) -> None:
        uniform = rebucket_to_preflight(_softhsm_block())
        assert uniform is not None
        assert uniform["total_calls"] == 85
        assert set(uniform["by_module"]) == {_MODULE}
        buckets = uniform["by_module"][_MODULE]["buckets"]
        assert schema.is_uniform_five(buckets) is True
        assert buckets["preflight"]["calls"] == 85
        by_fn = buckets["preflight"]["by_fn"]
        assert by_fn["C_GetMechanismInfo"]["calls"] == 68
        assert by_fn["C_GetMechanismInfo"]["by_rv"] == {"0": {"name": "CKR_OK", "count": 68}}
        assert by_fn["C_Initialize"]["calls"] == 1
        assert schema.is_module_first_block(uniform) is True

    def test_rebucket_rejects_garbage(self) -> None:
        assert rebucket_to_preflight(None) is None
        assert rebucket_to_preflight({}) is None
        assert rebucket_to_preflight({"total_calls": 3, "by_module": {}}) is None


class TestRecoveryIncluded:
    def test_recovery_probe_collects_with_recovery_unit(self, tmp_path: Path) -> None:
        from pkcs11_check.core.recovery import RECOVERY_UNIT

        counters = _counters(tmp_path, unit=RECOVERY_UNIT, attempt=1)
        _plant_producer(counters.counters_dir, unit=RECOVERY_UNIT, attempt=1, pid=5150)
        records, _commit = collect_preflight_counters(
            counters,
            child_pid=5150,
            returncode=0,
            timed_out=False,
            manifest_status="error",
            manifest_reason=None,
        )
        assert len(records) == 2  # note + synth
        note, synth = records
        assert note["$report_type"] == "PreflightNote"
        assert note["unit"] == RECOVERY_UNIT
        assert note["run_id"] == _RUN
        assert schema.is_preflight_synth_record(synth) is True
        assert synth["total_calls"] == 85
        assert synth["run_id"] == _RUN

    def test_recovery_probe_auto_engages_from_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pkcs11_check.core.recovery as rec_mod

        rec_mod.reset_probe_attempts_for_tests()
        counters_dir = tmp_path / "counters"
        evidence = tmp_path / "preflight-counters.jsonl"
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_DIR", str(counters_dir))
        monkeypatch.setenv(RUN_ID_ENV, _RUN)
        monkeypatch.setenv(PREFLIGHT_EVIDENCE_ENV, str(evidence))
        _plant_producer(counters_dir, unit="recovery", attempt=1, pid=5150)
        _patch_popen(monkeypatch, _FakePopen(pid=5150, wait_results=0))
        # The probe owns its manifest temp file; a real child would write it.
        # Pre-seeding is impossible, so the empty temp reads as a dead probe --
        # but the engaged collection still retains the planted evidence.
        live = rec_mod.probe_provider_liveness(
            tmp_path / "m.so", interface="auto", slot=0, timeout=5
        )
        assert live is False
        lines = evidence.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 4  # start + note + synth + finish
        synth = json.loads(lines[2])
        assert schema.is_preflight_synth_record(synth) is True
        assert synth["total_calls"] == 85

    def test_recovery_probe_disengaged_without_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pkcs11_check.core.recovery as rec_mod

        monkeypatch.delenv("PKCS11_CHECK_COUNTERS_DIR", raising=False)
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        seen: dict[str, Any] = {}

        def _capture(*args: Any, **kwargs: Any) -> CapabilityManifest:
            seen["counters"] = kwargs.get("counters")
            return _ok_manifest()

        monkeypatch.setattr(rec_mod, "run_preflight_subprocess", _capture)
        assert (
            rec_mod.probe_provider_liveness(tmp_path / "m.so", interface="auto", slot=0, timeout=5)
            is True
        )
        assert seen["counters"] is None

    def test_recovery_probe_rejects_reserved_unknown_run_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # First-tier R9: preflight/recovery engagement stamps the
        # ambient run id into synth/partial/lost/note records, so it
        # guards the reservation at resolve time -- fail-closed
        # before engagement, never a partial "unknown" run.
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_DIR", str(tmp_path / "counters"))
        monkeypatch.setenv(RUN_ID_ENV, "unknown")
        monkeypatch.setenv(PREFLIGHT_EVIDENCE_ENV, str(tmp_path / "preflight-counters.jsonl"))
        with pytest.raises(CounterPersistenceError, match="reserved run_id"):
            PreflightCounters.resolve_from_env(unit="recovery", attempt=1)


class TestDoctorExcluded:
    def test_doctor_passes_no_counters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.cli import doctor_cmd
        from pkcs11_check.core.doctor_probe import LoginProbe

        mod = tmp_path / "m.so"
        mod.write_bytes(b"\x7fELF")
        seen: dict[str, Any] = {"counters": "unset"}

        def _capture(*args: Any, **kwargs: Any) -> CapabilityManifest:
            seen["counters"] = kwargs.get("counters", None)
            return _ok_manifest()

        monkeypatch.setattr(doctor_cmd, "run_preflight_subprocess", _capture)
        monkeypatch.setattr(
            doctor_cmd, "run_login_probe_subprocess", lambda *a, **k: LoginProbe("ok")
        )
        doctor_cmd.doctor_command(module=mod, interface="auto", slot=0, pin=None, timeout=10)
        assert seen["counters"] is None
        assert "PKCS11_CHECK_COUNTERS_DIR" not in os.environ
        assert PREFLIGHT_EVIDENCE_ENV not in os.environ

    def test_disengaged_child_env_scrubs_counters_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_DIR", "/tmp/counters")
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_UNIT", "a.py")
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_ATTEMPT", "3")
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_ROLE", "unit")
        monkeypatch.setenv(RUN_ID_ENV, "stale-id")
        monkeypatch.setenv(PREFLIGHT_EVIDENCE_ENV, "/tmp/evidence.jsonl")
        monkeypatch.setenv("_P11CHECK_PROBE_SEQ", "7")
        monkeypatch.setenv("_P11CHECK_PROBE_SIDECAR", "/tmp/probe.json")
        monkeypatch.setenv("_P11CHECK_PROBE_PARENT", "p" * 32)
        monkeypatch.setenv("_P11CHECK_PROBE_RUN", "R1")
        monkeypatch.setenv("_P11CHECK_PROBE_UNIT", "a.py")
        monkeypatch.setenv("_P11CHECK_PROBE_ATTEMPT", "0")
        monkeypatch.setenv("_P11CHECK_PROBE_ROLE", "unit")
        monkeypatch.setenv("_P11CHECK_PROBE_ISOLATION", "file")
        env = preflight_child_env(None)
        for key in (
            "PKCS11_CHECK_COUNTERS_DIR",
            "PKCS11_CHECK_COUNTERS_UNIT",
            "PKCS11_CHECK_COUNTERS_ATTEMPT",
            "PKCS11_CHECK_COUNTERS_ROLE",
            RUN_ID_ENV,
            PREFLIGHT_EVIDENCE_ENV,
            "_P11CHECK_PROBE_SEQ",
            "_P11CHECK_PROBE_SIDECAR",
            "_P11CHECK_PROBE_PARENT",
            "_P11CHECK_PROBE_RUN",
            "_P11CHECK_PROBE_UNIT",
            "_P11CHECK_PROBE_ATTEMPT",
            "_P11CHECK_PROBE_ROLE",
            "_P11CHECK_PROBE_ISOLATION",
        ):
            assert key not in env

    def test_engaged_child_env_overlays_preflight_identity(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        env = preflight_child_env(counters)
        assert env["PKCS11_CHECK_COUNTERS_DIR"] == str(counters.counters_dir)
        assert env["PKCS11_CHECK_COUNTERS_UNIT"] == PREFLIGHT_UNIT
        assert env["PKCS11_CHECK_COUNTERS_ATTEMPT"] == "0"
        assert env["PKCS11_CHECK_COUNTERS_ROLE"] == "preflight"
        assert env[RUN_ID_ENV] == _RUN
        assert PREFLIGHT_EVIDENCE_ENV not in env
        assert "_P11CHECK_PROBE_SEQ" not in env

    def test_disengaged_real_child_registers_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Volkswagen-proof: even with a counters dir exported in the caller
        # env, a disengaged (doctor / plugin re-probe) child inherits no
        # identity and registers nothing.
        counters_dir = tmp_path / "counters"
        counters_dir.mkdir()
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_DIR", str(counters_dir))
        monkeypatch.setenv(RUN_ID_ENV, "stale-id")
        manifest = run_preflight_subprocess(
            tmp_path / "missing.so",
            interface="auto",
            slot=0,
            timeout=60,
            output_path=tmp_path / "manifest.json",
        )
        assert manifest.status == "error"
        assert manifest.reason == "module_unloadable"
        assert list(counters_dir.rglob("*.json")) == []


class TestRunIdPresent:
    def test_census_records_carry_run_id(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        (synth,), _commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        assert synth["run_id"] == _RUN
        (note, lost), _commit = collect_preflight_counters(
            _counters(tmp_path, unit="other"),
            child_pid=4243,
            returncode=-11,
            timed_out=False,
            manifest_status="crashed",
            manifest_reason=None,
        )
        assert note["run_id"] == _RUN
        assert lost["run_id"] == _RUN

    def test_fingerprint_ignores_all_counters_plumbing(self) -> None:
        from pkcs11_check.core._run_state import (
            _POLICY_IGNORED_ENV_KEYS,
            _STATE_IGNORED_ENV_KEYS,
            build_policy_fingerprint,
            build_state_fingerprint,
        )

        plumbing = (
            "PKCS11_CHECK_ISOLATION",
            RUN_ID_ENV,
            "PKCS11_CHECK_COUNTERS_DIR",
            "PKCS11_CHECK_COUNTERS_UNIT",
            "PKCS11_CHECK_COUNTERS_ATTEMPT",
            "PKCS11_CHECK_COUNTERS_ROLE",
            PREFLIGHT_EVIDENCE_ENV,
        )
        for key in plumbing:
            assert key in _POLICY_IGNORED_ENV_KEYS, key
            assert key in _STATE_IGNORED_ENV_KEYS, key
        # Explicit env dicts (never the ambient os.environ): any other
        # fingerprinted key in the ambient env would alias the comparison.
        base = {"PATH": "/usr/bin:/bin", "P11TEST_PIN": "pin-value"}
        bare_state = build_state_fingerprint(["a.py"], [], base)
        bare_policy = build_policy_fingerprint([], base)
        for key in plumbing:
            probe = dict(base)
            probe[key] = "sentinel-value"
            assert build_state_fingerprint(["a.py"], [], probe) == bare_state, key
            assert build_policy_fingerprint([], probe) == bare_policy, key
        altogether = dict(base)
        for key in plumbing:
            altogether[key] = "sentinel-value"
        assert build_state_fingerprint(["a.py"], [], altogether) == bare_state
        assert build_policy_fingerprint([], altogether) == bare_policy
        # The probe channel keys ride an underscore prefix outside every
        # fingerprint namespace, which is why the enumeration omits them.
        probed = dict(base)
        probed["_P11CHECK_PROBE_SEQ"] = "9"
        probed["_P11CHECK_PROBE_SIDECAR"] = "/tmp/probe.json"
        assert build_state_fingerprint(["a.py"], [], probed) == bare_state
        assert build_policy_fingerprint([], probed) == bare_policy


class TestHarnessErrorBlocksProvider:
    @pytest.fixture
    def sealed_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[Path, pytest.MonkeyPatch]:
        from pkcs11_check.core import call_counters
        from pkcs11_check.core._counters_durability import seal

        call_counters.reset_for_tests()
        root = tmp_path / "counters"
        root.mkdir()
        (root / "registrations").mkdir()
        seal(root, reason="test")
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_DIR", str(root))
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_UNIT", PREFLIGHT_UNIT)
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_ATTEMPT", "0")
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_ROLE", "preflight")
        monkeypatch.setenv(RUN_ID_ENV, _RUN)
        yield root, monkeypatch
        call_counters.reset_for_tests()

    def test_sealed_dir_registration_raises_harness_error(
        self, sealed_dir: tuple[Path, pytest.MonkeyPatch]
    ) -> None:
        from pkcs11_check.core import call_counters

        with pytest.raises(CounterPersistenceError):
            call_counters.ensure_registered()

    def test_c_call_blocked_before_module_entry(
        self, sealed_dir: tuple[Path, pytest.MonkeyPatch]
    ) -> None:
        from collections import Counter

        from pkcs11_check.raw.api import RawPKCS11

        invoked: list[str] = []

        def _stub(*args: Any) -> int:
            invoked.append("C_Initialize")
            return 0

        raw = RawPKCS11.__new__(RawPKCS11)
        raw._call_log = Counter()  # type: ignore[attr-defined]
        raw._call_log_ok = Counter()  # type: ignore[attr-defined]
        raw._rv_trace = None  # type: ignore[attr-defined]
        raw._journal = None  # type: ignore[attr-defined]
        raw._funcs = {"C_Initialize": _stub}  # type: ignore[attr-defined]
        raw._used_mechanisms = set()  # type: ignore[attr-defined]
        raw._mechanism_counts = Counter()  # type: ignore[attr-defined]
        raw._module_id = _MODULE  # type: ignore[attr-defined]
        with pytest.raises(CounterPersistenceError):
            raw._call("C_Initialize")
        assert invoked == []

    @needs_posix
    def test_permission_denied_dir_raises_harness_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.core import call_counters

        call_counters.reset_for_tests()
        root = tmp_path / "counters"
        root.mkdir()
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_DIR", str(root))
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_UNIT", PREFLIGHT_UNIT)
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_ATTEMPT", "0")
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_ROLE", "preflight")
        monkeypatch.setenv(RUN_ID_ENV, _RUN)
        os.chmod(root, 0o500)
        try:
            with pytest.raises(CounterPersistenceError):
                call_counters.ensure_registered()
        finally:
            os.chmod(root, 0o700)
            call_counters.reset_for_tests()

    def test_probe_maps_harness_error_to_manifest_reason(self, tmp_path: Path) -> None:
        module_path = tmp_path / "module.so"
        module_path.touch()
        with patch(
            "pkcs11_check.core.preflight.load_module",
            side_effect=CounterPersistenceError("sealed"),
        ):
            manifest = probe_capabilities(module_path, interface="auto", slot=0)
        assert manifest.status == "error"
        assert manifest.reason == "counter_persistence"
        assert manifest.reason != "module_unloadable"
        assert manifest.error is not None and "counter" in manifest.error.lower()

    def test_cli_maps_counter_persistence_reason_to_exit_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")

        def _counter_failure(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            return CapabilityManifest(
                status="error",
                module_path=str(module_arg),
                requested_interface="auto",
                interface_version=None,
                slot_index=0,
                slot_count=None,
                mechanisms=[],
                error="CounterPersistenceError: counters dir sealed",
                reason="counter_persistence",
            )

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _counter_failure)
        result = PlainCliRunner().invoke(
            app, ["test", "--module", str(module), "--ignore-disabled-tests"]
        )
        assert result.exit_code == 2
        assert "counter" in result.output.lower()


class TestFailedPreflightEvidence:
    def _run_engaged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake: _FakePopen,
        *,
        manifest: CapabilityManifest | None = None,
        plant: bool = True,
    ) -> tuple[CapabilityManifest, PreflightCounters]:
        counters = _counters(tmp_path)
        if plant:
            _plant_producer(counters.counters_dir, pid=fake.pid)
        _patch_popen(monkeypatch, fake)
        output_path = tmp_path / "manifest.json"
        if manifest is not None:
            save_manifest(output_path, manifest)
        got = run_preflight_subprocess(
            tmp_path / "m.so",
            interface="auto",
            slot=0,
            timeout=5,
            output_path=output_path,
            counters=counters,
        )
        return got, counters

    def _evidence_records(self, counters: PreflightCounters) -> list[dict[str, Any]]:
        lines = counters.evidence_path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    def test_error_manifest_with_counts_retains_session(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failed = CapabilityManifest(
            status="error",
            module_path="m.so",
            requested_interface="auto",
            interface_version=None,
            slot_index=0,
            slot_count=None,
            mechanisms=[],
            error="RuntimeError: slot 9 not found",
        )
        got, counters = self._run_engaged(
            tmp_path, monkeypatch, _FakePopen(pid=4242, wait_results=0), manifest=failed
        )
        assert got.status == "error"
        records = self._evidence_records(counters)
        assert [record["$report_type"] for record in records] == [
            "SessionStart",
            "PreflightNote",
            "CallCountersReport",
            "SessionFinish",
        ]
        assert records[1]["status"] == "error"
        assert records[1]["run_id"] == _RUN
        assert schema.is_preflight_synth_record(records[2]) is True
        assert records[2]["total_calls"] == 85
        payload = extract_call_counters_from_jsonl(counters.evidence_path)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True

    def test_unloadable_without_registration_retains_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failed = CapabilityManifest(
            status="error",
            module_path="m.so",
            requested_interface="auto",
            interface_version=None,
            slot_index=0,
            slot_count=None,
            mechanisms=[],
            error="OSError: cannot open",
            reason="module_unloadable",
        )
        got, counters = self._run_engaged(
            tmp_path,
            monkeypatch,
            _FakePopen(pid=4242, wait_results=0),
            manifest=failed,
            plant=False,
        )
        assert got.status == "error"
        assert got.reason == "module_unloadable"
        assert not counters.evidence_path.exists()

    def test_error_without_registration_retains_unknown_loss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failed = CapabilityManifest(
            status="error",
            module_path="m.so",
            requested_interface="auto",
            interface_version=None,
            slot_index=0,
            slot_count=None,
            mechanisms=[],
            error="RuntimeError: slot 9 not found",
        )
        got, counters = self._run_engaged(
            tmp_path,
            monkeypatch,
            _FakePopen(pid=4243, wait_results=0),
            manifest=failed,
            plant=False,
        )
        assert got.status == "error"
        records = self._evidence_records(counters)
        assert [record["$report_type"] for record in records] == [
            "SessionStart",
            "PreflightNote",
            "CallCountersLost",
            "SessionFinish",
        ]
        lost = records[2]
        assert lost["end_state"] == "unknown"
        assert lost["pid"] == 4243
        assert lost["run_id"] == _RUN
        payload = extract_call_counters_from_jsonl(counters.evidence_path)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is False

    def test_crash_with_sidecar_retains_partial_plus_loss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        got, counters = self._run_engaged(
            tmp_path, monkeypatch, _FakePopen(pid=4242, wait_results=-11)
        )
        assert got.status == "crashed"
        records = self._evidence_records(counters)
        assert [record["$report_type"] for record in records] == [
            "SessionStart",
            "PreflightNote",
            "CallCountersPartial",
            "CallCountersLost",
            "SessionFinish",
        ]
        partial, lost = records[2], records[3]
        assert partial["truncated"] is True
        assert partial["total_calls"] == 85
        assert partial["worker_uuid"] == _UUID_A
        assert lost["end_state"] == "crashed"
        assert lost["worker_uuid"] == _UUID_A
        assert lost["pid"] == 4242
        payload = extract_call_counters_from_jsonl(counters.evidence_path)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is False
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]

    def test_clean_exit_with_torn_sidecar_retains_conflict_loss(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        sidecar = next(counters.counters_dir.glob("*.partial.json"))
        sidecar.write_text("{torn json", encoding="utf-8")
        records, _commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        assert [record["$report_type"] for record in records] == [
            "PreflightNote",
            "CallCountersLost",
        ]
        assert records[1]["end_state"] == "conflict"
        assert records[1]["worker_uuid"] == _UUID_A

    def test_clean_exit_with_missing_sidecar_retains_unknown_loss(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        for sidecar in counters.counters_dir.glob("*.partial.json"):
            sidecar.unlink()
        records, _commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        assert [record["$report_type"] for record in records] == [
            "PreflightNote",
            "CallCountersLost",
        ]
        assert records[1]["end_state"] == "unknown"
        assert records[1]["worker_uuid"] == _UUID_A

    def test_crash_without_registration_retains_pid_loss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        got, counters = self._run_engaged(
            tmp_path, monkeypatch, _FakePopen(pid=4244, wait_results=-11), plant=False
        )
        assert got.status == "crashed"
        records = self._evidence_records(counters)
        assert [record["$report_type"] for record in records] == [
            "SessionStart",
            "PreflightNote",
            "CallCountersLost",
            "SessionFinish",
        ]
        assert records[2]["end_state"] == "crashed"
        assert records[2]["pid"] == 4244
        assert "worker_uuid" not in records[2]

    def test_timeout_retains_partial_plus_loss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakePopen(pid=4242, wait_results=[subprocess.TimeoutExpired("cmd", 5), -9])
        got, counters = self._run_engaged(tmp_path, monkeypatch, fake)
        assert got.status == "timeout"
        assert fake.killed is True
        records = self._evidence_records(counters)
        assert [record["$report_type"] for record in records] == [
            "SessionStart",
            "PreflightNote",
            "CallCountersPartial",
            "CallCountersLost",
            "SessionFinish",
        ]
        assert records[3]["end_state"] == "timeout"
        assert records[3]["worker_uuid"] == _UUID_A

    def test_evidence_never_carries_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("P11TEST_PIN", "s3cret-pin-value")
        got, counters = self._run_engaged(
            tmp_path, monkeypatch, _FakePopen(pid=4242, wait_results=-11)
        )
        assert got.status == "crashed"
        raw = counters.evidence_path.read_bytes()
        assert b"s3cret-pin-value" not in raw
        for record in self._evidence_records(counters):
            assert schema.find_secret_keys(record) == ()

    def test_manifest_identical_with_and_without_counters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        output_plain = tmp_path / "manifest-plain.json"
        output_engaged = tmp_path / "manifest-engaged.json"
        save_manifest(output_plain, _ok_manifest())
        save_manifest(output_engaged, _ok_manifest())
        _patch_popen(monkeypatch, _FakePopen(pid=4242, wait_results=0))
        plain = run_preflight_subprocess(
            tmp_path / "m.so",
            interface="auto",
            slot=0,
            timeout=5,
            output_path=output_plain,
        )
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        engaged = run_preflight_subprocess(
            tmp_path / "m.so",
            interface="auto",
            slot=0,
            timeout=5,
            output_path=output_engaged,
            counters=counters,
        )
        assert engaged == plain

    def test_evidence_append_failure_warns_never_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        counters.evidence_path.mkdir()  # a directory: appends fail
        output_path = tmp_path / "manifest.json"
        save_manifest(output_path, _ok_manifest())
        _patch_popen(monkeypatch, _FakePopen(pid=4242, wait_results=0))
        with pytest.warns(UserWarning, match="preflight counter evidence"):
            got = run_preflight_subprocess(
                tmp_path / "m.so",
                interface="auto",
                slot=0,
                timeout=5,
                output_path=output_path,
                counters=counters,
            )
        assert got.status == "ok"


class TestRoleRows:
    def _role_session(self, pid: int, role: str | None, *, run_id: str = _RUN) -> dict[str, Any]:
        block = _softhsm_block()
        # Distinct producers (distinct uuids): same-(run, uuid) repeats are
        # torn-append retries and fold first-wins, never twice.
        record: dict[str, Any] = {
            "$report_type": "CallCountersReport",
            "pid": pid,
            "isolation": "none",
            "probes_lost": 0,
            "total_calls": block["total_calls"],
            "by_module": block["by_module"],
            "run_id": run_id,
            "worker_uuid": f"{pid:032x}",
        }
        if role is not None:
            record["role"] = role
        return record

    def test_unit_role_omitted_others_rendered(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                self._role_session(100, "unit"),
                self._role_session(102, "retry"),
                self._role_session(104, "confirmation"),
                self._role_session(106, "preflight"),
                self._role_session(108, None),
                {"$report_type": "SessionFinish"},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 85 * 5
        rows = {row["pid"]: row for row in payload["by_process"]}
        assert "role" not in rows[100]
        assert "role" not in rows[108]
        assert rows[102]["role"] == "retry"
        assert rows[104]["role"] == "confirmation"
        assert rows[106]["role"] == "preflight"
        for row in payload["by_process"]:
            assert schema.is_process_row(row) is True

    def test_invalid_role_fails_record_closed(self, tmp_path: Path) -> None:
        bad = self._role_session(100, "bogus")
        assert schema.is_session_record(bad) is False
        lonely = _write_jsonl(
            tmp_path / "lonely.jsonl",
            [{"$report_type": "SessionStart"}, bad, {"$report_type": "SessionFinish"}],
        )
        assert extract_call_counters_from_jsonl(lonely) is None
        mixed = _write_jsonl(
            tmp_path / "mixed.jsonl",
            [
                {"$report_type": "SessionStart"},
                bad,
                self._role_session(102, "preflight"),
                {"$report_type": "SessionFinish"},
            ],
        )
        payload = extract_call_counters_from_jsonl(mixed)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert [row["pid"] for row in payload["by_process"]] == [102]


class TestEvidenceSplice:
    def test_splice_appends_evidence_scope(self, tmp_path: Path) -> None:
        from pkcs11_check.cli.test_cmd import splice_preflight_evidence

        jsonl_path = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, {"$report_type": "SessionFinish"}],
        )
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        records, _commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        appended = append_preflight_evidence(counters.evidence_path, records)
        assert appended == 1
        assert splice_preflight_evidence(jsonl_path, counters.evidence_path) == 1
        payload = extract_call_counters_from_jsonl(jsonl_path)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True

    def test_splice_missing_evidence_is_noop(self, tmp_path: Path) -> None:
        from pkcs11_check.cli.test_cmd import splice_preflight_evidence

        jsonl_path = _write_jsonl(tmp_path / "report.jsonl", [{"$report_type": "SessionStart"}])
        before = jsonl_path.read_bytes()
        assert splice_preflight_evidence(jsonl_path, tmp_path / "absent.jsonl") == 0
        assert jsonl_path.read_bytes() == before

    def test_refresh_results_patches_counters(self, tmp_path: Path) -> None:
        from pkcs11_check.cli.test_cmd import refresh_results_call_counters

        synth, _commit = collect_preflight_counters(
            _counters(tmp_path),
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        # No planted producer + ok status: the tripwire loss (see the loud
        # second-collect test); plant first for a countable synth.
        assert synth[0]["$report_type"] == "PreflightNote"
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        (session,), _commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        jsonl_path = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, session, {"$report_type": "SessionFinish"}],
        )
        results_path = tmp_path / "pkcs11-check-results.json"
        results_path.write_text(
            json.dumps({"call_counters": {"total_calls": 0}, "summary": {"failed": 1}}),
            encoding="utf-8",
        )
        assert refresh_results_call_counters(results_path, jsonl_path) is True
        patched = json.loads(results_path.read_text(encoding="utf-8"))
        assert patched["call_counters"]["total_calls"] == 85
        assert patched["summary"] == {"failed": 1}

    def test_evidence_path_derives_from_state_file(self, tmp_path: Path) -> None:
        from pkcs11_check.core.preflight import preflight_evidence_path_for_state

        state_file = tmp_path / ".pkcs11-check-isolation-state.json"
        assert preflight_evidence_path_for_state(state_file) == state_file.with_name(
            ".pkcs11-check-isolation-state.json.preflight-counters.jsonl"
        )


class TestCensusEngagement:
    def test_isolated_path_allocates_state_sibling_and_drops_caller_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        # A stale caller export: the CLI drops it (saved for restore) and
        # allocates its own run-owned dir instead. The env var is child
        # plumbing, not an opt-in.
        caller_dir = tmp_path / "caller-counters"
        caller_dir.mkdir()
        monkeypatch.setenv("PKCS11_CHECK_COUNTERS_DIR", str(caller_dir))
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        seen: dict[str, Any] = {}

        def fake_preflight(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            seen["counters"] = kwargs.get("counters")
            seen["preflight_run"] = os.environ.get(RUN_ID_ENV)
            seen["preflight_dir_env"] = os.environ.get("PKCS11_CHECK_COUNTERS_DIR")
            seen["dir_exists_at_census"] = kwargs["counters"].counters_dir.is_dir()
            kwargs["output_path"].write_text("{}", encoding="utf-8")
            return _ok_manifest()

        def fake_discover(targets: object, default_root: Path, **kwargs: Any) -> list[str]:
            return [str(default_root / "test_alpha.py")]

        def fake_run(units: object, pytest_args: object, **kwargs: Any) -> int:
            seen["run_id"] = os.environ.get(RUN_ID_ENV)
            seen["evidence_env"] = os.environ.get(PREFLIGHT_EVIDENCE_ENV)
            seen["run_dir_env"] = os.environ.get("PKCS11_CHECK_COUNTERS_DIR")
            return 0

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
        monkeypatch.setattr(test_cmd, "discover_pytest_units", fake_discover)
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
        state_file = tmp_path / "state.json"
        try:
            result = PlainCliRunner().invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "file",
                    "--state-file",
                    str(state_file),
                    "--ignore-disabled-tests",
                ],
            )
            seen["leaked_run"] = os.environ.get(RUN_ID_ENV)
            seen["leaked_evidence"] = os.environ.get(PREFLIGHT_EVIDENCE_ENV)
            seen["restored_dir"] = os.environ.get("PKCS11_CHECK_COUNTERS_DIR")
        finally:
            os.environ.pop(RUN_ID_ENV, None)
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
        assert result.exit_code == 0
        counters = seen["counters"]
        assert isinstance(counters, PreflightCounters)
        # N-C3: fresh series allocate a run-specific sibling (never the
        # reused canonical dir, which would absorb a dead series' calls).
        allocated = counters.counters_dir
        assert allocated.parent == state_file.parent
        assert allocated.name.startswith("state.json.counters.")
        nonce = allocated.name.removeprefix("state.json.counters.")
        assert len(nonce) == 8 and all(c in "0123456789abcdef" for c in nonce)
        assert seen["dir_exists_at_census"] is True
        assert seen["preflight_dir_env"] == str(allocated)
        assert seen["run_dir_env"] == str(allocated)
        assert counters.unit == PREFLIGHT_UNIT
        assert counters.attempt == 0
        assert counters.run_id == seen["run_id"] == seen["preflight_run"]
        assert seen["evidence_env"] == str(counters.evidence_path)
        assert counters.evidence_path == state_file.with_name("state.json.preflight-counters.jsonl")
        assert seen["leaked_run"] is None
        assert seen["leaked_evidence"] is None
        assert seen["restored_dir"] == str(caller_dir)

    def test_none_path_allocates_tempdir_and_scrubs_before_pytest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        monkeypatch.delenv("PKCS11_CHECK_COUNTERS_DIR", raising=False)
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        seen: dict[str, Any] = {}

        def fake_preflight(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            seen["counters"] = kwargs.get("counters")
            kwargs["output_path"].write_text("{}", encoding="utf-8")
            return _ok_manifest()

        def fake_main(args: list[str]) -> int:
            seen["pytest_dir_env"] = os.environ.get("PKCS11_CHECK_COUNTERS_DIR")
            seen["pytest_evidence_env"] = os.environ.get(PREFLIGHT_EVIDENCE_ENV)
            seen["pytest_run_env"] = os.environ.get(RUN_ID_ENV)
            report_path = Path(args[args.index("--report-log") + 1])
            report_path.write_text(
                json.dumps({"$report_type": "SessionStart"})
                + "\n"
                + json.dumps({"$report_type": "SessionFinish", "exitstatus": 0})
                + "\n",
                encoding="utf-8",
            )
            return 0

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
        monkeypatch.setattr(test_cmd.pytest, "main", fake_main)
        try:
            result = PlainCliRunner().invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "none",
                    "--ignore-disabled-tests",
                ],
            )
            seen["leaked_dir"] = os.environ.get("PKCS11_CHECK_COUNTERS_DIR")
        finally:
            os.environ.pop(RUN_ID_ENV, None)
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
            os.environ.pop("PKCS11_CHECK_COUNTERS_DIR", None)
        assert result.exit_code == 0
        counters = seen["counters"]
        assert isinstance(counters, PreflightCounters)
        # A fresh tempdir (not a state sibling: none has no state), owned by
        # this run and removed afterwards.
        assert counters.counters_dir.parent.resolve() == Path(tempfile.gettempdir()).resolve()
        assert not counters.counters_dir.exists()
        # The in-process session runs disengaged (no collecting parent could
        # survive its death); attribution keys stay for the session record.
        assert seen["pytest_dir_env"] is None
        assert seen["pytest_evidence_env"] is None
        assert seen["pytest_run_env"] == counters.run_id
        assert seen["leaked_dir"] is None

    def test_resume_reuses_state_recorded_counters_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from pkcs11_check.core._run_state import save_run_state
        from pkcs11_check.core._run_units import FileRunState
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        recorded = tmp_path / "recorded-counters"
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(units=[], fingerprint="", results=[], counters_dir=str(recorded)),
        )
        monkeypatch.delenv("PKCS11_CHECK_COUNTERS_DIR", raising=False)
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        seen: dict[str, Any] = {}

        def fake_preflight(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            seen["counters"] = kwargs.get("counters")
            kwargs["output_path"].write_text("{}", encoding="utf-8")
            return _ok_manifest()

        def fake_discover(targets: object, default_root: Path, **kwargs: Any) -> list[str]:
            return [str(default_root / "test_alpha.py")]

        def fake_run(units: object, pytest_args: object, **kwargs: Any) -> int:
            seen["barrier_plan"] = kwargs.get("counters_barrier_plan")
            return 0

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
        monkeypatch.setattr(test_cmd, "discover_pytest_units", fake_discover)
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
        try:
            result = PlainCliRunner().invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "file",
                    "--resume",
                    "--state-file",
                    str(state_file),
                    "--ignore-disabled-tests",
                ],
            )
        finally:
            os.environ.pop(RUN_ID_ENV, None)
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
            os.environ.pop("PKCS11_CHECK_COUNTERS_DIR", None)
        assert result.exit_code == 0
        counters = seen["counters"]
        assert isinstance(counters, PreflightCounters)
        assert counters.counters_dir == recorded
        plan = seen["barrier_plan"]
        assert isinstance(plan, dict)
        assert set(plan) == {
            "barrier_ok",
            "fenced",
            "unresolved",
            "skipped_units",
            "cache_records",
            "collected_runs",
            "consumed",
            "counters_dir",
        }

    def test_stale_seal_resume_unseals_before_census(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """C2a: the resume barrier (unseal) runs before the census probe."""
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from pkcs11_check.core._counters_durability import is_sealed, seal
        from pkcs11_check.core._run_state import save_run_state
        from pkcs11_check.core._run_units import FileRunState
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        recorded = tmp_path / "recorded-counters"
        seal(recorded, reason="interrupted-run")
        assert is_sealed(recorded) is True
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(units=[], fingerprint="", results=[], counters_dir=str(recorded)),
        )
        monkeypatch.delenv("PKCS11_CHECK_COUNTERS_DIR", raising=False)
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        seen: dict[str, Any] = {}

        def fake_preflight(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            counters = kwargs.get("counters")
            seen["sealed_at_census"] = (
                is_sealed(counters.counters_dir) if counters is not None else "disengaged"
            )
            kwargs["output_path"].write_text("{}", encoding="utf-8")
            return _ok_manifest()

        def fake_discover(targets: object, default_root: Path, **kwargs: Any) -> list[str]:
            return [str(default_root / "test_alpha.py")]

        def fake_run(units: object, pytest_args: object, **kwargs: Any) -> int:
            return 0

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
        monkeypatch.setattr(test_cmd, "discover_pytest_units", fake_discover)
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
        try:
            result = PlainCliRunner().invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "file",
                    "--resume",
                    "--state-file",
                    str(state_file),
                    "--ignore-disabled-tests",
                ],
            )
        finally:
            os.environ.pop(RUN_ID_ENV, None)
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
            os.environ.pop("PKCS11_CHECK_COUNTERS_DIR", None)
        assert result.exit_code == 0
        assert seen["sealed_at_census"] is False

    def test_barrier_runs_before_census_on_resume(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """C2b (resume): prepare_resume is called before the census probe."""
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from pkcs11_check.core._run_state import save_run_state
        from pkcs11_check.core._run_units import FileRunState
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        recorded = tmp_path / "recorded-counters"
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(units=[], fingerprint="", results=[], counters_dir=str(recorded)),
        )
        monkeypatch.delenv("PKCS11_CHECK_COUNTERS_DIR", raising=False)
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        events: list[str] = []
        real_prepare = test_cmd.prepare_resume

        def _spy_prepare(root: Path, **kwargs: Any) -> dict[str, Any]:
            events.append("barrier")
            return real_prepare(root, **kwargs)

        def fake_preflight(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            events.append("census")
            kwargs["output_path"].write_text("{}", encoding="utf-8")
            return _ok_manifest()

        def fake_discover(targets: object, default_root: Path, **kwargs: Any) -> list[str]:
            return [str(default_root / "test_alpha.py")]

        def fake_run(units: object, pytest_args: object, **kwargs: Any) -> int:
            return 0

        monkeypatch.setattr(test_cmd, "prepare_resume", _spy_prepare)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
        monkeypatch.setattr(test_cmd, "discover_pytest_units", fake_discover)
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
        try:
            result = PlainCliRunner().invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "file",
                    "--resume",
                    "--state-file",
                    str(state_file),
                    "--ignore-disabled-tests",
                ],
            )
        finally:
            os.environ.pop(RUN_ID_ENV, None)
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
            os.environ.pop("PKCS11_CHECK_COUNTERS_DIR", None)
        assert result.exit_code == 0
        assert events == ["barrier", "census"]

    def test_fresh_barrier_runs_before_census(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """C2b (fresh): unseal+sweep runs before the census probe."""
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        monkeypatch.delenv("PKCS11_CHECK_COUNTERS_DIR", raising=False)
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        events: list[str] = []
        real_sweep = test_cmd.sweep_orphans

        def _spy_sweep(root: Path, **kwargs: Any) -> dict[str, int]:
            events.append("barrier")
            return real_sweep(root, **kwargs)

        def fake_preflight(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            events.append("census")
            kwargs["output_path"].write_text("{}", encoding="utf-8")
            return _ok_manifest()

        def fake_discover(targets: object, default_root: Path, **kwargs: Any) -> list[str]:
            return [str(default_root / "test_alpha.py")]

        def fake_run(units: object, pytest_args: object, **kwargs: Any) -> int:
            return 0

        monkeypatch.setattr(test_cmd, "sweep_orphans", _spy_sweep)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
        monkeypatch.setattr(test_cmd, "discover_pytest_units", fake_discover)
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
        state_file = tmp_path / "state.json"
        try:
            result = PlainCliRunner().invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "file",
                    "--state-file",
                    str(state_file),
                    "--ignore-disabled-tests",
                ],
            )
        finally:
            os.environ.pop(RUN_ID_ENV, None)
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
            os.environ.pop("PKCS11_CHECK_COUNTERS_DIR", None)
        assert result.exit_code == 0
        assert events == ["barrier", "census"]

    def test_barrier_failure_refuses_resume_before_census(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """N-C2: a failed seal stops the resume before any provider work."""
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from pkcs11_check.core import _counters_durability as durability_mod
        from pkcs11_check.core._run_state import save_run_state
        from pkcs11_check.core._run_units import FileRunState
        from tests._plain_cli_runner import PlainCliRunner

        module = tmp_path / "dummy.so"
        module.write_text("", encoding="utf-8")
        recorded = tmp_path / "recorded-counters"
        state_file = tmp_path / "state.json"
        save_run_state(
            state_file,
            FileRunState(units=[], fingerprint="", results=[], counters_dir=str(recorded)),
        )
        monkeypatch.delenv("PKCS11_CHECK_COUNTERS_DIR", raising=False)
        monkeypatch.delenv(RUN_ID_ENV, raising=False)
        monkeypatch.delenv(PREFLIGHT_EVIDENCE_ENV, raising=False)
        provider_work: list[str] = []

        def _broken_seal(*args: Any, **kwargs: Any) -> Any:
            raise durability_mod.CounterPersistenceError("EACCES")

        def fake_preflight(module_arg: Path, **kwargs: Any) -> CapabilityManifest:
            provider_work.append("census")
            kwargs["output_path"].write_text("{}", encoding="utf-8")
            return _ok_manifest()

        def fake_discover(targets: object, default_root: Path, **kwargs: Any) -> list[str]:
            return [str(default_root / "test_alpha.py")]

        def fake_run(units: object, pytest_args: object, **kwargs: Any) -> int:
            provider_work.append("run")
            return 0

        monkeypatch.setattr(durability_mod, "seal", _broken_seal)
        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", fake_preflight)
        monkeypatch.setattr(test_cmd, "discover_pytest_units", fake_discover)
        monkeypatch.setattr(test_cmd, "run_isolated_pytest_units", fake_run)
        try:
            result = PlainCliRunner().invoke(
                app,
                [
                    "test",
                    "--module",
                    str(module),
                    "--isolation",
                    "file",
                    "--resume",
                    "--state-file",
                    str(state_file),
                    "--ignore-disabled-tests",
                ],
            )
        finally:
            os.environ.pop(RUN_ID_ENV, None)
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
            os.environ.pop("PKCS11_CHECK_COUNTERS_DIR", None)
        assert result.exit_code == 2
        assert provider_work == []


def _retry_session(*, uuid: str | None = _UUID_A) -> dict[str, Any]:
    """A synth-shaped session for retry/dedup tests (uuid-bearing unless None)."""
    block = _softhsm_block()
    record: dict[str, Any] = {
        "$report_type": "CallCountersReport",
        "pid": 4242,
        "isolation": "none",
        "probes_lost": 0,
        "run_id": _RUN,
        "role": "preflight",
        "total_calls": block["total_calls"],
        "by_module": block["by_module"],
    }
    if uuid is not None:
        record["worker_uuid"] = uuid
    return record


# --------------------------------------------------------------------------
# C7: non-consuming collection + first-wins session dedup
# --------------------------------------------------------------------------


class TestNonConsumingCollection:
    def test_collect_twice_without_commit_returns_identical_records_and_keeps_files(
        self, tmp_path: Path
    ) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        kwargs: dict[str, Any] = {
            "child_pid": 4242,
            "returncode": 0,
            "timed_out": False,
            "manifest_status": "ok",
            "manifest_reason": None,
        }
        first, _commit_first = collect_preflight_counters(counters, **kwargs)
        second, _commit_second = collect_preflight_counters(counters, **kwargs)
        assert len(first) == 1
        assert second == first
        assert schema.is_preflight_synth_record(first[0]) is True
        assert list((counters.counters_dir / "registrations").glob("*.json")) != []
        assert list(counters.counters_dir.glob("*.partial.json")) != []

    def test_failed_evidence_append_leaves_files_for_later_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        counters.evidence_path.mkdir()  # a directory: appends fail
        output_path = tmp_path / "manifest.json"
        save_manifest(output_path, _ok_manifest())
        _patch_popen(monkeypatch, _FakePopen(pid=4242, wait_results=0))
        with pytest.warns(UserWarning, match="preflight counter evidence"):
            got = run_preflight_subprocess(
                tmp_path / "m.so",
                interface="auto",
                slot=0,
                timeout=5,
                output_path=output_path,
                counters=counters,
            )
        assert got.status == "ok"
        # The evidence never landed, so the source files stay for a later
        # pass instead of being destroyed with the in-memory records.
        assert list((counters.counters_dir / "registrations").glob("*.json")) != []
        assert list(counters.counters_dir.glob("*.partial.json")) != []

    def test_successful_retain_consumes_after_append(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        output_path = tmp_path / "manifest.json"
        save_manifest(output_path, _ok_manifest())
        _patch_popen(monkeypatch, _FakePopen(pid=4242, wait_results=0))
        got = run_preflight_subprocess(
            tmp_path / "m.so",
            interface="auto",
            slot=0,
            timeout=5,
            output_path=output_path,
            counters=counters,
        )
        assert got.status == "ok"
        records = [
            json.loads(line)
            for line in counters.evidence_path.read_text(encoding="utf-8").splitlines()
        ]
        assert [record["$report_type"] for record in records] == [
            "SessionStart",
            "CallCountersReport",
            "SessionFinish",
        ]
        assert [path for path in counters.counters_dir.rglob("*") if path.is_file()] == []

    def test_torn_append_retry_folds_session_exactly_once(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        kwargs: dict[str, Any] = {
            "child_pid": 4242,
            "returncode": 0,
            "timed_out": False,
            "manifest_status": "ok",
            "manifest_reason": None,
        }
        records, commit = collect_preflight_counters(counters, **kwargs)
        assert len(records) == 1
        # First pass appends, then dies before commit; the retry pass
        # re-collects the same records and appends the same scope again.
        append_preflight_evidence(counters.evidence_path, records)
        retry, commit_retry = collect_preflight_counters(counters, **kwargs)
        assert retry == records
        append_preflight_evidence(counters.evidence_path, retry)
        commit()
        commit_retry()
        payload = extract_call_counters_from_jsonl(counters.evidence_path)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True
        assert payload["by_process"] == [
            {
                "pid": 4242,
                "isolation": "none",
                "total_calls": 85,
                "complete": True,
                "worker_uuid": _UUID_A,
                "role": "preflight",
            }
        ]

    def test_repeated_uuid_session_folds_first_wins(self, tmp_path: Path) -> None:
        synth = _retry_session()
        assert schema.is_session_record(synth) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                synth,
                dict(synth),
                {"$report_type": "SessionFinish"},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True
        assert [row["pid"] for row in payload["by_process"]] == [4242]

    def test_uuid_less_legacy_sessions_keep_fold_every(self, tmp_path: Path) -> None:
        bare = _retry_session(uuid=None)
        assert schema.is_session_record(bare) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                bare,
                dict(bare),
                {"$report_type": "SessionFinish"},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        # No attribution possible without a uuid: both copies still sum.
        assert payload["total_calls"] == 170
        assert payload["complete"] is True


# --------------------------------------------------------------------------
# I3: uniform-five rebucket + preflight partial attribution
# --------------------------------------------------------------------------


class TestPreflightUniformFive:
    def test_rebucket_emits_uniform_five_with_zero_others(self) -> None:
        uniform = rebucket_to_preflight(_softhsm_block())
        assert uniform is not None
        assert schema.is_module_first_block(uniform) is True
        buckets = uniform["by_module"][_MODULE]["buckets"]
        assert schema.is_uniform_five(buckets) is True
        assert buckets["preflight"]["calls"] == 85
        for name in ("test", "setup_teardown", "session_provisioning", "module_init"):
            assert buckets[name] == {"calls": 0, "by_fn": {}}
        by_fn = buckets["preflight"]["by_fn"]
        assert by_fn["C_GetMechanismInfo"]["calls"] == 68
        assert by_fn["C_GetMechanismInfo"]["by_rv"] == {"0": {"name": "CKR_OK", "count": 68}}

    def test_uniform_synth_valid_and_folds(self, tmp_path: Path) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        (synth,), _commit = collect_preflight_counters(
            counters,
            child_pid=4242,
            returncode=0,
            timed_out=False,
            manifest_status="ok",
            manifest_reason=None,
        )
        assert schema.is_preflight_synth_record(synth) is True
        for module_block in synth["by_module"].values():
            assert schema.is_uniform_five(module_block["buckets"]) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, synth, {"$report_type": "SessionFinish"}],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True

    def test_dead_preflight_row_carries_role_isolation_truncated_end_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counters = _counters(tmp_path)
        _plant_producer(counters.counters_dir, pid=4242)
        _patch_popen(monkeypatch, _FakePopen(pid=4242, wait_results=-11))
        got = run_preflight_subprocess(
            tmp_path / "m.so",
            interface="auto",
            slot=0,
            timeout=5,
            output_path=tmp_path / "manifest.json",
            counters=counters,
        )
        assert got.status == "crashed"
        payload = extract_call_counters_from_jsonl(counters.evidence_path)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 4242,
                "isolation": "none",
                "total_calls": 85,
                "complete": False,
                "worker_uuid": _UUID_A,
                "role": "preflight",
                "truncated": True,
                "end_state": "crashed",
            }
        ]

    def test_worker_partial_row_unchanged_control(self, tmp_path: Path) -> None:
        block = _softhsm_block()
        partial: dict[str, Any] = {
            "$report_type": "CallCountersPartial",
            "worker_uuid": _UUID_B,
            "truncated": True,
            "total_calls": block["total_calls"],
            "by_module": block["by_module"],
            "run_id": _RUN,
            "unit": "a.py",
            "attempt": 0,
            "pid": 5150,
        }
        assert schema.is_sidecar_partial(partial) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, partial, {"$report_type": "SessionFinish"}],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 5150,
                "isolation": "unknown",
                "total_calls": 85,
                "complete": False,
                "worker_uuid": _UUID_B,
                "truncated": True,
            }
        ]
