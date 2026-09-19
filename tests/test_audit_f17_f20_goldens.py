"""Goldens for audit findings F17-F20 (2026-09-19 v0.19-to-HEAD framework audit).

Each test pins the fixed behaviour with a reproduction of the original failure
mode; all are behaviour-scoped (no line counts, no snapshots).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.classification import clear as clear_records
from pkcs11_check.classification import get_records
from pkcs11_check.core._report_records import _report_record_cache_dir
from pkcs11_check.core._run_state import load_run_state, save_run_state
from pkcs11_check.core.file_runner import FileRunState, _reset_fresh_run_artifacts
from pkcs11_check.core.merge import merge_results_payloads
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import (
    CK_UNAVAILABLE_INFORMATION,
    CKA_CHECK_VALUE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

# ---------------------------------------------------------------------------
# F17: fresh-run reset must survive a symlinked report-record cache dir
# ---------------------------------------------------------------------------


def test_reset_unlinks_symlinked_cache_dir_without_touching_target(
    tmp_path: Path,
) -> None:
    """A relocated (symlinked) cache dir must not abort the fresh-run reset.

    Regression: ``shutil.rmtree`` on the symlink raised ``OSError``. The fix
    unlinks the link only; the relocated tree itself is left intact (deleting
    through the link could wipe an unrelated tree).
    """
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    target = tmp_path / "relocated-cache"
    target.mkdir()
    marker = target / "shard.jsonl"
    marker.write_text("{}\n", encoding="utf-8")
    cache_dir = _report_record_cache_dir(state_file)
    cache_dir.symlink_to(target, target_is_directory=True)

    _reset_fresh_run_artifacts(state_file, None)

    assert not state_file.exists()
    assert not cache_dir.exists() and not cache_dir.is_symlink()
    assert marker.read_text(encoding="utf-8") == "{}\n"


def test_reset_still_clears_a_real_cache_dir(tmp_path: Path) -> None:
    """The non-symlink path keeps its original clear-the-directory behaviour."""
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    cache_dir = _report_record_cache_dir(state_file)
    cache_dir.mkdir()
    (cache_dir / "shard.jsonl").write_text("{}\n", encoding="utf-8")

    _reset_fresh_run_artifacts(state_file, None)

    assert not state_file.exists()
    assert not cache_dir.exists()


# ---------------------------------------------------------------------------
# F18: child-process pipes must survive stray non-UTF-8 provider bytes
# ---------------------------------------------------------------------------

_BAD_BYTES = b"marker-line \xff garbage\n"


def _decoding_run(
    stdout_bytes: bytes,
    stderr_bytes: bytes = b"",
    returncode: int = 0,
) -> Any:
    """Fake ``subprocess.run`` that decodes exactly the way CPython would.

    The contract under test is that the caller passes ``errors="replace"``:
    CPython's own decoding behaviour is stdlib business, but a caller that
    omits ``errors=`` gets strict decoding and raises ``UnicodeDecodeError``
    on ``_BAD_BYTES`` -- which is precisely the F18 failure.
    """

    def fake(cmd: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if kwargs.get("text"):
            encoding = kwargs.get("encoding", "utf-8")
            errors = kwargs.get("errors", "strict")
            stdout = stdout_bytes.decode(encoding, errors)
            stderr = stderr_bytes.decode(encoding, errors)
        else:
            stdout, stderr = stdout_bytes, stderr_bytes  # type: ignore[assignment]
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    return fake


def test_probe_runner_survives_bad_bytes_on_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.testcases._probes.runner import run_probe

    monkeypatch.setattr(subprocess, "run", _decoding_run(_BAD_BYTES))
    result = run_probe("session", {"module_path": "dummy"})
    assert result.returncode == 0
    assert "marker-line � garbage" in result.stdout


def test_unit_discovery_keeps_good_nodeids_despite_bad_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.core._unit_discovery import collect_pytest_nodeids

    payload = b"test_a.py::test_1\nbad\xffline\n"
    monkeypatch.setattr(subprocess, "run", _decoding_run(payload))
    assert collect_pytest_nodeids(["test_a.py"], []) == ["test_a.py::test_1"]


def test_login_probe_survives_bad_bytes_on_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from pkcs11_check.core.doctor_probe import run_login_probe_subprocess

    stdout = b'{"status": "ok", "detail": "fine"}\n'
    monkeypatch.setattr(subprocess, "run", _decoding_run(stdout, stderr_bytes=_BAD_BYTES))
    probe = run_login_probe_subprocess(
        tmp_path / "module.so", interface="auto", slot=0, pin=b"1234", timeout=5
    )
    assert (probe.status, probe.detail) == ("ok", "fine")


def test_collection_worker_survives_bad_bytes_on_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from pkcs11_check.core.collection import collect_pytest_item_metadata

    def fake(cmd: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        # Play the child's file-writing half: it receives --output on argv.
        out_argv = cmd[cmd.index("--output") + 1]
        Path(out_argv).write_text('{"items": []}\n', encoding="utf-8")
        return _decoding_run(_BAD_BYTES)(cmd, **kwargs)

    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setenv("PKCS11_CHECK_NO_COLLECTION_CACHE", "1")
    assert collect_pytest_item_metadata([str(tmp_path)], []) == []


def test_provenance_git_survives_non_utf8_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from pkcs11_check.provenance import _run_git

    monkeypatch.setattr(subprocess, "run", _decoding_run(b"\xff\xfe name\n"))
    assert _run_git(["log"], tmp_path) == "�� name"


def test_throwaway_mint_survives_bad_bytes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from pkcs11_check.testcases.test_threading import _mint_throwaway_token

    monkeypatch.setenv("PKCS11_CHECK_THROWAWAY_MODULE", "1")
    monkeypatch.setenv("PKCS11_CHECK_TOKEN_MINT_CMD", "true")
    monkeypatch.setattr(subprocess, "run", _decoding_run(_BAD_BYTES))
    assert _mint_throwaway_token(tmp_path) == str(tmp_path / "module.conf")


def test_threaded_workload_survives_bad_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.testcases.test_threading import _run_threaded_workload

    monkeypatch.setattr(subprocess, "run", _decoding_run(_BAD_BYTES))
    config = SimpleNamespace(slot=0, pin=None, module="dummy")
    rc, out, _err = _run_threaded_workload(config, workload="digest", threads=1, iters=1)
    assert rc == 0
    assert "marker-line � garbage" in out


def test_interop_run_survives_bad_bytes_from_a_real_child() -> None:
    """The one site whose command is a parameter gets a true end-to-end test."""
    from pkcs11_check.testcases.test_interop_openssl import _run

    rc, out, _err = _run(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'ok\\xff\\n')",
        ]
    )
    assert rc == 0
    assert out == "ok�\n"


# ---------------------------------------------------------------------------
# F19: shard merge duplicate-target guard + atomic state save
# ---------------------------------------------------------------------------


def _payload(target: str, status: str = "passed") -> dict[str, Any]:
    return {"summary": {"passed": 1}, "units": [{"target": target, "status": status}]}


def test_merge_rejects_duplicate_unit_target_across_shards() -> None:
    """Merging the same target twice would silently double-count summaries."""
    with pytest.raises(ValueError, match="duplicate unit targets"):
        merge_results_payloads([_payload("test_a.py"), _payload("test_a.py")], coverage=None)


def test_merge_accepts_repeated_pseudo_units() -> None:
    """Session-global pseudo-units legitimately repeat in every shard."""
    p1 = {
        "summary": {"passed": 1},
        "units": [
            {"target": "test_a.py", "status": "passed"},
            {"target": "<collection>", "status": "passed"},
            {"target": "<lifecycle>", "status": "passed"},
            {"target": "test_a.py::daemon-recovery-0", "status": "passed"},
        ],
    }
    p2 = {
        "summary": {"passed": 1},
        "units": [
            {"target": "test_b.py", "status": "passed"},
            {"target": "<collection>", "status": "passed"},
            {"target": "<lifecycle>", "status": "passed"},
            {"target": "test_b.py::daemon-recovery-0", "status": "passed"},
        ],
    }
    merged = merge_results_payloads([p1, p2], coverage=None)
    assert merged["summary"]["passed"] == 2
    assert len(merged["units"]) == 8


def test_save_run_state_is_atomic_and_leaves_no_tmp(tmp_path: Path) -> None:
    """A save either lands whole or not at all; no tmp file is left behind."""
    state_file = tmp_path / "state.json"
    state = FileRunState(units=["a.py"], fingerprint="fp", results=[])
    save_run_state(state_file, state)
    assert state_file.with_suffix(".json.tmp").exists() is False
    loaded = load_run_state(state_file)
    assert loaded is not None
    assert (loaded.units, loaded.fingerprint) == (["a.py"], "fp")


# ---------------------------------------------------------------------------
# F20: optional_if_absent swallows only an affirmative TYPE_INVALID refusal
# ---------------------------------------------------------------------------


def _sentinel_read(ckr: int) -> Any:
    def _get(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        return ckr

    return read_attributes(SimpleNamespace(C_GetAttributeValue=_get), 1, 1, [CKA_CHECK_VALUE])


def test_optional_absent_stays_silent_for_type_invalid() -> None:
    """The legitimate optional-attribute omission: module has no such attr."""
    clear_records()
    before = len(get_records())
    value = attr_or_record(
        _sentinel_read(int(CKR_ATTRIBUTE_TYPE_INVALID)),
        CKA_CHECK_VALUE,
        label="KCV",
        optional_if_absent=True,
    )
    assert value is MISSING_ATTRIBUTE
    assert len(get_records()) == before


def test_optional_absent_stays_silent_for_a_plain_omission() -> None:
    """A mapping with nothing observed at all is an unsupported attribute.

    Pins the KCV skip behaviour: a plain dict (no ``refusals`` channel, no
    sentinel observation) stays silent under ``optional_if_absent`` -- only a
    genuinely observed CKR_OK-plus-sentinel is recorded (see next test).
    """
    clear_records()
    before = len(get_records())
    value = attr_or_record(
        {},
        CKA_CHECK_VALUE,
        label="KCV",
        optional_if_absent=True,
    )
    assert value is MISSING_ATTRIBUTE
    assert len(get_records()) == before


def test_optional_absent_records_ckr_ok_plus_sentinel() -> None:
    """CKR_OK with no value is a spec-shape deviation even for optional attrs.

    Regression: the ``refusal is None`` disjunct swallowed it silently while
    the default path recorded it.
    """
    clear_records()
    value = attr_or_record(
        _sentinel_read(int(CKR_OK)),
        CKA_CHECK_VALUE,
        label="KCV",
        optional_if_absent=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.actual_ckr is None
