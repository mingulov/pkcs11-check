"""Subprocess mechanism telemetry must survive ingestion and plugin aggregation."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import plugin
from pkcs11_check.raw.types_std import CKM_AES_CTR, CKM_CHACHA20
from pkcs11_check.testcases import _raw_subprocess, _subprocess_preamble
from pkcs11_check.testcases._probes import session as probe_session

CKR_MECHANISM_INVALID = 0x70


class _ReportLog:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def _write_json_data(self, record: dict[str, Any]) -> None:
        self.records.append(record)


@pytest.mark.parametrize(
    "coverage_module,ingest_name,drain_name",
    [
        pytest.param(
            _raw_subprocess,
            "ingest_raw_subprocess_coverage",
            "get_raw_subprocess_coverage",
            id="raw",
        ),
        pytest.param(
            _subprocess_preamble,
            "ingest_subprocess_coverage",
            "get_preamble_subprocess_coverage",
            id="session",
        ),
    ],
)
def test_ingestion_normalizes_json_mechanism_ids_to_integers(
    tmp_path: Path,
    coverage_module: Any,
    ingest_name: str,
    drain_name: str,
) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "call_log": {"C_Encrypt": 2},
                "mechanism_counts": {str(int(CKM_AES_CTR)): 2},
                "call_log_ok": {"C_Encrypt": 1},
            }
        ),
        encoding="utf-8",
    )
    drain = getattr(coverage_module, drain_name)
    drain()

    getattr(coverage_module, ingest_name)(str(coverage_path))
    _functions, mechanisms, _function_ok, _mechanism_rvs = drain()

    assert mechanisms == Counter({int(CKM_AES_CTR): 2})


def test_plugin_merges_both_subprocess_mechanism_channels_into_counts_and_used(
    tmp_path: Path,
) -> None:
    raw_path = tmp_path / "raw.json"
    raw_path.write_text(
        json.dumps(
            {
                "call_log": {"C_Encrypt": 1},
                "mechanism_counts": {str(int(CKM_AES_CTR)): 2},
            }
        ),
        encoding="utf-8",
    )
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps(
            {
                "call_log": {"C_Decrypt": 1},
                "mechanism_counts": {str(int(CKM_CHACHA20)): 3},
            }
        ),
        encoding="utf-8",
    )
    _raw_subprocess.get_raw_subprocess_coverage()
    _subprocess_preamble.get_preamble_subprocess_coverage()
    _raw_subprocess.ingest_raw_subprocess_coverage(str(raw_path))
    _subprocess_preamble.ingest_subprocess_coverage(str(session_path))
    stash = {
        plugin._CUMULATIVE_FUNCTIONS: set(),
        plugin._CUMULATIVE_FUNCTION_COUNTS: Counter(),
        plugin._CUMULATIVE_FUNCTION_OK_COUNTS: Counter(),
        plugin._CUMULATIVE_USED_MECHANISMS: set(),
        plugin._CUMULATIVE_MECHANISM_COUNTS: Counter(),
        plugin._CUMULATIVE_MECHANISMS: set(),
    }
    item = SimpleNamespace(
        path=Path("/tmp/testcases/test_probe.py"),
        session=SimpleNamespace(config=SimpleNamespace(stash=stash)),
        funcargs={},
    )

    plugin.pytest_runtest_teardown(item, None)

    assert stash[plugin._CUMULATIVE_MECHANISM_COUNTS] == Counter(
        {int(CKM_AES_CTR): 2, int(CKM_CHACHA20): 3}
    )
    assert stash[plugin._CUMULATIVE_USED_MECHANISMS] == {
        int(CKM_AES_CTR),
        int(CKM_CHACHA20),
    }


def test_session_probe_writer_serializes_mechanism_rv_counts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    coverage_path = tmp_path / "coverage.json"
    monkeypatch.setenv("_P11CHECK_SUBPROCESS_COVERAGE", str(coverage_path))
    raw = SimpleNamespace(
        call_log={"C_Encrypt": 1},
        mechanism_counts={int(CKM_AES_CTR): 1},
        call_log_ok={"C_Encrypt": 1},
        mechanism_rv_counts={int(CKM_AES_CTR): {0: 1}},
    )

    probe_session._write_coverage(raw)

    payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert payload["mechanism_rv_counts"] == {str(int(CKM_AES_CTR)): {"0": 1}}


def test_plugin_emits_subprocess_rv_state_from_cumulative_telemetry(tmp_path: Path) -> None:
    rv_key = getattr(plugin, "_CUMULATIVE_MECHANISM_RV_COUNTS", None)
    assert rv_key is not None, "plugin needs cumulative mechanism RV state"
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                "call_log": {"C_Encrypt": 1, "C_Decrypt": 2},
                "mechanism_counts": {
                    str(int(CKM_AES_CTR)): 1,
                    str(int(CKM_CHACHA20)): 2,
                },
                "mechanism_rv_counts": {
                    str(int(CKM_AES_CTR)): {"0": 1},
                    str(int(CKM_CHACHA20)): {str(CKR_MECHANISM_INVALID): 2},
                },
            }
        ),
        encoding="utf-8",
    )
    _subprocess_preamble.get_preamble_subprocess_coverage()
    _subprocess_preamble.ingest_subprocess_coverage(str(coverage_path))
    report_log = _ReportLog()
    stash = {
        plugin._CUMULATIVE_FUNCTIONS: set(),
        plugin._RAW_INSTANCE: SimpleNamespace(
            available_function_names=lambda: set(),
            mechanism_rv_counts={},
        ),
        plugin._CUMULATIVE_FUNCTION_COUNTS: Counter(),
        plugin._CUMULATIVE_FUNCTION_OK_COUNTS: Counter(),
        plugin._CUMULATIVE_USED_MECHANISMS: set(),
        plugin._CUMULATIVE_MECHANISM_COUNTS: Counter(),
        plugin._CUMULATIVE_MECHANISMS: {"CKM_AES_CTR", "CKM_CHACHA20"},
        plugin._CUMULATIVE_MECHANISM_DETAILS: set(),
        plugin._CUMULATIVE_DETAIL_COUNTS: Counter(),
        plugin._BOOTSTRAP_FUNCTION_COUNTS: {},
        plugin._SELECTION_TELEMETRY_KEY: {},
        plugin._MODULE_SESSION_HEALTH_METRICS: {"checks": 0, "duration_s": 0.0},
        plugin._PROVISIONING_COUNTS: Counter(),
        rv_key: defaultdict(Counter),
    }
    config = SimpleNamespace(
        stash=stash,
        getoption=lambda name, default=None: {"p11_module": "/tmp/module.so"}.get(name, default),
        _report_log_plugin=report_log,
    )
    item = SimpleNamespace(
        path=Path("/tmp/testcases/test_probe.py"),
        session=SimpleNamespace(config=config),
        funcargs={},
    )

    plugin.pytest_runtest_teardown(item, None)
    plugin.pytest_sessionfinish(SimpleNamespace(config=config), 0)

    coverage_report = next(
        record for record in report_log.records if record.get("$report_type") == "CoverageReport"
    )
    mechanism_coverage = coverage_report["mechanism_coverage"]
    assert mechanism_coverage["invoked_counts"] == {
        "CKM_AES_CTR": 1,
        "CKM_CHACHA20": 2,
    }
    assert mechanism_coverage["accepted_names"] == ["CKM_AES_CTR"]
    assert mechanism_coverage["rejected_cleanly_names"] == ["CKM_CHACHA20"]
