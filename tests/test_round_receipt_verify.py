"""CLI + contract tests for the CI round-receipt verifier (Task E4).

Each test builds a valid receipt/lock pair, mutates ONE aspect, and asserts
the exit code plus the exact field named on stderr.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from scripts.verify_round_receipt import (
    EXIT_INVALID,
    EXIT_USAGE,
    EXIT_VALID,
    RECEIPT_CONTRACT_V,
    compute_bundle_identity,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_round_receipt.py"

FW_SHA = "a" * 40
P11LAB_SHA = "b" * 40
EVAL_SHA = "c" * 40
BASE_SHA = "d" * 40


def _hex64(char: str) -> str:
    return char * 64


def make_lock() -> dict[str, Any]:
    return {
        "receipt_contract_v": RECEIPT_CONTRACT_V,
        "p11lab_ref": P11LAB_SHA,
        "evaluator_fw_ref": EVAL_SHA,
        "baseline_fw_sha": BASE_SHA,
        "tiers": {
            "pr-smoke": {
                "lanes": ["softhsm2"],
                "quorum": {"note": "TBD-E5"},
                "budgets": {"note": "TBD-E5"},
            },
        },
    }


def make_receipt() -> dict[str, Any]:
    digests = {"softhsm2": _hex64("e")}
    lanes = {
        name: {"verdict": "pass", "admitted": True, "evidence_digest": digest}
        for name, digest in digests.items()
    }
    return {
        "receipt_contract_v": RECEIPT_CONTRACT_V,
        "tier": "pr-smoke",
        "framework_sha": FW_SHA,
        "p11lab_sha": P11LAB_SHA,
        "baseline_fw_sha": BASE_SHA,
        "evaluator_sha": EVAL_SHA,
        "policy_hash": _hex64("1"),
        "profile_hash": _hex64("2"),
        "catalog_hash": _hex64("3"),
        "corpus_hash": _hex64("4"),
        "disabled_hash": _hex64("5"),
        "handoff_identity": "handoff/test",
        "runtime_identity": "runtime/test",
        "bundle_identity": compute_bundle_identity(digests),
        "wheel_hashes": {"pkcs11_check-0.0.0-py3-none-any.whl": _hex64("f")},
        "lanes": lanes,
        "run_id": "run-1",
        "attempt": 1,
        "job_ids": {},
    }


def _write(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run(receipt: Path, lock: Path, expect_fw: str = FW_SHA) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(receipt), "--lock", str(lock), "--expect-fw", expect_fw],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )


def _valid_pair(tmp_path: Path) -> tuple[Path, Path]:
    return (
        _write(tmp_path / "receipt.json", make_receipt()),
        _write(tmp_path / "lock.json", make_lock()),
    )


def _recompute_bundle(payload: dict[str, Any]) -> None:
    payload["bundle_identity"] = compute_bundle_identity(
        {name: entry["evidence_digest"] for name, entry in payload["lanes"].items()}
    )


def test_valid_receipt_passes(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_VALID, result.stderr


def test_framework_sha_mismatch(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["framework_sha"] = "0" * 40
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "framework_sha" in result.stderr


def test_p11lab_sha_mismatch(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["p11lab_sha"] = "0" * 40
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "p11lab_sha" in result.stderr


def test_evaluator_sha_mismatch(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["evaluator_sha"] = "0" * 40
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "evaluator_sha" in result.stderr


def test_stale_baseline(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["baseline_fw_sha"] = "0" * 40
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "baseline_fw_sha" in result.stderr


def test_contract_version_mismatch(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["receipt_contract_v"] = 999
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "receipt_contract_v" in result.stderr


def test_missing_required_lane(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    del payload["lanes"]["softhsm2"]
    _recompute_bundle(payload)
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "lanes.softhsm2" in result.stderr


def test_unexpected_lane(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"]["evil-lane"] = {
        "verdict": "pass",
        "admitted": True,
        "evidence_digest": _hex64("a"),
    }
    _recompute_bundle(payload)
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "lanes.evil-lane" in result.stderr


def test_unadmitted_pass(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"]["softhsm2"]["admitted"] = False
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "lanes.softhsm2.admitted" in result.stderr


def test_malformed_evidence_digest(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"]["softhsm2"]["evidence_digest"] = "not-hex"
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "lanes.softhsm2.evidence_digest" in result.stderr


def test_bundle_mismatch(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"]["softhsm2"]["evidence_digest"] = _hex64("b")
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "bundle_identity" in result.stderr
    assert result.stderr.count("error:") == 1, result.stderr


def test_unknown_tier(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["tier"] = "nope"
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "tier" in result.stderr


def test_malformed_receipt_json(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    receipt.write_text("{", encoding="utf-8")
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr


def test_missing_receipt_file(tmp_path: Path) -> None:
    _, lock = _valid_pair(tmp_path)
    result = _run(tmp_path / "nope.json", lock)
    assert result.returncode == EXIT_USAGE, result.stderr


def test_missing_lock_file(tmp_path: Path) -> None:
    receipt, _ = _valid_pair(tmp_path)
    result = _run(receipt, tmp_path / "nope.json")
    assert result.returncode == EXIT_USAGE, result.stderr


def test_malformed_lock_json(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    lock.write_text("{", encoding="utf-8")
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr


def test_malformed_lock_schema(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    bad_lock = make_lock()
    bad_lock["tiers"]["pr-smoke"]["quorum"] = "not-an-object"
    _write(lock, bad_lock)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr
    assert "tiers.pr-smoke.quorum" in result.stderr


def test_empty_expect_fw(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    result = _run(receipt, lock, expect_fw="")
    assert result.returncode == EXIT_USAGE, result.stderr
