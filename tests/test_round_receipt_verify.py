"""CLI + contract tests for the CI round-receipt verifier (Task E4).

Each test builds a valid receipt/lock pair, mutates ONE aspect, and asserts
the exit code plus the exact field named on stderr.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.verify_round_receipt import (
    EXIT_INVALID,
    EXIT_USAGE,
    EXIT_VALID,
    RECEIPT_CONTRACT_V,
    compute_bundle_identity,
    main,
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
    # Two-lane tier so the roster stays non-empty after deleting one lane
    # (R29: an empty receipt roster fails the non-empty rule instead).
    lock_payload = make_lock()
    lock_payload["tiers"]["pr-smoke"]["lanes"] = ["softhsm2", "kryoptic"]
    lock = _write(tmp_path / "lock.json", lock_payload)
    payload = make_receipt()
    payload["lanes"]["kryoptic"] = {
        "verdict": "pass",
        "admitted": True,
        "evidence_digest": _hex64("a"),
    }
    del payload["lanes"]["softhsm2"]
    _recompute_bundle(payload)
    receipt = _write(tmp_path / "receipt.json", payload)
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


# --- Fix round 1 (review R1): decode/parser INFRA, total bundle check,
# --- non-empty lanes (R29), and hardening coverage.


def test_receipt_with_invalid_utf8_bytes_is_infra(tmp_path: Path) -> None:
    _, lock = _valid_pair(tmp_path)
    receipt = tmp_path / "receipt.json"
    receipt.write_bytes(b'{"receipt_contract_v": \xff}')
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_lock_with_invalid_utf8_bytes_is_infra(tmp_path: Path) -> None:
    receipt, _ = _valid_pair(tmp_path)
    lock = tmp_path / "lock.json"
    lock.write_bytes(b'{"receipt_contract_v": \xff}')
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_lock_with_huge_integer_is_infra(tmp_path: Path) -> None:
    receipt, _ = _valid_pair(tmp_path)
    raw = json.dumps(make_lock())
    needle = '"receipt_contract_v": 1'
    assert needle in raw
    lock = tmp_path / "lock.json"
    lock.write_text(raw.replace(needle, f'"receipt_contract_v": {"9" * 5000}'), encoding="utf-8")
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_deeply_nested_receipt_never_tracebacks(tmp_path: Path) -> None:
    # Reviewer probe shape (10k nested arrays). Where the parser raises
    # RecursionError (this venv's 3.13, like the reviewer's interpreter)
    # the exit is 2 via the INFRA handler; where it parses (3.14's
    # iterative scanner handles >=200k levels) the non-object top level
    # fails validation with exit 1. Either way: handled, an error: line,
    # zero tracebacks.
    _, lock = _valid_pair(tmp_path)
    receipt = tmp_path / "receipt.json"
    receipt.write_text("[" * 10000 + "]" * 10000, encoding="utf-8")
    result = _run(receipt, lock)
    assert result.returncode in (EXIT_INVALID, EXIT_USAGE), result.stderr
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_recursion_error_maps_to_infra_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Deterministic pin of the RecursionError -> exit 2 path on every
    # interpreter (the real parser only raises it on some versions).
    def _boom(_text: str) -> Any:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(json, "loads", _boom)
    receipt, lock = _valid_pair(tmp_path)
    assert main([str(receipt), "--lock", str(lock), "--expect-fw", FW_SHA]) == EXIT_USAGE
    assert "error:" in capsys.readouterr().err


def test_surrogate_digest_reports_rule6_without_crash(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"]["softhsm2"]["evidence_digest"] = chr(0xD800)
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "Traceback" not in result.stderr
    assert "lanes.softhsm2.evidence_digest" in result.stderr
    assert result.stderr.count("error:") == 1, result.stderr


def test_surrogate_digest_preserves_other_diagnostics(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"]["softhsm2"]["evidence_digest"] = chr(0xD800)
    payload["policy_hash"] = "bad"
    payload["attempt"] = 0
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "Traceback" not in result.stderr
    assert "lanes.softhsm2.evidence_digest" in result.stderr
    assert "policy_hash" in result.stderr
    assert "attempt" in result.stderr
    assert result.stderr.count("error:") == 3, result.stderr


def test_surrogate_lane_name_reports_unexpected_lane(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"][f"{chr(0xD800)}evil"] = {
        "verdict": "pass",
        "admitted": True,
        "evidence_digest": _hex64("a"),
    }
    # Bundle intentionally NOT recomputed: the check must skip (no-cascade),
    # not crash on the unencodable name nor emit a spurious mismatch.
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "Traceback" not in result.stderr
    assert "unexpected lane" in result.stderr
    assert result.stderr.count("error:") == 1, result.stderr


def test_empty_tier_lanes_rejects_lock(tmp_path: Path) -> None:
    receipt, _ = _valid_pair(tmp_path)
    bad_lock = make_lock()
    bad_lock["tiers"]["pr-smoke"]["lanes"] = []
    lock = _write(tmp_path / "lock.json", bad_lock)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr
    assert "tiers.pr-smoke.lanes" in result.stderr


def test_empty_receipt_lanes_rejected(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["lanes"] = {}
    payload["bundle_identity"] = hashlib.sha256(b"").hexdigest()
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    assert "lanes: must be a non-empty object" in result.stderr


def test_empty_tier_and_empty_receipt_rejected_at_lock(tmp_path: Path) -> None:
    # The green-on-empty hole (empty tier + empty roster + empty-sha bundle
    # previously exited 0): the lock gate must fire first with exit 2.
    bad_lock = make_lock()
    bad_lock["tiers"]["pr-smoke"]["lanes"] = []
    lock = _write(tmp_path / "lock.json", bad_lock)
    payload = make_receipt()
    payload["lanes"] = {}
    payload["bundle_identity"] = hashlib.sha256(b"").hexdigest()
    receipt = _write(tmp_path / "receipt.json", payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_USAGE, result.stderr
    assert "tiers.pr-smoke.lanes" in result.stderr


# Independent bundle golden: canonical bytes for lanes a -> "1"*64,
# z -> "2"*64 are `a\0<1x64>\0z\0<2x64>\0` (134 bytes); hashed via
# `printf ... | sha256sum` in the shell (fix-round-1 report). Matches the
# reviewer's independently computed value.
BUNDLE_GOLDEN_AZ = "4b8e992c3a69482dc6cf017bd0a2766fb0d3b142d29aacf22bc745992a80bd8e"


def test_bundle_golden_matches_shell_sha256() -> None:
    assert compute_bundle_identity({"a": _hex64("1"), "z": _hex64("2")}) == BUNDLE_GOLDEN_AZ


def test_bundle_binding_is_order_independent() -> None:
    assert compute_bundle_identity({"z": _hex64("2"), "a": _hex64("1")}) == BUNDLE_GOLDEN_AZ


def test_multi_fault_receipt_reports_every_violation(tmp_path: Path) -> None:
    # Fail-loud batch: six distinct faults, all six lines, no cascade.
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["framework_sha"] = "0" * 40
    payload["policy_hash"] = "bad"
    payload["attempt"] = 0
    payload["run_id"] = ""
    payload["wheel_hashes"] = {}
    payload["lanes"]["softhsm2"]["admitted"] = False
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_INVALID, result.stderr
    for field in (
        "framework_sha",
        "policy_hash",
        "attempt",
        "run_id",
        "wheel_hashes",
        "lanes.softhsm2.admitted",
    ):
        assert field in result.stderr, field
    assert result.stderr.count("error:") == 6, result.stderr


def test_unknown_top_level_keys_ignored(tmp_path: Path) -> None:
    receipt, lock = _valid_pair(tmp_path)
    payload = make_receipt()
    payload["future_field"] = {"nested": [1, 2, 3]}
    _write(receipt, payload)
    result = _run(receipt, lock)
    assert result.returncode == EXIT_VALID, result.stderr
