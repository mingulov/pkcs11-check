"""F14 acceptance: round-0198 routing consequences on deterministic fixtures.

Reruns 0198-shaped raw records (P11C-0198-004/012/018) through
extract -> enrich and compares group identity, summary, severity, and
disposition:

* openCryptoki / Pico HSM / PivApplet / tpm2-pkcs11 timeout records become
  evidence-rerun leads (UNRESOLVED_ATTRIBUTION / EVIDENCE_RERUN);
* BouncyHSM / YKCS11 underfills and the SC-HSM SIGSEGV stay provider-visible
  (PROVIDER_BUG / PROVIDER_REPORT);
* Cosmian / pkcs11-rs SIGKILLs stay crash evidence -- never timeout-classified.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.core.file_runner import crash_classification
from pkcs11_check.core.process_observation import build_process_observation
from pkcs11_check.report.correlate import enrich
from pkcs11_check.report.extract import extract_groups
from pkcs11_check.report.health import outcome_counts


def _test_report(nodeid: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "$report_type": "TestReport",
        "when": "call",
        "nodeid": nodeid,
        "outcome": "failed",
        "user_properties": [["pkcs11_classification", records]],
    }


def _classification(**over: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "reason": "accepted_invalid",
        "outcome": "fail",
        "severity": "HIGH",
        "kind": None,
        "label": "",
        "summary": "",
        "operation": None,
        "mechanism": None,
        "expected_ckr": None,
        "actual_ckr": None,
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "detail": None,
        "schema": 1,
    }
    rec.update(over)
    return rec


def test_runner_timeout_records_become_evidence_rerun_leads(tmp_path: Path) -> None:
    """0198 openCryptoki-style runner watchdog timeouts: probe_incomplete,
    HIGH, EVIDENCE_RERUN -- loud, but not provider bug recommendations."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    obs = build_process_observation("unit", "unit", 0, 124, timed_out=True)
    record = crash_classification(
        returncode=None, target="tests/test_rsa.py", timed_out=True, observation=obs
    )
    groups = extract_groups(path, crashes=[record])
    enrich(groups, module_issues_text="", provider="opencryptoki")
    (group,) = groups
    assert group["reason"] == "probe_incomplete"
    assert group["outcome"] == "fail"
    assert group["severity"] == "HIGH"
    assert "crash" not in str(group["summary"]).lower()
    assert group["category"] == "UNRESOLVED_ATTRIBUTION"
    assert group["routing"] == "EVIDENCE_RERUN"
    assert outcome_counts(groups)["fail"] == 1


def test_probe_timeout_records_become_evidence_rerun_leads(tmp_path: Path) -> None:
    """0198 Pico HSM / PivApplet / tpm2-pkcs11-style in-test 4 GiB probe
    timeouts: locally probe_incomplete, routed to evidence rerun."""
    path = tmp_path / "report.jsonl"
    rec = _classification(
        reason="probe_incomplete",
        outcome="fail",
        severity="HIGH",
        label="C_GenerateRandom(ptr, len=0x100000008)",
        summary=(
            "C_GenerateRandom(ptr, len=0x100000008): probe timed out after 180 s "
            "without returning -- completion/progress unknown"
        ),
        detail={
            "termination": {
                "kind": "timeout",
                "raw_code": 124,
                "signal_name": None,
                "windows_status": None,
            }
        },
    )
    nodeid = (
        "src/pkcs11_check/testcases/security/test_random_length_truncation.py"
        "::TestGenerateRandomLengthTruncation"
        "::test_generate_random_oversized_length_rejects_or_honors"
    )
    path.write_text(json.dumps(_test_report(nodeid, [rec])) + "\n", encoding="utf-8")
    groups = extract_groups(path, crashes=[])
    enrich(groups, module_issues_text="", provider="tpm2-pkcs11")
    (group,) = groups
    assert group["reason"] == "probe_incomplete"
    assert group["category"] == "UNRESOLVED_ATTRIBUTION"
    assert group["routing"] == "EVIDENCE_RERUN"
    assert outcome_counts(groups)["fail"] == 1


def test_completed_underfill_stays_provider_visible(tmp_path: Path) -> None:
    """0198 BouncyHSM/YKCS11-style completed CKR_OK + UNDERFILL:1: a completed
    measurement of silent truncation stays an accepted-invalid provider finding."""
    path = tmp_path / "report.jsonl"
    rec = _classification(
        reason="accepted_invalid",
        outcome="fail",
        severity="HIGH",
        label="C_GenerateRandom 64-bit length truncated (silent under-fill)",
        summary=(
            "C_GenerateRandom 64-bit length truncated (silent under-fill): "
            "accepted invalid (CKR_OK) -- must reject"
        ),
        expected_ckr=["CKR_ARGUMENTS_BAD"],
        actual_ckr="CKR_OK",
        detail={"underfill": 1},
    )
    nodeid = (
        "src/pkcs11_check/testcases/security/test_random_length_truncation.py"
        "::TestGenerateRandomLengthTruncation"
        "::test_generate_random_oversized_length_rejects_or_honors"
    )
    path.write_text(json.dumps(_test_report(nodeid, [rec])) + "\n", encoding="utf-8")
    groups = extract_groups(path, crashes=[])
    enrich(groups, module_issues_text="", provider="bouncyhsm")
    (group,) = groups
    assert group["reason"] == "accepted_invalid"
    assert group["category"] == "PROVIDER_BUG"
    assert group["routing"] == "PROVIDER_REPORT"


def test_sigsegv_crash_stays_provider_visible(tmp_path: Path) -> None:
    """0198 SC-HSM-style SIGSEGV: real crash evidence keeps the provider route."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    record = crash_classification(returncode=-11, target="tests/test_random.py")
    groups = extract_groups(path, crashes=[record])
    enrich(groups, module_issues_text="", provider="sc-hsm")
    (group,) = groups
    assert group["reason"] == "crash"
    assert group["category"] == "PROVIDER_BUG"
    assert group["routing"] == "PROVIDER_REPORT"


def test_sigkill_is_crash_evidence_not_timeout(tmp_path: Path) -> None:
    """0198 Cosmian/pkcs11-rs-style SIGKILLs need OOM attribution -- they must
    never be timeout-classified."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    record = crash_classification(returncode=-9, target="tests/test_kdf.py")
    groups = extract_groups(path, crashes=[record])
    enrich(groups, module_issues_text="", provider="cosmian")
    (group,) = groups
    assert group["reason"] == "crash"
    assert group["reason"] != "probe_incomplete"
    assert "timed out" not in str(group["summary"]).lower()
    assert group["routing"] == "PROVIDER_REPORT"


def test_unresolved_records_reject_known_issue_override(tmp_path: Path) -> None:
    """Even a module-issues text matching the record keeps unresolved and
    unclassified failures off the DOCS_ONLY route."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    timeout = crash_classification(returncode=None, target="tests/test_rsa.py", timed_out=True)
    groups = extract_groups(path, crashes=[timeout])
    groups.append(
        {
            "test_file": "tests/test_rsa.py",
            "reason": "unclassified",
            "outcome": "fail",
            "severity": "HIGH",
            "kind": None,
            "operation": "C_Verify",
            "mechanism": "CKM_ECDSA_SHA256",
            "expected_ckr": None,
            "actual_ckr": None,
            "spec_ref": "",
            "summary": "raw failure",
            "count": 1,
            "nodeids": [],
            "vector_ids": [],
            "sources": [],
            "param_breakdown": {},
        }
    )
    snippet = "## provider\n- C_Verify with CKM_ECDSA_SHA256 flakes sometimes.\n"
    enrich(groups, module_issues_text=snippet, provider="provider")
    assert groups[0]["routing"] == "EVIDENCE_RERUN"
    assert groups[1]["routing"] == "MANUAL_REVIEW"
