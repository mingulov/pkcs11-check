"""The subprocess-coverage channel must propagate per-function CKR_OK counts
(call_log_ok) end to end, so the hollow-pass oracle sees productive invocations
from the isolated child processes where most tests run."""

from __future__ import annotations

import json

from pkcs11_check.testcases import _subprocess_preamble as pre


def test_ingest_and_drain_propagate_call_log_ok(tmp_path) -> None:
    cov = tmp_path / "cov.json"
    cov.write_text(
        json.dumps(
            {
                "call_log": {"C_Sign": 5, "C_Verify": 3},
                "mechanism_counts": {},
                "call_log_ok": {"C_Sign": 4},  # 4 of 5 signs returned CKR_OK
            }
        ),
        encoding="utf-8",
    )
    # Drain any residue first so this test is order-independent.
    pre.get_preamble_subprocess_coverage()

    pre.ingest_subprocess_coverage(str(cov))
    func, _mech, func_ok = pre.get_preamble_subprocess_coverage()

    assert func["C_Sign"] == 5
    assert func_ok["C_Sign"] == 4
    assert func_ok.get("C_Verify", 0) == 0  # no OK key -> zero

    # Draining cleared the OK accumulator too (no leak into the next run).
    _f, _m, func_ok_again = pre.get_preamble_subprocess_coverage()
    assert func_ok_again == {}


def test_missing_call_log_ok_key_is_tolerated(tmp_path) -> None:
    cov = tmp_path / "cov.json"
    # No "call_log_ok" key at all -> tolerated as empty.
    cov.write_text(
        json.dumps({"call_log": {"C_Sign": 1}, "mechanism_counts": {}}), encoding="utf-8"
    )
    pre.get_preamble_subprocess_coverage()
    pre.ingest_subprocess_coverage(str(cov))
    func, _mech, func_ok = pre.get_preamble_subprocess_coverage()
    assert func["C_Sign"] == 1
    assert func_ok == {}
