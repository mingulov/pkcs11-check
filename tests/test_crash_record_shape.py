from pkcs11_check.core.file_runner import crash_classification


def test_sigsegv_crash_record():
    rec = crash_classification(returncode=-11, target="x/test_y.py")
    assert rec["reason"] == "crash" and rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH" and rec["detail"]["signal"] == "SIGSEGV"


def test_sigabrt_crash_record():
    rec = crash_classification(returncode=-6, target="x/test_y.py")
    assert rec["detail"]["signal"] == "SIGABRT"


def test_timeout_record():
    # F14/P11C-0198-012 contract change: a runner-owned typed timeout is
    # probe_incomplete, never a crash. The mode detail key is preserved.
    rec = crash_classification(returncode=None, target="x/test_y.py", timed_out=True)
    assert rec["detail"]["mode"] == "timeout"
    assert rec["reason"] == "probe_incomplete" and rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH"


def test_runner_timeout_is_probe_incomplete_not_crash():
    """F14/P11C-0198-012: a runner-owned typed timeout is FAIL/HIGH
    probe_incomplete, never a crash, and carries no fabricated CKR."""
    from pkcs11_check.core.file_runner import crash_classification as cc

    rec = cc(returncode=None, target="x/test_y.py", timed_out=True)
    assert rec["reason"] == "probe_incomplete"
    assert rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH"
    assert "crash" not in str(rec["summary"]).lower()
    assert "timed out" in str(rec["summary"]).lower()
    assert rec["actual_ckr"] is None
    assert rec["expected_ckr"] is None


def test_observation_timeout_is_probe_incomplete_not_crash():
    """F14/P11C-0198-012: structured termination kind=timeout (e.g. a 0198 lane
    observation with raw_code 124) routes the same way as the timed_out flag."""
    from pkcs11_check.core.file_runner import crash_classification as cc
    from pkcs11_check.core.process_observation import build_process_observation

    obs = build_process_observation("x/test_y.py", "unit", 0, 124, timed_out=True)
    assert obs["termination"]["kind"] == "timeout"  # fixture sanity
    rec = cc(returncode=124, target="x/test_y.py", observation=obs)
    assert rec["reason"] == "probe_incomplete"
    assert rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH"
    assert "crash" not in str(rec["summary"]).lower()
    assert rec["actual_ckr"] is None


def test_signal_stays_crash_evidence():
    """F14/P11C-0198-012: signals (incl. SIGKILL) remain crash evidence."""
    from pkcs11_check.core.file_runner import crash_classification as cc
    from pkcs11_check.core.process_observation import build_process_observation

    for rc in (-11, -6, -9):
        rec = cc(returncode=rc, target="x/test_y.py")
        assert rec["reason"] == "crash", rc
        assert rec["outcome"] == "fail" and rec["severity"] == "HIGH"
    obs = build_process_observation("x/test_y.py", "unit", 0, -9)
    rec = cc(returncode=-9, target="x/test_y.py", observation=obs)
    assert rec["reason"] == "crash"
    assert "SIGKILL" in str(rec["summary"]) or "signal" in str(rec["summary"]).lower()


def test_windows_exception_has_distinct_crash_summary():
    """F14/P11C-0198-012: a Windows exception is a crash with its own summary."""
    from pkcs11_check.core.file_runner import crash_classification as cc

    rec = cc(returncode=0xC0000005, target="x/test_y.py")
    assert rec["reason"] == "crash"
    assert "exception" in str(rec["summary"]).lower()
    assert str(rec["summary"]) != "x/test_y.py: process crashed"


def test_external_kill_is_probe_incomplete_not_crash():
    """F14/P11C-0198-012: an externally killed process (OOM/operator) has
    unresolved attribution -- loud, but not crash evidence."""
    from pkcs11_check.core.file_runner import crash_classification as cc
    from pkcs11_check.core.process_observation import build_process_observation

    obs = build_process_observation("x/test_y.py", "unit", 0, None, external_kill=True)
    assert obs["termination"]["kind"] == "external-kill"  # fixture sanity
    rec = cc(returncode=None, target="x/test_y.py", observation=obs)
    assert rec["reason"] == "probe_incomplete"
    assert rec["outcome"] == "fail"
    assert "crash" not in str(rec["summary"]).lower()


def test_ordinary_exit_is_probe_incomplete_not_crash():
    """F14/P11C-0198-012: a unit that exited without completing has unknown
    completion -- probe_incomplete, never a crash."""
    from pkcs11_check.core.file_runner import crash_classification as cc
    from pkcs11_check.core.process_observation import build_process_observation

    obs = build_process_observation("x/test_y.py", "unit", 0, 1)
    assert obs["termination"]["kind"] == "exit"  # fixture sanity
    rec = cc(returncode=1, target="x/test_y.py", observation=obs)
    assert rec["reason"] == "probe_incomplete"
    assert "crash" not in str(rec["summary"]).lower()


def test_unknown_termination_is_probe_incomplete_not_crash():
    """F14/P11C-0198-012: no termination facts at all is unresolved, not a crash."""
    from pkcs11_check.core.file_runner import crash_classification as cc

    rec = cc(returncode=None, target="x/test_y.py")
    assert rec["reason"] == "probe_incomplete"
    assert rec["outcome"] == "fail"
    assert "crash" not in str(rec["summary"]).lower()


def test_abrupt_exit_is_crash_evidence():
    """F14/P11C-0198-012: a marker-positive abrupt self-exit is crash evidence
    with its own summary -- the module terminated its host from inside the call."""
    from pkcs11_check.core.file_runner import crash_classification as cc
    from pkcs11_check.core.process_observation import (
        SUBPROCESS_ABRUPT_EXIT_MARKER,
        build_process_observation,
    )

    obs = build_process_observation(
        "x/test_y.py", "unit", 0, 3, stderr=f"module output\n{SUBPROCESS_ABRUPT_EXIT_MARKER}:3\n"
    )
    assert obs["termination"]["kind"] == "abrupt_exit"  # fixture sanity
    rec = cc(returncode=3, target="x/test_y.py", observation=obs)
    assert rec["reason"] == "crash"
    assert rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH"
    assert "terminated itself" in str(rec["summary"])
    assert rec["actual_ckr"] is None
    assert rec["expected_ckr"] is None


def test_termination_kinds_map_to_distinct_reasons_and_summaries():
    """F14/P11C-0198-012: the seven termination kinds each get their own
    (reason, summary) identity -- nothing merges or shares a description."""
    from pkcs11_check.core.file_runner import crash_classification as cc
    from pkcs11_check.core.process_observation import (
        SUBPROCESS_ABRUPT_EXIT_MARKER,
        build_process_observation,
    )

    target = "x/test_y.py"
    records = {
        "timeout": cc(returncode=None, target=target, timed_out=True),
        "signal": cc(returncode=-11, target=target),
        "exception": cc(returncode=0xC0000005, target=target),
        "external-kill": cc(
            returncode=None,
            target=target,
            observation=build_process_observation(target, "unit", 0, None, external_kill=True),
        ),
        "abrupt_exit": cc(
            returncode=3,
            target=target,
            observation=build_process_observation(
                target, "unit", 0, 3, stderr=f"{SUBPROCESS_ABRUPT_EXIT_MARKER}:3"
            ),
        ),
        "exit": cc(
            returncode=1,
            target=target,
            observation=build_process_observation(target, "unit", 0, 1),
        ),
        "unknown": cc(returncode=None, target=target),
    }
    identities = {(str(r["reason"]), str(r["summary"])) for r in records.values()}
    assert len(identities) == 7
    for rec in records.values():
        assert rec["actual_ckr"] is None  # no fabricated CKR on any path
        assert rec["expected_ckr"] is None
