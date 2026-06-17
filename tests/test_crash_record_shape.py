from pkcs11_check.core.file_runner import crash_classification


def test_sigsegv_crash_record():
    rec = crash_classification(returncode=-11, target="x/test_y.py")
    assert rec["reason"] == "crash" and rec["outcome"] == "fail"
    assert rec["severity"] == "HIGH" and rec["detail"]["signal"] == "SIGSEGV"


def test_sigabrt_crash_record():
    rec = crash_classification(returncode=-6, target="x/test_y.py")
    assert rec["detail"]["signal"] == "SIGABRT"


def test_timeout_record():
    rec = crash_classification(returncode=None, target="x/test_y.py", timed_out=True)
    assert rec["detail"]["mode"] == "timeout"
    assert rec["reason"] == "crash" and rec["outcome"] == "fail"
