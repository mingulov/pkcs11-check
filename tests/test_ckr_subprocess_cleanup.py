from __future__ import annotations

from pathlib import Path

from pkcs11_check.testcases.ckr import _subprocess


def test_ckr_subprocess_cleanup_registers_idempotent_session_cleanup() -> None:
    assert hasattr(_subprocess, "ckr_subprocess_cleanup_setup")
    script = _subprocess.ckr_subprocess_cleanup_setup(session_var="sess")

    assert "def _p11check_cleanup_session():" in script
    assert "_p11check_cleaned = False" in script
    assert "global _p11check_cleaned" in script
    assert "if _p11check_cleaned:" in script
    assert "_p11check_cleaned = True" in script
    assert "raw.C_CloseSession(sess)" in script
    assert "raw.C_Finalize(None)" in script
    assert "import atexit as _p11check_atexit" in script
    assert "_p11check_atexit.register(_p11check_cleanup_session)" in script

    cleanup_pos = script.index("def _p11check_cleanup_session():")
    register_pos = script.index("_p11check_atexit.register(_p11check_cleanup_session)")
    assert register_pos > cleanup_pos


def test_destructive_ckr_subprocesses_use_registered_cleanup() -> None:
    source = Path("src/pkcs11_check/testcases/ckr/test_ckr_destructive.py").read_text()

    assert "ckr_subprocess_rv_trace_setup" in source
    assert source.count("ckr_subprocess_cleanup_setup()") >= 4
    assert 'globals().get("_p11check_cleanup_session")' in source
    assert "{ckr_subprocess_cleanup_setup()}" not in source
