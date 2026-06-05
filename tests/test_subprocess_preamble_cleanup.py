from __future__ import annotations

from pkcs11_check.testcases._subprocess_preamble import subprocess_session_preamble


def test_subprocess_session_preamble_registers_idempotent_cleanup() -> None:
    script = subprocess_session_preamble("/tmp/pkcs11.so")

    assert "_p11check_cleaned = False" in script
    assert "global _p11check_cleaned" in script
    assert "if _p11check_cleaned:" in script
    assert "_p11check_cleaned = True" in script
    assert "_atexit.register(cleanup)" in script

    cleanup_pos = script.index("def cleanup():")
    register_pos = script.index("_atexit.register(cleanup)")
    assert register_pos > cleanup_pos
