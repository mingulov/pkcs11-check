"""Tests for raw subprocess runner diagnostics."""

from __future__ import annotations

from typing import Any

from pkcs11_check.testcases import _raw_subprocess
from pkcs11_check.testcases._subprocess_trace import drain_subprocess_rv_trace


def test_run_raw_script_embeds_rv_trace_marker_emitter(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(args: list[str], **kwargs: Any) -> _Result:
        captured["script"] = args[2]
        captured["env"] = kwargs.get("env")
        return _Result()

    monkeypatch.setattr(_raw_subprocess.subprocess, "run", _fake_run)

    _raw_subprocess.run_raw_script(
        "from pkcs11_check.raw.api import RawPKCS11\n"
        "raw = RawPKCS11.from_lib('/path/to/module.so')\n",
        "print('OK')\n",
    )

    assert "PKCS11_CHECK_RV_TRACE" in captured["script"]
    assert "raw.enable_rv_trace(" in captured["script"]
    assert "P11_RV_TRACE_JSON:" in captured["script"]


def test_run_raw_script_records_child_rv_trace_marker(monkeypatch: Any) -> None:
    marker = 'P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Sign","rv":0,"rv_name":"CKR_OK"}]'

    class _Result:
        returncode = 0
        stdout = marker
        stderr = ""

    def _fake_run(args: list[str], **kwargs: Any) -> _Result:
        return _Result()

    monkeypatch.setattr(_raw_subprocess.subprocess, "run", _fake_run)

    _raw_subprocess.run_raw_script("raw = object()\n", "print('OK')\n")

    assert drain_subprocess_rv_trace() == [{"i": 0, "fn": "C_Sign", "rv": 0, "rv_name": "CKR_OK"}]


def test_run_raw_script_registers_cleanup_before_script_body(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(args: list[str], **kwargs: Any) -> _Result:
        captured["script"] = args[2]
        return _Result()

    monkeypatch.setattr(_raw_subprocess.subprocess, "run", _fake_run)

    _raw_subprocess.run_raw_script(
        "raw = object()\nhSession = 1\n",
        "import sys\nsys.exit(0)\n",
        cleanup="raw.C_CloseSession(hSession)\nraw.C_Finalize(None)\n",
    )

    script = captured["script"]
    assert "def _p11check_cleanup_raw_subprocess():" in script
    assert "_p11check_atexit.register(_p11check_cleanup_raw_subprocess)" in script
    assert "sys.exit(0)" in script
    register_call = "_p11check_atexit.register(_p11check_cleanup_raw_subprocess)"
    assert script.index(register_call) < script.index("sys.exit(0)")
    assert "        raw.C_CloseSession(hSession)\n    except Exception:" in script
    assert "        raw.C_Finalize(None)\n    except Exception:" in script
    assert script.index("        raw.C_CloseSession(hSession)") < script.index(
        "        raw.C_Finalize(None)"
    )
