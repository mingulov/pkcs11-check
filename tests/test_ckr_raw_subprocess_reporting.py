"""Meta-tests for raw CKR subprocess result reporting."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases._subprocess_trace import (
    drain_subprocess_rv_trace,
)
from pkcs11_check.testcases.ckr import (
    test_ckr_dual,
    test_ckr_fault_inject,
    test_ckr_null_params,
    test_ckr_raw_args_bad,
    test_ckr_raw_multipart,
    test_ckr_raw_state,
    test_ckr_universal,
    test_ckr_v30_raw,
    test_ckr_v32_raw,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

RawCheck = Callable[[int, str, str, str], None]


def _assert_child_script_compiles(script: str) -> None:
    compile(script, "<pkcs11-check-child-script>", "exec")


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def _raise_function_not_supported(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )


@pytest.mark.parametrize(
    "check",
    [test_ckr_v30_raw._check, test_ckr_v32_raw._check],
)
def test_raw_check_reports_signal_as_crash(check: RawCheck) -> None:
    """Negative subprocess return codes are crash findings."""
    with pytest.raises(pytest.fail.Exception, match="subprocess crashed with signal 11"):
        check(-11, "", "segmentation fault", "C_Test")


@pytest.mark.parametrize(
    "check",
    [test_ckr_v30_raw._check, test_ckr_v32_raw._check],
)
def test_raw_check_reports_positive_exit_as_subprocess_failure(check: RawCheck) -> None:
    """Assertion failures inside the child process are not crash findings."""
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        check(1, "CKR:0x00000007", "AssertionError: unexpected CKR", "C_Test")


@pytest.mark.parametrize(
    "module",
    [test_ckr_v30_raw, test_ckr_v32_raw],
)
def test_versioned_raw_subprocesses_emit_and_record_rv_trace(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> None:
    """Hand-rolled v3.x CKR subprocesses must feed failed reports with child traces."""
    marker = 'P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Test","rv":48,"rv_name":"CKR_DEVICE_ERROR"}]'
    scripts: list[str] = []

    def run_child(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        scripts.append(args[2])
        return subprocess.CompletedProcess(args=args, returncode=1, stdout=marker, stderr="")

    monkeypatch.setattr(module.subprocess, "run", run_child)

    module._run("/fake/p11.so", None, "print('OK')\n")

    assert len(scripts) == 1
    _assert_child_script_compiles(scripts[0])
    assert "P11_RV_TRACE_JSON:" in scripts[0]
    assert "raw.enable_rv_trace(" in scripts[0]
    assert drain_subprocess_rv_trace() == [
        {"i": 0, "fn": "C_Test", "rv": 48, "rv_name": "CKR_DEVICE_ERROR"}
    ]


def test_ckr_subprocess_helper_reports_positive_exit_as_child_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        assert_ckr_subprocess_ok(
            1,
            "",
            "AssertionError: setup failed",
            context="CKR setup probe",
        )


def test_ckr_subprocess_helper_converts_setup_marker_to_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception, match="AES key generation rejected"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            "",
            context="CKR setup probe",
        )


def test_fault_proxy_subprocesses_emit_rv_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fault-proxy CKR subprocesses must preserve setup-xfail child traces."""
    scripts: list[str] = []

    def _run_subprocess(args: list[str], **_kwargs: Any) -> SimpleNamespace:
        scripts.append(args[2])
        return SimpleNamespace(
            returncode=0,
            stdout="OK:encrypt_decrypt_roundtrip\n",
            stderr="",
        )

    monkeypatch.setattr(test_ckr_fault_inject, "_skip_if_no_proxy", lambda: None)
    monkeypatch.setattr(test_ckr_fault_inject, "_PROXY_PATH", "/tmp/fault-proxy.so")
    monkeypatch.setattr(test_ckr_fault_inject.subprocess, "run", _run_subprocess)

    test_ckr_fault_inject.TestFaultProxyBasic().test_proxy_encrypt_decrypt(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(scripts) == 1
    _assert_child_script_compiles(scripts[0])
    assert "P11_RV_TRACE_JSON:" in scripts[0]
    assert "enable_rv_trace(" in scripts[0]


def test_double_encrypt_init_dispatches_state_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The double-EncryptInit state test dispatches the operation-state probe.

    (rv-trace preservation is now handled + covered in the shared ``probe_main``
    infra, so the legacy in-script rv-trace assertions are dropped here.)
    """
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="CKR:0x00000000\nOK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_state, "run_probe", fake_run_probe)

    test_ckr_raw_state.TestOperationActive().test_double_encrypt_init(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_raw_state"
    assert params["probe"] == "double_encrypt_init"


def test_ckr_multipart_subprocesses_emit_rv_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multipart raw subprocess tests must preserve failed child traces."""
    scripts: list[str] = []

    def _run_subprocess(args: list[str], **_kwargs: Any) -> SimpleNamespace:
        scripts.append(args[2])
        return SimpleNamespace(returncode=0, stdout="CKR:0x00000091\nOK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_multipart.subprocess, "run", _run_subprocess)

    test_ckr_raw_multipart._run_raw_test("/tmp/provider.so", None, 'print("OK")\n')

    assert len(scripts) == 1
    _assert_child_script_compiles(scripts[0])
    assert "P11_RV_TRACE_JSON:" in scripts[0]
    assert "enable_rv_trace(" in scripts[0]


def test_ckr_null_result_positive_exit_records_child_trace() -> None:
    """Parent-side NULL probe failures must retain child RV trace output."""
    marker = (
        'P11_RV_TRACE_JSON:[{"i":0,"fn":"C_OpenSession","rv":176,"rv_name":"CKR_SESSION_COUNT"}]'
    )

    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        test_ckr_null_params._check_null_result("C_GenerateRandom", 1, marker, "")

    assert drain_subprocess_rv_trace() == [
        {"i": 0, "fn": "C_OpenSession", "rv": 176, "rv_name": "CKR_SESSION_COUNT"}
    ]


def test_ckr_null_result_parses_ckr_before_trace_marker() -> None:
    """Trace marker lines appended to stdout must not break CKR parsing."""
    test_ckr_null_params._check_null_result(
        "C_GetInfo",
        0,
        'CKR:0x00000007\nP11_RV_TRACE_JSON:[{"i":0,"fn":"C_GetInfo","rv":7}]',
        "",
    )
    assert drain_subprocess_rv_trace() == [{"i": 0, "fn": "C_GetInfo", "rv": 7}]


def test_ckr_subprocess_helper_requires_ok_marker() -> None:
    with pytest.raises(pytest.fail.Exception, match="did not emit an OK marker"):
        assert_ckr_subprocess_ok(0, "CKR:0x00000000\n", "", context="CKR setup probe")


def test_universal_fault_proxy_subprocess_emits_rv_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Universal fault-proxy subprocess must preserve child traces."""
    scripts: list[str] = []

    def _run_subprocess(args: list[str], **_kwargs: Any) -> SimpleNamespace:
        scripts.append(args[2])
        return SimpleNamespace(returncode=0, stdout="OK:DEVICE_REMOVED\n", stderr="")

    monkeypatch.setattr(Path, "exists", lambda _self: True)
    monkeypatch.setattr(test_ckr_universal.subprocess, "run", _run_subprocess)

    test_ckr_universal.TestUniversalRealTriggers().test_device_removed_via_fault_proxy(
        SimpleNamespace(module="/tmp/provider.so")
    )

    assert len(scripts) == 1
    _assert_child_script_compiles(scripts[0])
    assert "P11_RV_TRACE_JSON:" in scripts[0]
    assert "enable_rv_trace(" in scripts[0]


def test_raw_args_bad_setup_marker_is_xfail() -> None:
    """NULL-mechanism rows should classify failed setup key generation."""
    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ckr_raw_args_bad._assert_ok(
            0,
            "SETUP_XFAIL:AES setup unavailable: CKR_FUNCTION_NOT_SUPPORTED\n",
            "",
            "C_EncryptInit(NULL mech)",
        )


def test_raw_args_bad_encrypt_null_mech_dispatches_encrypt_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The encrypt-init NULL-mechanism test dispatches the encrypt-init probe."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_args_bad, "run_probe", fake_run_probe)

    test_ckr_raw_args_bad.TestArgsBadNullPointers().test_encrypt_init_null_mechanism(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_raw_args_bad"
    assert params["probe"] == "encrypt_init"


def test_raw_args_bad_generate_key_null_mech_dispatches_generate_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generate-key NULL-mechanism test dispatches the generate-key probe."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_args_bad, "run_probe", fake_run_probe)

    test_ckr_raw_args_bad.TestArgsBadNullPointers().test_generate_key_null_mechanism(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_raw_args_bad"
    assert params["probe"] == "generate_key"


def test_ckr_dual_reports_positive_subprocess_exit_as_child_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR operation-state child assertion exits must not be labelled crashes."""

    def fake_run_probe(probe: str, params: Any, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="AssertionError: setup failed",
        )

    monkeypatch.setattr(test_ckr_dual, "run_probe", fake_run_probe)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        test_case.test_encrypt_without_init(SimpleNamespace(module="/fake/p11.so", pin=None))


def test_ckr_dual_encrypt_wrapper_xfails_advertised_aes_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="128-bit key generation"):
        test_ckr_dual.TestOperationStateWrapper().test_encrypt_twice_succeeds(rs)


def test_ckr_dual_sign_then_encrypt_xfails_advertised_aes_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_rsa_keypair",
        lambda *_args, **_kwargs: (10, 11),
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", lambda *_args, **_kwargs: (10, 11))
    monkeypatch.setattr(test_ckr_dual, "sign_single", lambda *_args, **_kwargs: b"s" * 256)
    monkeypatch.setattr(test_ckr_dual, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_KEY_GEN", "RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="128-bit key generation"):
        test_ckr_dual.TestOperationStateWrapper().test_sign_then_encrypt(rs)


def test_encrypt_without_init_dispatches_encrypt_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The encrypt-without-init test dispatches its own probe (no AES key setup)."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK:encrypt_without_init\n", stderr="")

    monkeypatch.setattr(test_ckr_dual, "run_probe", fake_run_probe)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    test_case.test_encrypt_without_init(SimpleNamespace(module="/fake/p11.so", pin=None))

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_dual"
    assert params["probe"] == "encrypt_without_init"


def test_double_digest_init_dispatches_digest_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The double-DigestInit test dispatches the operation-active probe."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK:double_digest_init_active\n", stderr="")

    monkeypatch.setattr(test_ckr_dual, "run_probe", fake_run_probe)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    test_case.test_double_digest_init_via_subprocess(
        SimpleNamespace(module="/fake/p11.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_dual"
    assert params["probe"] == "double_digest_init"
