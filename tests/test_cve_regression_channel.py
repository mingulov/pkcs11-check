"""CVE regression probe: wrong-output roundtrips ride the provider channel.

A mismatched RSA roundtrip in the crash-safety probe must surface as a
wrong_result provider finding, not pass silently behind the OK:/ERROR:
crash-only contract. Clean errors without a finding still pass.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check import classification as C
from pkcs11_check.testcases._probes import cve_regression as probe_mod
from pkcs11_check.testcases._probes._emit import PROVIDER_FINDING_MARKER
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.security import test_cve_regression


def _wrong_pt_ctx() -> ProbeContext:
    class _Raw:
        def C_CloseSession(self, *args: Any) -> int:  # noqa: N802
            # Must match the PKCS#11 entry-point name the probe calls.
            return 0

        def C_Finalize(self, *args: Any) -> int:  # noqa: N802
            # Must match the PKCS#11 entry-point name the probe calls.
            return 0

    return ProbeContext(
        raw=cast(Any, _Raw()),
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )


def test_wrong_plaintext_emits_provider_finding(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(probe_mod, "gen_rsa_keypair", lambda *a, **k: (11, 12))
    monkeypatch.setattr(probe_mod, "encrypt_single", lambda *a, **k: b"ct")
    monkeypatch.setattr(probe_mod, "decrypt_single", lambda *a, **k: b"WRONG-PLAINTEXT!")
    monkeypatch.setattr(probe_mod, "destroy_quietly", lambda *a, **k: None)
    probe_mod._run_rsa_encrypt_decrypt(_wrong_pt_ctx(), {})
    out = capsys.readouterr().out
    assert "ERROR:" in out
    marker = next(line for line in out.splitlines() if line.startswith(PROVIDER_FINDING_MARKER))
    payload = json.loads(marker.removeprefix(PROVIDER_FINDING_MARKER))
    assert payload["reason"] == "wrong_result"
    assert payload["kind"] == "crypto"
    assert payload["operation"] == "C_Decrypt"
    assert payload["mechanism"] == "CKM_RSA_PKCS"


def _cfg() -> Any:
    return SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)


def test_parent_records_wrong_result_on_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    C.clear()
    stdout = (
        PROVIDER_FINDING_MARKER
        + json.dumps(
            {
                "schema": 1,
                "reason": "wrong_result",
                "kind": "crypto",
                "operation": "C_Decrypt",
                "mechanism": "CKM_RSA_PKCS",
                "detail": "decrypted plaintext does not match",
            }
        )
        + "\nERROR: AssertionError: roundtrip mismatch\n"
    )

    def _capture(probe: str, params: dict[str, object], **_kw: object) -> ProbeResult:
        return ProbeResult(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(test_cve_regression, "run_probe", _capture)
    with pytest.raises(pytest.fail.Exception):
        test_cve_regression.TestDecryptCrashRegression().test_rsa_encrypt_decrypt_no_crash(_cfg())
    rec = C.get_records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.operation == "C_Decrypt"
    assert rec.mechanism == "CKM_RSA_PKCS"


def test_parent_passes_on_clean_error_without_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.clear()

    def _capture(probe: str, params: dict[str, object], **_kw: object) -> ProbeResult:
        return ProbeResult(returncode=0, stdout="ERROR: CkrError: keygen refused\n", stderr="")

    monkeypatch.setattr(test_cve_regression, "run_probe", _capture)
    test_cve_regression.TestDecryptCrashRegression().test_rsa_encrypt_decrypt_no_crash(_cfg())
