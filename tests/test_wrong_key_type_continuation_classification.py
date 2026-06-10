"""Classification meta-tests for wrong-key-type continuation hardening.

A module that is lenient at ``C_SignInit``/``C_VerifyInit`` with a wrong key
type (returns ``CKR_OK``) but then SAFELY refuses at the terminal
``C_Sign``/``C_Verify`` (clean ``CK_RV``, no produced output, no crash) leaves
no usable operation behind -- which is the test's own documented contract
("must not leave a usable operation behind"). Per the classification model that
is a recorded deviation (xfail), not a hard fail. Only a *produced* signature (a
usable wrong-key operation = Type-C self-contradiction) or a crash is a genuine
break (fail).

softhsm2 is the one provider that exhibits the lenient-init-but-safe-op path
(``C_SignInit(CKM_ECDSA, RSA)`` -> ``CKR_OK``; ``C_Sign`` -> ``CKR_GENERAL_ERROR``);
kryoptic/NSS/opencryptoki reject at init (pass).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.testcases.ckr import test_ckr_wrong_key_type_hardening as hardening
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

# --- outer classifier markers ---------------------------------------------


def test_deviation_marker_is_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception, match="lenient init"):
        assert_ckr_subprocess_ok(
            0,
            "DEVIATION_XFAIL:C_SignInit accepted (CKR_OK) but C_Sign safely refused "
            "with CKR_GENERAL_ERROR -- lenient init, no usable operation\n",
            "",
            context="wrong-key continuation",
        )


def test_break_marker_is_fail() -> None:
    with pytest.raises(pytest.fail.Exception, match="usable wrong-key operation"):
        assert_ckr_subprocess_ok(
            0,
            "BREAK:C_SignInit returned CKR_OK and C_Sign PRODUCED a signature -- "
            "usable wrong-key operation\n",
            "",
            context="wrong-key continuation",
        )


def test_ok_marker_passes() -> None:
    assert_ckr_subprocess_ok(
        0,
        "OK:C_SignInit rejected wrong RSA key for ECDSA: CKR_KEY_TYPE_INCONSISTENT\n",
        "",
        context="wrong-key continuation",
    )


def test_crash_is_fail() -> None:
    with pytest.raises(pytest.fail.Exception, match="crashed with signal 11"):
        assert_ckr_subprocess_ok(-11, "", "segfault", context="wrong-key continuation")


# --- inner scripts discriminate by effect ---------------------------------


def test_sign_script_discriminates() -> None:
    script = hardening._SIGN_WITH_RSA_UNDER_ECDSA
    assert "BREAK:" in script
    assert "DEVIATION_XFAIL:" in script
    assert "C_Sign(" in script
    compile(script, "<sign-probe>", "exec")


def test_verify_script_discriminates() -> None:
    script = hardening._VERIFY_WITH_RSA_UNDER_ECDSA
    assert "BREAK:" in script
    assert "DEVIATION_XFAIL:" in script
    assert "C_Verify(" in script
    compile(script, "<verify-probe>", "exec")


# --- end-to-end through the test bodies -----------------------------------


def _wire(monkeypatch: pytest.MonkeyPatch, *, rc: int, stdout: str) -> None:
    monkeypatch.setattr(hardening, "run_with_coverage", lambda *a, **k: (rc, stdout, ""))
    monkeypatch.setattr(hardening, "_require_rsa_sign_verify_setup", lambda rs: None)
    monkeypatch.setattr(hardening, "_preamble", lambda cfg: "")


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(module="/fake/p11.so", pin=None)


def _rs() -> SimpleNamespace:
    return SimpleNamespace(has_mechanism=lambda name: True)


def test_sign_continuation_lenient_safe_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, rc=0, stdout="DEVIATION_XFAIL:lenient init, no usable operation\n")
    with pytest.raises(pytest.xfail.Exception):
        hardening.TestWrongAsymmetricKeyTypeContinuation().test_wrong_asymmetric_key_type_sign_continuation_no_crash(
            _rs(), _cfg()
        )


def test_sign_continuation_break_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, rc=0, stdout="BREAK:usable wrong-key operation\n")
    with pytest.raises(pytest.fail.Exception):
        hardening.TestWrongAsymmetricKeyTypeContinuation().test_wrong_asymmetric_key_type_sign_continuation_no_crash(
            _rs(), _cfg()
        )


def test_verify_continuation_lenient_safe_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, rc=0, stdout="DEVIATION_XFAIL:lenient init, no usable operation\n")
    with pytest.raises(pytest.xfail.Exception):
        hardening.TestWrongAsymmetricKeyTypeContinuation().test_wrong_asymmetric_key_type_verify_continuation_no_crash(
            _rs(), _cfg()
        )
