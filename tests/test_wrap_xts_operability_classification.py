"""Meta-tests: KW/KWP and XTS KAT runners classify via the operability probe.

Same effect-based model as the AEAD runners (triage H2): a canonical
known-answer operation per (mechanism, direction) decides whether clean vector
errors are "advertised but not operational" (xfail), parameter-shape deviations
(xfail), or findings (re-raised). Valid-vector integrity rejections on unwrap
are findings only when canonical decrypt works.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.acvp.aes import test_wrap as wrap
from pkcs11_check.testcases.acvp.aes import test_xts as xts


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


class _Session:
    raw = object()
    sh = 1

    @staticmethod
    def has_mechanism(name: str) -> bool:
        return name in ("AES_KEY_WRAP", "AES_KEY_WRAP_KWP", "AES_XTS")


def _general_error(*_a: Any, **_k: Any) -> bytes:
    raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))


def _canonical_kw_ct() -> bytes:
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap

    return aes_key_wrap(wrap.PROBE_KEK, wrap.PROBE_KW_PT)


def test_kw_wrap_wholly_non_operational_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wrap, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(wrap, "encrypt_single", _general_error)

    vec = {"key": bytes(16), "pt": bytes(16), "ct_expected": bytes(24)}
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        wrap.test_acvp_aes_kw_wrap(_Session(), "tc1", vec)


def test_kw_unwrap_valid_reject_with_dead_decrypt_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid KW vector rejected with an integrity-style CKR is only a finding
    if canonical decrypt works; a dead decrypt path is not-operational."""
    monkeypatch.setattr(wrap, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(wrap, "decrypt_single", _general_error)
    monkeypatch.setattr(wrap, "encrypt_single", _general_error)

    vec = {"key": bytes(16), "ct": bytes(24), "pt_expected": bytes(16), "test_passed": True}
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        wrap.test_acvp_aes_kw_unwrap(_Session(), "tc1", vec)


def test_kw_unwrap_valid_reject_with_working_decrypt_is_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wrap, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda *a, **k: None)
    canonical_ct = _canonical_kw_ct()

    def _decrypt(_raw: Any, _sh: int, _key: int, _mech: Any, ct: bytes, **_k: Any) -> bytes:
        if ct == canonical_ct:
            return wrap.PROBE_KW_PT
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(wrap, "decrypt_single", _decrypt)

    vec = {"key": bytes(16), "ct": bytes(24), "pt_expected": bytes(16), "test_passed": True}
    with pytest.raises(pytest.fail.Exception, match="valid KW vector rejected"):
        wrap.test_acvp_aes_kw_unwrap(_Session(), "tc1", vec)


def test_kw_unwrap_invalid_reject_on_dead_mech_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid KW ciphertext rejection on a NOT_OPERATIONAL mechanism is a vacuous xfail.

    When the canonical probe also refuses (the mechanism is dead), the invalid-ciphertext
    rejection proves nothing — the module rejected both without evaluating the input.
    The runner must downgrade to xfail("vacuous reject ...").

    The complementary case — OPERATIONAL mechanism rejecting an invalid KW ciphertext
    stays a genuine pass — is covered by ``test_kw_unwrap_invalid_reject_on_live_mech_passes``
    below.
    """
    monkeypatch.setattr(wrap, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda *a, **k: None)
    # Both the vector decrypt and the canonical probe hit _general_error
    # -> NOT_OPERATIONAL -> vacuous reject.
    monkeypatch.setattr(wrap, "decrypt_single", _general_error)

    vec = {"key": bytes(16), "ct": bytes(24), "pt_expected": bytes(16), "test_passed": False}
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        wrap.test_acvp_aes_kw_unwrap(_Session(), "tc1", vec)


def test_kw_unwrap_invalid_reject_on_live_mech_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPERATIONAL AES-KW mechanism rejecting an invalid ciphertext is a genuine pass.

    When the canonical probe succeeds, the module demonstrably evaluates the input;
    an invalid-ciphertext rejection is the correct outcome and must not be downgraded.
    """
    monkeypatch.setattr(wrap, "_import_aes_key", lambda *a, **k: 7)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda *a, **k: None)
    canonical_ct = _canonical_kw_ct()
    calls: dict[str, int] = {"n": 0}

    def _decrypt_live(_raw: Any, _sh: int, _key: int, _mech: Any, ct: bytes, **_kw: Any) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:
            # First call: vector under test — reject the invalid ciphertext.
            raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))
        # Second call: canonical probe — succeed, proving OPERATIONAL.
        if ct == canonical_ct:
            return wrap.PROBE_KW_PT
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(wrap, "decrypt_single", _decrypt_live)
    monkeypatch.setattr(wrap, "encrypt_single", lambda *a, **k: canonical_ct)

    vec = {"key": bytes(16), "ct": bytes(24), "pt_expected": bytes(16), "test_passed": False}
    # Returns normally (no xfail) = PASS: rejection by an operational mechanism is genuine.
    wrap.test_acvp_aes_kw_unwrap(_Session(), "tc1", vec)


def test_xts_encrypt_wholly_non_operational_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # The canonical operability probe still uses raw import_secret_key; the test
    # body uses the negotiated variant. Stub both so whichever path runs is covered.
    monkeypatch.setattr(xts, "import_secret_key", lambda *a, **k: 7)
    monkeypatch.setattr(xts, "import_secret_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(xts, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(xts, "encrypt_single", _general_error)

    vec = {
        "key": bytes(32),
        "pt": bytes(32),
        "ct_expected": bytes(32),
        "tweak": bytes(16),
    }
    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        xts.test_acvp_aes_xts_encrypt(_Session(), "tc1", vec)
