"""Regression tests for the F7 security-policy attribute-access migration.

Covers the four attack-simulation suites migrated in this slice:
``test_api_security.py``, ``test_cve_regression.py``, ``test_tookan.py`` and
``test_unwrap_reimport.py``.  Every test drives the real, migrated production
test method directly (via monkeypatched provider primitives) so the assertion
is on *runtime behavior*, not on the analyzer's diagnostic count.

Three behavior classes are proven per site class:

  1. Red -> green: an omitted attribute produces a structured record (correct
     ``reason``, ``operation == "C_GetAttributeValue"``, ``mechanism is None``,
     ``spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"``) instead of a
     ``KeyError`` crash or a silently swallowed ``None``.
  2. Continuation: an omission does not prevent independent work in the same
     test, and object handles are still destroyed.
  3. Present-but-malformed / missing-sibling-does-not-mask: where a proven
     policy violation is independently evidenced, a missing sibling attribute
     never downgrades the hard finding.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases.security import test_api_security as api_sec
from pkcs11_check.testcases.security import test_cve_regression as cve
from pkcs11_check.testcases.security import test_tookan as tookan
from pkcs11_check.testcases.security import test_unwrap_reimport as reimport
from tests._attribute_access_guard import analyze_file

_SECURITY_DIR = Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "security"
_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    """Reset the recorder and install the stale-mechanism scaffold.

    ``C.clear()`` zeroes ``_active_mechanism``, which would make every
    ``mechanism is None`` assertion in this file pass vacuously.  Installing a
    stale mechanism for EVERY test means a readback record that wrongly inherits
    the ambient mechanism is caught, not silently accepted.
    """
    C.clear()
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    yield
    C.clear()


_OUTCOMES = (pytest.fail.Exception, pytest.xfail.Exception, pytest.skip.Exception)


def _expect_hard_fail(call: Callable[[], None]) -> None:
    """Run a production probe body and require a hard ``fail`` outcome.

    ``pytest.raises(pytest.fail.Exception)`` is NOT enough: an imperative
    ``pytest.xfail()`` raised by the body would propagate, pytest would mark THIS
    test xfailed, and every assertion below would be skipped -- so a downgrade of
    the finding to an xfail would survive silently.
    """
    try:
        call()
    except pytest.fail.Exception:
        return
    except _OUTCOMES as exc:  # pragma: no cover - mutation guard
        pytest.fail(f"expected a hard fail, got {type(exc).__name__}: {exc}")
    pytest.fail("expected a hard fail, but the probe completed")


def _expect_completion(call: Callable[[], None]) -> None:
    """Run a production probe body and require it to complete with no outcome raised.

    Guards against an extra terminal record (a second classify() for one
    observation) silently xfailing the test instead of failing it.
    """
    try:
        call()
    except _OUTCOMES as exc:  # pragma: no cover - mutation guard
        pytest.fail(f"expected the probe to complete, got {type(exc).__name__}: {exc}")


def _session(**extra: Any) -> SimpleNamespace:
    defaults: dict[str, Any] = {"raw": object(), "sh": 1}
    defaults.update(extra)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Analyzer-clean prevention guards (one per owned production file).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "test_api_security.py",
        "test_cve_regression.py",
        "test_tookan.py",
        "test_unwrap_reimport.py",
    ],
)
def test_security_policy_files_are_analyzer_clean(filename: str) -> None:
    """The F7 security-policy migration remains covered by the prevention gate."""
    assert analyze_file(_SECURITY_DIR / filename) == []


# ---------------------------------------------------------------------------
# test_api_security.py
# ---------------------------------------------------------------------------


def test_encrypt_disabled_missing_readback_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single dependent check: a missing CKA_ENCRYPT readback records and returns."""
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 501)
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_completion(
        lambda: api_sec.TestKeyUsageRestrictions().test_encrypt_disabled_removes_capability(
            _session()
        )
    )

    assert destroyed == [501]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.kind == "policy"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF


def test_decrypt_only_key_missing_decrypt_does_not_mask_encrypt_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two independent checks: a missing CKA_DECRYPT must not hide a CKA_ENCRYPT break."""
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 502)
    # CKA_DECRYPT omitted; CKA_ENCRYPT present but WRONG (True instead of False).
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {CKA_ENCRYPT: True})
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(AssertionError):
        api_sec.TestKeyUsageRestrictions().test_decrypt_only_key(_session())

    # Cleanup still ran despite the AssertionError raised by the independent
    # CKA_ENCRYPT check.
    assert destroyed == [502]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_sensitive_value_absent_is_a_silent_pass_not_a_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_VALUE correctly absent on a SENSITIVE key must not be recorded as a deviation."""
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 503)
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_completion(
        lambda: api_sec.TestSensitiveExtraction().test_sensitive_key_value_not_readable(_session())
    )

    assert destroyed == [503]
    # The secure default (protection held) is not a deviation: nothing recorded.
    assert C.get_records() == []


def test_sensitive_value_present_is_a_hard_fail_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_VALUE readable on a SENSITIVE key is the finding: a structured hard fail."""
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 504)
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"leaked"})
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_hard_fail(
        lambda: api_sec.TestSensitiveExtraction().test_sensitive_key_value_not_readable(_session())
    )

    assert destroyed == [504]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "policy"
    assert records[0].operation == "C_GetAttributeValue"


def _patch_wrap_decrypt_oracle(
    monkeypatch: pytest.MonkeyPatch, attrs: dict[Any, Any], destroyed: list[int]
) -> None:
    monkeypatch.setattr(api_sec, "_skip_unless_mechanism", lambda *_a, **_k: None)
    monkeypatch.setattr(api_sec, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(api_sec, "_raw_gen_aes_key", lambda *_a, **_k: 511)  # dual_key_h
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 512)  # target_h
    monkeypatch.setattr(api_sec, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(api_sec, "decrypt_single", lambda *_a, **_k: b"0123456789abcdef")
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))


def test_wrap_decrypt_oracle_missing_claim_readback_stays_a_hard_policy_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recovered key material stays a hard finding when the claim readback is absent.

    The module ACCEPTED a ``CKA_EXTRACTABLE=False`` template at C_GenerateKey;
    that acceptance is the claim.  An unreadable ``CKA_EXTRACTABLE`` must not
    downgrade a proven wrap-then-decrypt key extraction to an xfail/LOW.
    """
    destroyed: list[int] = []
    _patch_wrap_decrypt_oracle(monkeypatch, {}, destroyed)  # CKA_EXTRACTABLE gone

    _expect_hard_fail(
        lambda: api_sec.TestWrapDecryptOracle().test_wrap_decrypt_combination_prevented(_session())
    )

    assert destroyed == [512, 511]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"


def test_wrap_decrypt_oracle_observed_extractable_true_is_an_honest_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OBSERVED CKA_EXTRACTABLE=True is a real non-claim: xfail, not a hard fail.

    This is the other half of the oracle -- the creation-acceptance fallback must
    not turn every provider into a policy violator.
    """
    destroyed: list[int] = []
    _patch_wrap_decrypt_oracle(monkeypatch, {CKA_EXTRACTABLE: True}, destroyed)

    with pytest.raises(pytest.xfail.Exception):
        api_sec.TestWrapDecryptOracle().test_wrap_decrypt_combination_prevented(_session())

    assert destroyed == [512, 511]
    assert [r.reason for r in C.get_records()] == ["honest_deviation"]


def test_private_key_missing_sensitive_does_not_mask_exponent_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A readable RSA private exponent stays a hard policy finding.

    ``CKA_SENSITIVE`` is omitted; the sibling ``CKA_EXTRACTABLE=False`` claim and
    the readable ``CKA_PRIVATE_EXPONENT`` are independently present, so the
    self-contradiction must still fire -- and the omission is recorded exactly
    once (by ``attr_or_record``), not twice.
    """
    monkeypatch.setattr(api_sec, "_gen_api_security_rsa_keypair", lambda *_a, **_k: (521, 522))
    monkeypatch.setattr(
        api_sec,
        "read_attributes",
        lambda *_a, **_k: {CKA_EXTRACTABLE: False, CKA_PRIVATE_EXPONENT: b"\xd0" * 32},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_hard_fail(
        lambda: api_sec.TestSensitiveExtraction().test_private_key_not_extractable(_session())
    )

    assert destroyed == [521, 522]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].label == "RSA private-key CKA_SENSITIVE readback"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"
    # The omission is NOT rendered as a value the provider never returned.
    assert "CKA_SENSITIVE=<unavailable>" in (records[1].summary or "")


def test_private_key_missing_protection_readback_is_recorded_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One omission, one record: absence must not ALSO fire the malformed classify."""
    monkeypatch.setattr(api_sec, "_gen_api_security_rsa_keypair", lambda *_a, **_k: (525, 526))
    # CKA_SENSITIVE omitted; CKA_EXTRACTABLE present; the exponent is correctly
    # NOT returned, so there is no contradiction -- only the omission.
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: False})
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda *_a, **_k: None)

    _expect_completion(
        lambda: api_sec.TestSensitiveExtraction().test_private_key_not_extractable(_session())
    )

    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational"]
    assert records[0].label == "RSA private-key CKA_SENSITIVE readback"


def test_private_key_malformed_protection_readback_is_recorded_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PRESENT-but-malformed protection attribute is still its own record."""
    monkeypatch.setattr(api_sec, "_gen_api_security_rsa_keypair", lambda *_a, **_k: (523, 524))
    monkeypatch.setattr(
        api_sec,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: b"\x01", CKA_EXTRACTABLE: False},
    )
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.xfail.Exception):
        api_sec.TestSensitiveExtraction().test_private_key_not_extractable(_session())

    records = C.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert records[0].label == "RSA private-key protection attributes malformed"


def test_non_extractable_value_present_is_a_hard_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_VALUE readable on a non-extractable key is the finding, not a crash."""
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 531)
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"leaked"})
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_hard_fail(
        lambda: api_sec.TestKeyUsageRestrictions().test_non_extractable_enforced(_session())
    )

    assert destroyed == [531]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "policy"
    assert records[0].label == "CKA_VALUE readable on non-extractable key"


def test_non_extractable_value_absent_records_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A correctly-protected key omits CKA_VALUE: the secure default, not a deviation."""
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 532)
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_completion(
        lambda: api_sec.TestKeyUsageRestrictions().test_non_extractable_enforced(_session())
    )

    assert destroyed == [532]
    assert C.get_records() == []


def test_copy_escalation_missing_source_claim_stays_a_hard_policy_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An escalated copy that exposes CKA_VALUE is a hard finding without the readback.

    The source key was CREATED with ``CKA_EXTRACTABLE=False`` and the module
    accepted it; an unreadable source attribute must not downgrade the proven
    escalation-plus-exposure.
    """
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 541)
    monkeypatch.setattr(api_sec, "copy_object", lambda *_a, **_k: 542)
    # First read: source CKA_EXTRACTABLE omitted.  Second read: the copy's
    # CKA_VALUE is readable -- the material actually escaped.
    reads = iter([{}, {CKA_VALUE: b"leaked-material"}])
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: next(reads))
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_hard_fail(
        lambda: api_sec.TestAttributeLaunderingViaCopy().test_copy_cannot_escalate_extractable(
            _session()
        )
    )

    assert destroyed == [542, 541]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"


def test_copy_downgrade_sensitive_exposing_value_is_a_hard_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copy that downgrades CKA_SENSITIVE and exposes CKA_VALUE stays a hard fail."""
    monkeypatch.setattr(api_sec, "_gen_api_security_aes_key", lambda *_a, **_k: 551)
    monkeypatch.setattr(api_sec, "copy_object", lambda *_a, **_k: 552)
    monkeypatch.setattr(api_sec, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"leaked"})
    destroyed: list[int] = []
    monkeypatch.setattr(api_sec, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_hard_fail(
        lambda: api_sec.TestAttributeLaunderingViaCopy().test_copy_cannot_downgrade_sensitive(
            _session()
        )
    )

    assert destroyed == [552, 551]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "policy"
    assert records[0].operation == "C_CopyObject"


# ---------------------------------------------------------------------------
# test_cve_regression.py
# ---------------------------------------------------------------------------


def test_roca_modulus_missing_is_structured_and_cleans_up_both_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing CKA_MODULUS records and returns before the ROCA math runs."""
    monkeypatch.setattr(cve, "_gen_cve_rsa_keypair_or_xfail", lambda *_a, **_k: (601, 602))
    monkeypatch.setattr(cve, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(cve, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_completion(lambda: cve.TestROCAFingerprint().test_rsa_modulus_not_roca(_session()))

    assert destroyed == [601, 602]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF


def test_tookan_unwrap_missing_sensitive_does_not_mask_extractable_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proven CKA_EXTRACTABLE=True violation must fire even if CKA_SENSITIVE is unreadable."""
    handles = iter([701, 702])
    monkeypatch.setattr(cve, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(cve, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(cve, "unwrap_key", lambda *_a, **_k: 703)
    # CKA_EXTRACTABLE present and violating; CKA_SENSITIVE omitted entirely.
    monkeypatch.setattr(cve, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: True})
    destroyed: list[int] = []
    monkeypatch.setattr(cve, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = _session(has_mechanism=lambda _n: True)
    _expect_hard_fail(
        lambda: cve.TestTookanUnwrapAttrs().test_unwrapped_key_preserves_extractable(session)
    )

    assert destroyed == [703, 701, 702]
    records = C.get_records()
    # Exactly two records: one per observation.  The omitted CKA_SENSITIVE is
    # recorded once by attr_or_record() -- the "protection readback" classify no
    # longer double-counts the same omission.
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].label == "Tookan unwrapped key CKA_SENSITIVE readback"
    assert records[0].kind == "policy"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"
    assert records[1].operation == "C_GetAttributeValue"
    assert "CKA_SENSITIVE=<unavailable>" in (records[1].summary or "")


def test_unwrapped_key_partial_readback_records_each_omission_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One omission, one record -- absence must not ALSO fire the malformed classify."""
    handles = iter([721, 722])
    monkeypatch.setattr(cve, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(cve, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(cve, "unwrap_key", lambda *_a, **_k: 723)
    # CKA_EXTRACTABLE present and honoring the template; CKA_SENSITIVE omitted.
    monkeypatch.setattr(cve, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: False})
    destroyed: list[int] = []
    monkeypatch.setattr(cve, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = _session(has_mechanism=lambda _n: True)
    _expect_completion(
        lambda: cve.TestTookanUnwrapAttrs().test_unwrapped_key_preserves_extractable(session)
    )

    assert destroyed == [723, 721, 722]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational"]
    assert records[0].label == "Tookan unwrapped key CKA_SENSITIVE readback"


def test_unwrapped_key_malformed_readback_is_still_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PRESENT-but-malformed protection value keeps its own metadata record."""
    handles = iter([731, 732])
    monkeypatch.setattr(cve, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(cve, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(cve, "unwrap_key", lambda *_a, **_k: 733)
    monkeypatch.setattr(
        cve,
        "read_attributes",
        lambda *_a, **_k: {CKA_EXTRACTABLE: False, CKA_SENSITIVE: b"\x01"},
    )
    monkeypatch.setattr(cve, "destroy_quietly", lambda *_a, **_k: None)

    session = _session(has_mechanism=lambda _n: True)
    with pytest.raises(pytest.xfail.Exception):
        cve.TestTookanUnwrapAttrs().test_unwrapped_key_preserves_extractable(session)

    records = C.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert records[0].label == "Tookan unwrapped key protection readback"
    assert "malformed" in (records[0].summary or "")


def _patch_unbound_unwrap(
    monkeypatch: pytest.MonkeyPatch,
    source_attrs: dict[Any, Any],
    result_attrs: dict[Any, Any],
    destroyed: list[int],
) -> Any:
    handles = iter([711, 712])
    reads = iter([source_attrs, result_attrs])
    monkeypatch.setattr(cve, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(cve, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(cve, "unwrap_key", lambda *_a, **_k: 713)
    monkeypatch.setattr(cve, "read_attributes", lambda *_a, **_k: next(reads))
    monkeypatch.setattr(cve, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    return _session(has_mechanism=lambda _n: True)


def test_unbound_unwrap_missing_sibling_does_not_mask_protected_material_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An observed protective attribute + readable CKA_VALUE stays a hard finding.

    ``CKA_EXTRACTABLE`` is omitted entirely; ``CKA_SENSITIVE=True`` and a nonempty
    ``CKA_VALUE`` on the SAME object are independent evidence of the
    self-contradiction, so the missing sibling must not gate it.
    """
    destroyed: list[int] = []
    session = _patch_unbound_unwrap(
        monkeypatch,
        {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True},
        {CKA_SENSITIVE: True, CKA_VALUE: b"leaked-material"},
        destroyed,
    )

    _expect_hard_fail(
        lambda: cve.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(session)
    )

    assert destroyed == [713, 711, 712]
    records = C.get_records()
    # One record for the omitted result CKA_EXTRACTABLE, then the hard finding.
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].label == "Tookan unbound unwrap result CKA_EXTRACTABLE readback"
    assert records[0].kind == "policy"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"
    assert records[1].label == "Tookan unbound unwrap result exposes protected key material"
    assert "CKA_EXTRACTABLE=<unavailable>" in (records[1].summary or "")


def test_unbound_unwrap_honored_template_records_only_the_omissions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A conformant unbound unwrap is not turned into a deviation by the oracle.

    The result honors the caller template exactly, so only the two source-key
    omissions are recorded -- no invented template-honouring deviation, and each
    omission is recorded exactly once.
    """
    destroyed: list[int] = []
    session = _patch_unbound_unwrap(
        monkeypatch,
        {},  # source claims unreadable: posture-only evidence
        {CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        destroyed,
    )

    _expect_completion(
        lambda: cve.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(session)
    )

    assert destroyed == [713, 711, 712]
    records = C.get_records()
    assert [r.reason for r in records] == ["honest_deviation", "honest_deviation"]
    assert [r.kind for r in records] == ["metadata", "metadata"]
    assert records[0].label == "Tookan unbound unwrap source key CKA_SENSITIVE readback"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


# ---------------------------------------------------------------------------
# test_tookan.py
# ---------------------------------------------------------------------------


def test_sensitive_preserved_baseline_missing_still_performs_the_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing baseline disables only the baseline check -- the probe still runs.

    The copy must still be created and its ``CKA_SENSITIVE`` still observed:
    otherwise a module that omits the baseline attribute but loses SENSITIVE on
    the copy (the Tookan vector) would never be probed at all.
    """
    monkeypatch.setattr(tookan, "gen_aes_key_or_xfail", lambda *_a, **_k: 801)
    # Baseline omitted; the COPY reports CKA_SENSITIVE=False -- SENSITIVE lost.
    reads = iter([{}, {CKA_SENSITIVE: False}])
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: next(reads))
    copied: list[int] = []

    def _copy(_raw: Any, _sh: int, _h: int, _attrs: Any) -> int:
        copied.append(804)
        return 804

    monkeypatch.setattr(tookan, "copy_object", _copy)
    destroyed: list[int] = []
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(AssertionError, match="SENSITIVE flag lost on copy"):
        tookan.TestSensitivePreservation().test_sensitive_preserved_on_copy(_session())

    assert copied == [804], "the copy must still be created when the baseline is missing"
    assert destroyed == [804, 801]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].kind == "policy"
    assert records[0].label == "CKA_SENSITIVE=True readback (pre-copy baseline)"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_sensitive_preserved_baseline_missing_and_copy_ok_is_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A conformant copy is not turned into a finding by the missing baseline."""
    monkeypatch.setattr(tookan, "gen_aes_key_or_xfail", lambda *_a, **_k: 805)
    reads = iter([{}, {CKA_SENSITIVE: True}])
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: next(reads))
    monkeypatch.setattr(tookan, "copy_object", lambda *_a, **_k: 806)
    destroyed: list[int] = []
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_completion(
        lambda: tookan.TestSensitivePreservation().test_sensitive_preserved_on_copy(_session())
    )

    assert destroyed == [806, 805]
    assert [r.reason for r in C.get_records()] == ["not_operational"]


def test_wrap_extraction_missing_claim_readback_stays_a_hard_policy_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tookan wrap+decrypt extraction stays CRITICAL when the claim readback is absent.

    ``gen_aes_key`` ACCEPTED the ``CKA_EXTRACTABLE=False`` / ``CKA_SENSITIVE=True``
    template; that acceptance is the claim.  Recovering >= 16 bytes of the
    protected key must not be downgraded because one attribute was unreadable.
    """
    handles = iter([841, 842])
    monkeypatch.setattr(tookan, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(tookan, "wrap_key", lambda *_a, **_k: b"wrapped-blob")
    monkeypatch.setattr(tookan, "decrypt_single", lambda *_a, **_k: b"0123456789abcdef")
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = _session(has_mechanism=lambda _n: True)
    _expect_hard_fail(
        lambda: tookan.TestWrapExtraction().test_wrap_decrypt_extraction_attempt(session)
    )

    assert destroyed == [841, 842]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].kind == "policy"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"


def test_wrap_extraction_observed_extractable_true_is_an_honest_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OBSERVED CKA_EXTRACTABLE=True is a real non-claim: xfail, not a hard fail."""
    handles = iter([843, 844])
    monkeypatch.setattr(tookan, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(tookan, "wrap_key", lambda *_a, **_k: b"wrapped-blob")
    monkeypatch.setattr(tookan, "decrypt_single", lambda *_a, **_k: b"0123456789abcdef")
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: True})
    destroyed: list[int] = []
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = _session(has_mechanism=lambda _n: True)
    with pytest.raises(pytest.xfail.Exception):
        tookan.TestWrapExtraction().test_wrap_decrypt_extraction_attempt(session)

    assert destroyed == [843, 844]
    assert [r.reason for r in C.get_records()] == ["honest_deviation"]


def test_sensitive_preserved_post_copy_missing_cleans_up_both_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing post-copy CKA_SENSITIVE readback records and both handles clean up."""
    monkeypatch.setattr(tookan, "gen_aes_key_or_xfail", lambda *_a, **_k: 802)
    monkeypatch.setattr(tookan, "copy_object", lambda *_a, **_k: 803)
    reads = iter([{CKA_SENSITIVE: True}, {}])
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: next(reads))
    destroyed: list[int] = []
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_completion(
        lambda: tookan.TestSensitivePreservation().test_sensitive_preserved_on_copy(_session())
    )

    # Nested finally structure: copy handle destroyed before the source key.
    assert destroyed == [803, 802]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational"]
    assert records[0].label == "CKA_SENSITIVE=True readback (post-copy)"


def test_extractable_escalation_on_copy_is_still_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine CKA_EXTRACTABLE False->True escalation on copy stays a hard fail."""
    monkeypatch.setattr(tookan, "gen_aes_key_or_xfail", lambda *_a, **_k: 811)
    monkeypatch.setattr(tookan, "copy_object", lambda *_a, **_k: 812)
    reads = iter([{CKA_EXTRACTABLE: False}, {CKA_EXTRACTABLE: True}])
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: next(reads))
    destroyed: list[int] = []
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    _expect_hard_fail(
        lambda: tookan.TestSensitivePreservation().test_extractable_cannot_escalate_on_copy(
            _session()
        )
    )

    assert destroyed == [812, 811]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "policy"


def _patch_cbc_oracle(
    monkeypatch: pytest.MonkeyPatch,
    tgt_attrs: dict[Any, Any],
    recovered: bytes,
    destroyed: list[int],
) -> Any:
    handles = iter([821, 822, 823])
    monkeypatch.setattr(tookan, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: tgt_attrs)
    monkeypatch.setattr(tookan, "encrypt_single", lambda *_a, **_k: b"\xab" * 32)
    monkeypatch.setattr(tookan, "wrap_key", lambda *_a, **_k: b"w" * 32)
    monkeypatch.setattr(tookan, "decrypt_single", lambda *_a, **_k: recovered)
    monkeypatch.setattr(tookan, "import_secret_key", lambda *_a, **_k: 823)
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    return _session(has_mechanism=lambda _n: True)


def test_cbc_oracle_missing_claim_readback_still_runs_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An absent CKA_EXTRACTABLE must not xfail the CBC extraction oracle away.

    ``absent`` is not ``observed CKA_EXTRACTABLE=True``: the module accepted the
    non-extractable template, so the oracle remains applicable and a verified
    end-to-end extraction is still reported.  The old code xfailed here with a
    label asserting the module "did not honor CKA_EXTRACTABLE=False" -- a claim
    that was never observed.
    """
    destroyed: list[int] = []
    session = _patch_cbc_oracle(monkeypatch, {}, b"k" * 32, destroyed)

    _expect_hard_fail(
        lambda: tookan.TestWrapExtraction().test_cbc_wrap_then_decrypt_extraction_oracle(session)
    )

    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].label == ("type-confusion wrap target CKA_EXTRACTABLE claim-check readback")
    assert records[0].kind == "policy"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"
    assert destroyed == [823, 822, 821]


def test_cbc_oracle_observed_extractable_true_is_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OBSERVED CKA_EXTRACTABLE=True genuinely makes the oracle inapplicable."""
    destroyed: list[int] = []
    session = _patch_cbc_oracle(monkeypatch, {CKA_EXTRACTABLE: True}, b"k" * 32, destroyed)

    with pytest.raises(pytest.xfail.Exception):
        tookan.TestWrapExtraction().test_cbc_wrap_then_decrypt_extraction_oracle(session)

    records = C.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert "did not honor" in records[0].label
    assert destroyed == [822, 821]


def test_unbound_unwrap_partial_readback_records_each_omission_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One omission, one record.

    The result honors CKA_SENSITIVE=False and omits CKA_EXTRACTABLE, so exactly
    one record is expected: neither the "protection readback" classify nor the
    "did not honor output template" classify may re-report the same omission.
    """
    destroyed: list[int] = []
    session = _patch_unbound_unwrap(
        monkeypatch,
        {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True},
        {CKA_SENSITIVE: False},
        destroyed,
    )

    _expect_completion(
        lambda: cve.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(session)
    )

    assert destroyed == [713, 711, 712]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational"]
    assert records[0].label == "Tookan unbound unwrap result CKA_EXTRACTABLE readback"


def test_unbound_unwrap_observed_template_deviation_is_still_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OBSERVED half that deviates is still reported when the sibling is absent."""
    destroyed: list[int] = []
    session = _patch_unbound_unwrap(
        monkeypatch,
        {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True},
        {CKA_EXTRACTABLE: False},  # requested True -> observed deviation
        destroyed,
    )

    with pytest.raises(pytest.xfail.Exception):
        cve.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(session)

    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational", "honest_deviation"]
    assert records[0].label == "Tookan unbound unwrap result CKA_SENSITIVE readback"
    assert records[1].label == "Tookan unbound unwrap result did not honor output template"


def _patch_type_confusion(
    monkeypatch: pytest.MonkeyPatch,
    reads: list[dict[Any, Any]],
    invalid_leg: Any,
    destroyed: list[int],
) -> Any:
    """Drive the Tookan §3.2 key-type-confusion probe end to end.

    ``invalid_leg`` is either an exception to raise from the CKK_DES3 unwrap
    (a refusal) or an object handle to return (type confusion ACCEPTED).
    """
    handles = iter([901, 902])
    read_iter = iter(reads)
    monkeypatch.setattr(tookan, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(tookan, "read_attributes", lambda *_a, **_k: next(read_iter))
    monkeypatch.setattr(tookan, "wrap_key", lambda *_a, **_k: b"wrapped-blob")
    monkeypatch.setattr(tookan, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 903)

    def _unwrap(*_a: Any, **_k: Any) -> int:
        if isinstance(invalid_leg, BaseException):
            raise invalid_leg
        return int(invalid_leg)

    monkeypatch.setattr(tookan, "unwrap_key", _unwrap)
    monkeypatch.setattr(tookan, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    return _session(has_mechanism=lambda _n: True)


def test_type_confusion_missing_value_readback_does_not_manufacture_a_crypto_break(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module that merely omits CKA_VALUE and REFUSES the confusion is conformant.

    Regression for the reproduced defect: normalising MISSING_ATTRIBUTE to None
    made ``valid_accepted`` False, and classify_discrimination() reported
    ``reason=accepted_invalid kind=crypto`` (CRITICAL, "the valid/un-tampered
    operation did not verify") against a provider that did the right thing.
    """
    destroyed: list[int] = []
    session = _patch_type_confusion(
        monkeypatch,
        [{}, {}],  # both CKA_VALUE readbacks omitted
        CkrAssertionError("refused", int(CKR_GENERAL_ERROR)),
        destroyed,
    )

    _expect_completion(
        lambda: tookan.TestKeyTypeConfusionOnUnwrap().test_unwrap_aes_as_des3_rejected(
            session, None
        )
    )

    assert destroyed == [903, 901, 902]
    records = C.get_records()
    # Exactly the two readback observations -- no invented crypto break.
    assert [r.reason for r in records] == ["not_operational", "not_operational"]
    assert [r.kind for r in records] == ["metadata", "metadata"]
    assert [r.outcome for r in records] == ["xfail", "xfail"]
    for rec in records:
        assert rec.operation == "C_GetAttributeValue"
        assert rec.mechanism is None
        assert rec.spec_ref == _SPEC_REF


def test_type_confusion_missing_value_readback_still_reports_an_accepted_confusion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing readback must not SUPPRESS the independently observable break.

    The invalid leg needs no readback: the module either refused cleanly or handed
    back a live CKK_DES3 handle.  The latter is a crypto break regardless.
    """
    destroyed: list[int] = []
    session = _patch_type_confusion(monkeypatch, [{}, {}], 904, destroyed)

    _expect_hard_fail(
        lambda: tookan.TestKeyTypeConfusionOnUnwrap().test_unwrap_aes_as_des3_rejected(
            session, None
        )
    )

    assert destroyed == [903, 904, 901, 902]
    records = C.get_records()
    assert [r.reason for r in records] == [
        "not_operational",
        "not_operational",
        "accepted_invalid",
    ]
    assert records[2].kind == "crypto"
    assert records[2].label == "Tookan: unwrap AES-KW blob as CKK_DES3 must be refused"


def test_type_confusion_oracle_intact_when_both_readbacks_are_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With both readbacks present, a correct refusal is a clean pass: no records."""
    destroyed: list[int] = []
    material = {CKA_VALUE: b"\x11" * 16}
    session = _patch_type_confusion(
        monkeypatch,
        [dict(material), dict(material)],
        CkrAssertionError("refused", int(CKR_GENERAL_ERROR)),
        destroyed,
    )

    _expect_completion(
        lambda: tookan.TestKeyTypeConfusionOnUnwrap().test_unwrap_aes_as_des3_rejected(
            session, None
        )
    )

    assert destroyed == [903, 901, 902]
    assert C.get_records() == []


def test_type_confusion_valid_leg_mismatch_is_still_a_critical_crypto_break(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The genuine discrimination oracle is untouched on an observable provider.

    Both CKA_VALUE readbacks are present but the valid leg returned the WRONG
    material: that is a real crypto break and must still fail CRITICAL.
    """
    destroyed: list[int] = []
    session = _patch_type_confusion(
        monkeypatch,
        [{CKA_VALUE: b"\x11" * 16}, {CKA_VALUE: b"\x22" * 16}],
        CkrAssertionError("refused", int(CKR_GENERAL_ERROR)),
        destroyed,
    )

    _expect_hard_fail(
        lambda: tookan.TestKeyTypeConfusionOnUnwrap().test_unwrap_aes_as_des3_rejected(
            session, None
        )
    )

    assert destroyed == [903, 901, 902]
    records = C.get_records()
    assert [r.reason for r in records] == ["accepted_invalid"]
    assert records[0].kind == "crypto"
    assert records[0].severity == "CRITICAL"
    assert "did not verify" in (records[0].summary or "")


# ---------------------------------------------------------------------------
# test_unwrap_reimport.py
# ---------------------------------------------------------------------------


def test_default_strip_missing_extractable_does_not_mask_value_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proven CKA_SENSITIVE=True + readable CKA_VALUE violation is not masked."""
    monkeypatch.setattr(reimport, "gen_aes_key", lambda *_a, **_k: 901)
    monkeypatch.setattr(reimport, "gen_aes_key_or_xfail", lambda *_a, **_k: 902)
    monkeypatch.setattr(reimport, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(reimport, "unwrap_key", lambda *_a, **_k: 903)
    # CKA_EXTRACTABLE omitted; CKA_SENSITIVE=True and CKA_VALUE readable prove
    # the violation independently of the omitted attribute.
    monkeypatch.setattr(
        reimport,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: True, CKA_VALUE: b"leaked-material"},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(reimport, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = _session(has_mechanism=lambda _n: True)
    _expect_hard_fail(
        lambda: reimport.TestDefaultStripIsPermitted().test_default_strip_is_permitted(session)
    )

    assert destroyed == [903, 902, 901]
    records = C.get_records()
    # One record per observation: the omitted CKA_EXTRACTABLE is recorded once.
    assert [r.reason for r in records] == ["not_operational", "self_contradiction"]
    assert records[0].label == "Default-strip unwrap result CKA_EXTRACTABLE readback"
    assert records[0].kind == "policy"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[1].kind == "policy"
    assert records[1].operation == "C_GetAttributeValue"
    assert "CKA_EXTRACTABLE=<unavailable>" in (records[1].summary or "")


def test_default_strip_partial_readback_records_each_omission_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One omission, one record, for the default-strip result readback."""
    monkeypatch.setattr(reimport, "gen_aes_key", lambda *_a, **_k: 911)
    monkeypatch.setattr(reimport, "gen_aes_key_or_xfail", lambda *_a, **_k: 912)
    monkeypatch.setattr(reimport, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(reimport, "unwrap_key", lambda *_a, **_k: 913)
    # CKA_SENSITIVE honors the template; CKA_EXTRACTABLE omitted; CKA_VALUE absent.
    monkeypatch.setattr(reimport, "read_attributes", lambda *_a, **_k: {CKA_SENSITIVE: False})
    destroyed: list[int] = []
    monkeypatch.setattr(reimport, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    session = _session(has_mechanism=lambda _n: True)
    _expect_completion(
        lambda: reimport.TestDefaultStripIsPermitted().test_default_strip_is_permitted(session)
    )

    assert destroyed == [913, 912, 911]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational"]
    assert records[0].label == "Default-strip unwrap result CKA_EXTRACTABLE readback"


def test_default_strip_observed_template_deviation_is_still_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OBSERVED deviating half is still reported when the sibling is absent."""
    monkeypatch.setattr(reimport, "gen_aes_key", lambda *_a, **_k: 921)
    monkeypatch.setattr(reimport, "gen_aes_key_or_xfail", lambda *_a, **_k: 922)
    monkeypatch.setattr(reimport, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(reimport, "unwrap_key", lambda *_a, **_k: 923)
    monkeypatch.setattr(reimport, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: False})
    monkeypatch.setattr(reimport, "destroy_quietly", lambda *_a, **_k: None)

    session = _session(has_mechanism=lambda _n: True)
    with pytest.raises(pytest.xfail.Exception):
        reimport.TestDefaultStripIsPermitted().test_default_strip_is_permitted(session)

    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational", "honest_deviation"]
    assert records[0].label == "Default-strip unwrap result CKA_SENSITIVE readback"
    assert records[1].label == "Default-strip unwrap result did not honor output template"


class _FakeGenerateKeyRaw:
    """Minimal ctypes-compatible ``C_GenerateKey`` double for the binding test."""

    def C_GenerateKey(  # noqa: N802 - PKCS#11 API naming
        self, _sh: int, _mech_ptr: Any, _tmpl_ptr: Any, _count: int, handle_ref: Any
    ) -> int:
        handle_ref._obj.value = 950
        return 0


def _patch_unwrap_template_binding(
    monkeypatch: pytest.MonkeyPatch, attrs: dict[Any, Any], destroyed: list[int]
) -> Any:
    monkeypatch.setattr(reimport, "_read_unwrap_template_claim", lambda *_a, **_k: None)
    monkeypatch.setattr(reimport, "gen_aes_key_or_xfail", lambda *_a, **_k: 951)
    monkeypatch.setattr(reimport, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(reimport, "unwrap_key", lambda *_a, **_k: 952)
    monkeypatch.setattr(reimport, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(reimport, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    return _session(raw=_FakeGenerateKeyRaw(), has_mechanism=lambda _n: True)


def test_unwrap_template_binding_missing_sensitive_records_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One omission, one record: the binding oracle is disabled, not double-counted."""
    destroyed: list[int] = []
    session = _patch_unwrap_template_binding(monkeypatch, {}, destroyed)

    _expect_completion(
        lambda: reimport.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(session)
    )

    assert destroyed == [952, 951, 950]
    records = C.get_records()
    assert [r.reason for r in records] == ["not_operational"]
    assert records[0].kind == "policy"
    assert records[0].label == "CKA_UNWRAP_TEMPLATE binding result CKA_SENSITIVE readback"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_unwrap_template_binding_bypass_is_still_a_hard_policy_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_SENSITIVE=False despite the binding stays a hard policy self-contradiction."""
    destroyed: list[int] = []
    session = _patch_unwrap_template_binding(monkeypatch, {CKA_SENSITIVE: False}, destroyed)

    _expect_hard_fail(
        lambda: reimport.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(session)
    )

    assert destroyed == [952, 951, 950]
    records = C.get_records()
    assert [r.reason for r in records] == ["self_contradiction"]
    assert records[0].kind == "policy"


def test_unwrap_template_binding_malformed_sensitive_is_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PRESENT-but-malformed CKA_SENSITIVE is still its own metadata record."""
    destroyed: list[int] = []
    session = _patch_unwrap_template_binding(monkeypatch, {CKA_SENSITIVE: b"\x00"}, destroyed)

    with pytest.raises(pytest.xfail.Exception):
        reimport.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(session)

    records = C.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert records[0].label == "CKA_UNWRAP_TEMPLATE sensitivity result malformed"
