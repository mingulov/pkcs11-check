"""Runtime classification meta-tests for CVE regression crypto reclassification.

Drives the invalid-EC-curve-OID import (CVE-2021-3798 pattern) offline with a
fake create_object, asserting the three-way model:

- module ACCEPTS the bogus-OID key (returns a handle) -> fail (crypto-correctness),
- module rejects with an expected curve/param code -> pass,
- module rejects with another clean code -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
)
from pkcs11_check.testcases.security import test_cve_regression


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _run(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, reject_rv: int = 0) -> None:
    if accepted:
        monkeypatch.setattr(test_cve_regression, "create_object", lambda *_a, **_k: 7)
    else:

        def _reject(*_a: object, **_k: object) -> int:
            raise CkrAssertionError(f"rv={reject_rv}", int(reject_rv))

        monkeypatch.setattr(test_cve_regression, "create_object", _reject)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_cve_regression,
        "skip_unless_create_object_supported",
        lambda *_a, **_k: None,
    )
    test_cve_regression.TestInvalidECCurve().test_import_ec_key_with_bad_oid(_session())


def test_accepted_bad_oid_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed):
        _run(monkeypatch, accepted=True)


def test_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, accepted=False, reject_rv=int(CKR_CURVE_NOT_SUPPORTED))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, accepted=False, reject_rv=int(CKR_DEVICE_ERROR))


# --- Tookan unbound-unwrap CKA_VALUE readback (Task 2b) --------------------


def _run_unbound_unwrap_value(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result_value_attrs: object,
) -> list[object]:
    """Drive test_unwrapped_key_cannot_unset_sensitive() with a scripted
    CKA_VALUE readback on the unwrap RESULT key; return the emitted records.
    """
    from pkcs11_check.raw.types_std import CKA_EXTRACTABLE, CKA_SENSITIVE

    calls = {"gen": 0}

    def _gen_aes_key(*_a: object, **_k: object) -> int:
        calls["gen"] += 1
        return calls["gen"]  # 1 = wrap_h, 2 = target/source key

    def _read(_raw: object, _sh: object, handle: int, _attrs: list[int]) -> object:
        if handle == 2:
            return {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True}
        assert handle == 99  # the unwrap result
        return result_value_attrs

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", _gen_aes_key)
    monkeypatch.setattr(test_cve_regression, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(test_cve_regression, "unwrap_key", lambda *_a, **_k: 99)
    monkeypatch.setattr(test_cve_regression, "read_attributes", _read)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)

    test_cve_regression.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(
        _session()
    )
    from pkcs11_check import classification as C  # noqa: N812

    return C.get_records()


def test_unbound_unwrap_value_sensitive_refusal_is_sanctioned_not_a_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean CKR_ATTRIBUTE_SENSITIVE refusal for CKA_VALUE is conformant.

    Verifies the site now RECORDS this refusal (proving the "already an
    emitted observation" comment removed from the source was false -- the
    sibling CKA_SENSITIVE/CKA_EXTRACTABLE attr_or_record() calls read
    different attributes and never mention CKA_VALUE), and that it lands as
    pass-class (sanctioned_refusal), not a deviation.
    """
    from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal
    from pkcs11_check.raw.types_std import (
        CKA_EXTRACTABLE,
        CKA_SENSITIVE,
        CKA_VALUE,
        CKR_ATTRIBUTE_SENSITIVE,
    )

    result = AttrReadResult()
    result[CKA_SENSITIVE] = False
    result[CKA_EXTRACTABLE] = True
    result.refusals[CKA_VALUE] = AttrRefusal(ckr=int(CKR_ATTRIBUTE_SENSITIVE))

    records = _run_unbound_unwrap_value(monkeypatch, result_value_attrs=result)

    value_records = [
        r for r in records if r.label == "Tookan unbound unwrap result CKA_VALUE readback"
    ]
    assert len(value_records) == 1
    assert value_records[0].reason == "sanctioned_refusal"
    assert value_records[0].actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"


def test_unbound_unwrap_value_silent_omission_is_recorded_honest_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A silent CKA_VALUE omission (no CKR at all) is now visible per provider.

    Before this change, this absence was read via ``_read_secret_or_absent()``
    and never reached report.jsonl at all -- proving the removed comment's
    claim ("already an emitted observation") false for this exact case.
    """
    from pkcs11_check.raw.types_std import CKA_EXTRACTABLE, CKA_SENSITIVE

    result = {CKA_SENSITIVE: False, CKA_EXTRACTABLE: True}

    records = _run_unbound_unwrap_value(monkeypatch, result_value_attrs=result)

    value_records = [
        r for r in records if r.label == "Tookan unbound unwrap result CKA_VALUE readback"
    ]
    assert len(value_records) == 1
    assert value_records[0].reason == "honest_deviation"
    assert value_records[0].kind == "metadata"
    assert value_records[0].actual_ckr is None


def test_unbound_unwrap_value_refusal_with_leaked_data_is_self_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal claiming CKR_ATTRIBUTE_SENSITIVE while still leaking bytes into
    the template is a self-contradiction that must now be caught: previously
    ``_read_secret_or_absent()`` had no refusals-channel awareness at all, so a
    module doing this was invisible.
    """
    from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal
    from pkcs11_check.raw.types_std import (
        CKA_EXTRACTABLE,
        CKA_SENSITIVE,
        CKA_VALUE,
        CKR_ATTRIBUTE_SENSITIVE,
    )

    result = AttrReadResult()
    result[CKA_SENSITIVE] = False
    result[CKA_EXTRACTABLE] = True
    result.refusals[CKA_VALUE] = AttrRefusal(ckr=int(CKR_ATTRIBUTE_SENSITIVE), leaked_len=16)

    records = _run_unbound_unwrap_value(monkeypatch, result_value_attrs=result)

    value_records = [
        r for r in records if r.label == "Tookan unbound unwrap result CKA_VALUE readback"
    ]
    assert len(value_records) == 1
    assert value_records[0].reason == "self_contradiction"
    assert value_records[0].kind == "policy"
