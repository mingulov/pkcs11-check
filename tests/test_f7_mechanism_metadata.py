"""Runtime regressions for the F7 slice 09 migration (mechanism metadata and templates).

Covers the 13 provider-backed attribute reads migrated in:
  - test_remaining_gaps.py  (template-attribute readback + enforcement + OTP attrs)
  - test_mech_wrap.py       (diagnostic-only CKA_VALUE readback on wrap roundtrip)
  - test_mech_attribute.py  (``_read_attr_safe`` -- hard xfail on a required attribute)
  - test_mech_keygen.py     (``_read_local_flag`` -- hard xfail on CKA_LOCAL)
  - test_mech_message.py    (``_claim_false_or_xfail`` -- presence-gated policy claim)
  - test_mech_negative.py   (``_claim_false_or_xfail`` -- presence-gated policy claim)

Each production file is exercised through its own module namespace with the provider
surface (``read_attributes``, key-generation helpers, ``rs.raw.C_*``) monkeypatched, so
these are real runtime calls into the migrated code paths, not re-implementations of
``attr_or_record`` itself (that contract is already covered by
``tests/test_required_attribute_presence.py``).

Site classes (13 diagnostics grouped by identical guard shape):

  A. Presence-gated policy claim, no termination on omission --
     ``_claim_false_or_xfail`` (test_mech_message.py, test_mech_negative.py). The three
     structurally identical inline ``claimed = ...`` sites in test_remaining_gaps.py's
     ``TestTemplateConstraintAttributes.test_*_template_enforces_*`` methods were of this
     shape too until the F7 claim-sweep fix: C_GenerateKey/C_CreateObject already proved
     creation-time acceptance of the nested-template attribute, so ``claimed`` now
     defaults to True and only a present-but-malformed readback can disprove it (a
     missing readback no longer downgrades the claim -- see
     tests/test_f7_remaining_gaps_template_claim_sweep.py and the tests below).
  B. Hard xfail via ``attr_or_record`` + ``raise_for_record`` (+ ``harness_error``
     totality fallback) -- ``_read_attr_safe`` (test_mech_attribute.py) and
     ``_read_local_flag`` (test_mech_keygen.py).
  C. Optional readback record with early ``return``, cleanup preserved --
     test_remaining_gaps.py's three ``test_*_template_attribute_readable`` methods and the
     ``CKA_OTP_FORMAT``/``CKA_OTP_LENGTH`` loop.
  D. Diagnostic-only readback that never influences the pass/fail oracle --
     test_mech_wrap.py's two CKA_VALUE reads in the raw-block unwrap mismatch diagnostic.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.types_std import (
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_LOCAL,
    CKA_SIGN,
    CKA_VALUE,
    CKA_WRAP_TEMPLATE,
)
from pkcs11_check.testcases import test_mech_attribute as ta
from pkcs11_check.testcases import test_mech_keygen as tk
from pkcs11_check.testcases import test_mech_message as tmsg
from pkcs11_check.testcases import test_mech_negative as tneg
from pkcs11_check.testcases import test_mech_wrap as mw
from pkcs11_check.testcases import test_remaining_gaps as rg
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _raw_session(**extra: Any) -> RawSession:
    extra.setdefault("raw", SimpleNamespace())
    return cast(RawSession, SimpleNamespace(sh=1, **extra))


# ---------------------------------------------------------------------------
# Class B: hard xfail via attr_or_record() + raise_for_record()
# ---------------------------------------------------------------------------


def test_read_attr_safe_missing_attribute_xfails_with_structured_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_mech_attribute._read_attr_safe: an omitted attribute is a structured xfail."""
    monkeypatch.setattr(ta, "read_attributes", lambda *_a, **_k: {})
    rs = _raw_session()

    with pytest.raises(pytest.xfail.Exception):
        ta._read_attr_safe(rs, 42, CKA_KEY_TYPE, "CKA_KEY_TYPE on test")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_read_attr_safe_present_value_returned_without_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ta, "read_attributes", lambda *_a, **_k: {CKA_KEY_TYPE: 5})
    rs = _raw_session()

    value = ta._read_attr_safe(rs, 42, CKA_KEY_TYPE, "CKA_KEY_TYPE on test")

    assert value == 5
    assert C.get_records() == []


def test_read_local_flag_missing_attribute_xfails_with_structured_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_mech_keygen._read_local_flag: an omitted CKA_LOCAL is a structured xfail."""
    monkeypatch.setattr(tk, "read_attributes", lambda *_a, **_k: {})
    rs = _raw_session()

    with pytest.raises(pytest.xfail.Exception):
        tk._read_local_flag(rs, 7, "generated key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_read_local_flag_present_value_returned_without_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tk, "read_attributes", lambda *_a, **_k: {CKA_LOCAL: True})
    rs = _raw_session()

    value = tk._read_local_flag(rs, 7, "generated key")

    assert value is True
    assert C.get_records() == []


# ---------------------------------------------------------------------------
# Class A: presence-gated policy claim, no termination on omission
# ---------------------------------------------------------------------------


def test_claim_false_message_missing_records_and_skips_policy_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_mech_message._claim_false_or_xfail: omission is recorded, not conflated

    into a policy-claim contradiction -- the downstream classify_policy_enforcement()
    call is skipped entirely for a missing attribute (it never observed a claim)."""
    monkeypatch.setattr(tmsg, "read_attributes", lambda *_a, **_k: {})
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(tmsg, "classify_policy_enforcement", lambda **kw: calls.append(kw))
    rs = _raw_session()

    tmsg._claim_false_or_xfail(rs, 9, CKA_SIGN, "CKA_SIGN on wrong-type key")

    assert calls == []
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_claim_false_message_present_true_still_calls_policy_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present (non-False) value keeps the original enforcement-check behavior."""
    monkeypatch.setattr(tmsg, "read_attributes", lambda *_a, **_k: {CKA_SIGN: True})
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(tmsg, "classify_policy_enforcement", lambda **kw: calls.append(kw))
    rs = _raw_session()

    tmsg._claim_false_or_xfail(rs, 9, CKA_SIGN, "CKA_SIGN on wrong-type key")

    assert calls == [{"claimed": False, "violated": False, "label": "CKA_SIGN on wrong-type key"}]
    assert C.get_records() == []


def test_claim_false_message_present_false_is_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tmsg, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(tmsg, "classify_policy_enforcement", lambda **kw: calls.append(kw))
    rs = _raw_session()

    tmsg._claim_false_or_xfail(rs, 9, CKA_SIGN, "CKA_SIGN on wrong-type key")

    assert calls == []
    assert C.get_records() == []


def test_claim_false_negative_missing_records_and_skips_policy_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same guard shape, duplicated in test_mech_negative.py."""
    monkeypatch.setattr(tneg, "read_attributes", lambda *_a, **_k: {})
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(tneg, "classify_policy_enforcement", lambda **kw: calls.append(kw))
    rs = _raw_session()

    tneg._claim_false_or_xfail(rs, 11, CKA_ENCRYPT, "CKA_ENCRYPT on wrong-type key")

    assert calls == []
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_claim_false_negative_present_true_still_calls_policy_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tneg, "read_attributes", lambda *_a, **_k: {CKA_ENCRYPT: True})
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(tneg, "classify_policy_enforcement", lambda **kw: calls.append(kw))
    rs = _raw_session()

    tneg._claim_false_or_xfail(rs, 11, CKA_ENCRYPT, "CKA_ENCRYPT on wrong-type key")

    assert calls == [
        {"claimed": False, "violated": False, "label": "CKA_ENCRYPT on wrong-type key"}
    ]
    assert C.get_records() == []


def _sequential_handles(values: list[int]) -> Any:
    it = iter(values)

    def _gen(*_args: Any, **_kwargs: Any) -> int:
        return next(it)

    return _gen


class _WrapEnforcementRaw:
    """Minimal C_GenerateKey / C_WrapKey stub: both calls succeed unconditionally."""

    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, _tmpl: Any, _count: int, out: Any
    ) -> int:
        out._obj.value = 401
        return 0

    def C_WrapKey(  # noqa: N802
        self, _sh: int, _mech: Any, _wrapping: int, _target: int, _pwrapped: Any, out_len: Any
    ) -> int:
        out_len._obj.value = 0
        return 0


def test_wrap_template_enforcement_missing_readback_stays_claimed_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep fix to the inline guard in test_remaining_gaps.py's enforcement
    test: C_GenerateKey above already returned CKR_OK for a template requesting
    CKA_WRAP_TEMPLATE, so a missing readback records honest_deviation metadata but
    must NOT downgrade the creation-time claim -- ``claimed`` stays True, and the
    real enforcement check (C_WrapKey) still drives its own, separate
    classify_policy_enforcement() call as a proven self-contradiction."""
    monkeypatch.setattr(rg, "gen_aes_key_or_xfail", _sequential_handles([601, 602]))
    monkeypatch.setattr(rg, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(rg, "destroy_quietly", lambda *_a, **_k: None)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(rg, "classify_policy_enforcement", lambda **kw: calls.append(kw))

    rs = _raw_session(raw=_WrapEnforcementRaw(), has_mechanism=lambda _n: True)

    rg.TestTemplateConstraintAttributes().test_wrap_template_enforces_target_attributes(rs)

    assert len(calls) == 1
    assert calls[0]["claimed"] is True
    assert calls[0]["violated"] is True
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


class _UnwrapEnforcementRaw:
    """Minimal C_GenerateKey / C_WrapKey / C_UnwrapKey stub for the unwrap-template site.

    All calls succeed; the two C_UnwrapKey calls (matching template, then violating
    template) hand back distinct handles so cleanup order is observable."""

    def __init__(self) -> None:
        self._unwrap_calls = 0

    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, _tmpl: Any, _count: int, out: Any
    ) -> int:
        out._obj.value = 701
        return 0

    def C_WrapKey(  # noqa: N802
        self, _sh: int, _mech: Any, _wrapping: int, _target: int, _pwrapped: Any, out_len: Any
    ) -> int:
        out_len._obj.value = 16
        return 0

    def C_UnwrapKey(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _unwrapping: int,
        _wrapped: Any,
        _wrapped_len: int,
        _tmpl: Any,
        _count: int,
        out: Any,
    ) -> int:
        self._unwrap_calls += 1
        out._obj.value = 703 if self._unwrap_calls == 1 else 704
        return 0


def test_unwrap_template_enforcement_missing_readback_stays_claimed_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep fix to the identical inline guard, independently copied for
    CKA_UNWRAP_TEMPLATE -- a distinct site from the wrap-template one above, so it
    needs its own regression."""
    monkeypatch.setattr(rg, "gen_aes_key_or_xfail", lambda *_a, **_k: 702)
    monkeypatch.setattr(rg, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(rg, "classify_policy_enforcement", lambda **kw: calls.append(kw))

    rs = _raw_session(raw=_UnwrapEnforcementRaw(), has_mechanism=lambda _n: True)

    rg.TestTemplateConstraintAttributes().test_unwrap_template_enforces_created_object_attributes(
        rs
    )

    assert len(calls) == 1
    assert calls[0]["claimed"] is True
    assert calls[0]["violated"] is True
    assert destroyed == [704, 703, 702, 701]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


class _DeriveEnforcementRaw:
    """Minimal C_CreateObject / C_DeriveKey stub for the derive-template site."""

    def __init__(self) -> None:
        self._derive_calls = 0

    def C_CreateObject(  # noqa: N802
        self, _sh: int, _tmpl: Any, _count: int, out: Any
    ) -> int:
        out._obj.value = 801
        return 0

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, _mech: Any, _base: int, _tmpl: Any, _count: int, out: Any
    ) -> int:
        self._derive_calls += 1
        out._obj.value = 802 if self._derive_calls == 1 else 803
        return 0


def test_derive_template_enforcement_missing_readback_stays_claimed_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep fix to the identical inline guard, independently copied for
    CKA_DERIVE_TEMPLATE."""
    monkeypatch.setattr(rg, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(rg, "classify_policy_enforcement", lambda **kw: calls.append(kw))

    rs = _raw_session(raw=_DeriveEnforcementRaw(), has_mechanism=lambda _n: True)

    rg.TestTemplateConstraintAttributes().test_derive_template_enforces_created_object_attributes(
        rs
    )

    assert len(calls) == 1
    assert calls[0]["claimed"] is True
    assert calls[0]["violated"] is True
    assert destroyed == [803, 802, 801]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


# ---------------------------------------------------------------------------
# Class C: optional readback record with early return, cleanup preserved
# ---------------------------------------------------------------------------


def test_wrap_template_readable_missing_is_recorded_and_key_destroyed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_remaining_gaps.TestTemplateConstraintAttributes.test_wrap_template_attribute_readable.

    A missing CKA_WRAP_TEMPLATE records honest_deviation and returns early -- but the
    ``finally`` still destroys the key (the F7 contract's "handles still clean up" rule)."""
    destroyed: list[int] = []
    monkeypatch.setattr(rg, "gen_aes_key_or_xfail", lambda *_a, **_k: 555)
    monkeypatch.setattr(rg, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    rs = _raw_session(has_mechanism=lambda _n: True)

    rg.TestTemplateConstraintAttributes().test_wrap_template_attribute_readable(rs)

    assert destroyed == [555]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_wrap_template_readable_present_passes_without_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(rg, "gen_aes_key_or_xfail", lambda *_a, **_k: 555)
    monkeypatch.setattr(
        rg, "read_attributes", lambda *_a, **_k: {CKA_WRAP_TEMPLATE: b"template-bytes"}
    )
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    rs = _raw_session(has_mechanism=lambda _n: True)

    rg.TestTemplateConstraintAttributes().test_wrap_template_attribute_readable(rs)

    assert destroyed == [555]
    assert C.get_records() == []


def test_unwrap_template_readable_missing_is_recorded_and_key_destroyed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same guard shape as the wrap variant, independently copied for CKA_UNWRAP_TEMPLATE --

    a distinct site, so it needs its own regression rather than relying on the wrap
    variant's coverage."""
    destroyed: list[int] = []
    monkeypatch.setattr(rg, "gen_aes_key_or_xfail", lambda *_a, **_k: 556)
    monkeypatch.setattr(rg, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    rs = _raw_session(has_mechanism=lambda _n: True)

    rg.TestTemplateConstraintAttributes().test_unwrap_template_attribute_readable(rs)

    assert destroyed == [556]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_derive_template_readable_missing_is_recorded_and_key_destroyed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same guard shape again, independently copied for CKA_DERIVE_TEMPLATE."""
    destroyed: list[int] = []
    monkeypatch.setattr(rg, "gen_aes_key_or_xfail", lambda *_a, **_k: 557)
    monkeypatch.setattr(rg, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    rs = _raw_session(has_mechanism=lambda _n: True)

    rg.TestTemplateConstraintAttributes().test_derive_template_attribute_readable(rs)

    assert destroyed == [557]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


class _HotpRaw:
    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, _tmpl: Any, _count: int, out: Any
    ) -> int:
        out._obj.value = 888
        return 0


def test_otp_attribute_loop_missing_both_records_each_and_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_remaining_gaps.TestOtpKeyAttributes.test_otp_key_format_attribute.

    Both CKA_OTP_FORMAT and CKA_OTP_LENGTH omitted -- the loop must record each
    omission independently (one missing attribute must not swallow the other) and
    still destroy the generated key."""
    destroyed: list[int] = []
    monkeypatch.setattr(rg, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    rs = _raw_session(raw=_HotpRaw(), has_mechanism=lambda _n: True)

    rg.TestOtpKeyAttributes().test_otp_key_format_attribute(rs)

    assert destroyed == [888]
    records = C.get_records()
    assert len(records) == 2
    for record in records:
        assert record.reason == "honest_deviation"
        assert record.operation == "C_GetAttributeValue"
        assert record.mechanism is None
        assert record.spec_ref == _SPEC_REF


def test_otp_attribute_loop_present_values_pass_without_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(
        rg,
        "read_attributes",
        lambda _raw, _sh, _handle, attr_types: {attr_types[0]: 4},
    )
    monkeypatch.setattr(rg, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    rs = _raw_session(raw=_HotpRaw(), has_mechanism=lambda _n: True)

    rg.TestOtpKeyAttributes().test_otp_key_format_attribute(rs)

    assert destroyed == [888]
    assert C.get_records() == []


# ---------------------------------------------------------------------------
# Class D: diagnostic-only readback that never influences the pass/fail oracle
# ---------------------------------------------------------------------------

_PLAINTEXT = b"\x5a\xa5\x5a\xa5" * 4


def _wrap_roundtrip_entry(mech_id: int) -> Any:
    return MechEntry(
        mech_id=mech_id,
        mech_name="TEST_RAW_BLOCK_WRAP",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(input_constraint="raw_block"),
    )


def test_wrap_original_value_missing_still_completes_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_mech_wrap: an omitted CKA_VALUE on the wrap *target* key is recorded, but

    the roundtrip proceeds and succeeds normally -- the omission is diagnostic-only and
    must never block or fail the actual wrap/unwrap verification.

    Destroy order is [201, 301, 101]: the production code destroys the wrap *target*
    key (201) immediately after a successful wrap, mid-``try`` (a pre-F7, pre-existing
    step -- "unwrapped copy must still work" -- unrelated to this migration), which
    zeroes ``target_key`` so the ``finally`` block's own destroy of it is a no-op; the
    ``finally`` then destroys the unwrapped key (301) followed by the wrapping key
    (101)."""
    entry = _wrap_roundtrip_entry(999001)
    destroyed: list[int] = []
    monkeypatch.setattr(mw, "ckm_name", lambda _mid: "CKM_TEST_RAW_BLOCK_WRAP")
    monkeypatch.setattr(mw, "_make_wrap_mech_param", lambda _entry: None)
    monkeypatch.setattr(mw, "_build_aes_wrap_key", lambda *_a, **_k: 101)
    monkeypatch.setattr(mw, "_build_target_aes_key", lambda *_a, **_k: 201)
    monkeypatch.setattr(mw, "encrypt_single", lambda *_a, **_k: b"\x00" * 16)
    monkeypatch.setattr(mw, "wrap_key", lambda *_a, **_k: b"wrapped-blob")
    monkeypatch.setattr(mw, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 301)
    monkeypatch.setattr(mw, "decrypt_single", lambda *_a, **_k: _PLAINTEXT)
    monkeypatch.setattr(mw, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(mw, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    rs = _raw_session(has_mechanism=lambda _n: True)
    p11_config = SimpleNamespace()

    mw.TestMechWrapRoundtrip().test_wrap_unwrap_aes_key(rs, p11_config, entry)

    assert destroyed == [201, 301, 101]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF


def test_wrap_unwrapped_value_missing_in_diagnostic_path_is_recorded_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unwrapped-key CKA_VALUE read (the raw-block mismatch diagnostic) is only

    reached when the decrypted plaintext does not match -- forcing that mismatch here
    to drive the second migrated site, and confirming the (pre-existing, unrelated)
    plaintext-mismatch assertion still fails hard while cleanup still runs."""
    entry = _wrap_roundtrip_entry(999002)
    destroyed: list[int] = []
    monkeypatch.setattr(mw, "ckm_name", lambda _mid: "CKM_TEST_RAW_BLOCK_WRAP")
    monkeypatch.setattr(mw, "_make_wrap_mech_param", lambda _entry: None)
    monkeypatch.setattr(mw, "_build_aes_wrap_key", lambda *_a, **_k: 101)
    monkeypatch.setattr(mw, "_build_target_aes_key", lambda *_a, **_k: 201)
    monkeypatch.setattr(mw, "encrypt_single", lambda *_a, **_k: b"\x00" * 16)
    monkeypatch.setattr(mw, "wrap_key", lambda *_a, **_k: b"wrapped-blob")
    monkeypatch.setattr(mw, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 301)

    def _read_attrs(_raw: Any, _sh: int, handle: int, _attr_types: Any) -> dict[int, Any]:
        if handle == 201:
            return {CKA_VALUE: b"original-secret-16"}
        if handle == 301:
            return {}
        raise AssertionError(f"unexpected handle {handle}")

    def _decrypt(_raw: Any, _sh: int, handle: int, _mech: Any, _data: Any, **_kw: Any) -> bytes:
        if handle == 301:
            return b"\xff" * 16  # force a mismatch vs. _PLAINTEXT
        return b"unused-diagnostic-block"

    monkeypatch.setattr(mw, "read_attributes", _read_attrs)
    monkeypatch.setattr(mw, "decrypt_single", _decrypt)
    monkeypatch.setattr(mw, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    rs = _raw_session(has_mechanism=lambda _n: True)
    p11_config = SimpleNamespace()

    with pytest.raises(AssertionError):
        mw.TestMechWrapRoundtrip().test_wrap_unwrap_aes_key(rs, p11_config, entry)

    assert destroyed == [201, 301, 101]
    records = [r for r in C.get_records() if r.operation == "C_GetAttributeValue"]
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
