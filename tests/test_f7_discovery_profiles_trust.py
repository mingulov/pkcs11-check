"""Regression tests for discovery / profiles / trust attribute-presence classification
(F7 slice 06).

Exercises the migrated call sites in ``src/pkcs11_check/testcases/{test_concurrent_sessions,
test_duplicate_labels, test_mechanism_objects, test_metamorphic, test_search,
test_object_search_patterns, test_object_visibility, test_profiles, test_trust_objects}.py``
directly (not through pytest collection of those files, which need a real PKCS#11 module) by
monkeypatching their collaborator functions and invoking the test methods / helpers with a fake
session. Each test proves a behavior contract from
``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f7-migration-contract.md``: a missing
attribute produces a structured, mechanism-free record instead of a ``KeyError`` crash;
independent work in the same test still runs; handles/sessions are still cleaned up; and a
present-but-wrong value still fails hard.

``test_trust_objects.py``'s single site (the Table 25 ``CKT_TRUST_UNKNOWN`` absent-default,
bounded to the CKA_TRUST_* usage-attribute family) is covered in depth in the extended
``tests/test_validation_trust_object_classification.py`` (an existing runtime-classification
file that already covered that production file); this file adds one end-to-end integration
test proving the guarded helper behaves correctly when driven through the real pytest test
method.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.compliance import clear_notes, get_notes
from pkcs11_check.raw.types_std import (
    CKA_ID,
    CKA_LABEL,
    CKA_MECHANISM_TYPE,
    CKA_PROFILE_ID,
    CKA_VALUE,
    CKM_AES_KEY_GEN,
    CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER,
)
from pkcs11_check.testcases import test_concurrent_sessions as concurrent
from pkcs11_check.testcases import test_duplicate_labels as duplicate
from pkcs11_check.testcases import test_mechanism_objects as mechanisms
from pkcs11_check.testcases import test_metamorphic as metamorphic
from pkcs11_check.testcases import test_object_search_patterns as search_patterns
from pkcs11_check.testcases import test_object_visibility as visibility
from pkcs11_check.testcases import test_profiles as profiles
from pkcs11_check.testcases import test_search as search
from pkcs11_check.testcases import test_trust_objects as trust
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    clear_notes()
    yield
    C.clear()
    clear_notes()


def _session(**extra: Any) -> SimpleNamespace:
    base = dict(raw=object(), sh=1, slot_id=0, has_mechanism=lambda _name: True)
    base.update(extra)
    return SimpleNamespace(**base)


_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


# =====================================================================================
# test_concurrent_sessions.py -- cross-session CKA_VALUE readback (unsafe_subscript)
# =====================================================================================


def test_concurrent_value_missing_records_and_still_confirms_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_VALUE on the second-session readback must not crash; the independent
    visibility assertion (``len(found) >= 1``) and cleanup must still run."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    closed: list[int] = []
    monkeypatch.setattr(concurrent, "skip_if_token_write_protected", lambda *_a: None)
    monkeypatch.setattr(concurrent, "skip_if_data_objects_unsupported", lambda *_a: None)
    monkeypatch.setattr(concurrent, "create_object", lambda *_a, **_k: 100)
    monkeypatch.setattr(concurrent, "_open_second_session", lambda _rs: 55)
    monkeypatch.setattr(concurrent, "find_objects", lambda *_a, **_k: [200])
    monkeypatch.setattr(concurrent, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(concurrent, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    monkeypatch.setattr(concurrent, "close_session_quietly", lambda _raw, sh: closed.append(sh))

    concurrent.TestConcurrentDataObjects().test_data_object_visible_across_sessions(
        _session(), SimpleNamespace()
    )

    assert closed == [55]
    assert destroyed == [100]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


# =====================================================================================
# test_duplicate_labels.py -- per-handle loop readback (unsafe_subscript)
# =====================================================================================


def test_duplicate_label_missing_value_on_one_handle_does_not_block_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A search result whose CKA_VALUE is omitted must not abort the loop over the
    remaining duplicate-labeled handles."""
    made = iter([21, 22])
    destroyed: list[int] = []
    monkeypatch.setattr(duplicate, "skip_if_data_objects_unsupported", lambda *_a: None)
    monkeypatch.setattr(duplicate, "create_object", lambda *_a, **_k: next(made))
    monkeypatch.setattr(duplicate, "find_objects", lambda *_a, **_k: [900, 901, 902])
    attrs_by_handle = {
        900: {},
        901: {CKA_VALUE: b"first"},
        902: {CKA_VALUE: b"second"},
    }
    monkeypatch.setattr(
        duplicate,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(duplicate, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    duplicate.TestDuplicateLabels().test_data_objects_same_label(_session())

    assert destroyed == [21, 22]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_duplicate_label_missing_value_on_a_real_duplicate_disables_completeness_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL regression: the omission must land on one of the TWO real duplicate
    handles the completeness oracle (``assert b"first"/b"second" in values``) actually
    checks -- not a decoy outside its domain. Historically this shape raised a bare
    ``AssertionError`` (reason="unclassified", the reserved bucket) because the guard
    stopped the assignment while the aggregate oracle still consumed the degraded
    ``values`` list. The omission must instead disable only the completeness oracle;
    cleanup must still run and the omission must still be recorded."""
    made = iter([31, 32])
    destroyed: list[int] = []
    monkeypatch.setattr(duplicate, "skip_if_data_objects_unsupported", lambda *_a: None)
    monkeypatch.setattr(duplicate, "create_object", lambda *_a, **_k: next(made))
    # Only the two REAL duplicate handles -- no decoy -- one of them omits CKA_VALUE.
    monkeypatch.setattr(duplicate, "find_objects", lambda *_a, **_k: [901, 902])
    attrs_by_handle = {
        901: {},
        902: {CKA_VALUE: b"second"},
    }
    monkeypatch.setattr(
        duplicate,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(duplicate, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    # Must not raise -- neither a bare AssertionError nor any other exception.
    duplicate.TestDuplicateLabels().test_data_objects_same_label(_session())

    assert destroyed == [31, 32]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


# =====================================================================================
# test_mechanism_objects.py -- _mechanism_type() helper (unsafe_subscript)
# =====================================================================================


def test_mechanism_type_missing_returns_sentinel_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(mechanisms, "read_attributes", lambda *_a, **_k: {})

    result = mechanisms._mechanism_type(_session(), 1)

    assert result is MISSING_ATTRIBUTE
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {
        "attribute": {"name": "CKA_MECHANISM_TYPE", "id": int(CKA_MECHANISM_TYPE)}
    }


def test_mechanism_type_present_but_wrong_type_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-malformed CKA_MECHANISM_TYPE (not an int) must still fail hard."""
    monkeypatch.setattr(mechanisms, "read_attributes", lambda *_a, **_k: {CKA_MECHANISM_TYPE: "x"})

    with pytest.raises(AssertionError):
        mechanisms._mechanism_type(_session(), 1)

    assert C.get_records() == []


def test_mechanism_type_is_known_loop_continues_past_missing_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One CKO_MECHANISM object with a missing type must not stop the survey of others."""
    monkeypatch.setattr(mechanisms, "_mechanism_objects", lambda _rs: [1, 2])
    attrs_by_handle = {1: {}, 2: {CKA_MECHANISM_TYPE: int(CKM_AES_KEY_GEN)}}
    monkeypatch.setattr(
        mechanisms,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )

    mechanisms.TestMechanismObjects().test_mechanism_type_is_known(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].detail == {
        "attribute": {"name": "CKA_MECHANISM_TYPE", "id": int(CKA_MECHANISM_TYPE)}
    }


# =====================================================================================
# test_metamorphic.py -- AES-KEY-WRAP round-trip readback (unsafe_subscript)
# =====================================================================================


def test_wrap_unwrap_missing_value_records_and_cleans_up_all_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_VALUE on the unwrapped-key readback must not crash; every handle
    created along the way must still be destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(metamorphic, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(metamorphic, "import_secret_key_negotiated", lambda *_a, **_k: 2)
    monkeypatch.setattr(metamorphic, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(metamorphic, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 3)
    monkeypatch.setattr(metamorphic, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(metamorphic, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    metamorphic.TestRoundTripInvariants().test_wrap_unwrap_preserves_material(
        _session(), SimpleNamespace()
    )

    assert destroyed == [3, 1, 2]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_wrap_unwrap_present_but_wrong_material_stays_hard_and_still_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong unwrapped key value is a real crypto-correctness break --
    it must still fail hard, and cleanup must still run despite the failure."""
    destroyed: list[int] = []
    monkeypatch.setattr(metamorphic, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(metamorphic, "import_secret_key_negotiated", lambda *_a, **_k: 2)
    monkeypatch.setattr(metamorphic, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(metamorphic, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 3)
    monkeypatch.setattr(metamorphic, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\x00" * 16})
    monkeypatch.setattr(metamorphic, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(Failed):
        metamorphic.TestRoundTripInvariants().test_wrap_unwrap_preserves_material(
            _session(), SimpleNamespace()
        )

    assert destroyed == [3, 1, 2]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"


# =====================================================================================
# test_search.py -- per-handle loop readback of CKA_LABEL (unsafe_subscript)
# =====================================================================================


def test_find_many_objects_continues_past_one_missing_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A decoy search result with no CKA_LABEL must not prevent finding the 50
    real bulk-labeled objects."""
    made = iter(range(1000, 1050))
    destroyed: list[int] = []
    monkeypatch.setattr(search, "gen_aes_key_or_xfail", lambda *_a, **_k: next(made))
    found_handles = [9000 + i for i in range(50)] + [9999]
    monkeypatch.setattr(search, "find_objects", lambda *_a, **_k: found_handles)
    attrs_by_handle: dict[int, dict[Any, Any]] = {
        9000 + i: {CKA_LABEL: f"bulk-{i:03d}"} for i in range(50)
    }
    attrs_by_handle[9999] = {}
    monkeypatch.setattr(
        search,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(search, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    search.TestObjectSearch().test_find_many_objects(_session())

    assert destroyed == list(range(1000, 1050))
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[0].detail == {"attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)}}


def test_find_many_objects_omission_on_a_real_bulk_object_disables_completeness_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL regression: the omission must land on one of the 50 REAL bulk objects
    the completeness oracle (``assert f"bulk-{i:03d}" in found_labels`` for all 50)
    actually checks -- not a decoy outside its domain. Historically this shape raised
    a bare ``AssertionError`` (reason="unclassified", the reserved bucket) because the
    guard stopped the assignment while the aggregate oracle still consumed the
    degraded ``found_labels`` set. The omission must instead disable only the
    completeness oracle; cleanup of all 50 handles must still run and the omission
    must still be recorded."""
    made = iter(range(2000, 2050))
    destroyed: list[int] = []
    monkeypatch.setattr(search, "gen_aes_key_or_xfail", lambda *_a, **_k: next(made))
    # No decoy -- exactly the 50 real handles, one of which omits CKA_LABEL.
    found_handles = [9000 + i for i in range(50)]
    monkeypatch.setattr(search, "find_objects", lambda *_a, **_k: found_handles)
    attrs_by_handle: dict[int, dict[Any, Any]] = {
        9000 + i: {CKA_LABEL: f"bulk-{i:03d}"} for i in range(1, 50)
    }
    attrs_by_handle[9000] = {}  # bulk-000's own handle omits its label
    monkeypatch.setattr(
        search,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(search, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    # Must not raise -- neither a bare AssertionError nor any other exception.
    search.TestObjectSearch().test_find_many_objects(_session())

    assert destroyed == list(range(2000, 2050))
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].mechanism is None
    assert records[0].spec_ref == _SPEC_REF
    assert records[0].detail == {"attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)}}


# =====================================================================================
# test_object_search_patterns.py -- RSA keypair CKA_ID linkage (unsafe_subscript x2)
# =====================================================================================


def test_rsa_keypair_id_linkage_missing_private_does_not_hide_wrong_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The decomposed linkage check must never let a missing sibling hide a present,
    wrong one: private CKA_ID missing + public CKA_ID wrong must still fail hard."""
    destroyed: list[int] = []
    monkeypatch.setattr(search_patterns, "_unique_id", lambda: b"expected-id")
    monkeypatch.setattr(search_patterns, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    attrs_by_handle = {11: {CKA_ID: b"WRONG-ID"}, 12: {}}
    monkeypatch.setattr(
        search_patterns,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(
        search_patterns, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    with pytest.raises(AssertionError):
        search_patterns.TestKeypairIDLinkage().test_rsa_keypair_same_id(_session())

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].detail == {"attribute": {"name": "CKA_ID", "id": int(CKA_ID)}}


def test_rsa_keypair_id_linkage_missing_private_with_correct_public_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: missing private CKA_ID with a correct public CKA_ID must not fail --
    only the unevaluable half of the check is skipped."""
    destroyed: list[int] = []
    monkeypatch.setattr(search_patterns, "_unique_id", lambda: b"expected-id")
    monkeypatch.setattr(search_patterns, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    attrs_by_handle = {11: {CKA_ID: b"expected-id"}, 12: {}}
    monkeypatch.setattr(
        search_patterns,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(
        search_patterns, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    search_patterns.TestKeypairIDLinkage().test_rsa_keypair_same_id(_session())

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"


# =====================================================================================
# test_object_visibility.py -- cross-session readback (unsafe_subscript x8)
# =====================================================================================


def test_token_object_value_preserved_missing_label_still_checks_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_LABEL and CKA_VALUE are independent oracles on the same readback: a missing
    label must not block the (still present, correct) value check."""
    opened = iter([10, 20])
    closed: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(visibility, "skip_if_token_write_protected", lambda *_a: None)
    monkeypatch.setattr(visibility, "get_pin_bytes", lambda *_a: b"1234")
    monkeypatch.setattr(visibility, "_open_rw_session", lambda *_a: next(opened))
    monkeypatch.setattr(visibility, "_create_data_obj", lambda *_a, **_k: 555)
    monkeypatch.setattr(visibility, "close_session_quietly", lambda _raw, sh: closed.append(sh))
    monkeypatch.setattr(visibility, "_find_data_by_label", lambda *_a, **_k: [777])
    payload = b"data-integrity-check-12345"
    monkeypatch.setattr(visibility, "read_attributes", lambda *_a, **_k: {CKA_VALUE: payload})
    monkeypatch.setattr(visibility, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    visibility.TestTokenObjectPersistence().test_token_object_value_preserved(
        _session(), SimpleNamespace()
    )

    assert closed == [10, 20]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].detail == {"attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)}}


def test_session_object_visibility_omission_is_not_reported_as_visibility_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session object found (hence visible) in a concurrent session, whose CKA_VALUE
    is then omitted, must record only the value-readback omission -- never a spurious
    visibility-violation finding. Handles/sessions must still be cleaned up."""
    opened = iter([30, 40])
    closed: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(visibility, "get_pin_bytes", lambda *_a: b"1234")
    monkeypatch.setattr(visibility, "_open_rw_session", lambda *_a: next(opened))
    monkeypatch.setattr(visibility, "_create_data_obj", lambda *_a, **_k: 111)
    monkeypatch.setattr(visibility, "close_session_quietly", lambda _raw, sh: closed.append(sh))
    monkeypatch.setattr(visibility, "_find_data_by_label", lambda *_a, **_k: [222])
    monkeypatch.setattr(visibility, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(visibility, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    visibility.TestSessionObjectCrossVisibility().test_session_object_visible_in_concurrent_session(
        _session(), SimpleNamespace()
    )

    assert closed == [40, 30]
    assert destroyed == [111]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_modify_value_cross_session_missing_readback_does_not_block_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing CKA_VALUE on the post-modification readback must not crash, and the
    modified object must still be found and destroyed in session A's cleanup."""
    opened = iter([50, 60])
    closed: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(visibility, "skip_if_token_write_protected", lambda *_a: None)
    monkeypatch.setattr(visibility, "get_pin_bytes", lambda *_a: b"1234")
    monkeypatch.setattr(visibility, "_open_rw_session", lambda *_a: next(opened))
    monkeypatch.setattr(visibility, "_create_data_obj", lambda *_a, **_k: 777)
    monkeypatch.setattr(visibility, "set_attributes", lambda *_a, **_k: None)
    monkeypatch.setattr(visibility, "close_session_quietly", lambda _raw, sh: closed.append(sh))

    def _find_data_by_label(_raw: Any, sh: int, _label: str) -> list[int]:
        return [888] if sh == 60 else [777]

    monkeypatch.setattr(visibility, "_find_data_by_label", _find_data_by_label)
    monkeypatch.setattr(visibility, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(visibility, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    visibility.TestCrossSessionModification().test_modify_value_cross_session(
        _session(), SimpleNamespace()
    )

    assert closed == [60, 50]
    assert destroyed == [777]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"


def test_modify_value_cross_session_present_but_wrong_stays_hard_and_still_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong post-modification value must still fail hard, and cleanup
    (session close + object destroy) must still run despite the raised failure."""
    opened = iter([50, 60])
    closed: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(visibility, "skip_if_token_write_protected", lambda *_a: None)
    monkeypatch.setattr(visibility, "get_pin_bytes", lambda *_a: b"1234")
    monkeypatch.setattr(visibility, "_open_rw_session", lambda *_a: next(opened))
    monkeypatch.setattr(visibility, "_create_data_obj", lambda *_a, **_k: 777)
    monkeypatch.setattr(visibility, "set_attributes", lambda *_a, **_k: None)

    def _find_data_by_label(_raw: Any, sh: int, _label: str) -> list[int]:
        return [888] if sh == 60 else [777]

    monkeypatch.setattr(visibility, "_find_data_by_label", _find_data_by_label)
    monkeypatch.setattr(visibility, "close_session_quietly", lambda _raw, sh: closed.append(sh))
    monkeypatch.setattr(visibility, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"stale"})
    monkeypatch.setattr(visibility, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(Failed):
        visibility.TestCrossSessionModification().test_modify_value_cross_session(
            _session(), SimpleNamespace()
        )

    assert closed == [60, 50]
    assert destroyed == [777]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# =====================================================================================
# test_profiles.py -- CKO_PROFILE readback (unsafe_subscript x3, unstructured_absence x1)
# =====================================================================================


def test_read_profile_ids_skips_handle_missing_id_and_collects_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_read_profile_ids`` must not raise on a profile object missing CKA_PROFILE_ID;
    it must record the omission and still return the other profiles' ids."""
    monkeypatch.setattr(profiles, "find_objects", lambda *_a, **_k: [1, 2])
    attrs_by_handle = {1: {}, 2: {CKA_PROFILE_ID: int(CKP_BASELINE_PROVIDER)}}
    monkeypatch.setattr(
        profiles,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )

    result = profiles._read_profile_ids(_session())

    assert result == {int(CKP_BASELINE_PROVIDER)}
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_PROFILE_ID", "id": int(CKA_PROFILE_ID)}}


def test_profile_objects_have_profile_id_loop_continues_past_missing_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The in-loop ``assert pid is not None`` site must not abort the survey when one
    CKO_PROFILE object's id is omitted."""
    monkeypatch.setattr(profiles.TestProfileObjects, "_get_profiles", lambda _self, _rs: [1, 2])
    attrs_by_handle = {1: {}, 2: {CKA_PROFILE_ID: int(CKP_EXTENDED_PROVIDER)}}
    monkeypatch.setattr(
        profiles,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )

    profiles.TestProfileObjects().test_profile_objects_have_profile_id(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].detail == {"attribute": {"name": "CKA_PROFILE_ID", "id": int(CKA_PROFILE_ID)}}


# =====================================================================================
# test_trust_objects.py -- integration through the guarded Table 25 default
# =====================================================================================


def test_trust_server_auth_check_continues_past_absent_attribute_via_real_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: driving the real pytest test method (not just the helper) with an
    absent CKA_TRUST_SERVER_AUTH must not crash, must apply the Table 25 default
    internally, must NOT emit a classification record (absence here is the
    spec-defined case, not a deviation), and must still surface the observation
    via a non-gating compliance note naming the omitted attribute."""
    monkeypatch.setattr(trust, "_find_trust_objects", lambda *_a, **_k: [1])
    monkeypatch.setattr(trust, "read_attributes", lambda *_a, **_k: {})

    trust.TestTrustObjects().test_trust_server_auth_is_known_value(_session())

    assert C.get_records() == []
    notes = get_notes()
    assert len(notes) == 1
    assert "CKA_TRUST_SERVER_AUTH" in notes[0].description
