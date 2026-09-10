"""Regression tests for object-metadata / import readback classification (F7 slice 02).

Exercises the migrated ``src/pkcs11_check/testcases/test_object.py`` call sites directly
(not through pytest collection of that file, which needs a real PKCS#11 module) by
monkeypatching its collaborator functions and invoking the test methods with a fake
session. Each test proves a specific behavior contract from
``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f7-migration-contract.md``:
a missing attribute produces a structured, mechanism-free record instead of a ``KeyError``
crash; independent work in the same test still runs; handles are still destroyed; and a
present-but-wrong value still fails hard.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKK_AES,
    CKK_RSA,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases import test_object as obj


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


# --- Site class A: single-attribute readback assert -----------------------------------


def test_object_label_missing_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_LABEL omitted on readback: no KeyError, one mechanism-free xfail record."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: 42)
    monkeypatch.setattr(obj, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(obj, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    obj.TestSessionObjects().test_create_secret_key_with_label(_session())

    assert destroyed == [42]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert rec.detail == {"attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)}}


def test_object_label_present_passes_without_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: a present CKA_LABEL still asserts correctly and records nothing."""
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: 42)
    monkeypatch.setattr(obj, "read_attributes", lambda *_a, **_k: {CKA_LABEL: "test-key-object"})
    monkeypatch.setattr(obj, "destroy_quietly", lambda *_a: None)

    obj.TestSessionObjects().test_create_secret_key_with_label(_session())

    assert C.get_records() == []


# --- Site class B: two independent attributes from one mapping ------------------------


def test_key_attributes_one_missing_one_present_continues_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_KEY_TYPE omitted must not block the independent CKA_CLASS check."""
    destroyed: list[int] = []
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: 7)
    monkeypatch.setattr(obj, "read_attributes", lambda *_a, **_k: {CKA_CLASS: CKO_SECRET_KEY})
    monkeypatch.setattr(obj, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    obj.TestSessionObjects().test_key_attributes_readable(_session())

    assert destroyed == [7]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert records[0].detail == {"attribute": {"name": "CKA_KEY_TYPE", "id": int(CKA_KEY_TYPE)}}


def test_key_attributes_present_but_wrong_class_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong CKA_CLASS must still fail hard, not be downgraded."""
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: 8)
    monkeypatch.setattr(
        obj,
        "read_attributes",
        lambda *_a, **_k: {CKA_KEY_TYPE: CKK_AES, CKA_CLASS: CKO_PUBLIC_KEY},
    )
    monkeypatch.setattr(obj, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError):
        obj.TestSessionObjects().test_key_attributes_readable(_session())

    # No omission occurred, so no classification record should have been emitted --
    # this is a plain hard pytest assertion failure, exactly as before the migration.
    assert C.get_records() == []


# --- Site class C: loop readback, continue on omission --------------------------------


def test_multiple_keys_loop_continues_past_missing_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A search result with a missing CKA_LABEL must not abort the whole loop."""
    destroyed: list[int] = []
    handles = iter([1, 2])
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(obj, "find_objects", lambda *_a, **_k: [1, 999, 2])
    attrs_by_handle = {
        1: {CKA_LABEL: "multi-1"},
        999: {},
        2: {CKA_LABEL: "multi-2"},
    }
    monkeypatch.setattr(
        obj,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(obj, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    obj.TestSessionObjects().test_multiple_keys_same_type(_session())

    assert destroyed == [1, 2]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert records[0].detail == {"attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)}}


def test_multiple_keys_aggregate_oracle_disabled_when_label_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An omitted CKA_LABEL on one of the two real keys must disable the aggregate
    membership oracle, not surface as a bare AssertionError (which the plugin's
    unclassified-record gate would then escalate to a HIGH unclassified failure).
    """
    destroyed: list[int] = []
    handles = iter([1, 2])
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(obj, "find_objects", lambda *_a, **_k: [1, 2])
    # Handle 1 (the "multi-1" key) omits CKA_LABEL on readback; handle 2 ("multi-2")
    # reads back normally. Pre-fix, "multi-1" would never land in `labels`, and the
    # aggregate `assert "multi-1" in labels` would raise a bare AssertionError.
    attrs_by_handle = {1: {}, 2: {CKA_LABEL: "multi-2"}}
    monkeypatch.setattr(
        obj,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(obj, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    obj.TestSessionObjects().test_multiple_keys_same_type(_session())  # must not raise

    assert destroyed == [1, 2]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].outcome == "xfail"
    assert records[0].mechanism is None
    assert records[0].detail == {"attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)}}


def test_find_by_object_class_missing_class_skips_assert_but_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A search result with a missing CKA_CLASS must not abort checking the next one."""
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: 5)
    monkeypatch.setattr(obj, "find_objects", lambda *_a, **_k: [501, 502])
    attrs_by_handle = {501: {}, 502: {CKA_CLASS: CKO_SECRET_KEY}}
    monkeypatch.setattr(
        obj,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(obj, "destroy_quietly", lambda *_a: None)

    obj.TestSessionObjects().test_find_by_object_class(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].detail == {"attribute": {"name": "CKA_CLASS", "id": int(CKA_CLASS)}}


def test_find_by_object_class_present_but_wrong_stays_hard_mid_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong CKA_CLASS anywhere in the loop must still fail hard."""
    monkeypatch.setattr(obj, "gen_aes_key_or_xfail", lambda *_a, **_k: 6)
    monkeypatch.setattr(obj, "find_objects", lambda *_a, **_k: [601, 602])
    attrs_by_handle = {601: {CKA_CLASS: CKO_SECRET_KEY}, 602: {CKA_CLASS: CKO_PUBLIC_KEY}}
    monkeypatch.setattr(
        obj,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: attrs_by_handle[handle],
    )
    monkeypatch.setattr(obj, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError):
        obj.TestSessionObjects().test_find_by_object_class(_session())

    assert C.get_records() == []


# --- Site class D: taint_escape resolution (RSA modulus/exponent -> helper call) ------


def test_rsa_import_missing_modulus_returns_early_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_MODULUS/CKA_PUBLIC_EXPONENT must skip the import, not crash."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(obj, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(obj, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(obj, "read_attributes", lambda *_a, **_k: {})

    def _boom(*_a: Any, **_k: Any) -> int:
        raise AssertionError("create_object must not run without modulus/exponent")

    monkeypatch.setattr(obj, "create_object", _boom)
    monkeypatch.setattr(obj, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    # Wrap the call so an escaping pytest.xfail() (pytest exits 0 on "xfailed", which
    # would silently make this gate vacuous against a reverted production change: the
    # pre-migration `rsa_public_key_from_attrs_or_xfail(attrs, ...)` call raises
    # pytest.xfail() on the empty mapping before any assertion below ever runs) is
    # turned into a hard pytest failure instead of being swallowed by pytest's own
    # xfail handling.
    try:
        obj.TestKeyImportExport().test_import_rsa_public_key(_session())
    except pytest.xfail.Exception as exc:
        pytest.fail(f"unexpected xfail escaped (production regression not caught): {exc!r}")

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 2
    assert {rec.reason for rec in records} == {"not_operational"}
    assert all(rec.operation == "C_GetAttributeValue" for rec in records)
    assert all(rec.mechanism is None for rec in records)
    assert all(rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for rec in records)
    assert {rec.detail["attribute"]["name"] for rec in records if rec.detail} == {
        "CKA_MODULUS",
        "CKA_PUBLIC_EXPONENT",
    }


def test_rsa_import_present_values_flow_through_resolved_not_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Present modulus/exponent must reach the helper and create_object unaltered."""
    modulus = b"\x00" * 254 + b"\x01\x01"
    exponent = b"\x01\x00\x01"
    seen_calls: list[dict[Any, Any]] = []

    def _fake_rsa_pub(attrs: Any, *, label: str) -> None:
        seen_calls.append(dict(attrs))

    monkeypatch.setattr(obj, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(obj, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(
        obj,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: (
            # An extra key (CKA_CLASS) beyond what was requested makes the raw mapping
            # discriminable from the resolved {CKA_MODULUS, CKA_PUBLIC_EXPONENT} dict the
            # production code must build -- if the raw tainted mapping ever escaped
            # unresolved, seen_calls below would show 3 keys instead of 2.
            {CKA_MODULUS: modulus, CKA_PUBLIC_EXPONENT: exponent, CKA_CLASS: CKO_PUBLIC_KEY}
            if handle == 11
            else {CKA_KEY_TYPE: CKK_RSA}
        ),
    )
    monkeypatch.setattr(obj, "rsa_public_key_from_attrs_or_xfail", _fake_rsa_pub)
    created_templates: list[dict[Any, Any]] = []

    def _fake_create_object(_raw: Any, _sh: Any, tmpl: dict[Any, Any]) -> int:
        created_templates.append(tmpl)
        return 99

    monkeypatch.setattr(obj, "create_object", _fake_create_object)
    destroyed: list[int] = []
    monkeypatch.setattr(obj, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    obj.TestKeyImportExport().test_import_rsa_public_key(_session())

    assert seen_calls == [{CKA_MODULUS: modulus, CKA_PUBLIC_EXPONENT: exponent}]
    assert created_templates[0][CKA_MODULUS] == modulus
    assert created_templates[0][CKA_PUBLIC_EXPONENT] == exponent
    assert destroyed == [99, 11, 12]
    assert C.get_records() == []


def test_signature_import_missing_exponent_returns_early_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing exponent on the sign/verify roundtrip must skip import, not crash."""
    destroyed: list[int] = []
    signed: list[int] = []
    monkeypatch.setattr(obj, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(obj, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (21, 22))

    def _fake_sign(_raw: Any, _sh: Any, priv: int, *_a: Any, **_k: Any) -> bytes:
        signed.append(priv)
        return b"sig"

    monkeypatch.setattr(obj, "sign_single", _fake_sign)
    monkeypatch.setattr(obj, "read_attributes", lambda *_a, **_k: {CKA_MODULUS: b"\x01\x02\x03"})

    def _boom_create(*_a: Any, **_k: Any) -> int:
        raise AssertionError("create_object must not run without the exponent")

    def _boom_verify(*_a: Any, **_k: Any) -> None:
        raise AssertionError("verify_single must not run when import was skipped")

    monkeypatch.setattr(obj, "create_object", _boom_create)
    monkeypatch.setattr(obj, "verify_single", _boom_verify)
    monkeypatch.setattr(obj, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    # See test_rsa_import_missing_modulus_returns_early_and_cleans_up above: an escaping
    # pytest.xfail() must fail this test, not be swallowed as a vacuously-passing xfail.
    try:
        obj.TestKeyImportExport().test_imported_key_verifies_signature(_session())
    except pytest.xfail.Exception as exc:
        pytest.fail(f"unexpected xfail escaped (production regression not caught): {exc!r}")

    assert signed == [22]  # independent work (signing with priv) ran before the skip
    assert destroyed == [21, 22]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_PUBLIC_EXPONENT", "id": int(CKA_PUBLIC_EXPONENT)}
    }
