"""Meta-test: build_wrap_context configured-KEK resolution path (no real module needed).

Covers _build_configured_wrap_context: handle probe / label search / class+key-type
dispatch. The RSA and secret MATERIAL paths are Task-4 stubs here (_fail + None);
this file only asserts the resolution + dispatch semantics land correctly and that
every failure path notes + returns None rather than raising or silently taking a
wrong match.

Follows the pattern of tests/test_wrap_context_bootstrap.py: monkeypatch
pkcs11_check.raw.recipes.find_objects/read_attributes and pkcs11_check.compliance.note,
reset _prov._PROFILE_CACHE between tests.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKK_AES,
    CKK_DES,
    CKK_EC,
    CKK_GENERIC_SECRET,
    CKK_RSA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_OBJECT_HANDLE_INVALID,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rs(sh: int) -> Any:
    """Synthetic RS object with no real module."""
    return type(
        "RS",
        (),
        {
            "raw": object(),
            "sh": sh,
            "slot_id": 0,
            "has_mechanism": lambda self, n: True,
        },
    )()


def _reset_cache() -> None:
    _prov._PROFILE_CACHE.clear()


def _cfg(
    *,
    wrap_key_label: str | None = None,
    wrap_key_handle: int | None = None,
    pin: str | None = "1234",
) -> Any:
    return SimpleNamespace(
        wrap_key_source="configured",
        wrap_key_label=wrap_key_label,
        wrap_key_handle=wrap_key_handle,
        wrap_key_value=None,
        wrap_oaep_hash="auto",
        pin=pin,
    )


def _notes_spy(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ComplianceLevel]]:
    """Capture (description, level) tuples from compliance.note calls."""
    captured: list[tuple[str, ComplianceLevel]] = []

    def fake_note(
        description: str,
        level: ComplianceLevel,
        reference: str = "",
        *,
        test_id: str = "",
    ) -> None:
        captured.append((description, level))

    monkeypatch.setattr("pkcs11_check.compliance.note", fake_note)
    return captured


# ---------------------------------------------------------------------------
# Neither knob given -> None + note; dispatch must not raise NotImplementedError
# ---------------------------------------------------------------------------


def test_neither_knob_returns_none_and_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    """wrap_key_source=configured with no label/handle -> None, note names the gap."""
    captured = _notes_spy(monkeypatch)
    _reset_cache()

    rs = _make_rs(sh=1)
    cfg = _cfg()

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, level = captured[0]
    assert "neither wrap_key_label nor wrap_key_handle given" in description
    assert level == ComplianceLevel.STANDARD


def test_configured_source_never_raises_notimplementederror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The NotImplementedError branch is gone: wrap_key_source='configured' always routes in."""
    _notes_spy(monkeypatch)
    _reset_cache()

    rs = _make_rs(sh=2)
    cfg = _cfg()

    # Must not raise -- neither NotImplementedError nor anything else.
    ctx = _prov.build_wrap_context(rs, cfg)
    assert ctx is None


# ---------------------------------------------------------------------------
# Label resolution: multi-match -> None, message names the count (never matches[0])
# ---------------------------------------------------------------------------


def test_label_multi_match_returns_none_names_count(monkeypatch: pytest.MonkeyPatch) -> None:
    """2 token objects share the configured label -> None; message says 'matched 2'."""
    captured = _notes_spy(monkeypatch)
    read_attr_calls: list[Any] = []

    def fake_find_objects(raw: Any, session: int, tmpl: Any, **kwargs: Any) -> list[int]:
        return [10, 20]

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        read_attr_calls.append(handle)
        return {}

    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find_objects)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=3)
    cfg = _cfg(wrap_key_label="shared-label")

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "matched 2 token objects" in description
    # Must never silently take matches[0] -- read_attributes is never reached.
    assert read_attr_calls == []


# ---------------------------------------------------------------------------
# Label resolution: zero matches with pin=None -> None, note mentions "no PIN"
# ---------------------------------------------------------------------------


def test_label_zero_match_pin_none_notes_no_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    """0 matches + no PIN configured -> note hints a private wrap key may be invisible."""
    captured = _notes_spy(monkeypatch)

    def fake_find_objects(raw: Any, session: int, tmpl: Any, **kwargs: Any) -> list[int]:
        return []

    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find_objects)
    _reset_cache()

    rs = _make_rs(sh=4)
    cfg = _cfg(wrap_key_label="missing-label", pin=None)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "matched 0 token objects" in description
    assert "no PIN" in description


def test_label_zero_match_with_pin_no_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """0 matches but a PIN IS configured -> no PIN hint (session was logged in)."""
    captured = _notes_spy(monkeypatch)

    def fake_find_objects(raw: Any, session: int, tmpl: Any, **kwargs: Any) -> list[int]:
        return []

    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find_objects)
    _reset_cache()

    rs = _make_rs(sh=5)
    cfg = _cfg(wrap_key_label="missing-label", pin="1234")

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "matched 0 token objects" in description
    assert "no PIN" not in description


# ---------------------------------------------------------------------------
# Stale handle: read_attributes raises CkrAssertionError -> None (not propagated)
# ---------------------------------------------------------------------------


def test_stale_handle_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured wrap_key_handle that no longer resolves -> CkrAssertionError -> None."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        raise CkrAssertionError("stale handle", CKR_OBJECT_HANDLE_INVALID)

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=6)
    cfg = _cfg(wrap_key_handle=999)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "wrap_key_handle not usable" in description


def test_handle_class_unreadable_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """read_attributes succeeds but omits CKA_CLASS (sensitive/unavailable) -> None."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        return {}  # CKA_CLASS omitted, not raised

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=7)
    cfg = _cfg(wrap_key_handle=42)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "CKA_CLASS unreadable" in description


# ---------------------------------------------------------------------------
# Dispatch: EC private key -> None WITHOUT KeyError (class dispatch before attr math)
# ---------------------------------------------------------------------------


def test_ec_private_key_returns_none_without_keyerror(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-RSA (EC) configured private key -> None, no KeyError from attribute math."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_PRIVATE_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_EC}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=8)
    cfg = _cfg(wrap_key_handle=55)

    # Must not raise KeyError (or anything else) -- a bare call is the assertion.
    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "configured private key is not RSA" in description


# ---------------------------------------------------------------------------
# Dispatch: RSA private key -> routes into the Task-4 stub (never raises)
# ---------------------------------------------------------------------------


def test_rsa_private_key_dispatches_to_material_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKO_PRIVATE_KEY + CKK_RSA -> _configured_rsa_material stub -> None (Task 4 not built)."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_PRIVATE_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_RSA}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=9)
    cfg = _cfg(wrap_key_handle=66)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "RSA configured-KEK path not yet built (Task 4)" in description


# ---------------------------------------------------------------------------
# Dispatch: AES secret key -> routes into the Task-4 stub (never raises)
# ---------------------------------------------------------------------------


def test_aes_secret_key_dispatches_to_material_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKO_SECRET_KEY + CKK_AES -> _configured_secret_material stub -> None (Task 4 not built)."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_SECRET_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_AES}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=10)
    cfg = _cfg(wrap_key_handle=77)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "secret configured-KEK path not yet built (Task 4)" in description


def test_generic_secret_key_dispatches_to_material_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKO_SECRET_KEY + CKK_GENERIC_SECRET is accepted too (dispatches to the same stub)."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_SECRET_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_GENERIC_SECRET}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=11)
    cfg = _cfg(wrap_key_handle=88)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "secret configured-KEK path not yet built (Task 4)" in description


def test_unsupported_secret_key_type_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKO_SECRET_KEY but a non-AES/generic-secret key type (e.g. DES) -> None."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_SECRET_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_DES}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=12)
    cfg = _cfg(wrap_key_handle=99)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "configured secret key type unsupported" in description


def test_unsupported_object_class_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured object that is neither a private key nor a secret key -> None."""
    captured = _notes_spy(monkeypatch)

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_PUBLIC_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_RSA}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=13)
    cfg = _cfg(wrap_key_handle=111)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "configured object class unsupported" in description


# ---------------------------------------------------------------------------
# Handle takes priority over label when both are configured
# ---------------------------------------------------------------------------


def test_handle_takes_priority_over_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both wrap_key_handle and wrap_key_label set -> handle wins; find_objects unused."""
    captured = _notes_spy(monkeypatch)
    find_objects_calls: list[Any] = []

    def fake_find_objects(raw: Any, session: int, tmpl: Any, **kwargs: Any) -> list[int]:
        find_objects_calls.append(tmpl)
        return [123]

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        assert handle == 42  # the configured handle, not a label-resolved one
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_PUBLIC_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_RSA}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find_objects)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=14)
    cfg = _cfg(wrap_key_handle=42, wrap_key_label="some-label")

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert find_objects_calls == []
    assert len(captured) == 1
