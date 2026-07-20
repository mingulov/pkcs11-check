"""Meta-test: build_wrap_context configured-KEK resolution path (no real module needed).

Covers _build_configured_wrap_context: handle probe / label search / class+key-type
dispatch, PLUS (Task 4) the real RSA/secret MATERIAL paths: public-half recovery
(_configured_rsa_pub_der), the usable()-gated strategy trial (_configured_strategy_trial),
and _configured_rsa_material/_configured_secret_material. Dispatch tests that used to
assert the Task-3 stub message now monkeypatch the (now real) material functions to
assert dispatch still routes correctly; the material paths themselves get dedicated
happy-path / all-fail / gate tests below.

Follows the pattern of tests/test_wrap_context_bootstrap.py: monkeypatch
pkcs11_check.raw.recipes.find_objects/read_attributes/unwrap_key/destroy_quietly and
pkcs11_check.compliance.note, reset _prov._PROFILE_CACHE between tests. ``_real_rsa_numbers``
mirrors the bootstrap test file's helper (real modulus/exponent bytes, not fixture strings).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_VALUE,
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


def _make_rs(sh: int, has_mechanism_fn: Any = None) -> Any:
    """Synthetic RS object with no real module."""
    has_mech: Any = has_mechanism_fn if has_mechanism_fn is not None else (lambda self, n: True)
    return type(
        "RS",
        (),
        {
            "raw": object(),
            "sh": sh,
            "slot_id": 0,
            "has_mechanism": has_mech,
        },
    )()


def _reset_cache() -> None:
    _prov._PROFILE_CACHE.clear()


def _real_rsa_numbers(bits: int = 2048) -> tuple[bytes, bytes]:
    """Generate a real RSA key and return (n_be_bytes, e_be_bytes)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub_numbers = priv.public_key().public_numbers()
    n = pub_numbers.n
    e = pub_numbers.e
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return n_bytes, e_bytes


def _cfg(
    *,
    wrap_key_label: str | None = None,
    wrap_key_handle: int | None = None,
    wrap_key_value: str | None = None,
    pin: str | None = "1234",
) -> Any:
    return SimpleNamespace(
        wrap_key_source="configured",
        wrap_key_label=wrap_key_label,
        wrap_key_handle=wrap_key_handle,
        wrap_key_value=wrap_key_value,
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
# Dispatch: RSA private key -> routes into _configured_rsa_material (never raises)
# ---------------------------------------------------------------------------


def test_rsa_private_key_dispatches_to_material_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKO_PRIVATE_KEY + CKK_RSA -> _configured_rsa_material called with (handle, label)."""
    calls: list[tuple[int, str | None]] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_PRIVATE_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_RSA}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    def fake_rsa_material(
        rs: Any, cfg: Any, handle: int, label: str | None, _fail: Any
    ) -> _prov.WrapContext | None:
        calls.append((handle, label))
        return None

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr(_prov, "_configured_rsa_material", fake_rsa_material)
    _reset_cache()

    rs = _make_rs(sh=9)
    cfg = _cfg(wrap_key_handle=66)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert calls == [(66, None)]


# ---------------------------------------------------------------------------
# Dispatch: AES secret key -> routes into _configured_secret_material (never raises)
# ---------------------------------------------------------------------------


def test_aes_secret_key_dispatches_to_material_function(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKO_SECRET_KEY + CKK_AES -> _configured_secret_material called with the handle."""
    calls: list[int] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_SECRET_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_AES}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    def fake_secret_material(
        rs: Any, cfg: Any, handle: int, _fail: Any
    ) -> _prov.WrapContext | None:
        calls.append(handle)
        return None

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr(_prov, "_configured_secret_material", fake_secret_material)
    _reset_cache()

    rs = _make_rs(sh=10)
    cfg = _cfg(wrap_key_handle=77)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert calls == [77]


def test_generic_secret_key_dispatches_to_material_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKO_SECRET_KEY + CKK_GENERIC_SECRET is accepted too (dispatches to the same function)."""
    calls: list[int] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if CKA_CLASS in attr_types:
            return {CKA_CLASS: CKO_SECRET_KEY}
        if CKA_KEY_TYPE in attr_types:
            return {CKA_KEY_TYPE: CKK_GENERIC_SECRET}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    def fake_secret_material(
        rs: Any, cfg: Any, handle: int, _fail: Any
    ) -> _prov.WrapContext | None:
        calls.append(handle)
        return None

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr(_prov, "_configured_secret_material", fake_secret_material)
    _reset_cache()

    rs = _make_rs(sh=11)
    cfg = _cfg(wrap_key_handle=88)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert calls == [88]


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


# ---------------------------------------------------------------------------
# Task 4: RSA material happy path -- public half via direct modulus/exponent read
# (label search for CKA_ID/CKA_LABEL public-key pairs comes up empty), trial
# round-trip succeeds, and the configured private key itself is never destroyed.
# ---------------------------------------------------------------------------


def test_rsa_happy_path_context_probe_and_never_destroys_kek(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA configured KEK resolves via direct modulus/exponent read; KEK handle never destroyed."""
    priv_handle = 66
    n_bytes, e_bytes = _real_rsa_numbers(2048)
    find_objects_calls: list[Any] = []
    unwrap_calls: list[int] = []
    destroyed: list[int] = []

    def fake_find_objects(raw: Any, session: int, tmpl: Any, **kwargs: Any) -> list[int]:
        find_objects_calls.append(tmpl)
        if len(find_objects_calls) == 1:
            return [priv_handle]  # wrap_key_label resolution in _build_configured_wrap_context
        return []  # CKA_LABEL-matched public-key search in _configured_rsa_pub_der -> leg 3

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if attr_types == (CKA_CLASS,):
            return {CKA_CLASS: CKO_PRIVATE_KEY}
        if attr_types == (CKA_KEY_TYPE,):
            return {CKA_KEY_TYPE: CKK_RSA}
        if attr_types == (CKA_ID,):
            return {}  # no CKA_ID -> skip leg 1 (no public-key-by-ID search)
        if CKA_MODULUS in attr_types and CKA_PUBLIC_EXPONENT in attr_types:
            return {CKA_MODULUS: n_bytes, CKA_PUBLIC_EXPONENT: e_bytes}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    def fake_unwrap_key(
        raw: Any,
        session: int,
        unwrapping_key: Any,
        wrapped_key: bytes,
        mechanism: Any,
        attrs: Any = None,
        *,
        mech_param: Any = None,
    ) -> int:
        unwrap_calls.append(unwrapping_key)
        return 900 + len(unwrap_calls)

    def fake_destroy_quietly(raw: Any, session: int, handle: int) -> None:
        destroyed.append(handle)

    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find_objects)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy_quietly)
    _reset_cache()

    rs = _make_rs(sh=20)
    cfg = _cfg(wrap_key_label="rsa-kek-label")

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is not None
    assert ctx.strategy_name is not None
    assert ctx.rsa_unwrap_handle == priv_handle
    assert ctx.rsa_pub_der is not None
    assert _prov.profile_for(rs).rsa_pub_der_probe == ctx.rsa_pub_der
    # The configured KEK's private-key handle must never be destroyed -- only the
    # trial probe handle returned by the (faked) C_UnwrapKey appears in destroyed.
    assert priv_handle not in destroyed
    assert len(destroyed) >= 1
    assert all(h != priv_handle for h in destroyed)


# ---------------------------------------------------------------------------
# Finding 1 (final-review harden): a PRESENT-but-degenerate RSA public half
# (e.g. zero-length CKA_MODULUS/CKA_PUBLIC_EXPONENT) must resolve to None via
# the normal "cannot recover the RSA public half" note -- never let
# RSAPublicNumbers(...).public_key() raise ValueError out to the test.
# ---------------------------------------------------------------------------


def test_rsa_degenerate_modulus_returns_none_not_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct-read leg returns present-but-empty CKA_MODULUS/CKA_PUBLIC_EXPONENT
    (e.g. b"") and no public object is found by CKA_ID or CKA_LABEL -> None,
    with the standard public-half-unrecoverable note, not a raw ValueError."""
    priv_handle = 66
    captured = _notes_spy(monkeypatch)
    find_objects_calls: list[Any] = []

    def fake_find_objects(raw: Any, session: int, tmpl: Any, **kwargs: Any) -> list[int]:
        find_objects_calls.append(tmpl)
        if len(find_objects_calls) == 1:
            return [priv_handle]  # wrap_key_label resolution in _build_configured_wrap_context
        return []  # CKA_LABEL-matched public-key search in _configured_rsa_pub_der -> leg 3

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if attr_types == (CKA_CLASS,):
            return {CKA_CLASS: CKO_PRIVATE_KEY}
        if attr_types == (CKA_KEY_TYPE,):
            return {CKA_KEY_TYPE: CKK_RSA}
        if attr_types == (CKA_ID,):
            return {}  # no CKA_ID -> skip leg 1 (no public-key-by-ID search)
        if CKA_MODULUS in attr_types and CKA_PUBLIC_EXPONENT in attr_types:
            # Present but degenerate: empty bytes -> int 0.
            return {CKA_MODULUS: b"", CKA_PUBLIC_EXPONENT: b""}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    monkeypatch.setattr("pkcs11_check.raw.recipes.find_objects", fake_find_objects)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    rs = _make_rs(sh=25)
    cfg = _cfg(wrap_key_label="rsa-kek-label")

    # Must not raise (ValueError from RSAPublicNumbers(0, 0).public_key() must
    # never escape) -- a bare call is part of the assertion.
    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(captured) == 1
    description, _level = captured[0]
    assert "cannot recover the RSA public half" in description


# ---------------------------------------------------------------------------
# Task 4: secret material happy path -- wrap_key_value hex is used directly,
# CKA_VALUE is never read off the token.
# ---------------------------------------------------------------------------


def test_secret_happy_path_with_wrap_key_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """Secret configured KEK with wrap_key_value hex -> aes_kwp wins; CKA_VALUE never read."""
    sym_handle = 77
    wkv_hex = "11" * 32  # 32 bytes -> valid AES-256 key length
    unwrap_calls: list[int] = []
    destroyed: list[int] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if attr_types == (CKA_CLASS,):
            return {CKA_CLASS: CKO_SECRET_KEY}
        if attr_types == (CKA_KEY_TYPE,):
            return {CKA_KEY_TYPE: CKK_AES}
        raise AssertionError(
            f"unexpected attr_types {attr_types!r} "
            "(CKA_VALUE must not be read when wrap_key_value is configured)"
        )

    def fake_unwrap_key(
        raw: Any,
        session: int,
        unwrapping_key: Any,
        wrapped_key: bytes,
        mechanism: Any,
        attrs: Any = None,
        *,
        mech_param: Any = None,
    ) -> int:
        unwrap_calls.append(unwrapping_key)
        return 800 + len(unwrap_calls)

    def fake_destroy_quietly(raw: Any, session: int, handle: int) -> None:
        destroyed.append(handle)

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy_quietly)
    _reset_cache()

    rs = _make_rs(sh=21)
    cfg = _cfg(wrap_key_handle=sym_handle, wrap_key_value=wkv_hex)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is not None
    assert ctx.strategy_name == "aes_kwp"
    assert ctx.aes_kek_handle == sym_handle
    assert ctx.sym_kek == bytes.fromhex(wkv_hex)
    assert ctx.rsa_pub_der is None
    assert ctx.rsa_unwrap_handle is None
    assert len(unwrap_calls) == 1
    assert sym_handle not in destroyed


# ---------------------------------------------------------------------------
# Task 4: non-extractable secret KEK without wrap_key_value -> CKA_VALUE unreadable
# -> sym_kek None -> AesKwp lacks material -> all-fail note + None.
# ---------------------------------------------------------------------------


def test_secret_nonextractable_without_wrap_key_value_all_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-extractable secret KEK, no wrap_key_value -> CKA_VALUE read fails -> None."""
    sym_handle = 88
    captured = _notes_spy(monkeypatch)
    unwrap_calls: list[Any] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if attr_types == (CKA_CLASS,):
            return {CKA_CLASS: CKO_SECRET_KEY}
        if attr_types == (CKA_KEY_TYPE,):
            return {CKA_KEY_TYPE: CKK_AES}
        if attr_types == (CKA_VALUE,):
            raise CkrAssertionError("value unreadable", CKR_OBJECT_HANDLE_INVALID)
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    def fake_unwrap_key(*args: Any, **kwargs: Any) -> int:
        unwrap_calls.append((args, kwargs))
        raise AssertionError("unwrap_key must not be called: no strategy has material")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    _reset_cache()

    rs = _make_rs(sh=22)
    cfg = _cfg(wrap_key_handle=sym_handle)  # wrap_key_value stays None

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert unwrap_calls == []
    assert len(captured) == 1
    description, _level = captured[0]
    assert "failed every usable strategy" in description


# ---------------------------------------------------------------------------
# Task 4: usable() gate -- a profile that advertises no unwrap mechanism must
# reject every strategy before any unwrap_key call is ever attempted.
# ---------------------------------------------------------------------------


def test_usable_gate_rejects_all_no_unwrap_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """No advertised unwrap mechanism -> every strategy.usable() False -> None, no C_UnwrapKey."""
    captured = _notes_spy(monkeypatch)
    unwrap_calls: list[Any] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if attr_types == (CKA_CLASS,):
            return {CKA_CLASS: CKO_SECRET_KEY}
        if attr_types == (CKA_KEY_TYPE,):
            return {CKA_KEY_TYPE: CKK_AES}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    def fake_unwrap_key(*args: Any, **kwargs: Any) -> int:
        unwrap_calls.append((args, kwargs))
        raise AssertionError("unwrap_key must not be called: no strategy is usable")

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    _reset_cache()

    rs = _make_rs(sh=23, has_mechanism_fn=lambda self, n: False)
    cfg = _cfg(wrap_key_handle=99, wrap_key_value="22" * 16)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert unwrap_calls == []
    assert len(captured) == 1
    description, _level = captured[0]
    assert "failed every usable strategy" in description


# ---------------------------------------------------------------------------
# Task 4: all-trials-fail -- material is available (has_material True) but every
# C_UnwrapKey trial is refused -> all candidates exhausted -> note + None.
# ---------------------------------------------------------------------------


def test_all_trials_fail_note_and_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Material resolves fine but C_UnwrapKey always refuses -> every trial exhausted -> None."""
    priv_handle = 111
    n_bytes, e_bytes = _real_rsa_numbers(2048)
    captured = _notes_spy(monkeypatch)
    unwrap_calls: list[int] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if attr_types == (CKA_CLASS,):
            return {CKA_CLASS: CKO_PRIVATE_KEY}
        if attr_types == (CKA_KEY_TYPE,):
            return {CKA_KEY_TYPE: CKK_RSA}
        if attr_types == (CKA_ID,):
            return {}
        if CKA_MODULUS in attr_types and CKA_PUBLIC_EXPONENT in attr_types:
            return {CKA_MODULUS: n_bytes, CKA_PUBLIC_EXPONENT: e_bytes}
        raise AssertionError(f"unexpected attr_types {attr_types!r}")

    def fake_unwrap_key(
        raw: Any,
        session: int,
        unwrapping_key: Any,
        wrapped_key: bytes,
        mechanism: Any,
        attrs: Any = None,
        *,
        mech_param: Any = None,
    ) -> int:
        unwrap_calls.append(unwrapping_key)
        raise CkrAssertionError("unwrap refused", CKR_OBJECT_HANDLE_INVALID)

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    _reset_cache()

    rs = _make_rs(sh=24)
    cfg = _cfg(wrap_key_handle=priv_handle)

    ctx = _prov.build_wrap_context(rs, cfg)

    assert ctx is None
    assert len(unwrap_calls) >= 1
    assert len(captured) == 1
    description, _level = captured[0]
    assert "failed every usable strategy" in description
