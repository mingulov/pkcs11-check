"""QC8a + QC8b contracts (#61.1, #61.2): wrap/KEM handle roles and unwrap defaults.

Drives the real production methods in ``ckr/test_ckr_wrap``,
``ckr/test_ckr_kem`` and ``security/test_unwrap_reimport`` against a
scriptable raw ``C_*`` fake. Only staging factories are monkeypatched;
classification, ``read_attributes`` and the full-inventory delta run for
real. Mapping (preflight C11): this file is QC8a + QC8b;
``tests/test_derived_key_format_contract.py`` is QC8c.
"""

from __future__ import annotations

import ctypes
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_ALWAYS_SENSITIVE,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_UNEXTRACTABLE,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
)
from pkcs11_check.testcases.ckr import test_ckr_kem as tkem
from pkcs11_check.testcases.ckr import test_ckr_wrap as tcw
from pkcs11_check.testcases.security import test_unwrap_reimport as unwrap_mod

_OK = int(CKR_OK)
_UNDEFINED = 0x12345678
_DEAD_HANDLE = 0x777
_CT_PATTERN = b"\xa5" * 1088
_MISSING = object()
_MALFORMED = object()
_U64 = int(CK_UNAVAILABLE_INFORMATION)


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    classification.clear()
    yield
    classification.clear()


def _fill(out: Any, value: int, ctype: Any = CK_ULONG) -> None:
    ctypes.cast(out, ctypes.POINTER(ctype)).contents.value = value


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    decoded: dict[int, bytes] = {}
    if tmpl is None:
        return decoded
    for i in range(int(count)):
        alen = int(tmpl[i].ulValueLen)
        addr = tmpl[i].pValue
        decoded[int(tmpl[i].type)] = (
            bytes(ctypes.string_at(addr, alen)) if addr and alen > 0 else b""
        )
    return decoded


class _Obj:
    def __init__(self, role: str) -> None:
        self.role = role
        self.destroyed = False
        self.attrs: dict[int, Any] = {}


class _Token:
    """Scriptable fake token: live-object store plus per-leg defect knobs."""

    def __init__(self) -> None:
        self.objects: dict[int, _Obj] = {}
        self.created: list[int] = []
        self.destroyed: list[int] = []
        self._next = 41
        self.events: list[str] = []
        self.wrap_calls: list[dict[str, Any]] = []
        self.unwrap_calls: list[dict[str, Any]] = []
        self.encap_calls: list[dict[str, Any]] = []
        self.decap_calls: list[dict[str, Any]] = []
        self.find_calls = 0
        self._find_pending: list[int] = []
        # Probe scripting (invalid-handle legs).
        self.probe_rv: int = _OK
        self.probe_handle_write: str = "sentinel"  # sentinel|zero|dead|created
        self.probe_creates: bool = False
        self.probe_created_handle: int | None = None
        # QC8b scripting.
        self.unwrapped_attrs: dict[int, Any] = {
            int(CKA_EXTRACTABLE): True,
            int(CKA_SENSITIVE): False,
            int(CKA_ALWAYS_SENSITIVE): False,
            int(CKA_NEVER_EXTRACTABLE): False,
        }
        self.operational_wrap_rv: int = _OK
        # Integrated-review (R9) scripting.
        self.fail_find_from_call: int | None = None
        self.find_fail_rv: int = int(CKR_GENERAL_ERROR)
        self.stage_rv: int | None = None
        self.stage_secret_mode: str = "created"  # created|foreign
        self.unwrap_rv: int = _OK
        self.unwrap_creates_on_refusal: bool = False
        self.unwrap_created_handle: int | None = None
        self.session = SimpleNamespace(raw=self, sh=7, has_mechanism=lambda _n: True)

    # -- staging factories (monkeypatched into production modules) ----------
    def _issue(self, role: str) -> int:
        handle = self._next
        self._next += 1
        self.objects[handle] = _Obj(role)
        self.created.append(handle)
        return handle

    def gen_aes_key(self, *_a: Any, **_k: Any) -> int:
        self.events.append("gen")
        return self._issue("staged")

    def gen_aes_key_or_xfail(self, *_a: Any, **_k: Any) -> int:
        self.events.append("gen")
        return self._issue("staged")

    def generate_ml_kem_keypair(self, *_a: Any, **_k: Any) -> tuple[int, int]:
        self.events.append("kem-gen")
        return self._issue("kem-pub"), self._issue("kem-priv")

    def _live(self, handle: int) -> bool:
        obj = self.objects.get(int(handle))
        return obj is not None and not obj.destroyed

    # -- raw C_* surface ------------------------------------------------------
    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.events.append("destroy")
        self.destroyed.append(int(handle))
        obj = self.objects.get(int(handle))
        if obj is not None:
            obj.destroyed = True
        return _OK

    def C_FindObjectsInit(self, _sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
        self.events.append("find-init")
        self.find_calls += 1
        if self.fail_find_from_call is not None and self.find_calls >= self.fail_find_from_call:
            self._find_pending = []
            return self.find_fail_rv
        self._find_pending = [h for h, o in self.objects.items() if not o.destroyed]
        return _OK

    def C_FindObjects(  # noqa: N802
        self, _sh: int, handles: Any, max_count: int, found: Any
    ) -> int:
        self.events.append("find")
        page = self._find_pending[: int(max_count)]
        self._find_pending = self._find_pending[len(page) :]
        for i, h in enumerate(page):
            handles[i] = h
        _fill(found, len(page))
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        self.events.append("find-final")
        self._find_pending = []
        return _OK

    def _probe_out(self, out: Any) -> int:
        """Apply the scripted creator-probe outcome; return the probe RV."""
        if self.probe_rv == _OK:
            handle = self._issue("probe-created")
            _fill(out, handle, CK_OBJECT_HANDLE)
            return _OK
        if self.probe_creates:
            created = self._issue("probe-created")  # left behind on refusal
            self.probe_created_handle = created
            if self.probe_handle_write == "created":
                _fill(out, created, CK_OBJECT_HANDLE)
                return self.probe_rv
        if self.probe_handle_write == "zero":
            _fill(out, 0, CK_OBJECT_HANDLE)
        elif self.probe_handle_write == "dead":
            _fill(out, _DEAD_HANDLE, CK_OBJECT_HANDLE)
        return self.probe_rv

    def _wrap_payload(self, out: Any, out_len: Any, rv: int) -> int:
        payload = b"W" * 24
        if out is None:
            _fill(out_len, len(payload) if rv == _OK else 0)
            return rv
        if rv == _OK:
            ctypes.memmove(out, payload, len(payload))
            _fill(out_len, len(payload))
        else:
            _fill(out_len, 0)
        return rv

    def C_WrapKey(  # noqa: N802
        self, _sh: int, _mech: Any, wrapping: int, target: int, out: Any, out_len: Any
    ) -> int:
        self.events.append("wrap")
        self.wrap_calls.append(
            {"wrapping": int(wrapping), "target": int(target), "query": out is None}
        )
        if not self._live(int(wrapping)) or not self._live(int(target)):
            if self.probe_creates:
                self.probe_created_handle = self._issue("probe-created")
            return self._wrap_payload(out, out_len, self.probe_rv)
        target_obj = self.objects[int(target)]
        if target_obj.role == "unwrapped":
            return self._wrap_payload(out, out_len, self.operational_wrap_rv)
        return self._wrap_payload(out, out_len, _OK)

    def C_UnwrapKey(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        unwrapping: int,
        _wrapped: Any,
        wrapped_len: int,
        tmpl: Any,
        count: int,
        out: Any,
    ) -> int:
        self.events.append("unwrap")
        attrs = _decode_template(tmpl, int(count))
        self.unwrap_calls.append(
            {"unwrapping": int(unwrapping), "len": int(wrapped_len), "attrs": attrs}
        )
        if not self._live(int(unwrapping)):
            return self._probe_out(out)
        if self.unwrap_rv != _OK:
            if self.unwrap_creates_on_refusal:
                created = self._issue("unwrapped")
                self.objects[created].attrs = dict(self.unwrapped_attrs)
                self.unwrap_created_handle = created
                _fill(out, created, CK_OBJECT_HANDLE)
            return self.unwrap_rv
        handle = self._issue("unwrapped")
        self.objects[handle].attrs = dict(self.unwrapped_attrs)
        _fill(out, handle, CK_OBJECT_HANDLE)
        return _OK

    def C_EncapsulateKey(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        pub: int,
        _tmpl: Any,
        _count: int,
        ct_buf: Any,
        ct_len: Any,
        secret: Any,
    ) -> int:
        self.events.append("encap")
        self.encap_calls.append({"pub": int(pub), "query": ct_buf is None})
        if not self._live(int(pub)):
            return self._probe_out(secret)
        if self.stage_rv is not None:
            return self.stage_rv
        if ct_buf is not None:
            ctypes.memmove(ct_buf, _CT_PATTERN, len(_CT_PATTERN))
        _fill(ct_len, len(_CT_PATTERN))
        if self.stage_secret_mode == "foreign":
            _fill(secret, int(pub), CK_OBJECT_HANDLE)
            return _OK
        handle = self._issue("kem-secret")
        _fill(secret, handle, CK_OBJECT_HANDLE)
        return _OK

    def C_DecapsulateKey(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        priv: int,
        _tmpl: Any,
        _count: int,
        ct_buf: Any,
        ct_len: int,
        secret: Any,
    ) -> int:
        self.events.append("decap")
        ct = bytes(ctypes.string_at(ctypes.addressof(ct_buf), int(ct_len)))
        self.decap_calls.append({"priv": int(priv), "ct": ct})
        if not self._live(int(priv)):
            return self._probe_out(secret)
        handle = self._issue("kem-secret")
        _fill(secret, handle, CK_OBJECT_HANDLE)
        return _OK

    def C_GetAttributeValue(  # noqa: N802
        self, _sh: int, handle: int, tmpl: Any, count: int
    ) -> int:
        obj = self.objects[int(handle)]
        rv = _OK
        for i in range(int(count)):
            attr = int(tmpl[i].type)
            value = obj.attrs.get(attr, _MISSING)
            if value is _MISSING:
                tmpl[i].ulValueLen = _U64
                rv = int(CKR_ATTRIBUTE_TYPE_INVALID)
                continue
            if value is _MALFORMED:
                data = b"\x01\x00"
            else:
                data = b"\x01" if value else b"\x00"
            if tmpl[i].pValue:
                ctypes.memmove(tmpl[i].pValue, data, min(len(data), int(tmpl[i].ulValueLen)))
            tmpl[i].ulValueLen = len(data)
        return rv


def _patch_wrap(mp: pytest.MonkeyPatch, fake: _Token) -> None:
    mp.setattr(tcw, "gen_aes_key", fake.gen_aes_key)


def _patch_kem(mp: pytest.MonkeyPatch, fake: _Token) -> None:
    mp.setattr(tkem, "_generate_ml_kem_keypair", fake.generate_ml_kem_keypair)


def _patch_unwrap_mod(mp: pytest.MonkeyPatch, fake: _Token) -> None:
    mp.setattr(unwrap_mod, "gen_aes_key", fake.gen_aes_key)
    mp.setattr(unwrap_mod, "gen_aes_key_or_xfail", fake.gen_aes_key_or_xfail)


def _must_fail(fn: Any, *args: Any, **kw: Any) -> Any:
    with pytest.raises(Failed) as ei:
        fn(*args, **kw)
    assert not isinstance(ei.value, XFailed), f"expected fail, got xfail: {ei.value}"
    return classification.get_records()[-1]


def _must_xfail(fn: Any, *args: Any, **kw: Any) -> Any:
    with pytest.raises(XFailed):
        fn(*args, **kw)
    return classification.get_records()[-1]


def _assert_cleaned(fake: _Token) -> None:
    assert sorted(set(fake.destroyed)) == sorted(set(fake.created)), (
        fake.created,
        fake.destroyed,
    )
    assert len(fake.destroyed) == len(set(fake.destroyed)), f"double destroy: {fake.destroyed}"


def _assert_cleaned_except(fake: _Token, alive: list[int]) -> None:
    """Every created handle except the unproved *alive* set destroyed once."""
    assert sorted(set(fake.destroyed)) == sorted(set(fake.created) - set(alive)), (
        fake.created,
        fake.destroyed,
        alive,
    )
    assert len(fake.destroyed) == len(set(fake.destroyed)), f"double destroy: {fake.destroyed}"
    for handle in alive:
        assert fake.objects[handle].destroyed is False


# --- QC8a role 2: wrapped target (RED 1, 2) ----------------------------------


def test_wrapped_target_destroyed_canonical_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_KEY_HANDLE_INVALID)
    _patch_wrap(monkeypatch, fake)
    tcw.TestWrapKeyErrors().test_wrapped_key_handle_invalid(
        fake.session, False, handle_kind="destroyed"
    )
    assert classification.get_records() == []
    assert fake.find_calls >= 2  # inventory brackets the judged call
    _assert_cleaned(fake)


@pytest.mark.parametrize("handle_kind", ["destroyed", "zero", "never_issued"])
def test_wrapped_target_object_handle_invalid_xfails(
    monkeypatch: pytest.MonkeyPatch, handle_kind: str
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_OBJECT_HANDLE_INVALID)
    _patch_wrap(monkeypatch, fake)
    rec = _must_xfail(
        tcw.TestWrapKeyErrors().test_wrapped_key_handle_invalid,
        fake.session,
        False,
        handle_kind=handle_kind,
    )
    assert rec.reason == "nonspec_reject"
    assert rec.kind == "lifecycle"
    assert rec.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
    assert rec.expected_ckr == ["CKR_KEY_HANDLE_INVALID"]
    _assert_cleaned(fake)


def test_wrapped_target_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.probe_rv = _OK
    _patch_wrap(monkeypatch, fake)
    rec = _must_fail(
        tcw.TestWrapKeyErrors().test_wrapped_key_handle_invalid,
        fake.session,
        False,
        handle_kind="zero",
    )
    assert rec.reason == "self_contradiction"
    _assert_cleaned(fake)


def test_wrapped_target_refusal_delta_xfails_unproved_alive_r1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_KEY_HANDLE_INVALID)
    fake.probe_creates = True
    _patch_wrap(monkeypatch, fake)
    rec = _must_xfail(
        tcw.TestWrapKeyErrors().test_wrapped_key_handle_invalid,
        fake.session,
        False,
        handle_kind="zero",
    )
    assert rec.reason == "honest_deviation"
    created = fake.probe_created_handle
    assert created is not None
    assert rec.detail["unproved_new_handles"] == [created]
    assert "wrapped_len_after" in rec.detail  # M1: wrap-role detail carried
    _assert_cleaned_except(fake, [created])


# --- QC8a role 1 extension: zero / never-issued wrapping key (RED 7) ---------


@pytest.mark.parametrize(
    ("rv", "outcome"),
    [
        (int(CKR_WRAPPING_KEY_HANDLE_INVALID), "pass"),
        (int(CKR_OBJECT_HANDLE_INVALID), "xfail"),
        (int(CKR_KEY_HANDLE_INVALID), "xfail"),
        (int(CKR_FUNCTION_FAILED), "xfail"),
        (0x80000001, "xfail"),
        (_UNDEFINED, "fail"),
        (_OK, "fail"),
    ],
)
@pytest.mark.parametrize("handle_kind", ["zero", "never_issued"])
def test_wrapping_key_zero_and_never_issued_tiers(
    monkeypatch: pytest.MonkeyPatch, handle_kind: str, rv: int, outcome: str
) -> None:
    fake = _Token()
    fake.probe_rv = rv
    _patch_wrap(monkeypatch, fake)
    fn = tcw.TestWrapKeyErrors().test_wrapping_key_handle_invalid_nonissued
    if outcome == "pass":
        fn(fake.session, False, handle_kind=handle_kind)
        assert classification.get_records() == []
    elif outcome == "xfail":
        rec = _must_xfail(fn, fake.session, False, handle_kind=handle_kind)
        assert rec.reason == "nonspec_reject"
        assert rec.expected_ckr == ["CKR_WRAPPING_KEY_HANDLE_INVALID"]
        assert rec.detail["new_handles"] == []  # M1: detail carried
        assert "wrapped_len_after" in rec.detail
    else:
        _must_fail(fn, fake.session, False, handle_kind=handle_kind)
    # Call shape: exactly one wrap, on a live staged target.
    assert len(fake.wrap_calls) == 1
    invalid = 0 if handle_kind == "zero" else fake.wrap_calls[0]["wrapping"]
    assert fake.wrap_calls[0]["wrapping"] == invalid
    if handle_kind == "never_issued":
        assert invalid not in (0, *fake.created)
        assert 0 < invalid < 2**32
    assert fake.wrap_calls[0]["target"] in fake.created
    _assert_cleaned(fake)


# --- QC8a role 3: unwrapping key (RED 3-6, 18) -------------------------------


def _run_unwrapping(mp: pytest.MonkeyPatch, fake: _Token, kind: str = "destroyed") -> None:
    _patch_wrap(mp, fake)
    tcw.TestUnwrapKeyErrors().test_unwrapping_key_handle_invalid(
        fake.session, False, handle_kind=kind
    )


@pytest.mark.parametrize("handle_kind", ["destroyed", "zero", "never_issued"])
def test_unwrapping_key_canonical_passes(monkeypatch: pytest.MonkeyPatch, handle_kind: str) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    _run_unwrapping(monkeypatch, fake, handle_kind)
    assert classification.get_records() == []
    # A genuine staging wrap precedes the probe; exactly one probe unwrap.
    assert fake.events.index("wrap") < fake.events.index("unwrap")
    assert len(fake.unwrap_calls) == 1
    assert fake.unwrap_calls[0]["len"] == 24
    _assert_cleaned(fake)


def test_unwrapping_key_accepted_after_destroy_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.probe_rv = _OK
    rec = _must_fail(_run_unwrapping, monkeypatch, fake)
    assert rec.reason == "self_contradiction"
    assert rec.kind == "lifecycle"
    assert rec.detail["new_handles"]  # leaked handle seen in the delta
    _assert_cleaned(fake)


def test_unwrap_refusal_unwritten_object_xfails_unproved_alive_r1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    fake.probe_creates = True
    rec = _must_xfail(_run_unwrapping, monkeypatch, fake)
    assert rec.reason == "honest_deviation"
    created = fake.probe_created_handle
    assert created is not None
    assert rec.detail["new_handles"] == [created]
    assert rec.detail["proved_new_handles"] == []
    assert rec.detail["unproved_new_handles"] == [created]
    _assert_cleaned_except(fake, [created])


def test_unwrap_refusal_writing_created_object_fails_r1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    fake.probe_creates = True
    fake.probe_handle_write = "created"
    rec = _must_fail(_run_unwrapping, monkeypatch, fake)
    assert rec.reason == "self_contradiction"
    created = fake.probe_created_handle
    assert created is not None
    assert rec.detail["proved_new_handles"] == [created]
    assert fake.destroyed.count(created) == 1
    _assert_cleaned(fake)


def test_unwrap_refusal_zero_write_is_not_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    fake.probe_handle_write = "zero"
    _run_unwrapping(monkeypatch, fake)
    assert classification.get_records() == []
    _assert_cleaned(fake)


def test_unwrap_refusal_dead_nonzero_write_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    fake.probe_handle_write = "dead"
    rec = _must_xfail(_run_unwrapping, monkeypatch, fake)
    assert rec.reason == "honest_deviation"
    assert rec.detail["handle_after"] == _DEAD_HANDLE
    assert rec.detail["handle_class"] == "dead-nonzero"
    assert rec.detail["new_handles"] == []
    assert _DEAD_HANDLE not in fake.destroyed  # never blind-destroyed
    _assert_cleaned(fake)


# --- QC8a roles 4-5: KEM keys (RED 8-10) -------------------------------------


def test_encap_destroyed_pub_key_handle_invalid_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_KEY_HANDLE_INVALID)
    _patch_kem(monkeypatch, fake)
    tkem.TestEncapsulateKeyErrors().test_encapsulation_key_handle_invalid(
        fake.session, False, handle_kind="destroyed"
    )
    assert classification.get_records() == []
    assert len(fake.encap_calls) == 1  # single raw call, no size-query pair
    assert fake.encap_calls[0]["query"] is False
    _assert_cleaned(fake)


def test_encap_object_handle_invalid_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_OBJECT_HANDLE_INVALID)
    _patch_kem(monkeypatch, fake)
    rec = _must_xfail(
        tkem.TestEncapsulateKeyErrors().test_encapsulation_key_handle_invalid,
        fake.session,
        False,
        handle_kind="zero",
    )
    assert rec.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
    assert rec.expected_ckr == ["CKR_KEY_HANDLE_INVALID"]
    assert len(fake.encap_calls) == 1
    _assert_cleaned(fake)


def test_decap_destroyed_priv_key_with_real_ciphertext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    _patch_kem(monkeypatch, fake)
    tkem.TestDecapsulateKeyErrors().test_decapsulation_key_handle_invalid(
        fake.session, False, handle_kind="destroyed"
    )
    assert classification.get_records() == []
    # Staging proof: one successful encapsulate precedes the decap probe and
    # the probe ciphertext is its output, not garbage.
    assert fake.events.index("encap") < fake.events.index("decap")
    assert fake.decap_calls[0]["ct"] == _CT_PATTERN
    _assert_cleaned(fake)


def test_decap_refusal_unwritten_secret_xfails_unproved_alive_r1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    fake.probe_creates = True
    _patch_kem(monkeypatch, fake)
    rec = _must_xfail(
        tkem.TestDecapsulateKeyErrors().test_decapsulation_key_handle_invalid,
        fake.session,
        False,
        handle_kind="never_issued",
    )
    assert rec.reason == "honest_deviation"
    created = fake.probe_created_handle
    assert created is not None
    assert rec.detail["new_handles"] == [created]
    assert rec.detail["proved_new_handles"] == []
    _assert_cleaned_except(fake, [created])


def test_decap_refusal_writing_created_secret_fails_r1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    fake.probe_creates = True
    fake.probe_handle_write = "created"
    _patch_kem(monkeypatch, fake)
    rec = _must_fail(
        tkem.TestDecapsulateKeyErrors().test_decapsulation_key_handle_invalid,
        fake.session,
        False,
        handle_kind="never_issued",
    )
    assert rec.reason == "self_contradiction"
    created = fake.probe_created_handle
    assert created is not None
    assert rec.detail["proved_new_handles"] == [created]
    assert fake.destroyed.count(created) == 1
    _assert_cleaned(fake)


# --- QC8a undefined RVs (RED 11) + cleanup sweep (RED 18) --------------------


@pytest.mark.parametrize("role", ["wrapped", "unwrapping", "encap", "decap"])
def test_handle_roles_undefined_rv_fails(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    fake = _Token()
    fake.probe_rv = _UNDEFINED

    def _wrapped() -> None:
        _patch_wrap(monkeypatch, fake)
        tcw.TestWrapKeyErrors().test_wrapped_key_handle_invalid(
            fake.session, False, handle_kind="zero"
        )

    def _encap() -> None:
        _patch_kem(monkeypatch, fake)
        tkem.TestEncapsulateKeyErrors().test_encapsulation_key_handle_invalid(
            fake.session, False, handle_kind="zero"
        )

    def _decap() -> None:
        _patch_kem(monkeypatch, fake)
        tkem.TestDecapsulateKeyErrors().test_decapsulation_key_handle_invalid(
            fake.session, False, handle_kind="zero"
        )

    runners: dict[str, Any] = {
        "wrapped": _wrapped,
        "unwrapping": lambda: _run_unwrapping(monkeypatch, fake, "zero"),
        "encap": _encap,
        "decap": _decap,
    }
    rec = _must_fail(runners[role])
    assert rec.kind == "metadata"
    assert rec.reason == "self_contradiction"
    _assert_cleaned(fake)


@pytest.mark.parametrize(
    "rv",
    [int(CKR_UNWRAPPING_KEY_HANDLE_INVALID), int(CKR_OBJECT_HANDLE_INVALID), _OK],
)
def test_unwrapping_cleanup_destroyed_equals_staged(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    fake = _Token()
    fake.probe_rv = rv
    if rv == _OK:
        _must_fail(_run_unwrapping, monkeypatch, fake)
    elif rv == int(CKR_OBJECT_HANDLE_INVALID):
        _must_xfail(_run_unwrapping, monkeypatch, fake)
    else:
        _run_unwrapping(monkeypatch, fake)
    _assert_cleaned(fake)


# --- QC8b: omitted CKA_EXTRACTABLE default (RED 12-17) -----------------------


def _run_omitted(mp: pytest.MonkeyPatch, fake: _Token) -> None:
    _patch_unwrap_mod(mp, fake)
    unwrap_mod.TestUnwrapOmittedExtractableDefault().test_omitted_extractable_defaults_true_and_wrappable(
        fake.session
    )


def _run_explicit_false(mp: pytest.MonkeyPatch, fake: _Token) -> None:
    _patch_unwrap_mod(mp, fake)
    unwrap_mod.TestUnwrapOmittedExtractableDefault().test_explicit_false_extractable_is_the_negative_control(
        fake.session
    )


def test_omitted_extractable_healthy_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    _run_omitted(monkeypatch, fake)
    assert classification.get_records() == []
    _assert_cleaned(fake)


@pytest.mark.parametrize("sensitive", [True, False])
def test_omitted_extractable_sensitive_either_value_passes(
    monkeypatch: pytest.MonkeyPatch, sensitive: bool
) -> None:
    fake = _Token()
    fake.unwrapped_attrs[int(CKA_SENSITIVE)] = sensitive
    _run_omitted(monkeypatch, fake)
    assert classification.get_records() == []
    _assert_cleaned(fake)


def test_omitted_extractable_missing_flag_is_the_defect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    del fake.unwrapped_attrs[int(CKA_EXTRACTABLE)]
    fake.operational_wrap_rv = int(CKR_KEY_UNEXTRACTABLE)
    rec = _must_xfail(_run_omitted, monkeypatch, fake)
    assert "CKA_EXTRACTABLE" in rec.label
    # The operational leg was still attempted, not skipped into a pass.
    unwrapped = [h for h, o in fake.objects.items() if o.role == "unwrapped"]
    assert any(c["target"] in unwrapped for c in fake.wrap_calls)
    _assert_cleaned(fake)


def test_omitted_extractable_true_claim_but_wrap_refused_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.operational_wrap_rv = int(CKR_KEY_UNEXTRACTABLE)
    rec = _must_fail(_run_omitted, monkeypatch, fake)
    assert rec.reason == "self_contradiction"
    assert rec.kind == "policy"
    _assert_cleaned(fake)


def test_omitted_extractable_false_default_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.unwrapped_attrs[int(CKA_EXTRACTABLE)] = False
    fake.operational_wrap_rv = int(CKR_KEY_UNEXTRACTABLE)
    rec = _must_fail(_run_omitted, monkeypatch, fake)
    assert rec.reason == "wrong_result"
    _assert_cleaned(fake)


@pytest.mark.parametrize("history", [int(CKA_ALWAYS_SENSITIVE), int(CKA_NEVER_EXTRACTABLE)])
def test_omitted_extractable_histories_true_fail(
    monkeypatch: pytest.MonkeyPatch, history: int
) -> None:
    fake = _Token()
    fake.unwrapped_attrs[history] = True
    fake.unwrapped_attrs[int(CKA_SENSITIVE)] = True  # token-specific outcome
    rec = _must_fail(_run_omitted, monkeypatch, fake)
    assert rec.kind == "metadata"
    _assert_cleaned(fake)


def test_explicit_false_canonical_refusal_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.unwrapped_attrs = {
        int(CKA_EXTRACTABLE): False,
        int(CKA_SENSITIVE): True,
        int(CKA_ALWAYS_SENSITIVE): True,
        int(CKA_NEVER_EXTRACTABLE): True,
    }
    fake.operational_wrap_rv = int(CKR_KEY_UNEXTRACTABLE)
    _run_explicit_false(monkeypatch, fake)
    assert classification.get_records() == []
    _assert_cleaned(fake)


def test_explicit_false_wrap_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.unwrapped_attrs = {
        int(CKA_EXTRACTABLE): False,
        int(CKA_SENSITIVE): True,
        int(CKA_ALWAYS_SENSITIVE): True,
        int(CKA_NEVER_EXTRACTABLE): True,
    }
    fake.operational_wrap_rv = _OK
    rec = _must_fail(_run_explicit_false, monkeypatch, fake)
    assert rec.reason == "self_contradiction"
    assert rec.kind == "policy"
    _assert_cleaned(fake)


def test_minimal_unwrap_template_really_omits_extractable_and_sensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    _run_omitted(monkeypatch, fake)
    assert len(fake.unwrap_calls) == 1
    attrs = fake.unwrap_calls[0]["attrs"]
    assert set(attrs) == {int(CKA_CLASS), int(CKA_KEY_TYPE), int(CKA_TOKEN)}
    assert int(CKA_EXTRACTABLE) not in attrs
    assert int(CKA_SENSITIVE) not in attrs
    assert int.from_bytes(attrs[int(CKA_CLASS)], sys.byteorder) == int(CKO_SECRET_KEY)
    assert int.from_bytes(attrs[int(CKA_KEY_TYPE)], sys.byteorder) == int(CKK_AES)
    assert attrs[int(CKA_TOKEN)] == b"\x00"


# --- Integrated re-review R9: staging ownership, undefined-RV preservation,
# --- and QC8b refused-unwrap creation ---------------------------------------


def test_decap_staging_foreign_secret_fails_without_destroying_it_r9(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.probe_rv = int(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
    fake.stage_secret_mode = "foreign"
    _patch_kem(monkeypatch, fake)
    rec = _must_fail(
        tkem.TestDecapsulateKeyErrors().test_decapsulation_key_handle_invalid,
        fake.session,
        False,
        handle_kind="never_issued",
    )
    assert rec.reason == "self_contradiction"
    pub = fake.created[0]
    assert fake.destroyed.count(pub) == 1
    _assert_cleaned(fake)


def test_decap_staging_undefined_rv_fails_r9(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Token()
    fake.stage_rv = _UNDEFINED
    _patch_kem(monkeypatch, fake)
    rec = _must_fail(
        tkem.TestDecapsulateKeyErrors().test_decapsulation_key_handle_invalid,
        fake.session,
        False,
        handle_kind="never_issued",
    )
    assert rec.reason == "self_contradiction"
    assert rec.kind == "metadata"
    _assert_cleaned(fake)


def test_decap_staging_clean_refusal_still_xfails_r9(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.stage_rv = int(CKR_FUNCTION_FAILED)
    _patch_kem(monkeypatch, fake)
    rec = _must_xfail(
        tkem.TestDecapsulateKeyErrors().test_decapsulation_key_handle_invalid,
        fake.session,
        False,
        handle_kind="never_issued",
    )
    assert rec.reason == "not_operational"
    _assert_cleaned(fake)


@pytest.mark.parametrize("role", ["wrapped", "encap"])
def test_undefined_refusal_survives_clean_inventory_failure_r9(
    monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    fake = _Token()
    fake.probe_rv = _UNDEFINED
    fake.fail_find_from_call = 2
    if role == "wrapped":
        _patch_wrap(monkeypatch, fake)
        rec = _must_fail(
            tcw.TestWrapKeyErrors().test_wrapped_key_handle_invalid,
            fake.session,
            False,
            handle_kind="zero",
        )
    else:
        _patch_kem(monkeypatch, fake)
        rec = _must_fail(
            tkem.TestEncapsulateKeyErrors().test_encapsulation_key_handle_invalid,
            fake.session,
            False,
            handle_kind="zero",
        )
    assert rec.reason == "self_contradiction"
    assert rec.kind == "metadata"
    assert rec.detail["inventory_rv"] == "CKR_GENERAL_ERROR"
    _assert_cleaned(fake)


def test_omitted_unwrap_clean_refusal_still_xfails_r9(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.unwrap_rv = int(CKR_FUNCTION_FAILED)
    rec = _must_xfail(_run_omitted, monkeypatch, fake)
    assert rec.reason == "not_operational"
    _assert_cleaned(fake)


def test_omitted_unwrap_refusal_creating_object_fails_r9(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.unwrap_rv = int(CKR_FUNCTION_FAILED)
    fake.unwrap_creates_on_refusal = True
    rec = _must_fail(_run_omitted, monkeypatch, fake)
    assert rec.reason == "self_contradiction"
    created = fake.unwrap_created_handle
    assert created is not None
    assert fake.destroyed.count(created) == 1
    _assert_cleaned(fake)


def test_explicit_false_unwrap_refusal_creating_object_fails_r9(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Token()
    fake.unwrap_rv = int(CKR_FUNCTION_FAILED)
    fake.unwrap_creates_on_refusal = True
    rec = _must_fail(_run_explicit_false, monkeypatch, fake)
    assert rec.reason == "self_contradiction"
    created = fake.unwrap_created_handle
    assert created is not None
    assert fake.destroyed.count(created) == 1
    _assert_cleaned(fake)
