"""Production-method contracts for QC7c CKA_UNIQUE_ID (#59.4).

Scope split (Task 18 brief ruling 6): this file covers QC7c only.
QC7a/QC7b/QC7d contracts live in ``test_attribute_encoding_contract.py``.

Every production leg is driven through its real testcase method in
``pkcs11_check.testcases.test_object_identity`` against a scriptable
fake token at the raw ``C_*`` layer. Fakes only; no provider is loaded.
Records must never carry unique-id bytes -- lengths only.
"""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CK_INFO,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_LABEL,
    CKA_UNIQUE_ID,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
)
from pkcs11_check.testcases import test_object_identity as identity_case
from tests._skip_assert import assert_skips, assert_xfails

_OK = int(CKR_OK)
_TYPE_INVALID = int(CKR_ATTRIBUTE_TYPE_INVALID)
_READ_ONLY = int(CKR_ATTRIBUTE_READ_ONLY)
_GENERAL = int(CKR_GENERAL_ERROR)
_UNAVAILABLE = int(CK_UNAVAILABLE_INFORMATION)
_UID = int(CKA_UNIQUE_ID)
_CALLER_UID = b"caller-supplied-id"


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    if tmpl is None:
        assert count == 0
        return {}
    decoded: dict[int, bytes] = {}
    for i in range(count):
        attr = tmpl[i]
        alen = int(attr.ulValueLen)
        addr = attr.pValue
        decoded[int(attr.type)] = ctypes.string_at(addr, alen) if addr and alen > 0 else b""
    return decoded


def _write_handle(ptr: Any, handle: int) -> None:
    ctypes.cast(ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = handle


class _IdentityRaw:
    """Scriptable fake token for the QC7c production methods."""

    def __init__(self) -> None:
        self.objects: dict[int, dict[int, bytes]] = {}
        self.destroyed: list[int] = []
        self.staged: list[int] = []
        self.create_calls: list[dict[int, bytes]] = []
        self.genkey_calls: list[dict[int, bytes]] = []
        self.copy_calls: list[dict[int, bytes]] = []
        self._next_handle = 200
        self._uid_counter = 0
        self._search: list[int] = []
        # Knobs.
        self.version: tuple[int, int] = (3, 2)
        self.getinfo_rv = _OK
        self.uid_mode = "fresh"  # fresh | missing | empty | duplicate | nonutf8
        self.copy_uid_mode = "fresh"  # fresh | same
        self.override_mode = "read_only"  # read_only | general | type_invalid | honor | ignore
        # O1 knobs: value written into the output handle on an override
        # refusal (None leaves the prefilled sentinel untouched), and a
        # per-operation object leaked before returning the refusal.
        self.override_handle_write: int | None = None
        self.override_leak_by_op: dict[str, str] = {}  # op -> labeled | unlabeled

    def _fresh_uid(self) -> bytes:
        self._uid_counter += 1
        if self.uid_mode == "duplicate":
            return b"same-id-for-all"
        if self.uid_mode == "nonutf8":
            return b"\xff\xfe" + str(self._uid_counter).encode()
        return f"uid-{self._uid_counter}".encode()

    def _alloc(self, attrs: dict[int, bytes], *, uid: bytes | None = None) -> int:
        self._next_handle += 1
        handle = self._next_handle
        stored = dict(attrs)
        if uid is not None:
            stored[_UID] = uid
        elif self.uid_mode == "missing":
            stored.pop(_UID, None)
        elif self.uid_mode == "empty":
            stored[_UID] = b""
        else:
            stored[_UID] = self._fresh_uid()
        self.objects[handle] = stored
        self.staged.append(handle)
        return handle

    def _override_outcome(self, attrs: dict[int, bytes]) -> int | None:
        """Return a refusal RV for a caller-UID template, or None to create."""
        if _UID not in attrs:
            return None
        if self.override_mode == "read_only":
            return _READ_ONLY
        if self.override_mode == "general":
            return _GENERAL
        if self.override_mode == "type_invalid":
            return _TYPE_INVALID
        return None  # honor / ignore: create

    def _apply_override_refusal(
        self, op: str, attrs: dict[int, bytes], handle_ptr: Any
    ) -> int | None:
        """Refuse a caller-UID template, applying the O1 leak/handle knobs."""
        refusal = self._override_outcome(attrs)
        if refusal is None:
            return None
        leak = self.override_leak_by_op.get(op, "none")
        if leak != "none":
            leak_attrs = dict(attrs)
            if leak == "unlabeled":
                leak_attrs.pop(int(CKA_LABEL), None)
            self._alloc(leak_attrs)
        if self.override_handle_write is not None:
            _write_handle(handle_ptr, self.override_handle_write)
        return refusal

    def _alloc_with_override(self, attrs: dict[int, bytes]) -> int:
        if _UID in attrs and self.override_mode == "honor":
            return self._alloc(attrs, uid=attrs[_UID])
        return self._alloc(attrs)

    # -- info / reads -------------------------------------------------------
    def C_GetInfo(self, info_ptr: Any) -> int:  # noqa: N802
        if self.getinfo_rv != _OK:
            return self.getinfo_rv
        info = ctypes.cast(info_ptr, ctypes.POINTER(CK_INFO)).contents
        info.cryptokiVersion.major = self.version[0]
        info.cryptokiVersion.minor = self.version[1]
        return _OK

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        stored = self.objects.get(int(handle))
        assert stored is not None, f"read from unknown handle {handle}"
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            blob = stored.get(attr)
            if blob is None:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(_TYPE_INVALID)
                continue
            if addr:
                ctypes.memmove(addr, blob, min(len(blob), cap))
            tmpl[i].ulValueLen = len(blob)
            row_rvs.append(_OK)
        return _TYPE_INVALID if _TYPE_INVALID in row_rvs else _OK

    # -- creators -------------------------------------------------------------
    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        if count == 0:
            return int(CKR_TEMPLATE_INCOMPLETE)
        attrs = _decode_template(tmpl, int(count))
        self.create_calls.append(attrs)
        refusal = self._apply_override_refusal("create", attrs, handle_ptr)
        if refusal is not None:
            return refusal
        _write_handle(handle_ptr, self._alloc_with_override(attrs))
        return _OK

    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        attrs = _decode_template(tmpl, int(count))
        self.genkey_calls.append(attrs)
        refusal = self._apply_override_refusal("generate", attrs, handle_ptr)
        if refusal is not None:
            return refusal
        _write_handle(handle_ptr, self._alloc_with_override(attrs))
        return _OK

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        pub_tmpl: Any,
        pub_count: int,
        priv_tmpl: Any,
        priv_count: int,
        pub_ptr: Any,
        priv_ptr: Any,
    ) -> int:
        pub = self._alloc(_decode_template(pub_tmpl, int(pub_count)))
        priv = self._alloc(_decode_template(priv_tmpl, int(priv_count)))
        _write_handle(pub_ptr, pub)
        _write_handle(priv_ptr, priv)
        return _OK

    def C_CopyObject(  # noqa: N802
        self, _sh: int, handle: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        attrs = _decode_template(tmpl, int(count)) if tmpl is not None else {}
        self.copy_calls.append(attrs)
        refusal = self._apply_override_refusal("copy", attrs, handle_ptr)
        if refusal is not None:
            return refusal
        source = dict(self.objects.get(int(handle), {}))
        source.update(attrs)
        if _UID in attrs and self.override_mode == "honor":
            copied = self._alloc(source, uid=attrs[_UID])
        elif self.copy_uid_mode == "same":
            copied = self._alloc(source, uid=source.get(_UID, b""))
        else:
            copied = self._alloc(source)
        _write_handle(handle_ptr, copied)
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        self.objects.pop(int(handle), None)
        return _OK

    # -- search -----------------------------------------------------------------
    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        wanted = _decode_template(tmpl, int(count))
        label = wanted.get(int(CKA_LABEL))
        self._search = [
            handle
            for handle, attrs in self.objects.items()
            if label is None or attrs.get(int(CKA_LABEL)) == label
        ]
        return _OK

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        take = self._search[: int(max_count)]
        for i, handle in enumerate(take):
            handles[i] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(take)
        self._search = []
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return _OK

    # -- KEM ----------------------------------------------------------------------
    def C_EncapsulateKey(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _pub: int,
        tmpl: Any,
        count: int,
        ct_buf: Any,
        ct_len_ptr: Any,
        handle_ptr: Any,
    ) -> int:
        ct_len = ctypes.cast(ct_len_ptr, ctypes.POINTER(CK_ULONG)).contents
        if ct_buf is None:
            ct_len.value = 8
            return int(CKR_BUFFER_TOO_SMALL)
        ctypes.memmove(ct_buf, b"\x33" * 8, 8)
        ct_len.value = 8
        attrs = _decode_template(tmpl, int(count)) if tmpl is not None else {}
        _write_handle(handle_ptr, self._alloc(attrs))
        return _OK

    def C_DecapsulateKey(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _priv: int,
        tmpl: Any,
        count: int,
        _ct: Any,
        _ct_len: int,
        handle_ptr: Any,
    ) -> int:
        attrs = _decode_template(tmpl, int(count)) if tmpl is not None else {}
        _write_handle(handle_ptr, self._alloc(attrs))
        return _OK


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _rs(fake: _IdentityRaw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=fake,
        sh=7,
        slot_id=0,
        has_mechanism=lambda *_a: True,
        has_mechanism_flag=lambda *_a: True,
    )


def _assert_cleanup(fake: _IdentityRaw) -> None:
    assert sorted(fake.destroyed) == sorted(fake.staged), (fake.destroyed, fake.staged)


def _assert_no_uid_bytes_in_records() -> None:
    for rec in C.get_records():
        blob = repr(rec.detail) + rec.summary
        assert "same-id-for-all" not in blob
        assert "uid-" not in blob
        assert _CALLER_UID.decode() not in blob


# --- healthy controls ----------------------------------------------------------


def test_created_objects_distinct_pass() -> None:
    fake = _IdentityRaw()
    identity_case.TestUniqueIdGeneration().test_created_objects_have_distinct_unique_ids(_rs(fake))
    _assert_cleanup(fake)


def test_generated_objects_distinct_pass() -> None:
    fake = _IdentityRaw()
    identity_case.TestUniqueIdGeneration().test_generated_objects_have_distinct_unique_ids(
        _rs(fake)
    )
    _assert_cleanup(fake)


def test_copy_gets_own_unique_id_pass() -> None:
    fake = _IdentityRaw()
    identity_case.TestUniqueIdGeneration().test_copy_gets_own_unique_id(_rs(fake))
    _assert_cleanup(fake)


def test_cross_creator_distinct_pass() -> None:
    fake = _IdentityRaw()
    identity_case.TestUniqueIdGeneration().test_unique_ids_distinct_across_creators(_rs(fake))
    _assert_cleanup(fake)


def test_kem_outputs_have_unique_ids_pass() -> None:
    fake = _IdentityRaw()
    identity_case.TestUniqueIdGeneration().test_kem_outputs_have_unique_ids(_rs(fake))
    _assert_cleanup(fake)


def test_unique_id_override_read_only_passes() -> None:
    fake = _IdentityRaw()
    identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create(_rs(fake))
    assert fake.staged == []
    identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_generate_and_copy(
        _rs(fake)
    )
    # The copy source was staged and must be cleaned up; no override object leaked.
    _assert_cleanup(fake)


# --- defect seeds (#18-#25) ------------------------------------------------------


def test_unique_id_missing_records_deviation() -> None:
    fake = _IdentityRaw()
    fake.uid_mode = "missing"
    assert_xfails(
        identity_case.TestUniqueIdGeneration().test_created_objects_have_distinct_unique_ids,
        _rs(fake),
    )
    assert any(rec.reason == "honest_deviation" for rec in C.get_records())
    _assert_cleanup(fake)


def test_unique_id_empty_fails() -> None:
    fake = _IdentityRaw()
    fake.uid_mode = "empty"
    with pytest.raises(Failed):
        identity_case.TestUniqueIdGeneration().test_created_objects_have_distinct_unique_ids(
            _rs(fake)
        )
    _assert_cleanup(fake)


def test_unique_id_duplicate_across_live_objects_fails() -> None:
    fake = _IdentityRaw()
    fake.uid_mode = "duplicate"
    with pytest.raises(Failed):
        identity_case.TestUniqueIdGeneration().test_unique_ids_distinct_across_creators(_rs(fake))
    _assert_no_uid_bytes_in_records()
    _assert_cleanup(fake)


def test_copy_retaining_source_unique_id_fails() -> None:
    fake = _IdentityRaw()
    fake.copy_uid_mode = "same"
    with pytest.raises(Failed):
        identity_case.TestUniqueIdGeneration().test_copy_gets_own_unique_id(_rs(fake))
    _assert_cleanup(fake)


def test_unique_id_override_honored_fails() -> None:
    fake = _IdentityRaw()
    fake.override_mode = "honor"
    with pytest.raises(Failed):
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create(_rs(fake))
    _assert_no_uid_bytes_in_records()
    _assert_cleanup(fake)


def test_unique_id_override_ignored_xfails() -> None:
    fake = _IdentityRaw()
    fake.override_mode = "ignore"
    assert_xfails(
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create,
        _rs(fake),
    )
    _assert_cleanup(fake)


def test_unique_id_override_other_clean_refusal_xfails() -> None:
    fake = _IdentityRaw()
    fake.override_mode = "general"
    assert_xfails(
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create,
        _rs(fake),
    )
    assert any(rec.actual_ckr == "CKR_GENERAL_ERROR" for rec in C.get_records())
    assert fake.staged == []


def test_unique_id_override_on_generate_honored_fails() -> None:
    fake = _IdentityRaw()
    fake.override_mode = "honor"
    with pytest.raises(Failed):
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_generate_and_copy(
            _rs(fake)
        )
    _assert_cleanup(fake)


def test_unique_id_below_version_floor_skips_visibly() -> None:
    fake = _IdentityRaw()
    fake.version = (2, 40)
    assert_skips(
        identity_case.TestUniqueIdGeneration().test_created_objects_have_distinct_unique_ids,
        _rs(fake),
        match="UNIQUE_ID",
    )
    assert fake.staged == []


def test_unique_id_getinfo_refusal_is_classified() -> None:
    fake = _IdentityRaw()
    fake.getinfo_rv = _GENERAL
    assert_xfails(
        identity_case.TestUniqueIdGeneration().test_created_objects_have_distinct_unique_ids,
        _rs(fake),
    )
    assert any(rec.actual_ckr == "CKR_GENERAL_ERROR" for rec in C.get_records())
    assert fake.staged == []


def test_unique_id_non_utf8_bytes_bucket() -> None:
    # Pinned bucket: a non-UTF8 id is an opaque byte-string id. Uniqueness
    # and nonemptiness are judged on the raw bytes; encoding alone passes.
    fake = _IdentityRaw()
    fake.uid_mode = "nonutf8"
    identity_case.TestUniqueIdGeneration().test_created_objects_have_distinct_unique_ids(_rs(fake))
    _assert_cleanup(fake)


# --- O1 refusal oracle (Task 18 Docker adjudication) --------------------------
#
# On a refused creator the spec defines no output-handle state: verdicts
# judge objects (label inventory + before/after inventory delta), never a
# bare handle write. Zero (CK_INVALID_HANDLE) and the untouched sentinel
# are the normalized writes; a dead nonzero write is an honest deviation.

_DEAD_HANDLE = 987_654


def _record(reason: str, label_part: str = "") -> Any:
    matches = [rec for rec in C.get_records() if rec.reason == reason and label_part in rec.label]
    assert len(matches) == 1, [(rec.reason, rec.label) for rec in C.get_records()]
    return matches[0]


def test_unique_id_override_zero_write_read_only_passes() -> None:
    fake = _IdentityRaw()
    fake.override_handle_write = 0
    identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create(_rs(fake))
    assert fake.staged == []
    assert fake.destroyed == []


def test_unique_id_override_zero_write_clean_refusal_xfails_nonspec() -> None:
    fake = _IdentityRaw()
    fake.override_mode = "general"
    fake.override_handle_write = 0
    assert_xfails(
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create,
        _rs(fake),
    )
    detail = _record("nonspec_reject", "C_CreateObject").detail
    assert detail["handle_after"] == 0
    assert detail["handle_class"] == "zero"
    assert detail["found_by_label"] == []
    assert detail["new_handles"] == []
    assert fake.staged == []
    assert fake.destroyed == []


def test_unique_id_override_zero_write_generate_and_copy_read_only_passes() -> None:
    fake = _IdentityRaw()
    fake.override_handle_write = 0
    identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_generate_and_copy(
        _rs(fake)
    )
    _assert_cleanup(fake)
    assert 0 not in fake.destroyed


def test_unique_id_override_dead_nonzero_handle_xfails_honest_deviation() -> None:
    fake = _IdentityRaw()
    fake.override_handle_write = _DEAD_HANDLE
    assert_xfails(
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create,
        _rs(fake),
    )
    detail = _record("honest_deviation", "C_CreateObject").detail
    assert detail["handle_after"] == _DEAD_HANDLE
    assert detail["handle_class"] == "dead-nonzero"
    assert detail["found_by_label"] == []
    assert detail["new_handles"] == []
    assert fake.staged == []
    assert _DEAD_HANDLE not in fake.destroyed


def test_unique_id_override_refusal_labeled_leak_fails() -> None:
    fake = _IdentityRaw()
    fake.override_mode = "general"
    fake.override_leak_by_op = {"create": "labeled"}
    with pytest.raises(Failed):
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create(_rs(fake))
    detail = _record("self_contradiction", "C_CreateObject").detail
    assert detail["handle_class"] == "sentinel"
    assert detail["found_by_label"] == fake.staged
    assert detail["new_handles"] == fake.staged
    _assert_cleanup(fake)


def test_unique_id_override_refusal_unlabeled_new_object_fails() -> None:
    fake = _IdentityRaw()
    fake.override_mode = "general"
    fake.override_leak_by_op = {"create": "unlabeled"}
    with pytest.raises(Failed):
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_create(_rs(fake))
    detail = _record("self_contradiction", "C_CreateObject").detail
    assert detail["handle_class"] == "sentinel"
    assert detail["found_by_label"] == []
    assert detail["new_handles"] == fake.staged
    _assert_cleanup(fake)


def test_unique_id_override_generate_leak_copy_zero_write_node() -> None:
    # SoftHSM shape from the adjudication: Generate refuses with
    # CKR_ATTRIBUTE_TYPE_INVALID yet leaks the labeled key (FAIL); Copy
    # refuses cleanly writing only CK_INVALID_HANDLE (nonspec xfail
    # record). The node FAILs via Generate alone.
    fake = _IdentityRaw()
    fake.override_mode = "type_invalid"
    fake.override_handle_write = 0
    fake.override_leak_by_op = {"generate": "labeled"}
    with pytest.raises(Failed):
        identity_case.TestUniqueIdOverride().test_unique_id_override_rejected_on_generate_and_copy(
            _rs(fake)
        )
    generate = _record("self_contradiction", "C_GenerateKey")
    assert generate.detail["found_by_label"] != []
    copy = _record("nonspec_reject", "C_CopyObject")
    assert copy.detail["handle_after"] == 0
    assert copy.detail["handle_class"] == "zero"
    assert copy.detail["found_by_label"] == []
    assert copy.detail["new_handles"] == []
    assert not [
        rec
        for rec in C.get_records()
        if rec.reason == "self_contradiction" and "C_CopyObject" in rec.label
    ]
    _assert_cleanup(fake)
