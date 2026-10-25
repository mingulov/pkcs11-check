"""QC9b logout object-lifetime contracts.

Behavioral contracts for PKCS#11 logout object lifetime, driven through the
production test methods against a stateful fake token. Native ctypes-level
fakes only; no provider is loaded and no Docker is used.

Covered production behavior:

- ``TestSessionObjectsAfterLogout`` (repaired premise): explicit
  CKA_PRIVATE/CKA_TOKEN requested AND read back; a surviving explicitly
  private session object FAILS. The legacy omitted-attribute stimulus is an
  independently selectable ``test_default_visibility_after_logout`` node (R9):
  a distinct default/visibility observation (a note, never a verdict).
- ``TestLogoutEffects.test_logout_object_lifetime_across_two_sessions``:
  explicit private-session / public-session / private-token objects across
  two sessions. Successful logout invalidates ALL old private handles,
  checked immediately after logout AND after relogin before reacquisition.
  The private-session object is destroyed, the public-session object
  remains, and the private-token object persists and is reacquirable. A
  reacquired token handle must also prove usable with matching identity;
  a reacquired handle may reuse the old integer. Held-open crypto/find
  operations are observations only (PKCS#11 v3.0 section 5.6.10 permits
  active operations to remain or terminate).
"""

from __future__ import annotations

import ctypes
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

import pkcs11_check.compliance as compliance
from pkcs11_check import classification as C  # noqa: N812 - matches project convention
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases import test_session_state_machine as tssm
from pkcs11_check.testcases.security import test_cve_regression

_BOOL_ATTRS = frozenset(
    {CKA_TOKEN, CKA_PRIVATE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SENSITIVE, CKA_EXTRACTABLE}
)
_ULONG_ATTRS = frozenset({CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN})
_UNAVAILABLE = 0xFFFFFFFFFFFFFFFF


def _fill_ulong(out: Any, value: int) -> None:
    """Write an out-handle passed as ``byref(ctypes_scalar)``."""
    ctypes.cast(out, ctypes.POINTER(ctypes.c_ulong)).contents.value = value


def _decode_template(tmpl_ptr: Any, count: int) -> dict[int, Any]:
    """Decode a packed creation/search template the way the token would."""
    decoded: dict[int, Any] = {}
    for i in range(count):
        attr = tmpl_ptr[i]
        atype = int(attr.type)
        size = int(attr.ulValueLen)
        raw = bytes(ctypes.string_at(attr.pValue, size)) if size and attr.pValue else b""
        if atype in _BOOL_ATTRS:
            decoded[atype] = len(raw) > 0 and raw[0] != 0
        elif atype in _ULONG_ATTRS:
            decoded[atype] = int.from_bytes(raw, sys.byteorder) if raw else 0
        else:
            decoded[atype] = raw
    return decoded


class _FakeObject:
    """One token object with logout-lifetime state."""

    def __init__(
        self,
        *,
        handle: int,
        label: bytes,
        klass: int,
        private: bool,
        token: bool,
        session: int,
    ) -> None:
        self.handle = handle
        self.label = label
        self.klass = klass
        self.private = private
        self.token = token
        self.session = session
        self.destroyed = False
        # Successful logout invalidates every private handle permanently;
        # relogin must not restore it (spec: "those handles remain invalid").
        self.valid = True


class _FakeRaw:
    """A stateful fake token answering the raw C_* logout-lifetime surface.

    Default switches model a conformant provider; each defect switch seeds
    exactly one deviation the production oracles must catch.
    """

    # noqa comments below: raw PKCS#11 entry-point names are mandated.
    def __init__(
        self,
        *,
        logout_rv: int = int(CKR_OK),
        stale_rv: int = int(CKR_OBJECT_HANDLE_INVALID),
        stale_ok_prefixes: tuple[bytes, ...] = (),
        keep_private_session: bool = False,
        destroy_public_session: bool = False,
        destroy_private_token: bool = False,
        resurrect_after_relogin: bool = False,
        reissue_handles: bool = False,
        readback_flip: bool = False,
        omit_attrs: frozenset[int] = frozenset(),
        find_op_rv: int = int(CKR_OK),
        digest_op_rv: int = int(CKR_OK),
        find_init_rv: int = int(CKR_OK),
        digest_init_rv: int = int(CKR_OK),
        find_miss_prefixes: tuple[bytes, ...] = (),
        keygen_rv: int = int(CKR_OK),
        create_rv: int = int(CKR_OK),
        default_private: bool = False,
        unusable_reacquired_prefixes: tuple[bytes, ...] = (),
        reacquired_identity_flip: bool = False,
        stale_refusal_with_data: bool = False,
    ) -> None:
        self._logout_rv = logout_rv
        self._stale_rv = stale_rv
        self._stale_ok_prefixes = stale_ok_prefixes
        self._keep_private_session = keep_private_session
        self._destroy_public_session = destroy_public_session
        self._destroy_private_token = destroy_private_token
        self._resurrect_after_relogin = resurrect_after_relogin
        self._reissue_handles = reissue_handles
        self._readback_flip = readback_flip
        self._omit_attrs = omit_attrs
        self._find_op_rv = find_op_rv
        self._digest_op_rv = digest_op_rv
        self._find_init_rv = find_init_rv
        self._digest_init_rv = digest_init_rv
        self._find_miss_prefixes = find_miss_prefixes
        self._keygen_rv = keygen_rv
        self._create_rv = create_rv
        self._default_private = default_private
        self._unusable_reacquired_prefixes = unusable_reacquired_prefixes
        self._reacquired_identity_flip = reacquired_identity_flip
        self._stale_refusal_with_data = stale_refusal_with_data
        self.logged_in = False
        self.logout_seen = False
        self._relogin_seen = False
        self._next_session = 11
        self._next_handle = 101
        self.sessions: set[int] = set()
        self.objects: dict[int, _FakeObject] = {}
        self._searches: dict[int, tuple[int | None, bytes | None, bool]] = {}
        # Ordered evidence log for sequencing assertions.
        self.ops: list[str] = []
        self.creations: list[tuple[int, dict[int, Any]]] = []
        self.reads: list[tuple[int, int, list[int]]] = []
        self.finds: list[tuple[int, bytes | None, list[int]]] = []
        self.destroys: list[tuple[int, int]] = []

    # -- sessions ------------------------------------------------------
    def C_OpenSession(self, slot_id: int, flags: int, *_args: Any) -> int:  # noqa: N802
        handle = self._next_session
        self._next_session += 1
        self.sessions.add(handle)
        _fill_ulong(_args[-1], handle)
        self.ops.append(f"open:{handle}")
        return int(CKR_OK)

    def C_CloseSession(self, session: int) -> int:  # noqa: N802
        self.sessions.discard(int(session))
        self._searches.pop(int(session), None)
        for obj in self.objects.values():
            if obj.session == int(session) and not obj.token:
                obj.destroyed = True
                obj.valid = False
        self.ops.append(f"close:{int(session)}")
        return int(CKR_OK)

    def C_Login(self, session: int, *_args: Any) -> int:  # noqa: N802
        self.ops.append("login")
        if self.logged_in:
            return int(CKR_USER_ALREADY_LOGGED_IN)
        if self.logout_seen:
            self._relogin_seen = True
        self.logged_in = True
        if self._reissue_handles:
            for old in [h for h, o in self.objects.items() if o.private and not o.destroyed]:
                obj = self.objects.pop(old)
                obj.handle = self._next_handle
                self._next_handle += 1
                self.objects[obj.handle] = obj
        return int(CKR_OK)

    def C_Logout(self, session: int) -> int:  # noqa: N802
        self.ops.append("logout")
        if self._logout_rv != int(CKR_OK):
            return self._logout_rv
        if not self.logged_in:
            return int(CKR_USER_NOT_LOGGED_IN)
        self.logged_in = False
        self.logout_seen = True
        for obj in self.objects.values():
            if obj.private:
                obj.valid = False
            if obj.token and obj.private and self._destroy_private_token:
                obj.destroyed = True
                obj.valid = False
            if not obj.token and not obj.private and self._destroy_public_session:
                obj.destroyed = True
                obj.valid = False
            if not obj.token and obj.private and not self._keep_private_session:
                obj.destroyed = True
                obj.valid = False
        return int(CKR_OK)

    # -- objects -------------------------------------------------------
    def _store(self, session: int, decoded: dict[int, Any], *, klass: int | None) -> _FakeObject:
        label = decoded.get(int(CKA_LABEL), b"")
        if isinstance(label, str):
            label = label.encode()
        requested = decoded.get(int(CKA_PRIVATE))
        private = bool(requested) if requested is not None else False
        if requested is None and self._default_private:
            # Seeded variant: this provider defaults omitted-attribute
            # objects to private, so logout destroys them.
            private = True
        if self._readback_flip and requested is not None:
            private = not private
        token = bool(decoded.get(int(CKA_TOKEN), False))
        obj = _FakeObject(
            handle=self._next_handle,
            label=bytes(label),
            klass=int(decoded.get(int(CKA_CLASS), klass)),
            private=private,
            token=token,
            session=int(session),
        )
        self._next_handle += 1
        self.objects[obj.handle] = obj
        self.creations.append((int(session), decoded))
        self.ops.append(f"create:{obj.label!r}")
        return obj

    def C_GenerateKey(  # noqa: N802
        self, session: int, _mech: Any, tmpl_ptr: Any, count: int, out: Any
    ) -> int:
        if self._keygen_rv != int(CKR_OK):
            return self._keygen_rv
        obj = self._store(session, _decode_template(tmpl_ptr, count), klass=int(CKO_SECRET_KEY))
        _fill_ulong(out, obj.handle)
        return int(CKR_OK)

    def C_CreateObject(self, session: int, tmpl_ptr: Any, count: int, out: Any) -> int:  # noqa: N802
        if self._create_rv != int(CKR_OK):
            return self._create_rv
        obj = self._store(session, _decode_template(tmpl_ptr, count), klass=int(CKO_DATA))
        _fill_ulong(out, obj.handle)
        return int(CKR_OK)

    def C_DestroyObject(self, session: int, handle: int) -> int:  # noqa: N802
        self.destroys.append((int(session), int(handle)))
        self.ops.append(f"destroy:{int(handle)}")
        obj = self.objects.get(int(handle))
        if obj is not None:
            obj.destroyed = True
            obj.valid = False
        return int(CKR_OK)

    # -- attribute reads ------------------------------------------------
    def _encode_attr(self, obj: _FakeObject | None, atype: int) -> bytes:
        if obj is None:
            if atype == int(CKA_CLASS):
                return int(CKO_SECRET_KEY).to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)
            return b"\x00"
        if atype == int(CKA_PRIVATE):
            return b"\x01" if obj.private else b"\x00"
        if atype == int(CKA_TOKEN):
            return b"\x01" if obj.token else b"\x00"
        if atype in _ULONG_ATTRS:
            value = obj.klass if atype == int(CKA_CLASS) else 0
            return int(value).to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)
        if atype == int(CKA_LABEL):
            if self._reacquired_identity_flip and self._relogin_seen:
                # Seeded defect: post-relogin identity reads report the
                # wrong label (only the usability leg reads labels then).
                return b"qc9b-wrong-label"
            return obj.label
        if atype == int(CKA_VALUE):
            return b"qc9b-public"
        return b"\x00"

    def C_GetAttributeValue(self, session: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        obj = self.objects.get(int(handle))
        self.reads.append((int(session), int(handle), [int(tmpl[i].type) for i in range(count)]))
        self.ops.append(f"read:{int(session)}:{int(handle)}")
        if obj is None or obj.destroyed or not obj.valid:
            if obj is not None and obj.label.startswith(self._stale_ok_prefixes):
                return self._answer_attrs(obj, tmpl, count)
            if obj is not None and self._resurrect_after_relogin and self._relogin_seen:
                # Defect: relogin revalidated the stale handle (use-after-logout).
                return self._answer_attrs(obj, tmpl, count)
            if self._stale_rv in (
                int(CKR_ATTRIBUTE_SENSITIVE),
                int(CKR_ATTRIBUTE_TYPE_INVALID),
            ):
                if self._stale_refusal_with_data:
                    # Seeded defect: the refusal CKR is accompanied by
                    # real attribute bytes (refusal-with-data).
                    self._answer_attrs(obj, tmpl, count)
                    return self._stale_rv
                # Faithful refusal shape: the overall refusal RV plus the
                # CK_UNAVAILABLE_INFORMATION sentinel per requested attribute.
                for i in range(count):
                    tmpl[i].ulValueLen = _UNAVAILABLE
            return self._stale_rv
        return self._answer_attrs(obj, tmpl, count)

    def _answer_attrs(self, obj: _FakeObject | None, tmpl: Any, count: int) -> int:
        size_query = all(tmpl[i].pValue is None for i in range(count))
        for i in range(count):
            atype = int(tmpl[i].type)
            if atype in self._omit_attrs:
                tmpl[i].ulValueLen = _UNAVAILABLE
                continue
            data = self._encode_attr(obj, atype)
            if size_query:
                tmpl[i].ulValueLen = len(data)
            elif tmpl[i].pValue is not None:
                ctypes.memmove(tmpl[i].pValue, data, len(data))
        return int(CKR_OK)

    # -- search ----------------------------------------------------------
    def C_FindObjectsInit(self, session: int, tmpl_ptr: Any, count: int) -> int:  # noqa: N802
        self.ops.append(f"find_init:{int(session)}")
        if self._find_init_rv != int(CKR_OK) and self._is_held_open_init(tmpl_ptr, count):
            return self._find_init_rv
        if tmpl_ptr is None or count == 0:
            self._searches[int(session)] = (None, None, True)
        else:
            decoded = _decode_template(tmpl_ptr, count)
            klass = decoded.get(int(CKA_CLASS))
            label = decoded.get(int(CKA_LABEL))
            self._searches[int(session)] = (
                int(klass) if klass is not None else None,
                bytes(label) if label is not None else None,
                False,
            )
        return int(CKR_OK)

    @staticmethod
    def _is_held_open_init(tmpl_ptr: Any, count: int) -> bool:
        # The production observation leg stages its held-open search with a
        # NULL template; every recipe find passes a label-scoped template.
        return tmpl_ptr is None or count == 0

    def C_FindObjects(self, session: int, buf: Any, max_count: int, out: Any) -> int:  # noqa: N802
        klass, label, held_open = self._searches.get(int(session), (None, None, False))
        if held_open and not self.logged_in:
            # The held-open observation leg continues its NULL-template
            # search while logged out; label-scoped recipe finds always
            # search (public objects stay visible while logged out).
            self.ops.append("find_continue")
            _fill_ulong(out, 0)
            return self._find_op_rv
        matches = [
            handle
            for handle, obj in sorted(self.objects.items())
            if not obj.destroyed
            and (self.logged_in or not obj.private)
            and (klass is None or obj.klass == klass)
            and (label is None or obj.label == label)
            and not (self.logout_seen and obj.label.startswith(self._find_miss_prefixes))
        ]
        for i, handle in enumerate(matches[: int(max_count)]):
            buf[i] = handle
            # A handle returned by a post-login search is a fresh usable
            # handle -- even when the token reuses the old integer. The old
            # handle stays dead until this reacquisition find returns it,
            # so the pre-reacquisition probes still observe rejection.
            obj = self.objects[handle]
            if self.logged_in and not obj.label.startswith(self._unusable_reacquired_prefixes):
                obj.valid = True
        _fill_ulong(out, min(len(matches), int(max_count)))
        self.finds.append((int(session), label, matches))
        self.ops.append(f"find:{label!r}")
        return int(CKR_OK)

    def C_FindObjectsFinal(self, session: int) -> int:  # noqa: N802
        self._searches.pop(int(session), None)
        self.ops.append("find_final")
        return int(CKR_OK)

    # -- digest (observation leg only) ------------------------------------
    def C_DigestInit(self, session: int, _mech: Any) -> int:  # noqa: N802
        self.ops.append(f"digest_init:{int(session)}")
        return self._digest_init_rv

    def C_DigestUpdate(self, session: int, _data: Any, _length: int) -> int:  # noqa: N802
        self.ops.append("digest_update")
        return self._digest_op_rv

    def C_DigestFinal(self, session: int, _buf: Any, _out_len: Any) -> int:  # noqa: N802
        self.ops.append("digest_final")
        return int(CKR_OK)


def _session(raw: _FakeRaw, mechanisms: set[str] | None = None) -> SimpleNamespace:
    supported = mechanisms if mechanisms is not None else {"AES_KEY_GEN", "SHA256"}
    return SimpleNamespace(raw=raw, sh=1, slot_id=7, has_mechanism=lambda name: name in supported)


def _config(pin: str | None = "1234") -> SimpleNamespace:
    return SimpleNamespace(pin=pin)


def _capture_notes(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, Any, str]]:
    notes: list[tuple[str, Any, str]] = []
    monkeypatch.setattr(
        compliance,
        "note",
        lambda description, level, reference="", **_kwargs: notes.append(
            (description, level, reference)
        ),
    )
    return notes


def _positions(ops: list[str], marker: str) -> list[int]:
    return [i for i, op in enumerate(ops) if op == marker]


# ---------------------------------------------------------------------------
# Repaired TestSessionObjectsAfterLogout premise
# ---------------------------------------------------------------------------


def test_explicit_private_object_destroyed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit stimulus is proven and destroyed; nothing downgraded to a note.

    The legacy omitted-attribute stimulus lives in its own independently
    selectable production node now (R9 split); this oracle creates exactly
    the explicit object and emits no observation on the conformant path.
    """
    raw = _FakeRaw()
    notes = _capture_notes(monkeypatch)

    test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
        _session(raw), _config()
    )

    # The explicit stimulus requests private + session attributes ...
    assert len(raw.creations) == 1
    explicit = raw.creations[0][1]
    assert explicit[int(CKA_PRIVATE)] is True
    assert explicit[int(CKA_TOKEN)] is False
    # ... and reads them back before logout to prove the oracle's premise.
    priv_handle = next(
        handle for handle, obj in raw.objects.items() if obj.label == explicit[int(CKA_LABEL)]
    )
    stimulus = [entry for entry in raw.reads if entry[1] == priv_handle]
    assert [int(CKA_PRIVATE), int(CKA_TOKEN)] in [entry[2] for entry in stimulus]
    # Destroyed as required: no verdict, and no observation either (the
    # default/visibility observation is a separate node).
    assert C.get_records() == []
    assert notes == []


def test_surviving_explicit_private_session_object_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hidden-not-destroyed (reappears after relogin) is a failure, not a note."""
    raw = _FakeRaw(keep_private_session=True)
    notes = _capture_notes(monkeypatch)

    with pytest.raises(Failed, match="success claimed then contradicted"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "lifecycle"
    assert "destroyed by C_Logout" in records[0].label
    # The failure is about the explicit object; nothing was downgraded to a note.
    assert notes == []
    # The invalidated-handle probes ran before the reacquisition find, so the
    # verdict distinguishes hiding (old handle dead, object back) from reuse.
    logout_at = _positions(raw.ops, "logout")[0]
    login_at = _positions(raw.ops, "login")[-1]
    assert logout_at < login_at
    post_login = raw.ops[login_at + 1 :]
    reads = [i for i, op in enumerate(post_login) if op.startswith("read:")]
    finds = [i for i, op in enumerate(post_login) if op.startswith("find:")]
    assert reads and finds and max(reads) < min(finds)


def test_old_private_handle_usable_after_logout_fails() -> None:
    """An old private handle answering after logout is a lifecycle failure."""
    raw = _FakeRaw(stale_rv=int(CKR_OK))

    with pytest.raises(Failed, match="accepted invalid"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert records[0].kind == "lifecycle"
    assert records[0].actual_ckr == "CKR_OK"
    assert records[0].expected_ckr == ["CKR_OBJECT_HANDLE_INVALID"]
    assert "immediately after C_Logout" in records[0].label


def test_old_private_handle_resurrected_after_relogin_fails() -> None:
    """Relogin must not resurrect an invalidated handle; reuse fails loudly."""
    raw = _FakeRaw(resurrect_after_relogin=True)

    with pytest.raises(Failed, match="accepted invalid"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert "after relogin before reacquisition" in records[0].label
    # The relogin checkpoint ran before any reacquisition find.
    login_at = _positions(raw.ops, "login")[-1]
    post_login = raw.ops[login_at + 1 :]
    assert any(op.startswith("read:") for op in post_login)
    assert not any(op.startswith("find:") for op in post_login)


def test_handle_probe_with_other_clean_ckr_xfails() -> None:
    """A non-canonical clean refusal on a stale handle is an honest deviation."""
    raw = _FakeRaw(stale_rv=int(CKR_KEY_HANDLE_INVALID))

    with pytest.raises(XFailed, match="old private handle"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    assert records[0].kind == "lifecycle"
    assert records[0].actual_ckr == "CKR_KEY_HANDLE_INVALID"
    assert records[0].expected_ckr == ["CKR_OBJECT_HANDLE_INVALID"]


def test_handle_probe_with_sensitive_refusal_xfails() -> None:
    """A CKR_ATTRIBUTE_SENSITIVE stale-handle refusal xfails with its own RV."""
    raw = _FakeRaw(stale_rv=int(CKR_ATTRIBUTE_SENSITIVE))

    with pytest.raises(XFailed, match="old private handle"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    assert records[0].kind == "lifecycle"
    assert records[0].actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    assert records[0].expected_ckr == ["CKR_OBJECT_HANDLE_INVALID"]


def test_handle_probe_with_type_invalid_refusal_xfails() -> None:
    """A CKR_ATTRIBUTE_TYPE_INVALID stale-handle refusal xfails with its own RV."""
    raw = _FakeRaw(stale_rv=int(CKR_ATTRIBUTE_TYPE_INVALID))

    with pytest.raises(XFailed, match="old private handle"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    assert records[0].kind == "lifecycle"
    assert records[0].actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert records[0].expected_ckr == ["CKR_OBJECT_HANDLE_INVALID"]


def test_handle_probe_with_sensitive_refusal_and_data_fails() -> None:
    """A SENSITIVE refusal accompanied by attribute bytes fails, not xfails."""
    raw = _FakeRaw(
        stale_rv=int(CKR_ATTRIBUTE_SENSITIVE),
        stale_refusal_with_data=True,
    )

    with pytest.raises(Failed, match="success claimed then contradicted"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 2
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "policy"
    assert records[0].actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    assert records[0].detail is not None
    assert records[0].detail["leaked_len"] == ctypes.sizeof(CK_ULONG)
    assert records[1].reason == "self_contradiction"
    assert records[1].kind == "lifecycle"
    assert "old private handle" in records[1].label
    assert "immediately after C_Logout" in records[1].label


def test_handle_probe_with_type_invalid_refusal_and_data_fails() -> None:
    """A TYPE_INVALID refusal accompanied by attribute bytes fails, not xfails."""
    raw = _FakeRaw(
        stale_rv=int(CKR_ATTRIBUTE_TYPE_INVALID),
        stale_refusal_with_data=True,
    )

    with pytest.raises(Failed, match="success claimed then contradicted"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 2
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "policy"
    assert records[0].actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert records[0].detail is not None
    assert records[0].detail["leaked_len"] == ctypes.sizeof(CK_ULONG)
    assert records[1].reason == "self_contradiction"
    assert records[1].kind == "lifecycle"
    assert "old private handle" in records[1].label
    assert "immediately after C_Logout" in records[1].label


def test_handle_probe_with_ok_but_no_value_fails_with_structured_record() -> None:
    """Sentinel-with-OK on a stale handle fails with a structured record, not accepted_invalid."""
    raw = _FakeRaw(
        stale_ok_prefixes=(b"logout-explicit-private-",),
        omit_attrs=frozenset({int(CKA_CLASS)}),
    )

    with pytest.raises(Failed, match="neither usable nor cleanly rejected") as excinfo:
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )
    # Still a fail, never an xfail (XFailed subclasses Failed) or a pass.
    assert type(excinfo.value) is Failed

    records = C.get_records()
    assert len(records) == 2
    assert records[0].reason == "not_operational"
    assert records[0].kind == "lifecycle"
    assert "CKA_CLASS readback" in records[0].label
    assert records[0].actual_ckr is None
    assert records[1].reason == "self_contradiction"
    assert records[1].kind == "lifecycle"
    assert "old private handle" in records[1].label
    assert "immediately after C_Logout" in records[1].label
    assert "neither usable nor cleanly rejected" in records[1].label


def test_setup_readback_mismatch_fails() -> None:
    """Creation claiming private but reading back public fails the premise."""
    raw = _FakeRaw(readback_flip=True)

    with pytest.raises(Failed, match="success claimed then contradicted"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) >= 1
    assert records[-1].reason == "self_contradiction"
    assert records[-1].kind == "lifecycle"


def test_setup_readback_omission_xfails() -> None:
    """An unreadable CKA_PRIVATE leaves the premise unprovable (xfail)."""
    raw = _FakeRaw(omit_attrs=frozenset({int(CKA_PRIVATE)}))

    with pytest.raises(XFailed, match="premise unprovable"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert records[-1].reason == "not_operational"
    assert records[-1].kind == "metadata"
    assert any("CKA_PRIVATE readback" in record.label for record in records)


def test_logout_failure_xfails_the_oracle() -> None:
    """Without a successful logout the destruction oracle cannot run."""
    raw = _FakeRaw(logout_rv=int(CKR_DEVICE_ERROR))

    with pytest.raises(XFailed, match="C_Logout after session-object probe"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    # The explicit stimulus is cleaned up on the failed-logout path (the
    # default stimulus is a separate node with its own cleanup proof).
    assert len(raw.destroys) == 1


def test_no_pin_skips_session_objects_after_logout() -> None:
    """No PIN configured means the logout oracle cannot run."""
    raw = _FakeRaw()
    with pytest.raises(pytest.skip.Exception, match="No PIN configured"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(raw), _config(pin=None)
        )
    assert raw.creations == []


# ---------------------------------------------------------------------------
# R9-retained default/visibility observation (own production node)
# ---------------------------------------------------------------------------


def _run_default_visibility(raw: _FakeRaw, pin: str | None = "1234") -> None:
    test_cve_regression.TestSessionObjectsAfterLogout().test_default_visibility_after_logout(
        _session(raw), _config(pin=pin)
    )


def test_default_attribute_object_visibility_observed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Healthy control: the omitted-attribute stimulus is preserved and noted."""
    raw = _FakeRaw()
    notes = _capture_notes(monkeypatch)

    _run_default_visibility(raw)

    # The legacy omitted-attribute stimulus is preserved as-is: no explicit
    # CKA_PRIVATE/CKA_TOKEN requested, exactly one object created.
    assert len(raw.creations) == 1
    default = raw.creations[0][1]
    assert int(CKA_PRIVATE) not in default
    assert int(CKA_TOKEN) not in default
    # The default object survives (public by default) and is recorded with
    # the repaired, narrowly worded observation -- never a verdict.
    assert C.get_records() == []
    assert len(notes) == 1
    description, _level, reference = notes[0]
    assert "Default-attribute session object visible" in description
    assert "visibility observation only" in description
    assert "5.6.10" in reference
    assert "Session objects survive C_Logout" not in description
    # The surviving observation object is cleaned up.
    assert len(raw.destroys) == 1


def test_default_attribute_object_destroyed_without_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Seeded variant: a provider defaulting to private destroys; no note fires."""
    raw = _FakeRaw(default_private=True)
    notes = _capture_notes(monkeypatch)

    _run_default_visibility(raw)

    assert C.get_records() == []
    assert notes == []
    assert raw.destroys == []


def test_default_visibility_logout_failure_xfails_the_oracle() -> None:
    """Without a successful logout the visibility observation cannot run."""
    raw = _FakeRaw(logout_rv=int(CKR_DEVICE_ERROR))

    with pytest.raises(XFailed, match="C_Logout after session-object probe"):
        _run_default_visibility(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    assert len(raw.destroys) == 1


def test_no_pin_skips_default_visibility_after_logout() -> None:
    """No PIN configured means the visibility observation cannot run."""
    raw = _FakeRaw()
    with pytest.raises(pytest.skip.Exception, match="No PIN configured"):
        _run_default_visibility(raw, pin=None)
    assert raw.creations == []


# ---------------------------------------------------------------------------
# Two-session logout object-lifetime matrix
# ---------------------------------------------------------------------------

_PRIV_PREFIX = b"qc9b-priv-session-"
_PUB_PREFIX = b"qc9b-pub-session-"
_TOK_PREFIX = b"qc9b-priv-token-"


def _run_matrix(raw: _FakeRaw, mechanisms: set[str] | None = None) -> None:
    tssm.TestLogoutEffects().test_logout_object_lifetime_across_two_sessions(
        _session(raw, mechanisms), _config()
    )


def _handle_by_prefix(raw: _FakeRaw, prefix: bytes) -> int:
    matches = [h for h, o in raw.objects.items() if o.label.startswith(prefix)]
    assert len(matches) == 1, [o.label for o in raw.objects.values()]
    return matches[0]


def _creation_by_prefix(raw: _FakeRaw, prefix: bytes) -> tuple[int, dict[int, Any]]:
    matches = [(s, d) for s, d in raw.creations if d.get(int(CKA_LABEL), b"").startswith(prefix)]
    assert len(matches) == 1, raw.creations
    return matches[0]


def test_conformant_lifetime_matrix_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Full QC9b matrix on a conformant provider: destroyed/hidden/persists."""
    raw = _FakeRaw()
    notes = _capture_notes(monkeypatch)

    _run_matrix(raw)

    assert C.get_records() == []
    # Objects created across two sessions with explicit attributes.
    priv_session, priv_decoded = _creation_by_prefix(raw, _PRIV_PREFIX)
    pub_session, pub_decoded = _creation_by_prefix(raw, _PUB_PREFIX)
    tok_session, tok_decoded = _creation_by_prefix(raw, _TOK_PREFIX)
    assert {priv_session, pub_session, tok_session} == {11, 12}
    assert pub_session != priv_session
    assert priv_decoded[int(CKA_PRIVATE)] is True
    assert priv_decoded[int(CKA_TOKEN)] is False
    assert pub_decoded[int(CKA_PRIVATE)] is False
    assert pub_decoded[int(CKA_TOKEN)] is False
    assert tok_decoded[int(CKA_PRIVATE)] is True
    assert tok_decoded[int(CKA_TOKEN)] is True
    priv_h = _handle_by_prefix(raw, _PRIV_PREFIX)
    pub_h = _handle_by_prefix(raw, _PUB_PREFIX)
    tok_h = _handle_by_prefix(raw, _TOK_PREFIX)

    # Every stimulus was read back before logout.
    for handle in (priv_h, pub_h, tok_h):
        asked = [entry[2] for entry in raw.reads if entry[1] == handle]
        assert [int(CKA_PRIVATE), int(CKA_TOKEN)] in asked

    # Checkpoint order: logout -> immediate probes (both sessions) ->
    # relogin -> pre-reacquisition probes -> reacquisition finds.
    logout_at = _positions(raw.ops, "logout")[0]
    login_at = _positions(raw.ops, "login")[-1]
    assert logout_at < login_at
    immediate = raw.ops[logout_at + 1 : login_at]
    immediate_reads = {op for op in immediate if op.startswith("read:")}
    assert immediate_reads == {
        f"read:11:{priv_h}",
        f"read:12:{priv_h}",
        f"read:11:{tok_h}",
        f"read:12:{tok_h}",
        f"read:12:{pub_h}",
    }
    post_login = raw.ops[login_at + 1 :]
    first_find = min(i for i, op in enumerate(post_login) if op.startswith("find:"))
    reacq_reads = {op for op in post_login[:first_find] if op.startswith("read:")}
    assert reacq_reads == {
        f"read:11:{priv_h}",
        f"read:12:{priv_h}",
        f"read:11:{tok_h}",
        f"read:12:{tok_h}",
    }

    # Verdicts: private-session destroyed, public-session remains,
    # private-token persists and is reacquirable under its old integer.
    post_finds = [entry for entry in raw.finds if entry[1] is not None and entry[0] in (11, 12)]
    priv_post = [entry for entry in post_finds if entry[1].startswith(_PRIV_PREFIX)]
    pub_post = [entry for entry in post_finds if entry[1].startswith(_PUB_PREFIX)]
    tok_post = [entry for entry in post_finds if entry[1].startswith(_TOK_PREFIX)]
    assert priv_post[-1][2] == []
    assert pub_post[-1][2] == [pub_h]
    assert tok_post[-1][2] == [tok_h]

    # Held-open operations remained usable: observed, never a verdict.
    assert len(notes) == 2
    assert all("remains usable" in description for description, _, _ in notes)
    assert all("observation only" in description for description, _, _ in notes)
    assert all("5.6.10" in reference for _, _, reference in notes)
    # Survivors cleaned up; the destroyed private object needs no destroy.
    assert set(raw.destroys) == {(12, pub_h), (11, tok_h)}


def test_reissued_handles_are_accepted() -> None:
    """A reacquired handle may equally use a brand-new integer."""
    raw = _FakeRaw(reissue_handles=True)

    _run_matrix(raw)

    assert C.get_records() == []
    tok_post = [
        entry for entry in raw.finds if entry[1] is not None and entry[1].startswith(_TOK_PREFIX)
    ]
    assert len(tok_post) == 2
    assert tok_post[0][2] != [] and tok_post[-1][2] != []
    # Relogin reissued the persisting token object under a new integer; the
    # oracle accepts it without comparing integers either way.
    assert tok_post[0][2] != tok_post[-1][2]


def test_hidden_private_session_object_fails() -> None:
    """Reappearing after relogin means hidden, not destroyed: fail."""
    raw = _FakeRaw(keep_private_session=True)

    with pytest.raises(Failed, match="success claimed then contradicted"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "lifecycle"
    assert "destroyed by C_Logout" in records[0].label


def test_usable_old_private_session_handle_fails() -> None:
    """An old private-session handle answering after logout fails."""
    raw = _FakeRaw(stale_ok_prefixes=(_PRIV_PREFIX,))

    with pytest.raises(Failed, match="accepted invalid"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert "private session object" in records[0].label
    assert "immediately after C_Logout" in records[0].label


def test_usable_old_private_token_handle_fails() -> None:
    """Invalidation covers private-token handles too, not just session ones."""
    raw = _FakeRaw(stale_ok_prefixes=(_TOK_PREFIX,))

    with pytest.raises(Failed, match="accepted invalid"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert "private token object" in records[0].label


def test_old_handles_resurrected_after_relogin_fail() -> None:
    """The relogin checkpoint catches revalidated stale handles in the matrix."""
    raw = _FakeRaw(resurrect_after_relogin=True)

    with pytest.raises(Failed, match="accepted invalid"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert "after relogin before reacquisition" in records[0].label
    # The immediate checkpoint passed first: invalidation held until relogin
    # (a stale probe logs one call -- the size query already rejects -- while
    # the valid public read logs the full two-call sequence).
    logout_at = _positions(raw.ops, "logout")[0]
    login_at = _positions(raw.ops, "login")[-1]
    immediate_reads = {op for op in raw.ops[logout_at + 1 : login_at] if op.startswith("read:")}
    priv_h = _handle_by_prefix(raw, _PRIV_PREFIX)
    pub_h = _handle_by_prefix(raw, _PUB_PREFIX)
    tok_h = _handle_by_prefix(raw, _TOK_PREFIX)
    assert immediate_reads == {
        f"read:11:{priv_h}",
        f"read:12:{priv_h}",
        f"read:11:{tok_h}",
        f"read:12:{tok_h}",
        f"read:12:{pub_h}",
    }


def test_unusable_reacquired_token_handle_fails() -> None:
    """A found-but-unusable reacquired token handle fails the oracle."""
    raw = _FakeRaw(unusable_reacquired_prefixes=(_TOK_PREFIX,))

    with pytest.raises(Failed, match="reacquired handle unusable"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "lifecycle"
    assert "private token object" in records[0].label
    assert "observed CKR_OBJECT_HANDLE_INVALID" in records[0].label


def test_reacquired_token_identity_mismatch_fails() -> None:
    """A reacquired token handle reporting the wrong identity fails."""
    raw = _FakeRaw(reacquired_identity_flip=True)

    with pytest.raises(Failed, match="expected identity"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "lifecycle"
    assert "private token object" in records[0].label


def test_destroyed_private_token_object_fails() -> None:
    """A token object must persist across logout and be reacquirable."""
    raw = _FakeRaw(destroy_private_token=True)

    with pytest.raises(Failed, match="success claimed then contradicted"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert "persists" in records[0].label


def test_destroyed_public_session_object_fails_at_handle_probe() -> None:
    """A public session object whose handle dies on logout fails the oracle."""
    raw = _FakeRaw(destroy_public_session=True)

    with pytest.raises(Failed, match="success claimed then contradicted"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert "public session object" in records[0].label
    assert "remains usable" in records[0].label
    assert "observed CKR_OBJECT_HANDLE_INVALID" in records[0].label


def test_unfindable_public_session_object_fails_at_reacquisition() -> None:
    """A public session object that cannot be re-found after relogin fails."""
    raw = _FakeRaw(find_miss_prefixes=(_PUB_PREFIX,))

    with pytest.raises(Failed, match="success claimed then contradicted"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert "remains" in records[0].label


def test_matrix_handle_probe_with_other_clean_ckr_xfails() -> None:
    """A non-canonical clean refusal on a stale handle is an honest deviation."""
    raw = _FakeRaw(stale_rv=int(CKR_KEY_HANDLE_INVALID))

    with pytest.raises(XFailed, match="old private handle"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    assert records[0].actual_ckr == "CKR_KEY_HANDLE_INVALID"
    assert records[0].expected_ckr == ["CKR_OBJECT_HANDLE_INVALID"]


def test_terminated_active_operations_are_observed_not_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminated held-open operations pass with a termination observation."""
    raw = _FakeRaw(
        find_op_rv=int(CKR_OPERATION_NOT_INITIALIZED),
        digest_op_rv=int(CKR_OPERATION_NOT_INITIALIZED),
    )
    notes = _capture_notes(monkeypatch)

    _run_matrix(raw)

    assert C.get_records() == []
    assert len(notes) == 2
    assert all("terminated with CKR_OPERATION_NOT_INITIALIZED" in d for d, _, _ in notes)
    assert all("observation only" in d for d, _, _ in notes)


def test_unstageable_active_operations_are_observed_not_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Observation legs that cannot be staged are noted, never failed."""
    raw = _FakeRaw(
        find_init_rv=int(CKR_FUNCTION_FAILED),
        digest_init_rv=int(CKR_FUNCTION_FAILED),
    )
    notes = _capture_notes(monkeypatch)

    _run_matrix(raw)

    assert C.get_records() == []
    assert len(notes) == 2
    assert all("not staged" in d for d, _, _ in notes)


def test_digest_observation_skipped_without_sha256(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without CKM_SHA256 only the find leg is observed."""
    raw = _FakeRaw()
    notes = _capture_notes(monkeypatch)

    _run_matrix(raw, {"AES_KEY_GEN"})

    assert C.get_records() == []
    assert len(notes) == 2
    assert any("CKM_SHA256 unavailable" in d for d, _, _ in notes)
    assert any("remains usable" in d for d, _, _ in notes)


def test_matrix_logout_failure_xfails_the_oracle() -> None:
    """Without a successful logout the lifetime oracle cannot run."""
    raw = _FakeRaw(logout_rv=int(CKR_DEVICE_ERROR))

    with pytest.raises(XFailed, match="C_Logout for object-lifetime oracle"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    assert len(raw.destroys) == 3


def test_matrix_setup_readback_mismatch_fails() -> None:
    """Creation claiming private but reading back public fails the premise."""
    raw = _FakeRaw(readback_flip=True)

    with pytest.raises(Failed, match="success claimed then contradicted"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) >= 1
    assert records[-1].reason == "self_contradiction"
    assert records[-1].kind == "lifecycle"


def test_matrix_no_pin_skips() -> None:
    """No PIN configured means the lifetime oracle cannot run."""
    raw = _FakeRaw()
    with pytest.raises(pytest.skip.Exception, match="No PIN configured"):
        tssm.TestLogoutEffects().test_logout_object_lifetime_across_two_sessions(
            _session(raw), _config(pin=None)
        )
    assert raw.creations == []


def test_failed_oracle_destroys_owned_token_object_p1() -> None:
    """P1: a detected defect must not leave the private token key behind."""
    raw = _FakeRaw(stale_ok_prefixes=(_TOK_PREFIX,))

    with pytest.raises(Failed, match="accepted invalid"):
        _run_matrix(raw)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert "private token object" in records[0].label
    tok_h = _handle_by_prefix(raw, _TOK_PREFIX)
    assert raw.objects[tok_h].destroyed is True, "owned token object leaked on failure"
    assert any(handle == tok_h for _session, handle in raw.destroys), raw.destroys


def test_failed_oracle_cleanup_failure_preserves_primary_p1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P1 pin: cleanup relogin failure never masks the primary finding."""
    raw = _FakeRaw(stale_ok_prefixes=(_TOK_PREFIX,))
    original = tssm._login_user_raw
    calls: list[int] = []

    def _flaky_login(raw_arg: Any, sh: int, pin_bytes: bytes | None) -> None:
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("cleanup relogin boom")
        original(raw_arg, sh, pin_bytes)

    monkeypatch.setattr(tssm, "_login_user_raw", _flaky_login)

    with pytest.raises(Failed, match="accepted invalid") as ei:
        _run_matrix(raw)

    notes = getattr(ei.value, "__notes__", [])
    assert any("cleanup relogin boom" in note for note in notes), notes
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert "private token object" in records[0].label


def test_owned_token_cleanup_without_primary_raises_r6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R6: with no primary verdict in flight, cleanup failure is not swallowed."""

    def _boom_find(_raw: Any, _sh: int, _tmpl: Any) -> list[int]:
        raise RuntimeError("cleanup find boom")

    monkeypatch.setattr(tssm, "find_objects", _boom_find)

    with pytest.raises(RuntimeError, match="cleanup find boom"):
        tssm._cleanup_owned_token_object(object(), 1, b"1234", object())


def test_token_label_unique_across_runs_p1() -> None:
    """P1: the owned token label is run-unique, never a recycled identity."""
    labels: list[bytes] = []
    for _ in range(2):
        C.clear()
        raw = _FakeRaw()
        _run_matrix(raw)
        _session_id, decoded = _creation_by_prefix(raw, _TOK_PREFIX)
        label = decoded[int(CKA_LABEL)]
        labels.append(label if isinstance(label, bytes) else str(label).encode())
    assert labels[0] != labels[1], labels
