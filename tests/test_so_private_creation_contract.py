"""Production-method contracts for QC10a SO private creation (#52.4).

Drives the real testcase methods in
``pkcs11_check.testcases.security.test_public_session_private_creation``
(``TestSOPrivateCreation`` + ``TestUserPrivateCreationControls``) against a
scriptable fake token at the raw ``C_*`` layer:

- SO negative legs (Create/Copy/Generate/Derive/Unwrap): canonical
  ``CKR_USER_NOT_LOGGED_IN`` refusal with zero inventory delta passes; other
  clean refusals xfail preserving the original RV; acceptance or undefined RVs
  fail; refused-but-leaked proved handles are destroyed + fail; unproved
  deltas stay alive + xfail; known failures survive inventory gaps;
- SO public-object controls run first inside each SO node (the function must
  work under SO before the refusal leg means anything): clean refusal there
  xfails the node, never passes;
- USER private-object controls: success + proved creation + ``CKA_PRIVATE``
  readback passes; clean refusal xfails, never passes;
- credential scoping: SO PIN authenticates SO, USER PIN restores USER, login
  state verified via ``C_GetSessionInfo`` (never assumed); restoration
  failures fail loudly with the primary outcome and the restoration RV.

Fakes only; no provider is loaded.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CK_TOKEN_INFO,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKS_RW_PUBLIC_SESSION,
    CKS_RW_SO_FUNCTIONS,
    CKS_RW_USER_FUNCTIONS,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases import _so_login as so_login_module
from pkcs11_check.testcases.security import test_public_session_private_creation as so_case
from tests._skip_assert import assert_skips, assert_xfails

_OK = int(CKR_OK)
_NOT_LOGGED_IN = int(CKR_USER_NOT_LOGGED_IN)
_CLEAN_REFUSAL = int(CKR_GENERAL_ERROR)
_OTHER_CLEAN = int(CKR_ARGUMENTS_BAD)
_TYPE_INVALID = int(CKR_ATTRIBUTE_TYPE_INVALID)
_VENDOR_REFUSAL = 0x80000001
_UNDEFINED_RV = 0x7FFFFFFF
_UNAVAILABLE = int(CK_UNAVAILABLE_INFORMATION)
_SO = int(CKU_SO)
_USER = int(CKU_USER)

_FIXTURE_SH = 7


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


def _ulong_bytes(value: int) -> bytes:
    return value.to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)


def _fill_ulong(ptr: Any, value: int) -> None:
    ctypes.cast(ptr, ctypes.POINTER(CK_ULONG)).contents.value = value


class _OmitPrivateRead:
    """Sentinel for ``private_read_script``: omit CKA_PRIVATE on that scripted read."""


_OMIT_PRIVATE_READ = _OmitPrivateRead()


class _SoCreationRaw:
    """Scriptable fake token for the QC10a SO/private-creation production methods."""

    def __init__(self) -> None:
        self.objects: dict[int, dict[int, bytes]] = {}
        self.sessions: set[int] = {_FIXTURE_SH}
        self.login_state = "user"  # user | so | out (token-wide)
        self.ops: list[str] = []
        self.logins: list[tuple[str, int]] = []  # (role, pin_len); no PIN bytes retained
        self.destroys: list[int] = []
        self.attempt_calls: list[dict[str, Any]] = []
        self.setup_creates: list[dict[str, Any]] = []
        self.setup_handles: list[int] = []
        self.finds: list[bytes | None] = []
        self.leaked: list[int] = []
        self._next_handle = 500
        self._next_session = 10
        self._search: list[int] = []
        # Knobs.
        self.setup_rv: int = _OK
        self.setup_script: list[int] = []
        self.setup_replay_handles: list[int] = []
        self.setup_proved_extra = False
        self.ok_companion: bool = False
        self.hide_ok_companion_from_so: bool = False
        self.hide_attempt_leak_from_so: bool = False
        self.attempt_script: list[int] = []
        self.attempt_leak = "none"  # none | proved | foreign
        self.attempt_handle_write: int | None = None
        self.so_login_rv: int = _OK
        self.user_relogin_rv: int = _OK
        self.logout_script: list[int] = []
        self.state_lie: int | None = None
        self.getsessioninfo_rv: int = _OK
        self.getsessioninfo_script: list[int] = []
        self.token_flags: int = 0
        self.gettokeninfo_rv: int = _OK
        self.find_init_script: list[int] = []
        self.getattr_rv: int | None = None
        self.getattr_omit: set[int] = set()
        self.private_read_blob: bytes | None = None
        self.private_read_script: list[bytes | None | _OmitPrivateRead] = []
        self._pending_private: tuple[bool, bytes | None | _OmitPrivateRead] = (False, None)
        self.sessioninfo_script: list[int | None] = []
        self.hide_from_so: set[int] = set()
        self.hide_setup_from_so: bool = False
        self.wrap_rv: int = _OK
        self.wrapped_blob = b"\xa6" * 24

    def _alloc(self, attrs: dict[int, bytes]) -> int:
        self._next_handle += 1
        handle = self._next_handle
        self.objects[handle] = dict(attrs)
        return handle

    def _is_attempt_session(self, session: int) -> bool:
        return int(session) != _FIXTURE_SH

    def _so_hidden(self, sh: int) -> set[int]:
        # Visibility follows the token-wide login state, not the session id:
        # SO-hidden objects become visible again once USER is restored.
        if not self._is_attempt_session(sh) or self.login_state != "so":
            return set()
        hidden = set(self.hide_from_so)
        if self.hide_setup_from_so:
            hidden.update(self.setup_handles)
        return hidden

    # -- sessions / login -------------------------------------------------
    def C_OpenSession(self, slot_id: int, flags: int, *_args: Any) -> int:  # noqa: N802
        handle = self._next_session
        self._next_session += 1
        self.sessions.add(handle)
        _fill_ulong(_args[-1], handle)
        self.ops.append(f"open:{handle}")
        return _OK

    def C_CloseSession(self, session: int) -> int:  # noqa: N802
        self.sessions.discard(int(session))
        self.ops.append(f"close:{int(session)}")
        return _OK

    def C_Login(self, session: int, user_type: int, pin_ptr: Any, pin_len: int) -> int:  # noqa: N802
        role = "so" if int(user_type) == _SO else ("user" if int(user_type) == _USER else "other")
        self.logins.append((role, int(pin_len)))
        self.ops.append(f"login:{role}")
        if role == "so":
            if self.login_state == "so":
                return int(CKR_USER_ALREADY_LOGGED_IN)
            if self.login_state == "user":
                return int(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
            if self.so_login_rv != _OK:
                return self.so_login_rv
            self.login_state = "so"
            return _OK
        if role == "user":
            if self.login_state == "user":
                return int(CKR_USER_ALREADY_LOGGED_IN)
            if self.user_relogin_rv != _OK:
                return self.user_relogin_rv
            self.login_state = "user"
            return _OK
        return int(CKR_USER_NOT_LOGGED_IN)

    def C_Logout(self, session: int) -> int:  # noqa: N802
        self.ops.append("logout")
        if self.logout_script:
            rv = self.logout_script.pop(0)
            if rv in (_OK, _NOT_LOGGED_IN):
                self.login_state = "out"
            return rv
        if self.login_state == "out":
            return _NOT_LOGGED_IN
        self.login_state = "out"
        return _OK

    def C_GetSessionInfo(self, session: int, info_ptr: Any) -> int:  # noqa: N802
        if self.getsessioninfo_script:
            scripted = self.getsessioninfo_script.pop(0)
            if scripted != _OK:
                return scripted
        elif self.getsessioninfo_rv != _OK:
            return self.getsessioninfo_rv
        forced: int | None = None
        if self.sessioninfo_script:
            forced = self.sessioninfo_script.pop(0)
        if forced is not None:
            state = forced
        elif self.state_lie is not None:
            state = self.state_lie
        elif self.login_state == "so":
            state = int(CKS_RW_SO_FUNCTIONS)
        elif self.login_state == "user":
            state = int(CKS_RW_USER_FUNCTIONS)
        else:
            state = int(CKS_RW_PUBLIC_SESSION)
        info = ctypes.cast(info_ptr, ctypes.POINTER(CK_SESSION_INFO)).contents
        info.slotID = 0
        info.state = state
        info.flags = 0
        info.ulDeviceError = 0
        self.ops.append(f"sessioninfo:{state}")
        return _OK

    def C_GetTokenInfo(self, slot_id: int, info_ptr: Any) -> int:  # noqa: N802
        if self.gettokeninfo_rv != _OK:
            return self.gettokeninfo_rv
        info = ctypes.cast(info_ptr, ctypes.POINTER(CK_TOKEN_INFO)).contents
        info.flags = self.token_flags
        return _OK

    # -- reads ------------------------------------------------------------
    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if self.getattr_rv is not None:
            return self.getattr_rv
        stored = self.objects.get(int(handle))
        assert stored is not None, f"read from unknown handle {handle}"
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            if attr in self.getattr_omit:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(_TYPE_INVALID)
                continue
            if attr == int(CKA_PRIVATE) and (self.private_read_script or self._pending_private[0]):
                # read_attributes issues a size query then a value read per
                # read; the scripted blob applies to both calls of one read.
                if not addr and not self._pending_private[0]:
                    scripted = self.private_read_script.pop(0)
                    self._pending_private = (True, scripted)
                else:
                    scripted = self._pending_private[1]
                    self._pending_private = (False, None)
                if isinstance(scripted, _OmitPrivateRead):
                    tmpl[i].ulValueLen = _UNAVAILABLE
                    row_rvs.append(_TYPE_INVALID)
                    continue
                blob: bytes | None = scripted if scripted is not None else stored.get(attr)
            elif attr == int(CKA_PRIVATE) and self.private_read_blob is not None:
                blob = self.private_read_blob
            else:
                blob = stored.get(attr)
            if blob is None:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(_TYPE_INVALID)
                continue
            if addr:
                ctypes.memmove(addr, blob, min(len(blob), cap))
            tmpl[i].ulValueLen = len(blob)
            row_rvs.append(_OK)
        if _TYPE_INVALID in row_rvs:
            return _TYPE_INVALID
        return _OK

    # -- creators ---------------------------------------------------------
    def _record_create(
        self, op: str, session: int, attrs: dict[int, bytes], handle_ptr: Any
    ) -> int:
        if not self._is_attempt_session(session):
            self.setup_creates.append({"op": op, "attrs": attrs})
            rv = self.setup_script.pop(0) if self.setup_script else self.setup_rv
            if rv != _OK:
                return rv
            if self.setup_replay_handles:
                _write_handle(handle_ptr, self.setup_replay_handles.pop(0))
                return _OK
            handle = self._alloc(attrs)
            self.setup_handles.append(handle)
            if self.setup_proved_extra:
                self.leaked.append(self._alloc(dict(attrs)))
            _write_handle(handle_ptr, handle)
            return _OK
        self.attempt_calls.append({"op": op, "attrs": attrs})
        assert self.attempt_script, f"attempt script exhausted at {op}"
        rv = self.attempt_script.pop(0)
        if rv != _OK:
            self._apply_attempt_leak(attrs)
            _write_handle(handle_ptr, self.attempt_handle_write if self.attempt_handle_write else 0)
            return rv
        stored = dict(attrs)
        if op == "copy":
            stored.setdefault(int(CKA_TOKEN), b"\x00")
        handle = self._alloc(stored)
        if self.ok_companion:
            companion = self._alloc({int(CKA_LABEL): b"qc10a-companion"})
            self.leaked.append(companion)
            if self.hide_ok_companion_from_so:
                self.hide_from_so.add(companion)
        _write_handle(
            handle_ptr,
            self.attempt_handle_write if self.attempt_handle_write is not None else handle,
        )
        return _OK

    def _apply_attempt_leak(self, attrs: dict[int, bytes]) -> None:
        if self.attempt_leak == "proved":
            leak = dict(attrs)
            leak.setdefault(int(CKA_TOKEN), b"\x00")
            leaked = self._alloc(leak)
            self.leaked.append(leaked)
            if self.hide_attempt_leak_from_so:
                self.hide_from_so.add(leaked)
        elif self.attempt_leak == "foreign":
            leaked = self._alloc({int(CKA_LABEL): b"qc10a-foreign"})
            self.leaked.append(leaked)
            if self.hide_attempt_leak_from_so:
                self.hide_from_so.add(leaked)

    def C_CreateObject(self, sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        return self._record_create("create", sh, _decode_template(tmpl, int(count)), handle_ptr)

    def C_CopyObject(  # noqa: N802
        self, sh: int, source: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        assert int(source) in self.objects, f"copy from unknown handle {source}"
        return self._record_create("copy", sh, _decode_template(tmpl, int(count)), handle_ptr)

    def C_GenerateKey(  # noqa: N802
        self, sh: int, _mech: Any, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        return self._record_create("generate", sh, _decode_template(tmpl, int(count)), handle_ptr)

    def C_DeriveKey(  # noqa: N802
        self, sh: int, _mech: Any, _base: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        return self._record_create("derive", sh, _decode_template(tmpl, int(count)), handle_ptr)

    def C_UnwrapKey(  # noqa: N802
        self,
        sh: int,
        _mech: Any,
        _kek: int,
        _wrapped: Any,
        _wrapped_len: int,
        tmpl: Any,
        count: int,
        handle_ptr: Any,
    ) -> int:
        return self._record_create("unwrap", sh, _decode_template(tmpl, int(count)), handle_ptr)

    def C_WrapKey(  # noqa: N802
        self, _sh: int, _mech: Any, _kek: int, _target: int, out: Any, out_len: Any
    ) -> int:
        if self.wrap_rv != _OK:
            return self.wrap_rv
        blob = bytes(self.wrapped_blob)
        if not out:
            _fill_ulong(out_len, len(blob))
            return _OK
        ctypes.memmove(out, blob, len(blob))
        _fill_ulong(out_len, len(blob))
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroys.append(int(handle))
        self.objects.pop(int(handle), None)
        return _OK

    # -- search -----------------------------------------------------------
    def C_FindObjectsInit(self, sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if self.find_init_script:
            scripted = self.find_init_script.pop(0)
            if scripted != _OK:
                return scripted
        wanted = _decode_template(tmpl, int(count))
        label = wanted.get(int(CKA_LABEL))
        self.finds.append(label)
        hidden = self._so_hidden(sh)
        self._search = [
            handle
            for handle, attrs in self.objects.items()
            if handle not in hidden and (label is None or attrs.get(int(CKA_LABEL)) == label)
        ]
        return _OK

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        take = self._search[: int(max_count)]
        for i, handle in enumerate(take):
            handles[i] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(take)
        self._search = self._search[len(take) :]
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return _OK


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    so_login_module._SO_PIN_REJECTED = False
    yield
    C.clear()
    so_login_module._SO_PIN_REJECTED = False


def _rs(fake: _SoCreationRaw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=fake,
        sh=_FIXTURE_SH,
        slot_id=0,
        has_mechanism=lambda *_a: True,
    )


def _secret(value: str) -> SimpleNamespace:
    return SimpleNamespace(get_secret_value=lambda: value)


def _config(*, pin: str | None = "1234", so_pin: str | None = "so-pin") -> SimpleNamespace:
    return SimpleNamespace(
        pin=_secret(pin) if pin is not None else None,
        so_pin=_secret(so_pin) if so_pin is not None else None,
    )


def _assert_fails(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Failed:
    """Call ``fn`` and assert it raises ``pytest.fail`` (never ``pytest.xfail``)."""
    try:
        fn(*args, **kwargs)
    except XFailed as exc:
        pytest.fail(f"expected pytest.fail(), got pytest.xfail() instead: {exc}")
    except Failed as exc:
        return exc
    pytest.fail(f"expected {fn} to call pytest.fail(), but it returned normally")


def _assert_fail_record(reason: str, kind: str | None) -> Any:
    records = C.get_records()
    assert len(records) == 1, [(rec.reason, rec.outcome) for rec in records]
    rec = records[0]
    assert rec.reason == reason
    assert rec.kind == kind
    assert rec.outcome == "fail"
    return rec


def _assert_xfail_record(reason: str) -> Any:
    records = C.get_records()
    assert len(records) == 1, [(rec.reason, rec.outcome) for rec in records]
    rec = records[0]
    assert rec.reason == reason
    assert rec.outcome == "xfail"
    return rec


_SO_LEGS: tuple[tuple[str, str], ...] = (
    ("test_so_cannot_create_private_object", "C_CreateObject"),
    ("test_so_cannot_copy_to_private_object", "C_CopyObject"),
    ("test_so_cannot_generate_private_key", "C_GenerateKey"),
    ("test_so_cannot_derive_private_key", "C_DeriveKey"),
    ("test_so_cannot_unwrap_private_key", "C_UnwrapKey"),
)

_USER_LEGS: tuple[tuple[str, str], ...] = (
    ("test_user_can_create_private_object", "C_CreateObject"),
    ("test_user_can_copy_to_private_object", "C_CopyObject"),
    ("test_user_can_generate_private_key", "C_GenerateKey"),
    ("test_user_can_derive_private_key", "C_DeriveKey"),
    ("test_user_can_unwrap_private_key", "C_UnwrapKey"),
)


def _run_so_leg(method: str, session: SimpleNamespace, config: SimpleNamespace) -> None:
    getattr(so_case.TestSOPrivateCreation(), method)(session, config)


def _run_user_leg(method: str, session: SimpleNamespace, config: SimpleNamespace) -> None:
    getattr(so_case.TestUserPrivateCreationControls(), method)(session, config)


# --- canonical refusal table ----------------------------------------------


def test_qc10a_canonical_table_covers_all_five_creators() -> None:
    table = so_case._QC10A_CANONICAL_REFUSAL
    assert set(table) == {
        "C_CreateObject",
        "C_CopyObject",
        "C_GenerateKey",
        "C_DeriveKey",
        "C_UnwrapKey",
    }
    for op, entry in table.items():
        assert entry["rvs"] == (int(CKR_USER_NOT_LOGGED_IN),), op
        assert entry["spec"], op


# --- SO legs: healthy -------------------------------------------------------


@pytest.mark.parametrize(("method", "op"), _SO_LEGS)
def test_so_leg_healthy_passes(method: str, op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    _run_so_leg(method, _rs(fake), _config())
    assert C.get_records() == []
    # Control (public) ran first, then the private refusal leg.
    short = {
        "C_CreateObject": "create",
        "C_CopyObject": "copy",
        "C_GenerateKey": "generate",
        "C_DeriveKey": "derive",
        "C_UnwrapKey": "unwrap",
    }[op]
    assert [call["op"] for call in fake.attempt_calls] == [short, short]
    privates = [call["attrs"].get(int(CKA_PRIVATE)) for call in fake.attempt_calls]
    assert privates == [b"\x00", b"\x01"], privates
    # Distinct labels per attempt; control object destroyed, nothing leaked.
    labels = [call["attrs"][int(CKA_LABEL)] for call in fake.attempt_calls]
    assert len(set(labels)) == 2
    assert len(fake.destroys) >= 1
    # Credential scoping + verified restoration evidence.
    assert ("so", len("so-pin")) in fake.logins
    assert ("user", len("1234")) in fake.logins
    assert fake.login_state == "user"
    assert any(entry.startswith("sessioninfo:") for entry in fake.ops)
    assert fake.ops.count("logout") >= 2


@pytest.mark.parametrize(("method", "op"), _SO_LEGS)
def test_so_leg_control_refusal_xfails_without_running_negative(method: str, op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_CLEAN_REFUSAL, _NOT_LOGGED_IN]
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.actual_ckr == ckr_name(_CLEAN_REFUSAL)
    assert len(fake.attempt_calls) == 1, "negative leg must not run on failed control"
    assert fake.login_state == "user", "restoration still applies on control xfail"


# --- SO legs: refusal tiers + ownership -------------------------------------


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
@pytest.mark.parametrize("rv", [_CLEAN_REFUSAL, _OTHER_CLEAN, _VENDOR_REFUSAL])
def test_so_leg_other_clean_refusal_xfails_with_original_rv(method: str, _op: str, rv: int) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, rv]
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.actual_ckr == ckr_name(rv)
    assert rec.expected_ckr == [ckr_name(_NOT_LOGGED_IN)]
    assert fake.login_state == "user"


@pytest.mark.parametrize(("method", "op"), _SO_LEGS)
def test_so_leg_acceptance_with_private_readback_fails(method: str, op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _OK]
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.operation == op
    assert fake.leaked == []
    created = [
        call for call in fake.attempt_calls if call["attrs"].get(int(CKA_PRIVATE)) == b"\x01"
    ]
    assert len(created) == 1
    assert fake.login_state == "user"


@pytest.mark.parametrize(("method", "op"), _SO_LEGS)
def test_so_leg_acceptance_with_public_readback_fails_unclaimed(method: str, op: str) -> None:
    """CKR_OK on a must-reject leg fails even when the readback says public:
    the refusal assertion does not depend on the protection claim."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _OK]
    fake.private_read_blob = b"\x00"
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("accepted_invalid", None)
    assert rec.operation == op
    assert "must reject" in (rec.summary or "")
    assert fake.login_state == "user"


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_undefined_refusal_rv_fails(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _UNDEFINED_RV]
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)
    assert fake.login_state == "user"


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_refusal_with_proved_leak_fails_and_destroys(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.attempt_leak = "proved"
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.detail["disposition"] == "refused-but-created"
    assert fake.leaked
    assert all(handle in fake.destroys for handle in fake.leaked)


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_refusal_with_foreign_leak_xfails_and_stays_alive(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.attempt_leak = "foreign"
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-effect"
    assert fake.leaked
    assert all(handle not in fake.destroys for handle in fake.leaked)


@pytest.mark.parametrize(("method", "op"), _SO_LEGS)
def test_so_leg_so_hidden_refused_leak_swept_after_restore(method: str, op: str) -> None:
    """A refused-but-created object invisible to the SO session must not pass:
    the post-restoration USER-side sweep finds it by attempt label."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.attempt_leak = "proved"
    fake.hide_attempt_leak_from_so = True
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.operation == op
    assert rec.detail["disposition"] == "refused-but-created"
    assert fake.leaked
    assert all(handle in fake.destroys for handle in fake.leaked)
    assert fake.login_state == "user"
    assert any(entry.startswith("close:") for entry in fake.ops)


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_control_with_hidden_companion_swept_after_restore(method: str, _op: str) -> None:
    """A control-window companion hidden from SO inventories must not pass:
    the post-restoration full-remainder sweep xfails it alive."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.ok_companion = True
    fake.hide_ok_companion_from_so = True
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-effect"
    assert rec.detail["new_handles"] == list(fake.leaked)
    assert fake.leaked
    assert all(handle not in fake.destroys for handle in fake.leaked)
    assert fake.login_state == "user"
    assert any(entry.startswith("close:") for entry in fake.ops)


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_control_with_companion_object_xfails_unproved(method: str, _op: str) -> None:
    """A positive leg that gains an unexpected delta companion is not a clean
    pass: the owned handle is cleaned and the companion stays alive."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.ok_companion = True
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-effect"
    assert fake.leaked
    assert all(handle not in fake.destroys for handle in fake.leaked)
    assert fake.login_state == "user"


_SO_LEGS_WITH_SOURCE = frozenset(
    {
        "test_so_cannot_copy_to_private_object",
        "test_so_cannot_derive_private_key",
        "test_so_cannot_unwrap_private_key",
    }
)


_SO_SETUP_FINDS = {
    "test_so_cannot_create_private_object": 0,
    "test_so_cannot_copy_to_private_object": 2,
    "test_so_cannot_generate_private_key": 0,
    "test_so_cannot_derive_private_key": 2,
    "test_so_cannot_unwrap_private_key": 4,
}


def _neg_after_script(method: str, tail_rv: int) -> list[int]:
    """Find script: setup before/after per setup handle + visibility (source legs)
    + control before/after + negative before OK."""
    script = [_OK] * _SO_SETUP_FINDS[method]
    script.extend([_OK] if method in _SO_LEGS_WITH_SOURCE else [])
    script.extend([_OK, _OK, _OK, tail_rv])
    return script


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_acceptance_with_failed_inventory_still_fails(method: str, _op: str) -> None:
    """Acceptance is a known failure: it survives a failed after-inventory."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _OK]
    fake.find_init_script = _neg_after_script(method, _CLEAN_REFUSAL)
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("accepted_invalid", None)
    assert rec.detail["disposition"] == "unproved-handle-alive"
    assert rec.detail["inventory_rv"] == ckr_name(_CLEAN_REFUSAL)


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_refusal_with_failed_inventory_xfails_unproved(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.find_init_script = _neg_after_script(method, _CLEAN_REFUSAL)
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-effect"
    assert rec.detail["inventory_rv"] == ckr_name(_CLEAN_REFUSAL)


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_undefined_inventory_rv_fails(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.find_init_script = _neg_after_script(method, _UNDEFINED_RV)
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_FindObjects"


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_malformed_private_readback_on_acceptance_fails(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _OK]
    fake.private_read_script = [None, b"\x01\x02"]
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "metadata")
    assert rec.detail["actual_type"] == "bytes"


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_control_acceptance_reading_private_fails(method: str, _op: str) -> None:
    """The public control asking False but reading True is a policy failure."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.private_read_blob = b"\x01"
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    _assert_fail_record("self_contradiction", "policy")
    assert len(fake.attempt_calls) == 1, "negative leg must not run after failed control"


@pytest.mark.parametrize(
    "method",
    [
        "test_so_cannot_copy_to_private_object",
        "test_so_cannot_derive_private_key",
        "test_so_cannot_unwrap_private_key",
    ],
)
def test_so_leg_hidden_source_xfails_before_any_attempt(method: str) -> None:
    """A source hidden from SO would mask the output-creation rule: xfail, no attempt."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.hide_setup_from_so = True
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert "visible" in rec.summary
    assert fake.attempt_calls == []
    assert fake.login_state == "user"


# --- SO legs: entry transition ----------------------------------------------


_CREATE = "test_so_cannot_create_private_object"


def test_so_leg_so_login_refusal_xfails_without_transition() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.so_login_rv = _CLEAN_REFUSAL
    assert_xfails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.actual_ckr == ckr_name(_CLEAN_REFUSAL)
    assert fake.attempt_calls == []
    assert rec.operation == "C_Login"


def test_so_leg_so_login_wrong_pin_skips() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.so_login_rv = int(CKR_PIN_INCORRECT)
    assert_skips(_run_so_leg, _CREATE, _rs(fake), _config())
    assert C.get_records() == []
    assert fake.attempt_calls == []


def test_so_leg_so_login_undefined_rv_fails() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.so_login_rv = _UNDEFINED_RV
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_Login"


def test_so_leg_entry_logout_refusal_xfails_without_transition() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.logout_script = [_CLEAN_REFUSAL]
    assert_xfails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Logout"
    assert fake.attempt_calls == []


def test_so_leg_entry_state_contradiction_fails() -> None:
    """C_Login(SO) OK but session state reads USER: the module contradicts itself."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.state_lie = int(CKS_RW_USER_FUNCTIONS)
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert rec.operation == "C_GetSessionInfo"
    assert fake.attempt_calls == []


def test_so_leg_entry_state_unreadable_xfails() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.getsessioninfo_script = [_CLEAN_REFUSAL]
    assert_xfails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_GetSessionInfo"
    assert fake.attempt_calls == []
    assert fake.login_state == "user"
    assert "close:10" in fake.ops


def test_so_leg_missing_pins_skip() -> None:
    fake = _SoCreationRaw()
    assert_skips(_run_so_leg, _CREATE, _rs(fake), _config(pin=None, so_pin=None))
    assert C.get_records() == []
    assert fake.logins == []


# --- SO legs: restoration ----------------------------------------------------


def test_so_leg_restoration_logout_refusal_fails_loudly() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.logout_script = [_OK, _CLEAN_REFUSAL]
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert rec.operation == "C_Logout"
    assert rec.detail["restoration_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert "primary" in rec.detail


def test_so_leg_restoration_relogin_refusal_fails_loudly() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.user_relogin_rv = _CLEAN_REFUSAL
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert rec.operation == "C_Login"
    assert rec.detail["restoration_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert "primary" in rec.detail


def test_so_leg_restoration_relogin_already_logged_in_fails() -> None:
    """Logout reported OK, then USER login claims already-logged-in: contradiction."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.user_relogin_rv = int(CKR_USER_ALREADY_LOGGED_IN)
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert rec.operation == "C_Login"
    assert rec.detail["restoration_rv"] == ckr_name(int(CKR_USER_ALREADY_LOGGED_IN))


def test_so_leg_restoration_wrong_state_fails_loudly() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.sessioninfo_script = [None, int(CKS_RW_PUBLIC_SESSION)]
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert rec.operation == "C_GetSessionInfo"
    assert "primary" in rec.detail


def test_so_leg_failed_primary_with_failed_restoration_keeps_both() -> None:
    """A failing primary verdict plus a restoration failure reports both RVs."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _UNDEFINED_RV]
    fake.user_relogin_rv = _CLEAN_REFUSAL
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.detail["restoration_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert rec.detail["primary_rv"] == ckr_name(_UNDEFINED_RV)


# --- SO legs: setup ----------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "test_so_cannot_copy_to_private_object",
        "test_so_cannot_derive_private_key",
        "test_so_cannot_unwrap_private_key",
    ],
)
def test_so_leg_setup_refusal_xfails_before_transition(method: str) -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.setup_rv = _CLEAN_REFUSAL
    assert_xfails(_run_so_leg, method, _rs(fake), _config())
    _assert_xfail_record("not_operational")
    assert ("so", len("so-pin")) not in fake.logins
    assert fake.attempt_calls == []


def test_so_leg_setup_undefined_rv_fails() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.setup_rv = _UNDEFINED_RV
    _assert_fails(_run_so_leg, "test_so_cannot_derive_private_key", _rs(fake), _config())
    _assert_fail_record("self_contradiction", "metadata")


def test_so_unwrap_leg_wrap_setup_refusal_xfails() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.wrap_rv = _CLEAN_REFUSAL
    assert_xfails(_run_so_leg, "test_so_cannot_unwrap_private_key", _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_WrapKey"


# --- USER private-creation controls -------------------------------------------


@pytest.mark.parametrize(("method", "_op"), _USER_LEGS)
def test_user_leg_healthy_passes(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    _run_user_leg(method, _rs(fake), _config())
    assert C.get_records() == []
    assert fake.login_state == "user"
    assert fake.destroys, "control object must be cleaned up"


# Fixture-session creates before the attempt itself (the fake routes every
# fixture-session create through the setup branch, so the refusal must be
# scripted past setup to reach the attempt branch it claims to test). The
# create leg probes support with an empty-template create first.
_USER_SETUP_CALLS = {
    "test_user_can_create_private_object": 1,
    "test_user_can_copy_to_private_object": 1,
    "test_user_can_generate_private_key": 0,
    "test_user_can_derive_private_key": 1,
    "test_user_can_unwrap_private_key": 2,
}


@pytest.mark.parametrize(("method", "op"), _USER_LEGS)
@pytest.mark.parametrize("rv", [_CLEAN_REFUSAL, _OTHER_CLEAN, _VENDOR_REFUSAL])
def test_user_leg_clean_refusal_xfails_never_passes(method: str, op: str, rv: int) -> None:
    fake = _SoCreationRaw()
    fake.setup_script = [_OK] * _USER_SETUP_CALLS[method] + [rv]
    assert_xfails(_run_user_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == op
    assert rec.actual_ckr == ckr_name(rv)


@pytest.mark.parametrize(("method", "op"), _USER_LEGS)
def test_user_leg_undefined_rv_fails(method: str, op: str) -> None:
    fake = _SoCreationRaw()
    fake.setup_script = [_OK] * _USER_SETUP_CALLS[method] + [_UNDEFINED_RV]
    _assert_fails(_run_user_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == op


@pytest.mark.parametrize(("method", "_op"), _USER_LEGS)
def test_user_leg_public_readback_fails_wrong_result(method: str, _op: str) -> None:
    """Asked private, got public: CKR_OK with the wrong effect fails."""
    fake = _SoCreationRaw()
    fake.private_read_blob = b"\x00"
    _assert_fails(_run_user_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "policy")
    assert rec.detail["expected_private"] is True
    assert rec.detail["actual_private"] is False


@pytest.mark.parametrize(("method", "_op"), _USER_LEGS)
def test_user_leg_missing_readback_xfails_unproved(method: str, _op: str) -> None:
    fake = _SoCreationRaw()
    fake.getattr_omit = {int(CKA_PRIVATE)}
    assert_xfails(_run_user_leg, method, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unreadable-value"


# --- credential scoping --------------------------------------------------------


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_uses_scoped_credentials_in_order(method: str, _op: str) -> None:
    """SO PIN authenticates SO; USER PIN restores USER; lengths prove the mapping."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    _run_so_leg(method, _rs(fake), _config(pin="user-pw", so_pin="officer-pw"))
    roles = [role for role, _ in fake.logins]
    assert roles[0] == "so"
    assert "user" in roles[1:]
    assert fake.logins[0] == ("so", len("officer-pw"))
    assert ("user", len("user-pw")) in fake.logins
    assert fake.login_state == "user"


# --- fix round 1 (R14-01): setup source needs ownership proof ----------------


def test_so_copy_leg_setup_returning_foreign_handle_xfails_without_destroy() -> None:
    """Setup returning pre-existing 41 is unproved: xfail, never trusted, never destroyed."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.objects[41] = {int(CKA_LABEL): b"someone-elses-object"}
    fake.setup_replay_handles = [41]
    assert_xfails(_run_so_leg, "test_so_cannot_copy_to_private_object", _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert 41 not in fake.destroys
    assert 41 in fake.objects


def test_so_copy_leg_setup_after_inventory_refusal_xfails_without_destroy() -> None:
    """Setup-after inventory refused: the source is unproved and stays alive."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_so_leg, "test_so_cannot_copy_to_private_object", _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert fake.setup_handles
    assert all(handle not in fake.destroys for handle in fake.setup_handles)


# --- fix round 1 (R14-02): early scope exits restore login state and close ---


def test_so_leg_so_login_refusal_restores_user_and_closes() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.so_login_rv = _CLEAN_REFUSAL
    assert_xfails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Login"
    assert fake.login_state == "user"
    assert "close:10" in fake.ops


def test_so_leg_entry_state_unreadable_upgrades_when_restoration_unverifiable() -> None:
    """Stickily unreadable state: the premise xfails, but restoration cannot be
    verified, so the leg upgrades to fail -- still restored and closed."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.getsessioninfo_rv = _CLEAN_REFUSAL
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = C.get_records()[0]
    assert rec.outcome == "fail"
    assert rec.detail is not None
    assert rec.detail["restoration_operation"] == "C_GetSessionInfo"
    assert rec.detail["restoration_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert fake.login_state == "user"
    assert "close:10" in fake.ops


def test_so_leg_entry_state_contradiction_restores_user_and_closes() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.state_lie = int(CKS_RW_USER_FUNCTIONS)
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert rec.operation == "C_GetSessionInfo"
    assert fake.login_state == "user"
    assert "close:10" in fake.ops


def test_so_leg_wrong_pin_skip_restores_user_and_closes() -> None:
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.so_login_rv = int(CKR_PIN_INCORRECT)
    assert_skips(_run_so_leg, _CREATE, _rs(fake), _config())
    assert C.get_records() == []
    assert fake.login_state == "user"
    assert "close:10" in fake.ops


def test_so_leg_entry_logout_refusal_closes_session() -> None:
    """Entry logout refused: login was never cleared, but the session must still close."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.logout_script = [_CLEAN_REFUSAL]
    assert_xfails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Logout"
    assert fake.login_state == "user"
    assert "close:10" in fake.ops


def test_so_leg_early_exit_restoration_failure_upgrades_to_fail() -> None:
    """SO login refused and USER restoration refused: loud fail with both outcomes."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.so_login_rv = _CLEAN_REFUSAL
    fake.user_relogin_rv = _CLEAN_REFUSAL
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = C.get_records()[0]
    assert rec.outcome == "fail"
    assert rec.detail is not None
    assert rec.detail["restoration_operation"] == "C_Login"
    assert rec.detail["restoration_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert rec.detail["primary"] == "leg-did-not-run"
    assert "close:10" in fake.ops


# --- fix round 1 (R14-07): positive judging covers proved extras --------------


@pytest.mark.parametrize(("method", "_op"), _USER_LEGS)
def test_user_leg_proved_extra_companion_fails_and_destroys_all_proved(
    method: str, _op: str
) -> None:
    """OK creating a proved-labeled sibling beside the returned handle: destroy both, fail."""
    fake = _SoCreationRaw()
    fake.setup_proved_extra = True
    _assert_fails(_run_user_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.detail["disposition"] == "created-extra"
    assert rec.detail["extra_handles"]
    for handle in rec.detail["proved_new_handles"]:
        assert handle in fake.destroys
    attempt_label = fake.setup_creates[-1]["attrs"][int(CKA_LABEL)]
    remaining = [
        handle
        for handle, attrs in fake.objects.items()
        if attrs.get(int(CKA_LABEL)) == attempt_label
    ]
    assert remaining == []


# --- fix round 1 (R14-08): record rewrites reset severity and reason ----------


@pytest.mark.parametrize(("method", "_op"), _SO_LEGS)
def test_so_leg_acceptance_with_missing_readback_fails_critical(method: str, _op: str) -> None:
    """Missing-private acceptance rewritten to policy failure must be CRITICAL, not LOW."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _OK]
    fake.private_read_script = [None, _OMIT_PRIVATE_READ]
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.severity == "CRITICAL"


def test_so_leg_xfail_primary_with_failed_restoration_drops_xfail_reason() -> None:
    """Xfail + restoration failure becomes FAIL with a fail reason and FAIL severity."""
    fake = _SoCreationRaw()
    fake.attempt_script = [_OK, _CLEAN_REFUSAL]
    fake.user_relogin_rv = _CLEAN_REFUSAL
    _assert_fails(_run_so_leg, _CREATE, _rs(fake), _config())
    rec = C.get_records()[0]
    assert rec.outcome == "fail"
    assert rec.reason == "self_contradiction"
    assert rec.severity == C.derive_verdict("self_contradiction", rec.kind)[1]
    assert rec.detail is not None
    assert rec.detail["restoration_rv"] == ckr_name(_CLEAN_REFUSAL)


# --- fix round 2 (F1): negative acceptance must destroy proved extras --------


class _NegAcceptExtraRaw(_SoCreationRaw):
    """Attempt-session OK on the negative leg gains a proved-labeled sibling."""

    proved_extra_on_attempt_ok = False

    def _record_create(
        self, op: str, session: int, attrs: dict[int, bytes], handle_ptr: Any
    ) -> int:
        if (
            self.proved_extra_on_attempt_ok
            and self._is_attempt_session(session)
            and len(self.attempt_calls) == 1
        ):
            assert self.attempt_script and self.attempt_script[0] == _OK
            rv = super()._record_create(op, session, attrs, handle_ptr)
            assert rv == _OK
            stored = dict(attrs)
            stored.setdefault(int(CKA_TOKEN), b"\x00")
            self.leaked.append(self._alloc(stored))
            return rv
        return super()._record_create(op, session, attrs, handle_ptr)


@pytest.mark.parametrize(("method", "op"), _SO_LEGS)
def test_so_leg_negative_acceptance_with_proved_extra_destroys_and_cites(
    method: str, op: str
) -> None:
    """SO negative acceptance with a proved sibling: destroy every proved handle, cite extras."""
    fake = _NegAcceptExtraRaw()
    fake.attempt_script = [_OK, _OK]
    fake.proved_extra_on_attempt_ok = True
    _assert_fails(_run_so_leg, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == op
    assert rec.detail["disposition"] == "created-extra"
    assert rec.detail["extra_handles"]
    assert sorted(rec.detail["extra_handles"]) == sorted(fake.leaked)
    for handle in rec.detail["proved_new_handles"]:
        assert handle in fake.destroys
    assert all(handle not in fake.objects for handle in fake.leaked)
    assert fake.login_state == "user"


# --- fix round 2 (F2): every QC10a setup site proves handle ownership ---------


class _F2SetupRaw(_SoCreationRaw):
    """F2 contracts: attribute-read spy + optional second-setup-create replay."""

    def __init__(self) -> None:
        super().__init__()
        self.reads: list[int] = []
        self.replay_second_setup_handle: int | None = None

    def C_GetAttributeValue(self, sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.reads.append(int(handle))
        return super().C_GetAttributeValue(sh, handle, tmpl, count)

    def _record_create(
        self, op: str, session: int, attrs: dict[int, bytes], handle_ptr: Any
    ) -> int:
        if (
            not self._is_attempt_session(session)
            and self.replay_second_setup_handle is not None
            and len(self.setup_creates) == 1
        ):
            self.setup_replay_handles.insert(0, self.replay_second_setup_handle)
            self.replay_second_setup_handle = None
        return super()._record_create(op, session, attrs, handle_ptr)


_SO_DERIVE = "test_so_cannot_derive_private_key"
_SO_UNWRAP = "test_so_cannot_unwrap_private_key"
_USER_COPY = "test_user_can_copy_to_private_object"
_USER_DERIVE = "test_user_can_derive_private_key"
_USER_UNWRAP = "test_user_can_unwrap_private_key"


def test_so_derive_leg_setup_returning_foreign_handle_xfails_without_destroy() -> None:
    """SO derive base returning pre-existing 41: unproved xfail, never read, never destroyed."""
    fake = _F2SetupRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.objects[41] = {int(CKA_LABEL): b"someone-elses-object"}
    fake.setup_replay_handles = [41]
    assert_xfails(_run_so_leg, _SO_DERIVE, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert 41 not in fake.destroys
    assert 41 in fake.objects
    assert 41 not in fake.reads
    assert ("so", len("so-pin")) not in fake.logins
    assert fake.attempt_calls == []


def test_so_derive_leg_setup_after_inventory_refusal_xfails_without_destroy() -> None:
    """SO derive setup-after inventory refused: the base is unproved and stays alive."""
    fake = _F2SetupRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_so_leg, _SO_DERIVE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert fake.setup_handles
    assert all(handle not in fake.destroys for handle in fake.setup_handles)
    assert fake.attempt_calls == []


def test_so_unwrap_leg_setup_returning_foreign_kek_xfails_before_target_setup() -> None:
    """SO unwrap KEK returning pre-existing 41: unproved xfail before the target is made."""
    fake = _F2SetupRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.objects[41] = {int(CKA_LABEL): b"victim-kek"}
    fake.setup_replay_handles = [41]
    assert_xfails(_run_so_leg, _SO_UNWRAP, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert 41 not in fake.destroys
    assert 41 in fake.objects
    assert 41 not in fake.reads
    assert len(fake.setup_creates) == 1
    assert ("so", len("so-pin")) not in fake.logins
    assert fake.attempt_calls == []


def test_so_unwrap_leg_setup_returning_foreign_target_xfails_after_proved_kek() -> None:
    """Proved KEK + foreign target 42: unproved xfail; the proved KEK is cleaned, 42 lives."""
    fake = _F2SetupRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.objects[42] = {int(CKA_LABEL): b"victim-target"}
    fake.replay_second_setup_handle = 42
    assert_xfails(_run_so_leg, _SO_UNWRAP, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert fake.setup_handles
    assert all(handle in fake.destroys for handle in fake.setup_handles)
    assert 42 not in fake.destroys
    assert 42 in fake.objects
    assert 42 not in fake.reads
    assert ("so", len("so-pin")) not in fake.logins
    assert fake.attempt_calls == []


def test_so_unwrap_leg_setup_after_inventory_refusal_xfails_without_destroy() -> None:
    """SO unwrap KEK setup-after inventory refused: the KEK is unproved and stays alive."""
    fake = _F2SetupRaw()
    fake.attempt_script = [_OK, _NOT_LOGGED_IN]
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_so_leg, _SO_UNWRAP, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert fake.setup_handles
    assert all(handle not in fake.destroys for handle in fake.setup_handles)
    assert len(fake.setup_creates) == 1
    assert fake.attempt_calls == []


def test_user_copy_leg_setup_returning_foreign_handle_xfails_without_destroy() -> None:
    """USER copy source returning pre-existing 41: unproved xfail, never read, never destroyed."""
    fake = _F2SetupRaw()
    fake.objects[41] = {int(CKA_LABEL): b"someone-elses-object"}
    fake.setup_replay_handles = [41]
    assert_xfails(_run_user_leg, _USER_COPY, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert 41 not in fake.destroys
    assert 41 in fake.objects
    assert 41 not in fake.reads
    assert len(fake.setup_creates) == 1


def test_user_copy_leg_setup_after_inventory_refusal_xfails_without_destroy() -> None:
    """USER copy setup-after inventory refused: the source is unproved and stays alive."""
    fake = _F2SetupRaw()
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_user_leg, _USER_COPY, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert fake.setup_handles
    assert all(handle not in fake.destroys for handle in fake.setup_handles)
    assert len(fake.setup_creates) == 1


def test_user_derive_leg_setup_returning_foreign_handle_xfails_without_destroy() -> None:
    """USER derive base returning pre-existing 41: unproved xfail, never read, never destroyed."""
    fake = _F2SetupRaw()
    fake.objects[41] = {int(CKA_LABEL): b"victim-base"}
    fake.setup_replay_handles = [41]
    assert_xfails(_run_user_leg, _USER_DERIVE, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert 41 not in fake.destroys
    assert 41 in fake.objects
    assert 41 not in fake.reads
    assert len(fake.setup_creates) == 1


def test_user_derive_leg_setup_after_inventory_refusal_xfails_without_destroy() -> None:
    """USER derive setup-after inventory refused: the base is unproved and stays alive."""
    fake = _F2SetupRaw()
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_user_leg, _USER_DERIVE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert fake.setup_handles
    assert all(handle not in fake.destroys for handle in fake.setup_handles)
    assert len(fake.setup_creates) == 1


def test_user_unwrap_leg_setup_returning_foreign_kek_xfails_before_target_setup() -> None:
    """USER unwrap KEK returning pre-existing 41: unproved xfail before the target is made."""
    fake = _F2SetupRaw()
    fake.objects[41] = {int(CKA_LABEL): b"victim-kek"}
    fake.setup_replay_handles = [41]
    assert_xfails(_run_user_leg, _USER_UNWRAP, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert 41 not in fake.destroys
    assert 41 in fake.objects
    assert 41 not in fake.reads
    assert len(fake.setup_creates) == 1


def test_user_unwrap_leg_setup_returning_foreign_target_xfails_after_proved_kek() -> None:
    """Proved KEK + foreign target 42: unproved xfail; the proved KEK is cleaned, 42 lives."""
    fake = _F2SetupRaw()
    fake.objects[42] = {int(CKA_LABEL): b"victim-target"}
    fake.replay_second_setup_handle = 42
    assert_xfails(_run_user_leg, _USER_UNWRAP, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert fake.setup_handles
    assert all(handle in fake.destroys for handle in fake.setup_handles)
    assert 42 not in fake.destroys
    assert 42 in fake.objects
    assert 42 not in fake.reads


def test_user_unwrap_leg_setup_after_inventory_refusal_xfails_without_destroy() -> None:
    """USER unwrap KEK setup-after inventory refused: the KEK is unproved and stays alive."""
    fake = _F2SetupRaw()
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_user_leg, _USER_UNWRAP, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert fake.setup_handles
    assert all(handle not in fake.destroys for handle in fake.setup_handles)
    assert len(fake.setup_creates) == 1
