"""Production-method contracts for QC10b context-auth transitions (#52.5).

Drives the real testcase methods in
``pkcs11_check.testcases.test_always_authenticate`` (``TestContextAuthTransitions``)
against a scriptable fake token at the raw ``C_*`` layer. The fake performs
real RSA-2048 ``SHA256/RSA_PKCS`` sign/verify and ``RSA_PKCS`` encrypt/decrypt
with a module-scoped key, so the production independent-verification legs run
for real; defect knobs seed exactly one grant-model deviation each:

- healthy: terminal consumption succeeds; replacement/cross-session/second-use
  without fresh re-auth rejects ``CKR_USER_NOT_LOGGED_IN``; length queries and
  ``CKR_BUFFER_TOO_SMALL`` preserve the grant; multipart Update preserves and
  Final consumes; decrypt failure terminates;
- permitted variation: other clean RVs on judged calls xfail with the
  original RV; staging (Init/Update/login/setup) clean refusals xfail as
  unmet premises, never pass and never fail;
- exact defect: grant leaks (cross-session, post-terminal, post-failure),
  grant consumed by a nonterminal call, wrong crypto output, or OK-on-tiny
  buffer all fail with function + phase evidence;
- malformed evidence: bad signatures, malformed public material, and
  undefined RVs fail; unreadable public material xfails unproved.

Also pins the per-function termination judge ``_qc10b_is_terminal`` and the
grant-applicability table exhaustively (pure functions, no provider needed).

Fakes only; no provider is loaded.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SIGNATURE_INVALID,
    CKR_USER_NOT_LOGGED_IN,
    CKU_CONTEXT_SPECIFIC,
)
from pkcs11_check.testcases import test_always_authenticate as taa
from tests._skip_assert import assert_skips, assert_xfails

_OK = int(CKR_OK)
_NOT_LOGGED_IN = int(CKR_USER_NOT_LOGGED_IN)
_NOT_INITIALIZED = int(CKR_OPERATION_NOT_INITIALIZED)
_BTS = int(CKR_BUFFER_TOO_SMALL)
_CLEAN_REFUSAL = int(CKR_GENERAL_ERROR)
_OTHER_CLEAN = int(CKR_ARGUMENTS_BAD)
_VENDOR_REFUSAL = 0x80000001
_UNDEFINED_RV = 0x7FFFFFFF
_UNAVAILABLE = int(CK_UNAVAILABLE_INFORMATION)
_CTX = int(CKU_CONTEXT_SPECIFIC)

_FIXTURE_SH = 7
_RSA_BYTES = 256

_RSA_KEY: Any = None


@pytest.fixture(scope="module", autouse=True)
def _rsa_key_module() -> Iterator[Any]:
    """One module-scoped RSA-2048 key backing every fake keypair handle."""
    global _RSA_KEY
    _RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    yield _RSA_KEY
    _RSA_KEY = None


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


def _read_ulong(ptr: Any) -> int:
    return int(ctypes.cast(ptr, ctypes.POINTER(CK_ULONG)).contents.value)


def _write_ulong(ptr: Any, value: int) -> None:
    ctypes.cast(ptr, ctypes.POINTER(CK_ULONG)).contents.value = value


class _CtxAuthRaw:
    """Scriptable fake token with real RSA for the QC10b production methods."""

    def __init__(self) -> None:
        assert _RSA_KEY is not None, "module RSA fixture did not run"
        self.key = _RSA_KEY
        numbers = self.key.public_key().public_numbers()
        self.modulus = numbers.n.to_bytes(_RSA_BYTES, "big")
        self.exponent = numbers.e.to_bytes(3, "big")
        self.objects: dict[int, dict[str, Any]] = {}
        self.sessions: set[int] = {_FIXTURE_SH}
        self.op_by_session: dict[int, dict[str, Any] | None] = {}
        self.destroys: list[int] = []
        self.sign_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []
        self.login_calls: list[int] = []
        self._next_handle = 500
        self._next_session = 10
        # Knobs.
        self.keygen_rv: int = _OK
        self.getattr_rv: int | None = None
        self.getattr_omit: set[int] = set()
        self.getattr_malformed: dict[int, bytes] = {}
        self.login_rv: int = _OK
        self.sign_script: list[int] = []
        self.sign_final_script: list[int] = []
        self.sign_update_script: list[int] = []
        self.sign_mode = "valid"  # valid | corrupt | short
        self.query_rv: int = _OK
        self.decrypt_script: list[int] = []
        self.decrypt_mode = "valid"  # valid | corrupt
        self.grant_leak = False
        self.grantless_rv: int = _NOT_LOGGED_IN
        self.grant_survives_terminal = False
        self.grant_consumed_by_query = False
        self.grant_consumed_by_bts = False
        # Fix-round-1 knobs (R14).
        self.keygen_alias_outputs = False
        self.keygen_refusal_leak = "none"  # none | proved | foreign
        self.keygen_success_extra = "none"  # none | proved | foreign (R16-02)
        self.leaked: list[int] = []
        self.reads: list[int] = []
        self.keygen_replay_handles: tuple[int, int] | None = None
        self.sign_rv_by_session: dict[int, list[int]] = {}
        self.sign_reported_len: int | None = None
        self.decrypt_reported_len: int | None = None
        self.encrypt_reported_len: int | None = None
        self.update_bts_retains_op = False
        self.find_init_script: list[int] = []
        self._search: list[int] = []

    def _alloc(self, entry: dict[str, Any]) -> int:
        self._next_handle += 1
        handle = self._next_handle
        self.objects[handle] = entry
        return handle

    def _op(self, session: int) -> dict[str, Any] | None:
        return self.op_by_session.get(int(session))

    def _terminate(self, session: int) -> None:
        self.op_by_session[int(session)] = None

    def _granted(self, session: int) -> bool:
        op = self._op(session)
        return bool(op and op["grant"]) or self.grant_leak

    # -- sessions -------------------------------------------------------
    def C_OpenSession(self, slot_id: int, flags: int, *_args: Any) -> int:  # noqa: N802
        handle = self._next_session
        self._next_session += 1
        self.sessions.add(handle)
        _write_ulong(_args[-1], handle)
        return _OK

    def C_CloseSession(self, session: int) -> int:  # noqa: N802
        self.sessions.discard(int(session))
        self.op_by_session.pop(int(session), None)
        return _OK

    def C_Login(self, session: int, user_type: int, _pin: Any, _pin_len: int) -> int:  # noqa: N802
        assert int(user_type) == _CTX, f"unexpected login type {user_type}"
        self.login_calls.append(int(session))
        if self._op(session) is None:
            return _NOT_INITIALIZED
        if self.login_rv != _OK:
            return self.login_rv
        op = self._op(session)
        assert op is not None
        op["grant"] = True
        return _OK

    # -- keypair setup ----------------------------------------------------
    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        pub_tmpl: Any,
        pub_count: int,
        priv_tmpl: Any,
        priv_count: int,
        pub_out: Any,
        priv_out: Any,
    ) -> int:
        if self.keygen_rv != _OK:
            if self.keygen_refusal_leak != "none":
                label = _decode_template(priv_tmpl, int(priv_count)).get(int(CKA_LABEL))
                entry: dict[str, Any] = {"kind": "refused-leak"}
                if self.keygen_refusal_leak == "proved" and label is not None:
                    entry["label"] = label
                self.leaked.append(self._alloc(entry))
            return self.keygen_rv
        pub_attrs = _decode_template(pub_tmpl, int(pub_count))
        priv_attrs = _decode_template(priv_tmpl, int(priv_count))
        assert priv_attrs.get(int(CKA_ALWAYS_AUTHENTICATE)) == b"\x01"
        if self.keygen_replay_handles is not None:
            pub, priv = self.keygen_replay_handles
            _write_handle(pub_out, pub)
            _write_handle(priv_out, priv)
            return _OK
        if self.keygen_alias_outputs:
            single = self._alloc({"kind": "aliased"})
            _write_handle(pub_out, single)
            _write_handle(priv_out, single)
            return _OK
        pub = self._alloc({"kind": "pub", "label": pub_attrs.get(int(CKA_LABEL))})
        priv = self._alloc({"kind": "priv", "label": priv_attrs.get(int(CKA_LABEL))})
        if self.keygen_success_extra != "none":
            extra_entry: dict[str, Any] = {"kind": "success-extra"}
            if self.keygen_success_extra == "proved":
                extra_entry["label"] = priv_attrs.get(int(CKA_LABEL))
            else:
                extra_entry["label"] = b"qc10b-foreign-success-extra"
            self.leaked.append(self._alloc(extra_entry))
        _write_handle(pub_out, pub)
        _write_handle(priv_out, priv)
        return _OK

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if self.getattr_rv is not None:
            return self.getattr_rv
        entry = self.objects.get(int(handle))
        assert entry is not None, f"read from unknown handle {handle}"
        self.reads.append(int(handle))
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            if attr in self.getattr_omit:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(int(CKR_ATTRIBUTE_TYPE_INVALID))
                continue
            if attr in self.getattr_malformed:
                blob: bytes | None = self.getattr_malformed[attr]
            elif attr == int(CKA_ALWAYS_AUTHENTICATE):
                blob = b"\x01"
            elif attr == int(CKA_LABEL):
                label_blob: Any = entry.get("label")
                blob = bytes(label_blob) if isinstance(label_blob, (bytes, bytearray)) else None
            elif attr == int(CKA_MODULUS):
                blob = bytes(self.modulus)
            elif attr == int(CKA_PUBLIC_EXPONENT):
                blob = bytes(self.exponent)
            else:
                blob = None
            if blob is None:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(int(CKR_ATTRIBUTE_TYPE_INVALID))
                continue
            if addr:
                ctypes.memmove(addr, blob, min(len(blob), cap))
            tmpl[i].ulValueLen = len(blob)
            row_rvs.append(_OK)
        if int(CKR_ATTRIBUTE_TYPE_INVALID) in row_rvs:
            return int(CKR_ATTRIBUTE_TYPE_INVALID)
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroys.append(int(handle))
        self.objects.pop(int(handle), None)
        return _OK

    # -- sign ---------------------------------------------------------------
    def _init_op(self, session: int, func: str, key: int) -> int:
        if self._op(session) is not None:
            return int(CKR_OPERATION_ACTIVE)
        self.op_by_session[int(session)] = {
            "func": func,
            "key": int(key),
            "grant": False,
            "data": [],
        }
        return _OK

    def C_SignInit(self, session: int, _mech: Any, key: int) -> int:  # noqa: N802
        return self._init_op(session, "sign", key)

    def _real_sign(self, data: bytes) -> bytes:
        sig: bytes = self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        if self.sign_mode == "corrupt":
            # XOR, not a fixed byte: setting byte 0 to 0x00 is a no-op (and a
            # flaky pass) whenever the genuine signature already starts there.
            return bytes((sig[0] ^ 0xFF,)) + sig[1:]
        if self.sign_mode == "short":
            return sig[:128]
        return sig

    def C_Sign(  # noqa: N802
        self, session: int, data_ptr: Any, data_len: int, sig_ptr: Any, sig_len_ptr: Any
    ) -> int:
        op = self._op(session)
        if op is None or op["func"] != "sign":
            return _NOT_INITIALIZED
        forced = self.sign_rv_by_session.get(int(session))
        if forced:
            self._terminate(session)
            return forced.pop(0)
        data = ctypes.string_at(data_ptr, int(data_len))
        query = sig_ptr is None
        self.sign_calls.append({"query": query, "data_len": len(data)})
        if not self._granted(session):
            self._terminate(session)
            return self.grantless_rv
        if query:
            if self.query_rv != _OK:
                self._terminate(session)
                return self.query_rv
            _write_ulong(sig_len_ptr, _RSA_BYTES)
            if self.grant_consumed_by_query:
                self._terminate(session)
            return _OK
        capacity = _read_ulong(sig_len_ptr)
        if capacity < _RSA_BYTES:
            _write_ulong(sig_len_ptr, _RSA_BYTES)
            if self.grant_consumed_by_bts:
                self._terminate(session)
            return _BTS
        rv = self.sign_script.pop(0) if self.sign_script else _OK
        if rv != _OK:
            self._terminate(session)
            return rv
        sig = self._real_sign(data)
        ctypes.memmove(sig_ptr, sig, len(sig))
        reported = self.sign_reported_len if self.sign_reported_len is not None else len(sig)
        _write_ulong(sig_len_ptr, reported)
        if not self.grant_survives_terminal:
            self._terminate(session)
        return _OK

    def C_SignUpdate(self, session: int, data_ptr: Any, data_len: int) -> int:  # noqa: N802
        op = self._op(session)
        if op is None or op["func"] != "sign":
            if self.sign_update_script:
                return self.sign_update_script.pop(0)
            return _NOT_INITIALIZED
        if self.sign_update_script:
            rv = self.sign_update_script.pop(0)
            if rv != _OK:
                if not (rv == _BTS and self.update_bts_retains_op):
                    self._terminate(session)
            else:
                op["data"].append(ctypes.string_at(data_ptr, int(data_len)))
            return rv
        op["data"].append(ctypes.string_at(data_ptr, int(data_len)))
        return _OK

    def C_SignFinal(self, session: int, sig_ptr: Any, sig_len_ptr: Any) -> int:  # noqa: N802
        op = self._op(session)
        if op is None or op["func"] != "sign":
            return _NOT_INITIALIZED
        if not self._granted(session):
            self._terminate(session)
            return self.grantless_rv
        capacity = _read_ulong(sig_len_ptr)
        if capacity < _RSA_BYTES:
            _write_ulong(sig_len_ptr, _RSA_BYTES)
            return _BTS
        rv = self.sign_final_script.pop(0) if self.sign_final_script else _OK
        if rv != _OK:
            self._terminate(session)
            return rv
        sig = self._real_sign(b"".join(op["data"]))
        ctypes.memmove(sig_ptr, sig, len(sig))
        reported = self.sign_reported_len if self.sign_reported_len is not None else len(sig)
        _write_ulong(sig_len_ptr, reported)
        if not self.grant_survives_terminal:
            self._terminate(session)
        return _OK

    # -- decrypt/encrypt ------------------------------------------------------
    def C_EncryptInit(self, session: int, _mech: Any, key: int) -> int:  # noqa: N802
        return self._init_op(session, "encrypt", key)

    def C_Encrypt(  # noqa: N802
        self, session: int, data_ptr: Any, data_len: int, out_ptr: Any, out_len_ptr: Any
    ) -> int:
        op = self._op(session)
        if op is None or op["func"] != "encrypt":
            return _NOT_INITIALIZED
        data = ctypes.string_at(data_ptr, int(data_len))
        if out_ptr is None:
            _write_ulong(out_len_ptr, _RSA_BYTES)
            return _OK
        ct = self.key.public_key().encrypt(data, padding.PKCS1v15())
        ctypes.memmove(out_ptr, ct, len(ct))
        reported = self.encrypt_reported_len if self.encrypt_reported_len is not None else len(ct)
        _write_ulong(out_len_ptr, reported)
        self._terminate(session)
        return _OK

    def C_DecryptInit(self, session: int, _mech: Any, key: int) -> int:  # noqa: N802
        return self._init_op(session, "decrypt", key)

    def _rsa_pkcs1v15_unpad(self, data: bytes) -> bytes:
        """Spec-shaped RSA decryption: raw RSA plus strict v1.5 unpadding.

        The stack's ``private_key.decrypt(PKCS1v15)`` never fails padding
        (OpenSSL implicit rejection), so the fake unpads explicitly to model
        a conformant provider: malformed padding raises ValueError, which the
        caller maps to CKR_ENCRYPTED_DATA_INVALID.
        """
        numbers = self.key.private_numbers()
        n = self.key.public_key().public_numbers().n
        c = int.from_bytes(data, "big")
        if len(data) != _RSA_BYTES or c >= n:
            raise ValueError("bad ciphertext length or range")
        em: bytes = pow(c, numbers.d, n).to_bytes(_RSA_BYTES, "big")
        if len(em) < 11 or em[0] != 0 or em[1] != 2:
            raise ValueError("bad v1.5 header")
        try:
            sep = em.index(b"\x00", 2)
        except ValueError:
            raise ValueError("no v1.5 separator") from None
        if sep < 10:
            raise ValueError("v1.5 pad too short")
        return em[sep + 1 :]

    def C_Decrypt(  # noqa: N802
        self, session: int, data_ptr: Any, data_len: int, out_ptr: Any, out_len_ptr: Any
    ) -> int:
        op = self._op(session)
        if op is None or op["func"] != "decrypt":
            return _NOT_INITIALIZED
        data = ctypes.string_at(data_ptr, int(data_len))
        self.decrypt_calls.append({"data_len": len(data)})
        if not self._granted(session):
            self._terminate(session)
            return self.grantless_rv
        capacity = _read_ulong(out_len_ptr)
        if capacity < _RSA_BYTES:
            _write_ulong(out_len_ptr, _RSA_BYTES)
            if self.grant_consumed_by_bts:
                self._terminate(session)
            return _BTS
        if self.decrypt_script:
            rv = self.decrypt_script.pop(0)
            self._terminate(session)
            return rv
        try:
            pt = self._rsa_pkcs1v15_unpad(data)
        except ValueError:
            self._terminate(session)
            return int(CKR_ENCRYPTED_DATA_INVALID)
        if self.decrypt_mode == "corrupt":
            pt = bytes((pt[0] ^ 0xFF,)) + pt[1:] if pt else b"\x00"
        ctypes.memmove(out_ptr, pt, len(pt))
        reported = self.decrypt_reported_len if self.decrypt_reported_len is not None else len(pt)
        _write_ulong(out_len_ptr, reported)
        if not self.grant_survives_terminal:
            self._terminate(session)
        return _OK

    # -- search ---------------------------------------------------------------
    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if self.find_init_script:
            scripted = self.find_init_script.pop(0)
            if scripted != _OK:
                return scripted
        assert tmpl is None and int(count) == 0, "context-auth fake supports full inventory only"
        self._search = sorted(self.objects)
        return _OK

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        take = self._search[: int(max_count)]
        for i, handle in enumerate(take):
            handles[i] = handle
        _write_ulong(found_ptr, len(take))
        self._search = self._search[len(take) :]
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return _OK


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _rs(fake: _CtxAuthRaw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=fake,
        sh=_FIXTURE_SH,
        slot_id=0,
        has_mechanism=lambda *_a: True,
    )


def _config(pin: str | None = "1234") -> SimpleNamespace:
    return SimpleNamespace(
        pin=SimpleNamespace(get_secret_value=lambda: pin) if pin is not None else None
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


_SIGN_SINGLE: tuple[str, ...] = (
    "test_context_terminal_sign_consumes_grant",
    "test_context_replacement_key_requires_fresh_reauth",
    "test_context_grant_rejected_across_sessions",
    "test_context_reauthentication_restores_after_consumption",
    "test_context_length_query_preserves_grant",
    "test_context_buffer_too_small_preserves_grant",
)

_SIGN_MULTI: tuple[str, ...] = (
    "test_context_multipart_update_preserves_grant",
    "test_context_multipart_final_consumes_grant",
)

_DECRYPT: tuple[str, ...] = (
    "test_context_terminal_decrypt_consumes_grant",
    "test_context_decrypt_failure_terminates_grant",
    "test_context_decrypt_bts_preserves_grant",
)

_ALL_NODES: tuple[str, ...] = _SIGN_SINGLE + _SIGN_MULTI + _DECRYPT


def _run(method: str, session: SimpleNamespace, config: SimpleNamespace) -> None:
    getattr(taa.TestContextAuthTransitions(), method)(session, config)


# --- termination judge + grant-applicability table ----------------------------


def test_qc10b_grant_applies_only_to_sign_and_decrypt() -> None:
    assert taa._QC10B_GRANT_APPLIES == frozenset({"sign", "decrypt"})
    assert taa._qc10b_grant_applies("sign") is True
    assert taa._qc10b_grant_applies("decrypt") is True
    for function in ("verify", "digest", "encrypt"):
        assert taa._qc10b_grant_applies(function) is False, function
    scope = taa._QC10B_FUNCTION_SCOPE
    assert set(scope) == {"sign", "decrypt", "verify", "digest", "encrypt"}
    for function, note in scope.items():
        assert isinstance(note, str) and note, function


@pytest.mark.parametrize("function", ["sign", "decrypt", "digest", "encrypt"])
@pytest.mark.parametrize("call", ["single", "final"])
def test_qc10b_buffered_calls_terminate_unless_bts_or_query(function: str, call: str) -> None:
    is_terminal = taa._qc10b_is_terminal
    assert is_terminal(function=function, call=call, rv=_OK) is True
    assert is_terminal(function=function, call=call, rv=_OK, is_length_query=True) is False
    assert is_terminal(function=function, call=call, rv=_BTS) is False
    assert is_terminal(function=function, call=call, rv=_CLEAN_REFUSAL) is True
    assert is_terminal(function=function, call=call, rv=_VENDOR_REFUSAL) is True
    assert is_terminal(function=function, call=call, rv=_NOT_LOGGED_IN) is True


@pytest.mark.parametrize("call", ["single", "final"])
def test_qc10b_verify_always_terminates(call: str) -> None:
    is_terminal = taa._qc10b_is_terminal
    assert is_terminal(function="verify", call=call, rv=_OK) is True
    assert is_terminal(function="verify", call=call, rv=int(CKR_SIGNATURE_INVALID)) is True
    assert is_terminal(function="verify", call=call, rv=_CLEAN_REFUSAL) is True
    assert is_terminal(function="verify", call=call, rv=_BTS) is True


@pytest.mark.parametrize(
    ("function", "bts_terminal"),
    [("sign", True), ("digest", True), ("encrypt", False), ("decrypt", False)],
)
def test_qc10b_update_terminality_per_function(function: str, bts_terminal: bool) -> None:
    is_terminal = taa._qc10b_is_terminal
    assert is_terminal(function=function, call="update", rv=_OK) is False
    assert is_terminal(function=function, call="update", rv=_BTS) is bts_terminal
    assert is_terminal(function=function, call="update", rv=_CLEAN_REFUSAL) is True


# --- healthy matrix -----------------------------------------------------------


@pytest.mark.parametrize("method", _ALL_NODES)
def test_healthy_passes(method: str) -> None:
    fake = _CtxAuthRaw()
    _run(method, _rs(fake), _config())
    assert C.get_records() == []


def test_terminal_sign_consumes_grant_second_use_rejected() -> None:
    """The terminal node proves consumption: reuse without re-auth rejects."""
    fake = _CtxAuthRaw()
    _run("test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    assert C.get_records() == []
    assert len(fake.sign_calls) >= 2


def test_cross_session_grant_stays_live_on_granting_session() -> None:
    """Misuse rejected on s2 while the s1 grant still verifies: session-bound."""
    fake = _CtxAuthRaw()
    _run("test_context_grant_rejected_across_sessions", _rs(fake), _config())
    assert C.get_records() == []
    assert any(call == _FIXTURE_SH for call in fake.login_calls)
    assert len(fake.sign_calls) >= 2


# --- exact defects: grant leaks -------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "test_context_terminal_sign_consumes_grant",
        "test_context_replacement_key_requires_fresh_reauth",
        "test_context_grant_rejected_across_sessions",
        "test_context_reauthentication_restores_after_consumption",
        "test_context_multipart_final_consumes_grant",
        "test_context_terminal_decrypt_consumes_grant",
        "test_context_decrypt_failure_terminates_grant",
    ],
)
def test_grant_leak_fails_with_function_and_phase(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.grant_leak = True
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.detail["function"] in ("sign", "decrypt")
    assert rec.detail["phase"]


@pytest.mark.parametrize(
    "method",
    [
        "test_context_terminal_sign_consumes_grant",
        "test_context_replacement_key_requires_fresh_reauth",
        "test_context_reauthentication_restores_after_consumption",
        "test_context_multipart_final_consumes_grant",
        "test_context_terminal_decrypt_consumes_grant",
    ],
)
def test_grant_surviving_terminal_call_fails(method: str) -> None:
    """A live op after a terminal call surfaces as OPERATION_ACTIVE: loud failure."""
    fake = _CtxAuthRaw()
    fake.grant_survives_terminal = True
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert rec.detail["function"] in ("sign", "decrypt")
    assert "terminal" in rec.detail["phase"]


def test_grant_consumed_by_length_query_fails() -> None:
    fake = _CtxAuthRaw()
    fake.grant_consumed_by_query = True
    _assert_fails(_run, "test_context_length_query_preserves_grant", _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.detail["function"] == "sign"
    assert "query" in rec.detail["phase"]


@pytest.mark.parametrize(
    "method",
    [
        "test_context_buffer_too_small_preserves_grant",
        "test_context_decrypt_bts_preserves_grant",
    ],
)
def test_grant_consumed_by_bts_fails(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.grant_consumed_by_bts = True
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert "too-small" in rec.detail["phase"] or "bts" in rec.detail["phase"].lower()


# --- exact defects: wrong crypto output ------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "test_context_terminal_sign_consumes_grant",
        "test_context_reauthentication_restores_after_consumption",
        "test_context_length_query_preserves_grant",
        "test_context_buffer_too_small_preserves_grant",
        "test_context_multipart_update_preserves_grant",
        "test_context_multipart_final_consumes_grant",
    ],
)
def test_corrupt_signature_fails_wrong_result(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.sign_mode = "corrupt"
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation in ("C_Sign", "C_SignFinal")


def test_short_signature_fails_wrong_result() -> None:
    # R15-04: the exact-length judge owns short reports (fires before verify).
    fake = _CtxAuthRaw()
    fake.sign_mode = "short"
    _assert_fails(_run, "test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Sign"
    assert rec.detail["reported_length"] == 128
    assert rec.detail["expected_length"] == 256


@pytest.mark.parametrize(
    "method",
    [
        "test_context_terminal_decrypt_consumes_grant",
        "test_context_decrypt_bts_preserves_grant",
    ],
)
def test_corrupt_decrypt_fails_wrong_result(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.decrypt_mode = "corrupt"
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Decrypt"


# --- permitted variation: staging premises --------------------------------------


@pytest.mark.parametrize("method", _ALL_NODES)
@pytest.mark.parametrize("rv", [int(CKR_FUNCTION_NOT_SUPPORTED), _CLEAN_REFUSAL])
def test_context_login_refusal_xfails_premise_unmet(method: str, rv: int) -> None:
    fake = _CtxAuthRaw()
    fake.login_rv = rv
    assert_xfails(_run, method, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Login"
    assert rec.actual_ckr == ckr_name(rv)


@pytest.mark.parametrize("method", _ALL_NODES)
def test_context_login_undefined_rv_fails(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.login_rv = _UNDEFINED_RV
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_Login"


@pytest.mark.parametrize("method", _ALL_NODES)
def test_keygen_refusal_xfails_with_producer_context(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.keygen_rv = _CLEAN_REFUSAL
    assert_xfails(_run, method, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.actual_ckr == ckr_name(_CLEAN_REFUSAL)


@pytest.mark.parametrize("method", _ALL_NODES)
def test_keygen_undefined_rv_fails(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.keygen_rv = _UNDEFINED_RV
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GenerateKeyPair"


@pytest.mark.parametrize("method", _ALL_NODES)
def test_setup_readback_omission_skips(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.getattr_omit = {int(CKA_ALWAYS_AUTHENTICATE)}
    assert_skips(_run, method, _rs(fake), _config())


@pytest.mark.parametrize("method", _ALL_NODES)
def test_missing_pin_skips(method: str) -> None:
    fake = _CtxAuthRaw()
    assert_skips(_run, method, _rs(fake), _config(pin=None))
    assert C.get_records() == []
    assert fake.login_calls == []


# --- permitted variation: judged-call tiers --------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "test_context_replacement_key_requires_fresh_reauth",
        "test_context_grant_rejected_across_sessions",
        "test_context_multipart_final_consumes_grant",
    ],
)
@pytest.mark.parametrize("rv", [_CLEAN_REFUSAL, _OTHER_CLEAN, _VENDOR_REFUSAL])
def test_grantless_use_other_clean_xfails_with_original_rv(method: str, rv: int) -> None:
    fake = _CtxAuthRaw()
    fake.grantless_rv = rv
    assert_xfails(_run, method, _rs(fake), _config())
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.actual_ckr == ckr_name(rv)
    assert rec.expected_ckr == [ckr_name(_NOT_LOGGED_IN)]


@pytest.mark.parametrize(
    "method",
    [
        "test_context_terminal_sign_consumes_grant",
        "test_context_length_query_preserves_grant",
        "test_context_buffer_too_small_preserves_grant",
    ],
)
@pytest.mark.parametrize("rv", [_CLEAN_REFUSAL, _OTHER_CLEAN, _VENDOR_REFUSAL])
def test_positive_sign_other_clean_xfails_never_passes(method: str, rv: int) -> None:
    fake = _CtxAuthRaw()
    fake.sign_script = [rv]
    assert_xfails(_run, method, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.actual_ckr == ckr_name(rv)


def test_length_query_refusal_xfails_premise() -> None:
    fake = _CtxAuthRaw()
    fake.query_rv = _CLEAN_REFUSAL
    assert_xfails(_run, "test_context_length_query_preserves_grant", _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Sign"
    assert rec.actual_ckr == ckr_name(_CLEAN_REFUSAL)


def test_decrypt_failure_other_clean_xfails_premise() -> None:
    """A non-ENCRYPTED_DATA_INVALID clean error cannot stage the failure-terminates leg."""
    fake = _CtxAuthRaw()
    fake.decrypt_script = [_CLEAN_REFUSAL]
    assert_xfails(_run, "test_context_decrypt_failure_terminates_grant", _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Decrypt"
    assert rec.actual_ckr == ckr_name(_CLEAN_REFUSAL)


def test_decrypt_garbage_accepted_xfails_premise() -> None:
    """OK on invalid padding stages no failure: the leg is untestable, never a pass."""
    fake = _CtxAuthRaw()
    fake.decrypt_script = [_OK]
    assert_xfails(_run, "test_context_decrypt_failure_terminates_grant", _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Decrypt"


@pytest.mark.parametrize("method", _ALL_NODES)
def test_undefined_rv_on_judged_call_fails(method: str) -> None:
    fake = _CtxAuthRaw()
    fake.sign_script = [_UNDEFINED_RV]
    fake.sign_final_script = [_UNDEFINED_RV]
    fake.decrypt_script = [_UNDEFINED_RV]
    _assert_fails(_run, method, _rs(fake), _config())
    _assert_fail_record("self_contradiction", "metadata")


# --- malformed evidence -----------------------------------------------------------


def test_malformed_modulus_fails_wrong_result() -> None:
    fake = _CtxAuthRaw()
    fake.getattr_malformed = {int(CKA_MODULUS): b"\x01\x02"}
    _assert_fails(_run, "test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "metadata")
    assert rec.operation == "C_GetAttributeValue"


def test_unreadable_modulus_xfails_unproved() -> None:
    fake = _CtxAuthRaw()
    fake.getattr_omit = {int(CKA_MODULUS)}
    assert_xfails(_run, "test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unreadable-value"


def test_query_length_mismatch_fails_wrong_result() -> None:
    """A length query reporting below 256 for RSA-2048 misleads the caller."""
    fake = _CtxAuthRaw()
    real_sign = _CtxAuthRaw.C_Sign

    def _short_query(
        self: _CtxAuthRaw,
        session: int,
        data_ptr: Any,
        data_len: int,
        sig_ptr: Any,
        sig_len_ptr: Any,
    ) -> int:
        if sig_ptr is None:
            _write_ulong(sig_len_ptr, 128)
            return _OK
        return real_sign(self, session, data_ptr, data_len, sig_ptr, sig_len_ptr)

    fake.C_Sign = _short_query.__get__(fake, _CtxAuthRaw)  # type: ignore[method-assign]
    _assert_fails(_run, "test_context_length_query_preserves_grant", _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.detail["actual_length"] == 128


# --- review fix round: reuse tiers, helper wiring, update termination --------


@pytest.mark.parametrize("rv", [_CLEAN_REFUSAL, _OTHER_CLEAN, _VENDOR_REFUSAL])
def test_reuse_update_noncanonical_refusal_xfails_nonspec_reject(rv: int) -> None:
    """A grantless reuse Update refused with a noncanonical clean code reads as
    an honest alternate rejection (nonspec_reject), like the grantless Final
    path -- not as a broken premise."""
    fake = _CtxAuthRaw()
    fake.sign_update_script = [_OK, rv]
    assert_xfails(_run, "test_context_multipart_final_consumes_grant", _rs(fake), _config())
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.operation == "C_SignUpdate"
    assert rec.actual_ckr == ckr_name(rv)


@pytest.mark.parametrize("function", ["verify", "digest", "encrypt"])
@pytest.mark.parametrize("judge", ["grantless", "preserved"])
def test_grant_judges_reject_non_grant_functions(function: str, judge: str) -> None:
    """The grant judges apply only inside the context-grant model; judging
    a non-grant function is a harness misuse and fails loudly."""
    fn = taa._qc10b_grantless_or_judge if judge == "grantless" else taa._qc10b_preserved_or_judge
    extra: dict[str, Any] = (
        {} if judge == "grantless" else {"reported_len": _RSA_BYTES, "capacity": _RSA_BYTES}
    )
    with pytest.raises(Failed):
        fn(
            _CLEAN_REFUSAL,
            operation="C_Verify",
            mechanism="CKM_SHA256_RSA_PKCS",
            function=function,
            phase="harness-misuse-probe",
            label="grant-applies guard",
            **extra,
        )
    _assert_fail_record("self_contradiction", "metadata")


def test_sign_update_error_terminates_operation() -> None:
    """A clean sign-Update error terminates the op: Final must report dead."""
    fake = _CtxAuthRaw()
    fake.sign_update_script = [_CLEAN_REFUSAL]
    _run("test_context_sign_update_error_terminates_operation", _rs(fake), _config())
    assert C.get_records() == []


def test_sign_update_error_operation_still_live_fails() -> None:
    """Final succeeding after an error-terminated Update is a loud failure."""
    fake = _CtxAuthRaw()
    fake.sign_update_script = [_CLEAN_REFUSAL]
    real_final = fake.C_SignFinal

    def _live_final(self: Any, session: int, sig_ptr: Any, sig_len_ptr: Any) -> int:
        self.op_by_session[int(session)] = {"func": "sign", "grant": True, "data": []}
        return real_final(session, sig_ptr, sig_len_ptr)

    fake.C_SignFinal = _live_final.__get__(fake, _CtxAuthRaw)  # type: ignore[method-assign]
    _assert_fails(_run, "test_context_sign_update_error_terminates_operation", _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.detail["function"] == "sign"


def test_sign_update_ok_has_no_error_to_judge_xfails() -> None:
    """A clean Update run carries no error: the termination premise is unmet."""
    fake = _CtxAuthRaw()
    assert_xfails(_run, "test_context_sign_update_error_terminates_operation", _rs(fake), _config())
    _assert_xfail_record("not_operational")


# --- update-error node staging parity (explicit: its judged call differs) ---

_UPDATE_ERROR_NODE = "test_context_sign_update_error_terminates_operation"


@pytest.mark.parametrize("rv", [int(CKR_FUNCTION_NOT_SUPPORTED), _CLEAN_REFUSAL])
def test_update_error_node_login_refusal_xfails_premise_unmet(rv: int) -> None:
    fake = _CtxAuthRaw()
    fake.login_rv = rv
    assert_xfails(_run, _UPDATE_ERROR_NODE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_Login"
    assert rec.actual_ckr == ckr_name(rv)


def test_update_error_node_login_undefined_rv_fails() -> None:
    fake = _CtxAuthRaw()
    fake.login_rv = _UNDEFINED_RV
    _assert_fails(_run, _UPDATE_ERROR_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_Login"


def test_update_error_node_keygen_refusal_xfails_with_producer_context() -> None:
    fake = _CtxAuthRaw()
    fake.keygen_rv = _CLEAN_REFUSAL
    assert_xfails(_run, _UPDATE_ERROR_NODE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.actual_ckr == ckr_name(_CLEAN_REFUSAL)


def test_update_error_node_keygen_undefined_rv_fails() -> None:
    fake = _CtxAuthRaw()
    fake.keygen_rv = _UNDEFINED_RV
    _assert_fails(_run, _UPDATE_ERROR_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GenerateKeyPair"


def test_update_error_node_setup_readback_omission_skips() -> None:
    fake = _CtxAuthRaw()
    fake.getattr_omit = {int(CKA_ALWAYS_AUTHENTICATE)}
    assert_skips(_run, _UPDATE_ERROR_NODE, _rs(fake), _config())


def test_update_error_node_missing_pin_skips() -> None:
    fake = _CtxAuthRaw()
    assert_skips(_run, _UPDATE_ERROR_NODE, _rs(fake), _config(pin=None))
    assert C.get_records() == []
    assert fake.login_calls == []


def test_update_error_node_undefined_update_rv_fails() -> None:
    fake = _CtxAuthRaw()
    fake.sign_update_script = [_UNDEFINED_RV]
    _assert_fails(_run, _UPDATE_ERROR_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_SignUpdate"


# --- fix round 1 (R14-01): setup handles need ownership proof ----------------

_QC10B_SETUP_NODES: tuple[str, ...] = _ALL_NODES + (_UPDATE_ERROR_NODE,)


@pytest.mark.parametrize("method", _QC10B_SETUP_NODES)
def test_setup_returning_foreign_handles_xfails_without_touching_them(method: str) -> None:
    """Keygen returning pre-existing 41/42 is unproved: xfail, never trusted, never destroyed."""
    fake = _CtxAuthRaw()
    fake.objects[41] = {"kind": "pub"}
    fake.objects[42] = {"kind": "priv"}
    fake.keygen_replay_handles = (41, 42)
    assert_xfails(_run, method, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert 41 not in fake.destroys
    assert 42 not in fake.destroys
    assert 41 in fake.objects and 42 in fake.objects


def test_setup_before_inventory_refusal_xfails_premise() -> None:
    fake = _CtxAuthRaw()
    fake.find_init_script = [_CLEAN_REFUSAL]
    assert_xfails(_run, "test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"


def test_setup_after_inventory_refusal_xfails_without_destroy() -> None:
    """Setup succeeded but ownership is unprovable: premise xfail, handles left alive."""
    fake = _CtxAuthRaw()
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run, "test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert fake.destroys == []


def test_setup_inventory_undefined_rv_fails() -> None:
    fake = _CtxAuthRaw()
    fake.find_init_script = [_UNDEFINED_RV]
    _assert_fails(_run, "test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_FindObjects"


# --- fix round 1 (R14-03): granting session judged before cross-session xfail -

_CROSS_SESSION_NODE = "test_context_grant_rejected_across_sessions"


def test_cross_session_grant_loss_after_nonspec_misuse_fails() -> None:
    """Session2 GENERAL_ERROR must not mask session1 losing its live grant."""
    fake = _CtxAuthRaw()
    fake.grantless_rv = _CLEAN_REFUSAL
    fake.sign_rv_by_session = {_FIXTURE_SH: [_NOT_LOGGED_IN]}
    _assert_fails(_run, _CROSS_SESSION_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.detail["phase"] == "granting-session-liveness"


def test_cross_session_corrupt_live_output_after_nonspec_misuse_fails() -> None:
    """Session2 GENERAL_ERROR must not mask a corrupt session1 signature."""
    fake = _CtxAuthRaw()
    fake.grantless_rv = _CLEAN_REFUSAL
    fake.sign_mode = "corrupt"
    _assert_fails(_run, _CROSS_SESSION_NODE, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Sign"


def test_cross_session_live_not_initialized_fails() -> None:
    """A dead granting-session operation is premature termination, never an xfail."""
    fake = _CtxAuthRaw()
    fake.sign_rv_by_session = {_FIXTURE_SH: [_NOT_INITIALIZED]}
    _assert_fails(_run, _CROSS_SESSION_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.detail["phase"] == "granting-session-liveness"


# --- fix round 1 (R14-04): reported output length is judged, never clamped ---


def test_terminal_sign_reported_length_mismatch_fails() -> None:
    """256-byte signature + CKR_OK + reported 257: the length lie fails loud."""
    fake = _CtxAuthRaw()
    fake.sign_reported_len = 257
    _assert_fails(_run, "test_context_terminal_sign_consumes_grant", _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Sign"
    assert rec.detail["reported_length"] == 257
    assert rec.detail["buffer_capacity"] == _RSA_BYTES


def test_terminal_decrypt_reported_length_mismatch_fails() -> None:
    fake = _CtxAuthRaw()
    fake.decrypt_reported_len = 257
    _assert_fails(_run, "test_context_terminal_decrypt_consumes_grant", _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Decrypt"
    assert rec.detail["reported_length"] == 257


def test_bts_retry_reported_length_mismatch_fails() -> None:
    """The preserved-output judge threads the reported length too."""
    fake = _CtxAuthRaw()
    fake.sign_reported_len = 257
    _assert_fails(_run, "test_context_buffer_too_small_preserves_grant", _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.detail["reported_length"] == 257


def test_cross_session_live_reported_length_mismatch_fails() -> None:
    """The cross-session inline judge threads the reported length too."""
    fake = _CtxAuthRaw()
    fake.sign_reported_len = 257
    _assert_fails(_run, _CROSS_SESSION_NODE, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.detail["reported_length"] == 257


# --- fix round 1 (R14-06): SignUpdate BTS routes through termination judging -


def test_sign_update_bts_retained_operation_fails() -> None:
    """BTS on Update with a live op behind it: the grant was not terminated."""
    fake = _CtxAuthRaw()
    fake.sign_update_script = [_BTS]
    fake.update_bts_retains_op = True
    _assert_fails(_run, _UPDATE_ERROR_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "policy")
    assert rec.detail["function"] == "sign"
    assert rec.detail["terminal"] is True


def test_sign_update_bts_terminated_operation_passes() -> None:
    """BTS on Update that really terminated the op passes like any clean error."""
    fake = _CtxAuthRaw()
    fake.sign_update_script = [_BTS]
    _run(_UPDATE_ERROR_NODE, _rs(fake), _config())
    assert C.get_records() == []


# --- fix round 2 (F3): staging encrypt output length is judged, never clamped -


@pytest.mark.parametrize("method", _DECRYPT)
def test_staging_encrypt_reported_length_mismatch_fails(method: str) -> None:
    """Staging C_Encrypt OK + reported 257 for a 256-byte buffer: length lie fails loud."""
    fake = _CtxAuthRaw()
    fake.encrypt_reported_len = 257
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Encrypt"
    assert rec.mechanism == "CKM_RSA_PKCS"
    assert rec.detail["reported_length"] == 257
    assert rec.detail["buffer_capacity"] == _RSA_BYTES


# --- fix round 3 (R15-02): aliased keypair outputs are rejected, never used --

_TERMINAL_SIGN_NODE = "test_context_terminal_sign_consumes_grant"


def test_keygen_aliased_handles_fails_without_touching_them() -> None:
    """Keygen returning the same handle for both halves: FAIL, no use, no destroy."""
    fake = _CtxAuthRaw()
    fake.keygen_alias_outputs = True
    expected = fake._next_handle + 1
    _assert_fails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.detail["disposition"] == "aliased-handles"
    assert rec.detail["returned_handles"] == [expected, expected]
    assert fake.destroys == []
    assert expected in fake.objects
    assert expected not in fake.reads


# --- fix round 3 (R15-03): keygen refusals reach after-inventory judging ----


def test_keygen_refusal_with_proved_leak_fails_and_destroys() -> None:
    """Keygen refusal that created our labeled key: refused-but-created FAIL, destroyed."""
    fake = _CtxAuthRaw()
    fake.keygen_rv = _CLEAN_REFUSAL
    fake.keygen_refusal_leak = "proved"
    _assert_fails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.detail["disposition"] == "refused-but-created"
    assert fake.leaked
    assert all(handle in fake.destroys for handle in fake.leaked)
    assert all(handle not in fake.objects for handle in fake.leaked)


def test_keygen_refusal_with_foreign_leak_xfails_alive() -> None:
    """Keygen refusal with an unproved delta: unproved-effect xfail, left alive."""
    fake = _CtxAuthRaw()
    fake.keygen_rv = _CLEAN_REFUSAL
    fake.keygen_refusal_leak = "foreign"
    assert_xfails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.detail["disposition"] == "unproved-effect"
    assert fake.leaked
    assert all(handle not in fake.destroys for handle in fake.leaked)
    assert all(handle in fake.objects for handle in fake.leaked)


def test_keygen_undefined_refusal_with_proved_leak_fails_and_cites() -> None:
    """Undefined keygen RV + proved leftover: FAIL cites the destroyed handles."""
    fake = _CtxAuthRaw()
    fake.keygen_rv = _UNDEFINED_RV
    fake.keygen_refusal_leak = "proved"
    _assert_fails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GenerateKeyPair"
    assert fake.leaked
    assert all(handle in fake.destroys for handle in fake.leaked)
    assert sorted(rec.detail["proved_new_handles"]) == sorted(fake.leaked)


# --- fix round 3 (R15-04): deterministic output lengths are judged exactly --


@pytest.mark.parametrize("method", _DECRYPT)
@pytest.mark.parametrize("reported", [0, 255])
def test_decrypt_nodes_short_encrypt_report_fails(method: str, reported: int) -> None:
    """Staging C_Encrypt OK reporting short of 256 fails exact-length judging."""
    fake = _CtxAuthRaw()
    fake.encrypt_reported_len = reported
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Encrypt"
    assert rec.mechanism == "CKM_RSA_PKCS"
    assert rec.detail["reported_length"] == reported
    assert rec.detail["expected_length"] == _RSA_BYTES


_R15_04_SIGN_SITES: tuple[tuple[str, str], ...] = (
    ("test_context_terminal_sign_consumes_grant", "C_Sign"),
    ("test_context_grant_rejected_across_sessions", "C_Sign"),
    ("test_context_buffer_too_small_preserves_grant", "C_Sign"),
    ("test_context_multipart_update_preserves_grant", "C_SignFinal"),
    ("test_context_multipart_final_consumes_grant", "C_SignFinal"),
)


@pytest.mark.parametrize(("method", "op"), _R15_04_SIGN_SITES)
@pytest.mark.parametrize("reported", [0, 255])
def test_sign_nodes_short_report_fails_exact_length(method: str, op: str, reported: int) -> None:
    """Single-shot/final RSA-2048 sign OK reporting short of 256 fails the length judge."""
    fake = _CtxAuthRaw()
    fake.sign_reported_len = reported
    _assert_fails(_run, method, _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == op
    assert rec.detail["reported_length"] == reported
    assert rec.detail["expected_length"] == _RSA_BYTES


# --- fix round 4 (R16-01): undefined keygen RV survives failed after-inventory --


@pytest.mark.parametrize("inv_rv", [_CLEAN_REFUSAL, _VENDOR_REFUSAL])
def test_keygen_undefined_with_failed_after_inventory_fails_with_both_rvs(inv_rv: int) -> None:
    """Undefined keygen + refused after-inventory: FAIL loud with both RVs, never xfail."""
    fake = _CtxAuthRaw()
    fake.keygen_rv = _UNDEFINED_RV
    fake.find_init_script = [_OK, inv_rv]
    _assert_fails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)
    assert rec.detail["operation_rv"] == ckr_name(_UNDEFINED_RV)
    assert rec.detail["inventory_rv"] == ckr_name(inv_rv)


def test_keygen_clean_refusal_with_failed_after_inventory_still_xfails() -> None:
    """Clean keygen refusal + refused after-inventory keeps the unproved xfail."""
    fake = _CtxAuthRaw()
    fake.keygen_rv = _CLEAN_REFUSAL
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"


# --- fix round 4 (R16-02): setup success judges proved extras -----------------


def test_keygen_success_with_proved_extra_fails_and_destroys() -> None:
    """Keygen OK creating returned pair + identically labeled extra: FAIL + destroy all."""
    fake = _CtxAuthRaw()
    fake.keygen_success_extra = "proved"
    _assert_fails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.detail["disposition"] == "created-extra"
    assert fake.leaked
    assert sorted(rec.detail["extra_handles"]) == sorted(fake.leaked)
    for handle in rec.detail["proved_new_handles"]:
        assert handle in fake.destroys
    assert all(handle not in fake.objects for handle in fake.leaked)


def test_keygen_success_with_foreign_companion_xfails_and_cleans_owned() -> None:
    """Keygen OK + foreign companion: owned pair cleaned, companion alive, xfail unproved."""
    fake = _CtxAuthRaw()
    fake.keygen_success_extra = "foreign"
    assert_xfails(_run, _TERMINAL_SIGN_NODE, _rs(fake), _config())
    rec = _assert_xfail_record("honest_deviation")
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.detail["disposition"] == "unproved-effect"
    assert fake.leaked
    assert all(handle not in fake.destroys for handle in fake.leaked)
    assert all(handle in fake.objects for handle in fake.leaked)


# --- fix round 4 (R16-03): length-query overestimates are legal ---------------


def _run_length_query_with_reported(fake: _CtxAuthRaw, reported: int) -> None:
    """Run the length-query node with the NULL-buffer query reporting ``reported``."""
    real_sign = _CtxAuthRaw.C_Sign

    def _scripted_query(
        self: _CtxAuthRaw,
        session: int,
        data_ptr: Any,
        data_len: int,
        sig_ptr: Any,
        sig_len_ptr: Any,
    ) -> int:
        if sig_ptr is None:
            _write_ulong(sig_len_ptr, reported)
            return _OK
        return real_sign(self, session, data_ptr, data_len, sig_ptr, sig_len_ptr)

    fake.C_Sign = _scripted_query.__get__(fake, _CtxAuthRaw)  # type: ignore[method-assign]
    _run("test_context_length_query_preserves_grant", _rs(fake), _config())


def test_length_query_overestimate_passes() -> None:
    """Query 257 + valid verified 256 followup: a healthy provider, must PASS."""
    fake = _CtxAuthRaw()
    _run_length_query_with_reported(fake, 257)
    assert C.get_records() == []


@pytest.mark.parametrize("reported", [100, 0])
def test_length_query_underestimate_fails(reported: int) -> None:
    """Query below 256 would overrun a real buffer: FAIL wrong_result."""
    fake = _CtxAuthRaw()
    real_sign = _CtxAuthRaw.C_Sign

    def _scripted_query(
        self: _CtxAuthRaw,
        session: int,
        data_ptr: Any,
        data_len: int,
        sig_ptr: Any,
        sig_len_ptr: Any,
    ) -> int:
        if sig_ptr is None:
            _write_ulong(sig_len_ptr, reported)
            return _OK
        return real_sign(self, session, data_ptr, data_len, sig_ptr, sig_len_ptr)

    fake.C_Sign = _scripted_query.__get__(fake, _CtxAuthRaw)  # type: ignore[method-assign]
    _assert_fails(_run, "test_context_length_query_preserves_grant", _rs(fake), _config())
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Sign"
    assert rec.detail["actual_length"] == reported


def test_length_query_negative_fails() -> None:
    """A negative query report is an under-estimate: FAIL wrong_result.

    CK_ULONG is unsigned so the raw layer cannot produce it; the node's
    ``< 256`` judge covers it defensively via a direct helper patch.
    """
    fake = _CtxAuthRaw()
    real_query = taa._qc10b_sign_query_raw

    def _negative_query(raw: Any, sh: int, msg: bytes) -> tuple[int, int]:
        assert raw is fake
        assert sh is not None and msg is not None
        return (_OK, -1)

    taa._qc10b_sign_query_raw = _negative_query
    try:
        _assert_fails(_run, "test_context_length_query_preserves_grant", _rs(fake), _config())
    finally:
        taa._qc10b_sign_query_raw = real_query
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_Sign"
    assert rec.detail["actual_length"] == -1
