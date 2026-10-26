"""Production-method contracts for QC9a DH peer encoding (#52.1).

Drives the real testcase methods in
``pkcs11_check.testcases.test_dh_key_agreement.TestDHPeerEncoding`` against a
scriptable fake token at the raw ``C_*`` layer:

- allowed-encoding matrix (ordinary / leading-zero-equivalent / full-width):
  fixed private exponent, independent ``pow()`` oracle, and a truncation
  detector leg whose full value is numerically distinct from its suffix;
- malformed slice (overlong / empty): canonical refusal passes, other clean
  refusals xfail with the original RV, acceptance fails;
- proved-new-only derived-handle ownership on every leg.

Fakes only; no provider is loaded. Records must never carry peer or secret
bytes -- lengths and match flags only.
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
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_DH_PKCS_DERIVE,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_dh_key_agreement as dh_case
from tests._skip_assert import assert_skips, assert_xfails

_OK = int(CKR_OK)
_TYPE_INVALID = int(CKR_ATTRIBUTE_TYPE_INVALID)
_SENSITIVE = int(CKR_ATTRIBUTE_SENSITIVE)
_PARAM_INVALID = int(CKR_MECHANISM_PARAM_INVALID)
_CLEAN_REFUSAL = int(CKR_GENERAL_ERROR)
_OTHER_CLEAN = int(CKR_ARGUMENTS_BAD)
_VENDOR_REFUSAL = 0x80000001
_UNDEFINED_RV = 0x7FFFFFFF
_UNAVAILABLE = int(CK_UNAVAILABLE_INFORMATION)

_DERIVE_MECH = int(CKM_DH_PKCS_DERIVE)


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


def _decode_mech_param(mech: Any) -> tuple[int, bytes]:
    ck = mech._obj
    plen = int(ck.ulParameterLen)
    pptr = ck.pParameter
    return int(ck.mechanism), (ctypes.string_at(pptr, plen) if pptr and plen > 0 else b"")


def _write_handle(ptr: Any, handle: int) -> None:
    ctypes.cast(ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = handle


def _independent_oracle(peer: bytes) -> bytes:
    """Independent shared-secret oracle: pow(peer, x, p), zero-padded to prime length."""
    prime = int.from_bytes(dh_case.DH_PRIME_2048, "big")
    exponent = int.from_bytes(dh_case._DH_RFC3526_GROUP14_ALICE_PRIVATE, "big")
    return pow(int.from_bytes(peer, "big"), exponent, prime).to_bytes(
        len(dh_case.DH_PRIME_2048), "big"
    )


def _ulong_bytes(value: int) -> bytes:
    return value.to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)


class _PeerEncodingRaw:
    """Scriptable fake token for the QC9a peer-encoding production methods."""

    def __init__(self) -> None:
        self.objects: dict[int, dict[int, bytes]] = {}
        self.sensitive_values: set[int] = set()
        self.destroyed: list[int] = []
        self.leaked: list[int] = []
        self.derived_handles: list[int] = []
        self.setup_handles: list[int] = []
        self.derive_calls: list[dict[str, Any]] = []
        self.create_calls: list[dict[int, bytes]] = []
        self.attr_reads: list[int] = []
        self._next_handle = 500
        self._search: list[int] = []
        # Knobs.
        self.setup_rv: int = _OK
        self.derive_rv: int | None = None  # None = CKR_OK path; else refusal RV.
        self.derive_value_mode = "oracle"  # oracle | suffix | garbage | sensitive
        self.garbage_value = b"\x5a" * 256
        self.derive_handle_write: int | None = None
        self.derive_leak = "none"  # none | labeled | unlabeled | foreign
        self.find_init_script: list[int] | None = None
        self.getattr_rv: int | None = None

    def _alloc(self, attrs: dict[int, bytes]) -> int:
        self._next_handle += 1
        handle = self._next_handle
        self.objects[handle] = dict(attrs)
        return handle

    # -- reads ------------------------------------------------------------
    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.attr_reads.append(int(handle))
        if self.getattr_rv is not None:
            return self.getattr_rv
        stored = self.objects.get(int(handle))
        assert stored is not None, f"read from unknown handle {handle}"
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            blob = stored.get(attr)
            sensitive = attr == int(CKA_VALUE) and int(handle) in self.sensitive_values
            if blob is None or sensitive:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(_SENSITIVE if sensitive else _TYPE_INVALID)
                continue
            if addr:
                ctypes.memmove(addr, blob, min(len(blob), cap))
            tmpl[i].ulValueLen = len(blob)
            row_rvs.append(_OK)
        if _TYPE_INVALID in row_rvs:
            return _TYPE_INVALID
        if _SENSITIVE in row_rvs:
            return _SENSITIVE
        return _OK

    # -- creators ---------------------------------------------------------
    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        attrs = _decode_template(tmpl, int(count))
        self.create_calls.append(attrs)
        if self.setup_rv != _OK:
            return self.setup_rv
        handle = self._alloc(attrs)
        self.setup_handles.append(handle)
        _write_handle(handle_ptr, handle)
        return _OK

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, mech: Any, _base: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        mech_id, peer = _decode_mech_param(mech)
        attrs = _decode_template(tmpl, int(count))
        self.derive_calls.append({"mech": mech_id, "peer": peer, "attrs": attrs})
        if self.derive_rv is not None:
            self._apply_derive_leak(attrs)
            if self.derive_handle_write is not None:
                _write_handle(handle_ptr, self.derive_handle_write)
            return self.derive_rv
        raw_len = attrs.get(int(CKA_VALUE_LEN))
        value_len = int.from_bytes(raw_len, sys.byteorder) if raw_len else 256
        full = _independent_oracle(peer)
        if self.derive_value_mode == "suffix":
            full = _independent_oracle(peer[1:])
        elif self.derive_value_mode == "garbage":
            full = bytes(self.garbage_value)
        stored = dict(attrs)
        stored[int(CKA_VALUE)] = full[-value_len:] if value_len < len(full) else full
        handle = self._alloc(stored)
        self.derived_handles.append(handle)
        if self.derive_value_mode == "sensitive":
            self.sensitive_values.add(handle)
        _write_handle(
            handle_ptr, self.derive_handle_write if self.derive_handle_write is not None else handle
        )
        return _OK

    def _apply_derive_leak(self, attrs: dict[int, bytes]) -> None:
        if self.derive_leak == "labeled":
            self.leaked.append(self._alloc(dict(attrs)))
        elif self.derive_leak == "unlabeled":
            leak = dict(attrs)
            leak.pop(int(CKA_LABEL), None)
            self.leaked.append(self._alloc(leak))
        elif self.derive_leak == "foreign":
            self.leaked.append(
                self._alloc(
                    {
                        int(CKA_LABEL): b"qc9a-foreign",
                        int(CKA_TOKEN): b"\x01",
                        int(CKA_CLASS): _ulong_bytes(int(CKO_PRIVATE_KEY)),
                    }
                )
            )

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        self.objects.pop(int(handle), None)
        return _OK

    # -- search -----------------------------------------------------------
    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if self.find_init_script:
            return self.find_init_script.pop(0)
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
        self._search = self._search[len(take) :]
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return _OK


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _rs(fake: _PeerEncodingRaw, *, mechanisms: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        raw=fake,
        sh=7,
        slot_id=0,
        has_mechanism=lambda *_a: mechanisms,
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


_ALLOWED_LEGS: tuple[tuple[str, str], ...] = (
    ("test_dh_peer_encoding_ordinary", "_QC9A_PEER_ORDINARY"),
    ("test_dh_peer_encoding_leading_zero", "_QC9A_PEER_LZ_PADDED"),
    ("test_dh_peer_encoding_full_width_suffix_detector", "_QC9A_PEER_FULL"),
)

_MALFORMED_LEGS: tuple[tuple[str, str], ...] = (
    ("test_dh_peer_encoding_rejects_overlong", "_QC9A_OVERLONG"),
    ("test_dh_peer_encoding_rejects_empty", "_QC9A_EMPTY"),
)


def _run_leg(method_name: str, session: SimpleNamespace) -> None:
    getattr(dh_case.TestDHPeerEncoding(), method_name)(session)


# --- oracle table ----------------------------------------------------------


def test_qc9a_oracle_matches_independent_modexp() -> None:
    peers = {
        "ordinary": dh_case._QC9A_PEER_ORDINARY,
        "lz_padded": dh_case._QC9A_PEER_LZ_PADDED,
        "full": dh_case._QC9A_PEER_FULL,
        "suffix": dh_case._QC9A_PEER_SUFFIX,
    }
    for name, peer in peers.items():
        assert dh_case._qc9a_oracle(int.from_bytes(peer, "big")) == _independent_oracle(peer), name


def test_qc9a_peer_table_shape_and_range() -> None:
    prime = int.from_bytes(dh_case.DH_PRIME_2048, "big")
    ordinary = dh_case._QC9A_PEER_ORDINARY
    minimal = dh_case._QC9A_PEER_LZ_MINIMAL
    padded = dh_case._QC9A_PEER_LZ_PADDED
    full = dh_case._QC9A_PEER_FULL
    suffix = dh_case._QC9A_PEER_SUFFIX
    overlong = dh_case._QC9A_OVERLONG
    empty = dh_case._QC9A_EMPTY
    assert len(ordinary) == 256 and ordinary[0] >= 0x80
    assert len(minimal) == 255 and minimal[0] != 0
    assert padded == b"\x00" + minimal
    assert int.from_bytes(padded, "big") == int.from_bytes(minimal, "big")
    assert len(full) == 256 and full[0] != 0
    assert suffix == full[1:]
    assert int.from_bytes(suffix, "big") != int.from_bytes(full, "big")
    assert len(overlong) == 257
    assert int.from_bytes(overlong, "big") > prime
    assert len(empty) == 0
    for peer in (ordinary, padded, full):
        assert 2 <= int.from_bytes(peer, "big") <= prime - 2
    assert len({ordinary, padded, full}) == 3
    assert ordinary != dh_case._DH_RFC3526_GROUP14_BOB_PUBLIC
    assert full != dh_case._DH_RFC3526_GROUP14_BOB_PUBLIC
    assert dh_case._QC9A_VALUE_LEN == len(dh_case.DH_PRIME_2048)


def test_qc9a_oracle_table_discriminates() -> None:
    oracles = {
        name: _independent_oracle(peer)
        for name, peer in (
            ("ordinary", dh_case._QC9A_PEER_ORDINARY),
            ("lz", dh_case._QC9A_PEER_LZ_PADDED),
            ("full", dh_case._QC9A_PEER_FULL),
            ("suffix", dh_case._QC9A_PEER_SUFFIX),
        )
    }
    assert len(set(oracles.values())) == 4
    assert _independent_oracle(dh_case._QC9A_PEER_LZ_PADDED) == _independent_oracle(
        dh_case._QC9A_PEER_LZ_MINIMAL
    )


# --- allowed-encoding matrix -------------------------------------------------


@pytest.mark.parametrize(("method", "peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_healthy_passes(method: str, peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    _run_leg(method, _rs(fake))
    assert C.get_records() == []
    assert len(fake.derive_calls) == 1
    expected_peer = getattr(dh_case, peer_attr)
    assert fake.derive_calls[0]["peer"] == expected_peer
    assert fake.derive_calls[0]["mech"] == _DERIVE_MECH
    template = fake.derive_calls[0]["attrs"]
    assert template[int(CKA_VALUE_LEN)] == _ulong_bytes(256)
    assert template[int(CKA_CLASS)] == _ulong_bytes(int(CKO_SECRET_KEY))
    assert template[int(CKA_KEY_TYPE)] == _ulong_bytes(int(CKK_GENERIC_SECRET))
    assert int(CKA_LABEL) in template
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.derived_handles)


@pytest.mark.parametrize(("method", "peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_garbage_value_fails(method: str, peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_value_mode = "garbage"
    expected_peer = getattr(dh_case, peer_attr)
    assert fake.garbage_value != _independent_oracle(expected_peer)
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.operation == "C_DeriveKey"
    assert rec.detail["matches_full_oracle"] is False
    assert rec.detail["actual_length"] == 256
    assert rec.detail["expected_length"] == 256
    assert rec.detail["peer_length"] == len(expected_peer)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.derived_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
@pytest.mark.parametrize("rv", [_CLEAN_REFUSAL, _OTHER_CLEAN, _VENDOR_REFUSAL])
def test_allowed_leg_clean_refusal_xfails_with_original_rv(
    method: str, _peer_attr: str, rv: int
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = rv
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("not_operational")
    assert rec.actual_ckr == ckr_name(rv)
    assert rec.operation == "C_DeriveKey"
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_undefined_rv_fails(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _UNDEFINED_RV
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_DeriveKey"
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_unreadable_value_xfails_unproved(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_value_mode = "sensitive"
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unreadable-value"
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.derived_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_value_read_error_xfails_unproved(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.getattr_rv = _CLEAN_REFUSAL
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unreadable-value"
    assert rec.detail["read_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.derived_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_value_read_undefined_rv_fails(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.getattr_rv = _UNDEFINED_RV
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_DeriveKey"
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.derived_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
@pytest.mark.parametrize("handle_kind", ["pre-existing", "dead-nonzero", "zero"])
def test_allowed_leg_unproved_handle_xfails_and_touches_nothing(
    method: str, _peer_attr: str, handle_kind: str
) -> None:
    fake = _PeerEncodingRaw()
    if handle_kind == "pre-existing":
        alien = fake._alloc({int(CKA_LABEL): b"qc9a-alien"})
        fake.derive_handle_write = alien
    elif handle_kind == "dead-nonzero":
        alien = 9999
        fake.derive_handle_write = alien
    else:
        alien = 0
        fake.derive_handle_write = 0
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-handle"
    assert alien not in fake.destroyed
    assert alien not in fake.attr_reads
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_refusal_with_proved_leak_fails_and_cleans(
    method: str, _peer_attr: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _CLEAN_REFUSAL
    fake.derive_leak = "labeled"
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_DeriveKey"
    assert fake.leaked
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.leaked)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
@pytest.mark.parametrize("leak", ["unlabeled", "foreign"])
def test_allowed_leg_refusal_with_unproved_delta_xfails_and_stays_alive(
    method: str, _peer_attr: str, leak: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _CLEAN_REFUSAL
    fake.derive_leak = leak
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-effect"
    assert fake.leaked
    assert all(handle not in fake.destroyed for handle in fake.leaked)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_setup_refusal_xfails_not_operational(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.setup_rv = _CLEAN_REFUSAL
    assert_xfails(_run_leg, method, _rs(fake))
    _assert_xfail_record("not_operational")
    assert fake.derive_calls == []
    assert fake.destroyed == []


@pytest.mark.parametrize(("method", "_peer_attr"), _ALLOWED_LEGS)
def test_allowed_leg_skips_without_mechanism(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    assert_skips(_run_leg, method, _rs(fake, mechanisms=False))
    assert fake.derive_calls == []
    assert fake.create_calls == []


def test_allowed_leg_inventory_before_undefined_rv_fails() -> None:
    fake = _PeerEncodingRaw()
    fake.find_init_script = [_UNDEFINED_RV]
    _assert_fails(_run_leg, _ALLOWED_LEGS[0][0], _rs(fake))
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_FindObjects"
    assert fake.derive_calls == []


def test_allowed_leg_inventory_after_clean_refusal_xfails_and_touches_nothing() -> None:
    fake = _PeerEncodingRaw()
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_leg, _ALLOWED_LEGS[0][0], _rs(fake))
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_FindObjects"
    assert len(fake.derived_handles) == 1
    derived = fake.derived_handles[0]
    assert derived not in fake.destroyed
    assert derived not in fake.attr_reads
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


# --- truncation detector -----------------------------------------------------


def test_full_width_suffix_defect_seed_fails_loudly() -> None:
    """A provider deriving from the truncated suffix must fail, flagged as such."""
    fake = _PeerEncodingRaw()
    fake.derive_value_mode = "suffix"
    _assert_fails(_run_leg, _ALLOWED_LEGS[2][0], _rs(fake))
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.detail["matches_full_oracle"] is False
    assert rec.detail["matches_suffix_oracle"] is True
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.derived_handles)


def test_full_width_garbage_matches_neither_oracle() -> None:
    fake = _PeerEncodingRaw()
    fake.derive_value_mode = "garbage"
    _assert_fails(_run_leg, _ALLOWED_LEGS[2][0], _rs(fake))
    rec = _assert_fail_record("wrong_result", "crypto")
    assert rec.detail["matches_full_oracle"] is False
    assert rec.detail["matches_suffix_oracle"] is False


def test_full_width_detector_is_load_bearing() -> None:
    """The (c) leg can only discriminate because the two oracles differ."""
    full_oracle = _independent_oracle(dh_case._QC9A_PEER_FULL)
    suffix_oracle = _independent_oracle(dh_case._QC9A_PEER_SUFFIX)
    assert full_oracle != suffix_oracle
    assert dh_case._qc9a_oracle(int.from_bytes(dh_case._QC9A_PEER_FULL, "big")) == full_oracle
    assert dh_case._qc9a_oracle(int.from_bytes(dh_case._QC9A_PEER_SUFFIX, "big")) == suffix_oracle


# --- malformed slice ---------------------------------------------------------


@pytest.mark.parametrize(("method", "peer_attr"), _MALFORMED_LEGS)
def test_malformed_leg_canonical_refusal_passes(method: str, peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _PARAM_INVALID
    _run_leg(method, _rs(fake))
    assert C.get_records() == []
    assert len(fake.derive_calls) == 1
    assert fake.derive_calls[0]["peer"] == getattr(dh_case, peer_attr)
    assert fake.derive_calls[0]["mech"] == _DERIVE_MECH
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
@pytest.mark.parametrize("rv", [_OTHER_CLEAN, _CLEAN_REFUSAL, _VENDOR_REFUSAL])
def test_malformed_leg_other_clean_refusal_xfails(method: str, _peer_attr: str, rv: int) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = rv
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.actual_ckr == ckr_name(rv)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_leg_acceptance_fails_and_cleans(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    _assert_fails(_run_leg, method, _rs(fake))
    _assert_fail_record("accepted_invalid", None)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.derived_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_leg_acceptance_with_unproved_handle_fails_without_touching(
    method: str, _peer_attr: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_handle_write = 9999
    _assert_fails(_run_leg, method, _rs(fake))
    _assert_fail_record("accepted_invalid", None)
    assert 9999 not in fake.destroyed
    assert 9999 not in fake.attr_reads
    assert len(fake.derived_handles) == 1
    assert fake.derived_handles[0] not in fake.destroyed
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_leg_undefined_rv_fails(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _UNDEFINED_RV
    _assert_fails(_run_leg, method, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_leg_canonical_refusal_with_proved_leak_fails(
    method: str, _peer_attr: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _PARAM_INVALID
    fake.derive_leak = "labeled"
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_DeriveKey"
    assert fake.leaked
    assert sorted(fake.destroyed) == sorted(fake.setup_handles + fake.leaked)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
@pytest.mark.parametrize("leak", ["unlabeled", "foreign"])
def test_malformed_leg_canonical_refusal_with_unproved_delta_xfails(
    method: str, _peer_attr: str, leak: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _PARAM_INVALID
    fake.derive_leak = leak
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-effect"
    assert fake.leaked
    assert all(handle not in fake.destroyed for handle in fake.leaked)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_leg_setup_refusal_xfails_not_operational(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.setup_rv = _CLEAN_REFUSAL
    assert_xfails(_run_leg, method, _rs(fake))
    _assert_xfail_record("not_operational")
    assert fake.derive_calls == []


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_leg_skips_without_mechanism(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    assert_skips(_run_leg, method, _rs(fake, mechanisms=False))
    assert fake.derive_calls == []
    assert fake.create_calls == []


# --- evidence hygiene --------------------------------------------------------


def test_records_never_carry_peer_or_secret_bytes() -> None:
    for mode in ("suffix", "garbage"):
        fake = _PeerEncodingRaw()
        fake.derive_value_mode = mode
        _assert_fails(_run_leg, _ALLOWED_LEGS[2][0], _rs(fake))
    for mode in ("oracle",):
        fake = _PeerEncodingRaw()
        fake.derive_value_mode = mode
        _assert_fails(_run_leg, _MALFORMED_LEGS[0][0], _rs(fake))
    blob = " ".join(repr(rec.detail) + (rec.summary or "") for rec in C.get_records())
    for peer_attr in (
        "_QC9A_PEER_ORDINARY",
        "_QC9A_PEER_LZ_MINIMAL",
        "_QC9A_PEER_LZ_PADDED",
        "_QC9A_PEER_FULL",
        "_QC9A_PEER_SUFFIX",
        "_QC9A_OVERLONG",
    ):
        assert getattr(dh_case, peer_attr).hex() not in blob
    assert (b"\x5a" * 256).hex() not in blob


# --- re-review round 12: known failures survive inventory gaps ----------------


_ALL_LEGS = _ALLOWED_LEGS + _MALFORMED_LEGS


@pytest.mark.parametrize(("method", "_peer_attr"), _ALL_LEGS)
def test_undefined_rv_with_after_inventory_failure_fails_r12(method: str, _peer_attr: str) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _UNDEFINED_RV
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_DeriveKey"
    assert rec.detail["inventory_rv"] == ckr_name(_CLEAN_REFUSAL)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_acceptance_with_after_inventory_failure_fails_alive_r12(
    method: str, _peer_attr: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("accepted_invalid", None)
    assert rec.operation == "C_DeriveKey"
    assert len(fake.derived_handles) == 1
    derived = fake.derived_handles[0]
    assert derived not in fake.destroyed
    assert derived not in fake.attr_reads
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _ALL_LEGS)
@pytest.mark.parametrize("leak", ["unlabeled", "foreign"])
def test_undefined_rv_with_unproved_delta_fails_r12(
    method: str, _peer_attr: str, leak: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _UNDEFINED_RV
    fake.derive_leak = leak
    _assert_fails(_run_leg, method, _rs(fake))
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_DeriveKey"
    assert fake.leaked
    assert all(handle not in fake.destroyed for handle in fake.leaked)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)


@pytest.mark.parametrize(("method", "_peer_attr"), _MALFORMED_LEGS)
def test_malformed_defined_refusal_with_after_inventory_failure_xfails_unproved_r12(
    method: str, _peer_attr: str
) -> None:
    fake = _PeerEncodingRaw()
    fake.derive_rv = _CLEAN_REFUSAL
    fake.find_init_script = [_OK, _CLEAN_REFUSAL]
    assert_xfails(_run_leg, method, _rs(fake))
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["disposition"] == "unproved-effect"
    assert rec.detail["inventory_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert rec.detail["derive_rv"] == ckr_name(_CLEAN_REFUSAL)
    assert sorted(fake.destroyed) == sorted(fake.setup_handles)
