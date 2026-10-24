"""QC2 byte-operation inheritance contracts (#52.2; normative part of #54.3).

Behavioral contracts for the §6.43 protection-inheritance legs in
``pkcs11_check.testcases.test_misc_kdf``: every production leg is driven
through its real test method against a scriptable fake token at the raw
``C_*`` layer. Fakes only; no provider is loaded and no Docker is used.

Covered production behavior:

- ``TestByteKdfInheritance`` (5 byte ops × 3 seals × 3 child-template
  modes; base+key additionally × {base, aux, both} seal placement):
  downgrade requests refuse with ``CKR_TEMPLATE_INCONSISTENT`` and create
  no object, matching/omitted templates succeed with sealed children.
  Two-key history/protection derives from BOTH sources via the
  mechanism's own rule (an aux-blind single-source formula fails).
- Success-path legs on every accepted child: ``SENSITIVE``,
  ``EXTRACTABLE``, ``ALWAYS_SENSITIVE``, ``NEVER_EXTRACTABLE``, raw
  ``CKA_VALUE`` refusal (``CKR_ATTRIBUTE_SENSITIVE``) and an
  independently validated wrap attempt (``CKR_KEY_UNEXTRACTABLE`` for
  unextractable children, success for extractable ones).
- ``TestByteKdfShortChild``: permitted 1-byte extraction from sealed
  (inheritance holds) and unsealed (KAT value) bases. Recovery
  composition is QC12b, not probed here.
- ``TestHkdfInheritanceScope``: HKDF from a sealed base under its own
  oracle (§6.62.3 independent selection — permitted unsealed children
  pass; histories and access follow the child's actual protection).
- Every child template carries an explicit ``CKA_VALUE_LEN``; the fake
  refuses incomplete templates with ``CKR_TEMPLATE_INCOMPLETE``.
- Seeded defects: forwarded caller template (the Haskoki pre-fix shape),
  aux-blind derivation, accepted-but-sealed downgrade, dropped or
  fabricated histories, value leaks, refusal-with-data, wrap of an
  unextractable child, phantom objects after refusal, malformed
  outputs, ignored explicit matching attributes — each must fail with
  its specified reason/kind.
- Permitted variation: alternate clean refusals xfail with the original
  RV preserved; clean wrap refusals of extractable children xfail
  (never fail policy); strengthened omitted children pass (one-sided
  oracle); missing wrap mechanism skips only the wrap leg; genuinely
  missing provisioning capabilities skip the dependent leg.
- History readback absence routing (G1): a history attribute omitted
  with no refusal CKR fails metadata; a defined clean refusal stays
  xfail skip evidence while the sibling component is still checked.
- Success-path legs collect nonterminating observations (value, wrap,
  histories, flags) and raise the strongest verdict; refused derives
  prove the no-object effect before cleanup; downgrade passes consult a
  matching operability control (vacuous rejections xfail).
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812 - matches project convention
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_ALWAYS_SENSITIVE,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_CONCATENATE_BASE_AND_KEY,
    CKM_CONCATENATE_DATA_AND_BASE,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_HKDF_DERIVE,
    CKM_XOR_BASE_AND_DATA,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_HOST_MEMORY,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_misc_kdf as tmisc
from pkcs11_check.testcases._import_negotiation import reset_import_negotiation_cache
from pkcs11_check.testcases._operability import reset_operability_cache
from pkcs11_check.testcases.mechanism_helpers import gen_generic_secret
from tests._skip_assert import assert_skips, assert_xfails

_OK = int(CKR_OK)
_SENSITIVE_RV = int(CKR_ATTRIBUTE_SENSITIVE)
_TYPE_INVALID = int(CKR_ATTRIBUTE_TYPE_INVALID)
_TEMPLATE_INCONSISTENT = int(CKR_TEMPLATE_INCONSISTENT)
_TEMPLATE_INCOMPLETE = int(CKR_TEMPLATE_INCOMPLETE)
_KEY_UNEXTRACTABLE = int(CKR_KEY_UNEXTRACTABLE)
_KEY_NOT_WRAPPABLE = int(CKR_KEY_NOT_WRAPPABLE)
_CLEAN_REJECT = int(CKR_FUNCTION_FAILED)
_HOST_MEMORY = int(CKR_HOST_MEMORY)
_MECHANISM_INVALID = int(CKR_MECHANISM_INVALID)
_UNDEFINED_RV = 0x7FFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF

_BASE_AND_KEY = int(CKM_CONCATENATE_BASE_AND_KEY)
_BASE_AND_DATA = int(CKM_CONCATENATE_BASE_AND_DATA)
_DATA_AND_BASE = int(CKM_CONCATENATE_DATA_AND_BASE)
_XOR = int(CKM_XOR_BASE_AND_DATA)
_EXTRACT = int(CKM_EXTRACT_KEY_FROM_KEY)
_HKDF = int(CKM_HKDF_DERIVE)

_BYTE_MECH_IDS = frozenset({_BASE_AND_KEY, _BASE_AND_DATA, _DATA_AND_BASE, _XOR, _EXTRACT})
_DERIVE_MECH_IDS = _BYTE_MECH_IDS | {_HKDF}

_REQ_SENSITIVE = "sensitive"
_REQ_EXTRACTABLE = "extractable"


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    C.clear()
    reset_import_negotiation_cache()
    reset_operability_cache()
    yield
    C.clear()
    reset_import_negotiation_cache()
    reset_operability_cache()


def _fill_ulong(out: Any, value: int) -> None:
    """Write an out-scalar passed as ``byref(ctypes_scalar)``."""
    ctypes.cast(out, ctypes.POINTER(ctypes.c_ulong)).contents.value = value


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    """Decode a captured template ptr + count into {attr_type: raw bytes}."""
    decoded: dict[int, bytes] = {}
    for i in range(count):
        atype = int(tmpl[i].type)
        alen = int(tmpl[i].ulValueLen)
        addr = tmpl[i].pValue
        decoded[atype] = bytes(ctypes.string_at(addr, alen)) if addr and alen > 0 else b""
    return decoded


def _decode_bool(raw: bytes) -> bool:
    assert len(raw) == 1, raw
    return raw[0] != 0


def _decode_ulong(raw: bytes) -> int:
    return int.from_bytes(raw, sys.byteorder)


def _decode_mech(mech: Any) -> tuple[int, int | None]:
    """Decode a mech byref into (CKM id, ulong param or None).

    Only single-CK_ULONG params (concatenate-base-and-key handle,
    extract bit offset) are decoded; struct params return None since the
    fake never needs their bytes (extract is the only value-computed
    mechanism and its param is a CK_ULONG).
    """
    ck = mech._obj
    mech_id = int(ck.mechanism)
    param: int | None = None
    addr = ck.pParameter
    if addr and int(ck.ulParameterLen) == ctypes.sizeof(CK_ULONG):
        param = int.from_bytes(ctypes.string_at(addr, ctypes.sizeof(CK_ULONG)), sys.byteorder)
    return mech_id, param


class _StoredKey:
    """One fake-token object: protection flags, histories, value, label."""

    def __init__(
        self,
        *,
        sensitive: bool,
        extractable: bool,
        value: bytes,
        label: str,
        role: str,
    ) -> None:
        self.sensitive = sensitive
        self.extractable = extractable
        # Histories for a freshly created key: true iff the flag held at
        # creation (created sealed and never changed).
        self.always_sensitive = sensitive
        self.never_extractable = not extractable
        self.value = value
        self.label = label
        self.role = role  # "gen" (generate/import) or "child" (derive)
        self.destroyed = False


class _ByteKdfFake:
    """Scriptable fake token for the QC2 inheritance legs.

    The fake keeps a real object store (flags, histories, values,
    labels) so healthy-mode derivation applies the genuine §6.43 rule:
    the child is sensitive when any source is sensitive, unextractable
    when any source is unextractable, with AND-combined histories.
    Defect knobs then perturb exactly one behavior each.
    """

    # noqa comments below: raw PKCS#11 entry-point names are mandated.

    def __init__(
        self,
        *,
        gen_script: list[int] | None = None,
        create_mode: str = "ok",
        create_refuse_rv: int = _CLEAN_REJECT,
        derive_mode: str = "healthy",
        derive_script: list[int] | None = None,
        dirty_handle: bool = False,
        refusal_creates_child: bool = False,
        control_creates_on_refusal: bool = False,
        zero_handle_ok: bool = False,
        history_mode: str = "healthy",
        source_mode: str = "honest",
        child_hide_flags: bool = False,
        hide_second_only: bool = False,
        child_malformed_flags: bool = False,
        value_mode: str = "healthy",
        value_raise_rv: int | None = None,
        flag_raise_rv: int | None = None,
        history_raise_rv: int | None = None,
        history_hide: bool = False,
        history_omit: bool = False,
        history_first_only: bool = False,
        child_malformed_histories: bool = False,
        source_hide_histories: bool = False,
        source_omit_histories: bool = False,
        source_malformed_always: bool = False,
        source_raise_rv: int | None = None,
        source_flip_histories: bool = False,
        wrap_mode: str = "healthy",
        find_mode: str = "healthy",
        find_refuse_rv: int = _CLEAN_REJECT,
        strengthen_omitted: bool = False,
        extract_corrupt: bool = False,
    ) -> None:
        self._gen_script = list(gen_script or [])
        self._create_mode = create_mode
        self._create_refuse_rv = create_refuse_rv
        self._derive_mode = derive_mode
        self._derive_script = list(derive_script or [])
        self._dirty_handle = dirty_handle
        self._refusal_creates_child = refusal_creates_child
        self._control_creates_on_refusal = control_creates_on_refusal
        self._zero_handle_ok = zero_handle_ok
        self._history_mode = history_mode
        self._source_mode = source_mode
        self._child_hide_flags = child_hide_flags
        self._hide_second_only = hide_second_only
        self._child_malformed_flags = child_malformed_flags
        self._value_mode = value_mode
        self._value_raise_rv = value_raise_rv
        self._flag_raise_rv = flag_raise_rv
        self._history_raise_rv = history_raise_rv
        self._history_hide = history_hide
        self._history_omit = history_omit
        self._history_first_only = history_first_only
        self._child_malformed_histories = child_malformed_histories
        self._source_hide_histories = source_hide_histories
        self._source_omit_histories = source_omit_histories
        self._source_malformed_always = source_malformed_always
        self._source_raise_rv = source_raise_rv
        self._source_flip_histories = source_flip_histories
        self._wrap_mode = wrap_mode
        self._find_mode = find_mode
        self._find_refuse_rv = find_refuse_rv
        self._strengthen_omitted = strengthen_omitted
        self._extract_corrupt = extract_corrupt
        self._next_handle = 100
        self.objects: dict[int, _StoredKey] = {}
        self.created: list[int] = []
        self.destroyed: list[int] = []
        self.derive_calls: list[dict[str, Any]] = []
        self.wrap_calls: list[dict[str, Any]] = []
        self.find_calls: list[dict[str, Any]] = []
        self._find_template: dict[int, bytes] | None = None

    def _issue(self) -> int:
        handle = self._next_handle
        self._next_handle += 1
        return handle

    def _store(
        self,
        *,
        sensitive: bool,
        extractable: bool,
        value: bytes,
        label: str,
        role: str,
    ) -> int:
        handle = self._issue()
        self.objects[handle] = _StoredKey(
            sensitive=sensitive,
            extractable=extractable,
            value=value,
            label=label,
            role=role,
        )
        self.created.append(handle)
        return handle

    def _gen_flags(self, attrs: dict[int, bytes]) -> tuple[bool, int, str, bytes, bool]:
        """Decode (sensitive, value_len, label, value, extractable) from a template."""
        sensitive_raw = attrs.get(int(CKA_SENSITIVE))
        sensitive = _decode_bool(sensitive_raw) if sensitive_raw is not None else False
        extractable_raw = attrs.get(int(CKA_EXTRACTABLE))
        extractable = _decode_bool(extractable_raw) if extractable_raw is not None else True
        length_raw = attrs.get(int(CKA_VALUE_LEN))
        length = _decode_ulong(length_raw) if length_raw else 32
        label_raw = attrs.get(int(CKA_LABEL), b"")
        label = label_raw.decode("utf-8", "replace")
        value = attrs.get(int(CKA_VALUE), b"")
        return sensitive, length, label, value, extractable

    def C_GenerateKey(self, _sh: int, _mech: Any, tmpl: Any, count: int, out: Any) -> int:  # noqa: N802
        rv = self._gen_script.pop(0) if self._gen_script else _OK
        if rv != _OK:
            return rv
        attrs = _decode_template(tmpl, count)
        sensitive, length, label, _, extractable = self._gen_flags(attrs)
        value = bytes([(self._next_handle + i) % 251 + 1 for i in range(length)])
        handle = self._store(
            sensitive=sensitive, extractable=extractable, value=value, label=label, role="gen"
        )
        _fill_ulong(out, handle)
        return _OK

    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, out: Any) -> int:  # noqa: N802
        if self._create_mode != "ok":
            return self._create_refuse_rv
        attrs = _decode_template(tmpl, count)
        sensitive, _length, label, value, extractable = self._gen_flags(attrs)
        handle = self._store(
            sensitive=sensitive, extractable=extractable, value=value, label=label, role="gen"
        )
        _fill_ulong(out, handle)
        return _OK

    def _flag_bytes(self, stored: _StoredKey, attr: int) -> bytes | None:
        """Serve a protection/history flag, honoring source/child defect knobs."""
        is_child = stored.role == "child"
        hidden = (
            {int(CKA_EXTRACTABLE)}
            if self._hide_second_only
            else {int(CKA_SENSITIVE), int(CKA_EXTRACTABLE)}
        )
        if is_child and self._child_hide_flags and attr in hidden:
            return None
        if not is_child and self._source_mode == "hide" and attr in hidden:
            return None
        if attr == int(CKA_SENSITIVE):
            value = stored.sensitive
            if not is_child and self._source_mode == "weaken":
                value = False
            if is_child and self._child_malformed_flags:
                return b"\x01\x00"  # malformed CK_BBOOL: 2 bytes, not 1
            return b"\x01" if value else b"\x00"
        if attr == int(CKA_EXTRACTABLE):
            value = stored.extractable
            if not is_child and self._source_mode == "weaken":
                value = True
            if is_child and self._child_malformed_flags:
                return b"\x01\x00"
            return b"\x01" if value else b"\x00"
        return None

    def _history_bytes(self, stored: _StoredKey, attr: int) -> bytes:
        always = stored.always_sensitive
        never = stored.never_extractable
        if stored.role == "gen" and self._source_flip_histories:
            always, never = True, True
        histories = {
            int(CKA_ALWAYS_SENSITIVE): always,
            int(CKA_NEVER_EXTRACTABLE): never,
        }
        return b"\x01" if histories[attr] else b"\x00"

    def _value_row(
        self, stored: _StoredKey, *, is_query: bool
    ) -> tuple[int, int | None, bytes | None]:
        """Return (rv, ulValueLen, fill) for one CKA_VALUE row."""
        sealed = stored.sensitive or not stored.extractable
        if self._value_mode == "leak" and sealed:
            return _OK, len(stored.value), stored.value
        if self._value_mode == "refuse_data" and sealed:
            # Refusal CKR with real bytes at a real length: the
            # leaked_len self-contradiction shape.
            if is_query:
                return _SENSITIVE_RV, len(stored.value), None
            return _SENSITIVE_RV, len(stored.value), stored.value
        if self._value_mode == "alternate" and sealed:
            return _TYPE_INVALID, _U64, None
        if self._value_mode == "no_ckr" and sealed:
            return _OK, _U64, None
        if self._value_mode == "refuse_unsealed" and not sealed:
            # A hiding token: the flags promise readability but the value
            # read is refused with the canonical sealed-child CKR.
            return _SENSITIVE_RV, _U64, None
        if sealed:
            return _SENSITIVE_RV, _U64, None
        return _OK, len(stored.value), stored.value

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        stored = self.objects.get(int(handle))
        assert stored is not None, f"read from unknown handle {handle}"
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            is_query = not addr
            if attr == int(CKA_VALUE) and self._value_raise_rv is not None:
                # Whole-call failure on a value row: outputs untouched.
                row_rvs.append(self._value_raise_rv)
                continue
            if (
                attr in (int(CKA_SENSITIVE), int(CKA_EXTRACTABLE))
                and stored.role == "child"
                and self._flag_raise_rv is not None
            ):
                row_rvs.append(self._flag_raise_rv)
                continue
            if (
                attr in (int(CKA_ALWAYS_SENSITIVE), int(CKA_NEVER_EXTRACTABLE))
                and stored.role == "child"
                and self._history_raise_rv is not None
            ):
                row_rvs.append(self._history_raise_rv)
                continue
            if stored.role == "gen" and self._source_raise_rv is not None:
                row_rvs.append(self._source_raise_rv)
                continue
            if attr == int(CKA_VALUE):
                rv, length, fill = self._value_row(stored, is_query=is_query)
            elif attr in (int(CKA_SENSITIVE), int(CKA_EXTRACTABLE)):
                data = self._flag_bytes(stored, attr)
                if data is None:
                    rv, length, fill = _TYPE_INVALID, _U64, None
                else:
                    rv, length, fill = _OK, len(data), data
            elif attr in (int(CKA_ALWAYS_SENSITIVE), int(CKA_NEVER_EXTRACTABLE)):
                if self._hide_second_only:
                    selected = attr == int(CKA_NEVER_EXTRACTABLE)
                elif self._history_first_only:
                    selected = attr == int(CKA_ALWAYS_SENSITIVE)
                else:
                    selected = True
                if stored.role == "child" and self._history_omit and selected:
                    # Omission: CKR_OK plus the sentinel with no refusal CKR.
                    rv, length, fill = _OK, _U64, None
                elif stored.role == "gen" and self._source_omit_histories and selected:
                    rv, length, fill = _OK, _U64, None
                elif stored.role == "child" and self._history_hide and selected:
                    rv, length, fill = _TYPE_INVALID, _U64, None
                elif stored.role == "child" and self._child_malformed_histories:
                    rv, length, fill = _OK, 2, b"\x01\x00"
                elif stored.role == "gen" and self._source_hide_histories and selected:
                    rv, length, fill = _TYPE_INVALID, _U64, None
                elif (
                    stored.role == "gen"
                    and self._source_malformed_always
                    and attr == int(CKA_ALWAYS_SENSITIVE)
                ):
                    # Malformed CK_BBOOL: 2 bytes, not 1. NEVER stays valid
                    # so the independently provable component is checkable.
                    rv, length, fill = _OK, 2, b"\x01\x00"
                else:
                    data = self._history_bytes(stored, attr)
                    rv, length, fill = _OK, len(data), data
            elif attr == int(CKA_LABEL):
                data = stored.label.encode()
                rv, length, fill = _OK, len(data), data
            else:
                rv, length, fill = _TYPE_INVALID, _U64, None
            if fill is not None and addr and not is_query:
                ctypes.memmove(addr, fill, min(len(fill), cap))
            if length is not None:
                tmpl[i].ulValueLen = length
            row_rvs.append(rv)
        for raised in (self._flag_raise_rv, self._history_raise_rv, self._source_raise_rv):
            if raised is not None and raised in row_rvs:
                return raised
        if self._value_raise_rv is not None and self._value_raise_rv in row_rvs:
            return self._value_raise_rv
        if _SENSITIVE_RV in row_rvs:
            return _SENSITIVE_RV
        if _TYPE_INVALID in row_rvs:
            return _TYPE_INVALID
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        stored = self.objects.get(int(handle))
        if stored is not None:
            stored.destroyed = True
        return _OK

    def _derive_sources(self, mech_id: int, base: int, param: int | None) -> list[_StoredKey]:
        """Resolve the source keys feeding the inheritance rule for one derive."""
        stored_base = self.objects.get(int(base))
        assert stored_base is not None, f"derive from unknown base {base}"
        if mech_id == _BASE_AND_KEY:
            assert param is not None, "base+key derive without aux handle param"
            stored_aux = self.objects.get(int(param))
            assert stored_aux is not None, f"derive with unknown aux {param}"
            if self._derive_mode == "aux_blind":
                # The single-source-formula defect: the aux key's seal is
                # ignored and only the base feeds the rule.
                return [stored_base]
            return [stored_base, stored_aux]
        return [stored_base]

    def _derive_child_flags(
        self,
        requested: dict[str, bool | None],
        *,
        mech_id: int,
        must_sensitive: bool,
        must_unextractable: bool,
    ) -> tuple[int, bool, bool]:
        """Apply the fake's derive-mode rule; return (rv, sensitive, extractable)."""
        req_sensitive = requested[_REQ_SENSITIVE]
        req_extractable = requested[_REQ_EXTRACTABLE]
        if self._derive_mode == "forward":
            # Haskoki pre-fix shape: the caller template is forwarded
            # verbatim, so a downgrade is accepted and the child is readable.
            return _OK, req_sensitive is True, req_extractable is not False
        if self._derive_mode == "accept_sealed":
            return _OK, True, False
        if self._derive_mode == "strip":
            # The weakening defect against an explicit template: every
            # protection request is ignored and the child is unsealed.
            return _OK, False, True
        if mech_id == _HKDF:
            # §6.62.3: HKDF child protection is independently selectable,
            # so downgrade requests are permitted, never refused. Omitted
            # attributes take the token's unsealed defaults.
            sensitive = req_sensitive if req_sensitive is not None else False
            extractable = req_extractable if req_extractable is not None else True
            return _OK, sensitive, extractable
        downgrade = (req_sensitive is False and must_sensitive) or (
            req_extractable is True and must_unextractable
        )
        if downgrade:
            return _TEMPLATE_INCONSISTENT, False, True
        if req_sensitive is not None:
            sensitive = req_sensitive
        elif must_sensitive or self._strengthen_omitted:
            sensitive = True
        else:
            sensitive = False
        if req_extractable is not None:
            extractable = req_extractable
        elif must_unextractable or self._strengthen_omitted:
            extractable = False
        else:
            extractable = True
        return _OK, sensitive, extractable

    def _derive_child_value(
        self,
        mech_id: int,
        sources: list[_StoredKey],
        param: int | None,
        attrs: dict[int, bytes],
    ) -> bytes:
        """Compute the stored child value (extract slices; else dummy bytes)."""
        length_raw = attrs.get(int(CKA_VALUE_LEN))
        assert length_raw, "derive without CKA_VALUE_LEN"
        length = _decode_ulong(length_raw)
        if mech_id == _EXTRACT:
            assert param is not None, "extract derive without bit-offset param"
            start = (int(param) // 8) if not self._extract_corrupt else 0
            base_value = sources[0].value
            if self._extract_corrupt:
                return bytes([(b + 1) % 256 for b in base_value[start : start + length]])
            return base_value[start : start + length]
        return b"\x77" * length

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, mech: Any, base: int, tmpl: Any, count: int, out: Any
    ) -> int:
        mech_id, param = _decode_mech(mech)
        assert mech_id in _DERIVE_MECH_IDS, f"unexpected derive mechanism {mech_id:#x}"
        attrs = _decode_template(tmpl, count)
        label = attrs.get(int(CKA_LABEL), b"").decode("utf-8", "replace")
        length_raw = attrs.get(int(CKA_VALUE_LEN))
        self.derive_calls.append(
            {
                "mech": mech_id,
                "base": int(base),
                "label": label,
                "value_len": _decode_ulong(length_raw) if length_raw else None,
            }
        )
        if self._derive_script:
            rv = self._derive_script.pop(0)
            control_refusal = self._control_creates_on_refusal and label.endswith(":operability")
            if rv != _OK and (self._refusal_creates_child or control_refusal):
                # The lifecycle defect: the refusal still created the
                # labelled child and leaked its handle to the caller.
                handle = self._store(
                    sensitive=True,
                    extractable=False,
                    value=b"\x99" * 16,
                    label=label,
                    role="child",
                )
                _fill_ulong(out, handle)
                return rv
            _fill_ulong(out, 999 if self._dirty_handle and rv != _OK else 0)
            return rv
        if int(CKA_VALUE_LEN) not in attrs:
            # §§6.43.3–6.43.6 + HKDF expansion: every row derives a
            # variable-length key, so the template must state CKA_VALUE_LEN.
            # Production always supplies one; this trips loudly if it stops.
            _fill_ulong(out, 0)
            return _TEMPLATE_INCOMPLETE
        sources = self._derive_sources(mech_id, int(base), param)
        must_sensitive = any(source.sensitive for source in sources)
        must_unextractable = any(not source.extractable for source in sources)
        requested: dict[str, bool | None] = {
            _REQ_SENSITIVE: (
                _decode_bool(attrs[int(CKA_SENSITIVE)]) if int(CKA_SENSITIVE) in attrs else None
            ),
            _REQ_EXTRACTABLE: (
                _decode_bool(attrs[int(CKA_EXTRACTABLE)]) if int(CKA_EXTRACTABLE) in attrs else None
            ),
        }
        rv, sensitive, extractable = self._derive_child_flags(
            requested,
            mech_id=mech_id,
            must_sensitive=must_sensitive,
            must_unextractable=must_unextractable,
        )
        if rv != _OK:
            _fill_ulong(out, 999 if self._dirty_handle else 0)
            return rv
        if self._zero_handle_ok:
            _fill_ulong(out, 0)
            return _OK
        value = self._derive_child_value(mech_id, sources, param, attrs)
        handle = self._store(
            sensitive=sensitive, extractable=extractable, value=value, label=label, role="child"
        )
        child = self.objects[handle]
        # Genuine §6.43 history rule: AND-combine the histories of the
        # sources that fed the rule (one source under aux_blind — that is
        # the defect being modelled).
        child.always_sensitive = all(source.always_sensitive for source in sources) and sensitive
        child.never_extractable = (
            all(source.never_extractable for source in sources) and not extractable
        )
        if self._history_mode == "drop":
            child.always_sensitive = False
            child.never_extractable = False
        elif self._history_mode == "fabricate":
            child.always_sensitive = True
            child.never_extractable = True
        _fill_ulong(out, handle)
        return _OK

    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.find_calls.append({"op": "init", "count": int(count)})
        if self._find_mode == "refuse":
            return self._find_refuse_rv
        self._find_template = _decode_template(tmpl, int(count)) if tmpl is not None else {}
        return _OK

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        self.find_calls.append({"op": "find", "max": int(max_count)})
        if self._find_mode == "phantom":
            handles[0] = 999
            _fill_ulong(found_ptr, 1)
            return _OK
        label = (self._find_template or {}).get(int(CKA_LABEL))
        matches = [
            handle
            for handle, stored in self.objects.items()
            if not stored.destroyed and (label is None or stored.label.encode() == label)
        ]
        for index, handle in enumerate(matches[: int(max_count)]):
            handles[index] = handle
        _fill_ulong(found_ptr, min(len(matches), int(max_count)))
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        self.find_calls.append({"op": "final"})
        self._find_template = None
        return _OK

    def _wrap_outcome(self, target: int) -> tuple[int, bytes]:
        """Return (rv, payload) for one C_WrapKey target."""
        stored = self.objects.get(int(target))
        assert stored is not None, f"wrap of unknown target {target}"
        mode = self._wrap_mode
        if mode == "wrap_any":
            return _OK, b"W" * 48
        if mode == "control_refuse" and stored.role == "gen":
            return _CLEAN_REJECT, b""
        if mode == "control_empty" and stored.role == "gen":
            return _OK, b""
        if stored.role == "gen":
            # The extractable control key always wraps cleanly (except in
            # the control-defect modes above).
            return _OK, b"W" * 48
        if mode == "refuse_child":
            return _KEY_UNEXTRACTABLE, b""
        if mode == "not_wrappable":
            # §5.18.3 permits token-specific refusal despite EXTRACTABLE.
            return _KEY_NOT_WRAPPABLE, b""
        if mode == "alternate":
            return _CLEAN_REJECT, b""
        if mode == "undefined":
            return _UNDEFINED_RV, b""
        if mode == "empty":
            return _OK, b""
        if stored.extractable:
            return _OK, b"W" * 48
        return _KEY_UNEXTRACTABLE, b""

    def C_WrapKey(  # noqa: N802
        self, _sh: int, _mech: Any, wrapping: int, target: int, out: Any, out_len: Any
    ) -> int:
        rv, payload = self._wrap_outcome(int(target))
        self.wrap_calls.append(
            {"wrapping": int(wrapping), "target": int(target), "rv": rv, "query": out is None}
        )
        if out is None:
            _fill_ulong(out_len, len(payload))
            return rv
        if rv == _OK and payload:
            ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return rv


def _rs(fake: _ByteKdfFake, *, mechs: set[str] | None = None) -> SimpleNamespace:
    if mechs is None:
        return SimpleNamespace(raw=fake, sh=1, has_mechanism=lambda _name: True)
    return SimpleNamespace(raw=fake, sh=1, has_mechanism=lambda name: name in mechs)


def _single(rs: SimpleNamespace, mech: str, seal: str, mode: str) -> None:
    tmisc.TestByteKdfInheritance().test_inheritance_single_source(rs, mech, seal, mode)


def _basekey(rs: SimpleNamespace, seal: str, mode: str, placement: str) -> None:
    tmisc.TestByteKdfInheritance().test_inheritance_base_and_key(rs, seal, mode, placement)


def _hkdf(rs: SimpleNamespace, mode: str) -> None:
    tmisc.TestHkdfInheritanceScope().test_hkdf_sealed_base(rs, mode)


def _short_sealed(rs: SimpleNamespace) -> None:
    tmisc.TestByteKdfShortChild().test_extract_single_byte_sealed_base_keeps_protection(rs)


def _short_unsealed(rs: SimpleNamespace) -> None:
    tmisc.TestByteKdfShortChild().test_extract_single_byte_unsealed_control(rs)


def _run_must_fail(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    """Run ``fn`` requiring ``pytest.fail``; an xfail here is a false pass.

    ``XFailed`` subclasses ``Failed``, so a bare ``pytest.raises(Failed)``
    would silently accept an xfail where a hard failure is required.
    """
    with pytest.raises(Failed) as exc_info:
        fn(*args, **kwargs)
    assert not isinstance(exc_info.value, XFailed), f"expected fail, got xfail: {exc_info.value}"


def _assert_fail_record(reason: str, kind: str | None) -> Any:
    records = C.get_records()
    assert len(records) == 1, [record.summary for record in records]
    assert records[0].reason == reason, records[0].summary
    assert records[0].kind == kind, records[0].summary
    assert records[0].outcome == "fail"
    return records[0]


def _assert_xfail_record(reason: str) -> Any:
    records = C.get_records()
    assert len(records) == 1, [record.summary for record in records]
    assert records[0].reason == reason, records[0].summary
    assert records[0].outcome == "xfail"
    return records[0]


def _assert_cleaned_up(fake: _ByteKdfFake) -> None:
    assert fake.created, "fake created no objects at all"
    assert set(fake.destroyed) >= set(fake.created), (fake.created, fake.destroyed)


_SINGLE_MECHS = [
    "CKM_CONCATENATE_BASE_AND_DATA",
    "CKM_CONCATENATE_DATA_AND_BASE",
    "CKM_XOR_BASE_AND_DATA",
    "CKM_EXTRACT_KEY_FROM_KEY",
]
_SEALS = ["sensitive_only", "unextractable_only", "both"]
_MODES = ["omitted", "matching", "downgrade"]
_PLACEMENTS = ["base", "aux", "both"]


def test_healthy_single_source_matrix_all_pass() -> None:
    """All 4×3×3 single-source cells pass on a conforming token."""
    for mech in _SINGLE_MECHS:
        for seal in _SEALS:
            for mode in _MODES:
                fake = _ByteKdfFake()
                _single(_rs(fake), mech, seal, mode)
                assert C.get_records() == [], (mech, seal, mode)
                _assert_cleaned_up(fake)
                C.clear()


def test_healthy_base_and_key_all_placements_pass() -> None:
    """All 3×3×3 two-key cells pass; both placements feed the rule."""
    for seal in _SEALS:
        for mode in _MODES:
            for placement in _PLACEMENTS:
                fake = _ByteKdfFake()
                _basekey(_rs(fake), seal, mode, placement)
                assert C.get_records() == [], (seal, mode, placement)
                _assert_cleaned_up(fake)
                C.clear()


def test_healthy_hkdf_modes_pass() -> None:
    """The HKDF scoping control passes in all three modes."""
    for mode in _MODES:
        fake = _ByteKdfFake()
        _hkdf(_rs(fake), mode)
        assert C.get_records() == [], mode
        _assert_cleaned_up(fake)
        C.clear()


def test_healthy_short_legs_pass() -> None:
    """Permitted 1-byte extraction succeeds, sealed and unsealed."""
    fake = _ByteKdfFake()
    _short_sealed(_rs(fake))
    assert C.get_records() == []
    _assert_cleaned_up(fake)
    C.clear()
    fake = _ByteKdfFake()
    _short_unsealed(_rs(fake))
    assert C.get_records() == []
    _assert_cleaned_up(fake)


def test_matrix_skips_when_mechanism_unavailable() -> None:
    """Each leg skips (not xfails) when its mechanism is not advertised."""
    assert_skips(_single, _rs(_ByteKdfFake(), mechs=set()), _SINGLE_MECHS[0], _SEALS[0], _MODES[0])
    assert_skips(_basekey, _rs(_ByteKdfFake(), mechs=set()), _SEALS[0], _MODES[0], _PLACEMENTS[0])
    assert_skips(_hkdf, _rs(_ByteKdfFake(), mechs=set()), _MODES[0])
    assert_skips(_short_sealed, _rs(_ByteKdfFake(), mechs=set()))
    assert_skips(_short_unsealed, _rs(_ByteKdfFake(), mechs=set()))


def test_source_gen_refusal_xfails_not_operational() -> None:
    """A refused sealed-source setup cannot prove the seal premise."""
    fake = _ByteKdfFake(gen_script=[_CLEAN_REJECT])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[2], "both", "matching")
    _assert_xfail_record("not_operational")


def test_weakened_source_report_xfails_premise_unprovable() -> None:
    """Sources reporting weaker flags than requested void the premise."""
    fake = _ByteKdfFake(source_mode="weaken")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_xfail_record("not_operational")


def test_hidden_source_flags_xfail_premise_unprovable() -> None:
    """Unreadable source flags void the seal premise."""
    fake = _ByteKdfFake(source_mode="hide")
    assert_xfails(_basekey, _rs(fake), "sensitive_only", "matching", "both")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert records[1].outcome == "xfail"


def test_unsealed_import_refusal_xfails_setup() -> None:
    """The short-child KAT control xfails when its import is refused."""
    fake = _ByteKdfFake(create_mode="refuse")
    assert_xfails(_short_unsealed, _rs(fake))
    _assert_xfail_record("not_operational")


def test_control_wrap_refused_xfails_wrap_setup() -> None:
    """A refused control wrap voids the wrap leg, not the child's verdict."""
    fake = _ByteKdfFake(wrap_mode="control_refuse")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[1], "both", "matching")
    record = _assert_xfail_record("not_operational")
    assert "control" in record.label.lower() or "wrap" in record.label.lower()


def test_control_wrap_empty_xfails_wrap_setup() -> None:
    """An empty control-wrap output voids the wrap leg."""
    fake = _ByteKdfFake(wrap_mode="control_empty")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[1], "sensitive_only", "matching")
    _assert_xfail_record("not_operational")


def test_wrapping_key_gen_refused_xfails_wrap_setup() -> None:
    """A refused wrapping-key setup xfails the wrap leg."""
    fake = _ByteKdfFake(gen_script=[_OK, _CLEAN_REJECT])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[3], "both", "matching")
    _assert_xfail_record("not_operational")


def test_downgrade_canonical_refusal_passes_without_object() -> None:
    """CKR_TEMPLATE_INCONSISTENT on downgrade passes and creates nothing."""
    fake = _ByteKdfFake()
    _basekey(_rs(fake), "both", "downgrade", "both")
    assert C.get_records() == []
    assert fake.find_calls, "downgrade refusal must be followed by a no-object search"
    # The operability probe derives (and destroys) a control child after
    # the search, so "creates nothing" means no surviving child object.
    assert all(stored.destroyed for stored in fake.objects.values() if stored.role == "child")
    _assert_cleaned_up(fake)


def test_downgrade_alternate_refusal_xfails_with_original_rv() -> None:
    """A clean non-canonical downgrade refusal xfails, preserving the RV."""
    fake = _ByteKdfFake(derive_script=[_CLEAN_REJECT])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert record.expected_ckr == ["CKR_TEMPLATE_INCONSISTENT"]


def test_downgrade_undefined_rv_fails_metadata() -> None:
    """An undefined downgrade RV is a return-value contract violation."""
    fake = _ByteKdfFake(derive_script=[_UNDEFINED_RV])
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[3], "unextractable_only", "downgrade")
    _assert_fail_record("self_contradiction", "metadata")


def test_downgrade_phantom_object_fails_lifecycle() -> None:
    """A labelled survivor after a refused derive fails the effect check."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT], find_mode="phantom")
    _run_must_fail(_basekey, _rs(fake), "both", "downgrade", "aux")
    _assert_fail_record("self_contradiction", "lifecycle")


def test_downgrade_find_refused_xfails_effect_unprovable() -> None:
    """A refused label search cannot prove the no-object effect."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT], find_mode="refuse")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[2], "sensitive_only", "downgrade")
    _assert_xfail_record("not_operational")


def test_downgrade_dirty_handle_records_deviation_and_passes() -> None:
    """A nonzero handle on refusal is hygienically destroyed and noted."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT], dirty_handle=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    assert 999 in fake.destroyed
    _assert_xfail_record("honest_deviation")


def test_downgrade_forwarded_template_fails_policy() -> None:
    """Accepting a downgrade with weakened flags fails (the #52.2 shape).

    Both observations are collected (S5): the policy failure from the
    weakened flags and the fallback template-contract failure from the
    acceptance itself; the strongest (first fail) is raised.
    """
    fake = _ByteKdfFake(derive_mode="forward")
    with pytest.raises(Failed) as exc_info:
        _single(_rs(fake), _SINGLE_MECHS[1], "both", "downgrade")
    assert not isinstance(exc_info.value, XFailed), f"expected fail, got xfail: {exc_info.value}"
    assert "weakened" in str(exc_info.value).lower()
    records = C.get_records()
    assert [record.reason for record in records] == ["self_contradiction", "accepted_invalid"]
    assert records[0].kind == "policy"


def test_downgrade_accepted_but_sealed_fails_accepted_invalid() -> None:
    """Accepting a must-refuse downgrade fails even when sealed defensively."""
    fake = _ByteKdfFake(derive_mode="accept_sealed")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "sensitive_only", "downgrade")
    _assert_fail_record("accepted_invalid", "metadata")


def test_omitted_forwarded_single_source_fails_policy() -> None:
    """Omitted attributes forwarded to weak defaults fail the flag check."""
    fake = _ByteKdfFake(derive_mode="forward")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[2], "both", "omitted")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.operation == "C_DeriveKey"


def test_omitted_forwarded_template_fails_policy() -> None:
    """Omitted attributes do not excuse a weakened child."""
    fake = _ByteKdfFake(derive_mode="forward")
    _run_must_fail(_basekey, _rs(fake), "unextractable_only", "omitted", "base")
    _assert_fail_record("self_contradiction", "policy")


def test_aux_blind_two_key_rule_fails_flags_and_histories() -> None:
    """A base-only formula fails: flags on the aux seal, histories on base.

    A matching template masks the defect (the caller asked for the right
    flags), so both legs use omitted templates: with the seal on aux the
    child flags weaken (policy), with the seal on base the flags agree
    but the base-only history contradicts the AND rule (metadata).
    """
    aux_fake = _ByteKdfFake(derive_mode="aux_blind")
    _run_must_fail(_basekey, _rs(aux_fake), "both", "omitted", "aux")
    _assert_fail_record("self_contradiction", "policy")
    C.clear()
    base_fake = _ByteKdfFake(derive_mode="aux_blind")
    _run_must_fail(_basekey, _rs(base_fake), "both", "omitted", "base")
    _assert_fail_record("self_contradiction", "metadata")


def test_history_drop_fails_metadata() -> None:
    """A lost ALWAYS/NEVER history fails the history check."""
    fake = _ByteKdfFake(history_mode="drop")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_history_fabrication_fails_metadata() -> None:
    """An invented ALWAYS history fails the history check."""
    fake = _ByteKdfFake(history_mode="fabricate")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[1], "unextractable_only", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_missing_child_flags_fail_metadata() -> None:
    """Hiding the child's protection flags fails; the seal is unprovable."""
    fake = _ByteKdfFake(child_hide_flags=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[3], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "self_contradiction"]
    assert records[0].outcome == "xfail"
    assert records[1].outcome == "fail"
    assert records[1].kind == "metadata"


def test_malformed_child_flags_fail_metadata() -> None:
    """A non-boolean child flag fails the shape check."""
    fake = _ByteKdfFake(child_malformed_flags=True)
    _run_must_fail(_basekey, _rs(fake), "both", "matching", "both")
    _assert_fail_record("self_contradiction", "metadata")


def test_derive_ok_with_zero_handle_fails_lifecycle() -> None:
    """CKR_OK with a zero handle is a lifecycle self-contradiction."""
    fake = _ByteKdfFake(derive_script=[_OK])
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "lifecycle")


def test_permitted_derive_refusal_xfails_not_operational() -> None:
    """A clean refusal of a matching derive xfails with the original RV."""
    fake = _ByteKdfFake(derive_script=[_CLEAN_REJECT])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_permitted_derive_undefined_rv_fails_metadata() -> None:
    """An undefined RV on a permitted derive fails the RV contract."""
    fake = _ByteKdfFake(derive_script=[_UNDEFINED_RV])
    _run_must_fail(_hkdf, _rs(fake), "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_sealed_value_leak_fails_policy() -> None:
    """A readable sealed-child value fails the readback leg."""
    fake = _ByteKdfFake(value_mode="leak")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[2], "sensitive_only", "matching")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.operation == "C_GetAttributeValue"


def test_refusal_with_data_fails_policy() -> None:
    """Refusal CKR plus real bytes fails the leak check."""
    fake = _ByteKdfFake(value_mode="refuse_data")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "omitted")
    records = C.get_records()
    assert [record.reason for record in records] == ["self_contradiction", "self_contradiction"]
    assert all(record.kind == "policy" for record in records)
    assert all(record.outcome == "fail" for record in records)


def test_readback_alternate_rv_xfails_with_original_rv() -> None:
    """A clean non-canonical value refusal xfails, preserving the RV."""
    fake = _ByteKdfFake(value_mode="alternate")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[1], "both", "matching")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert record.expected_ckr == ["CKR_ATTRIBUTE_SENSITIVE"]


def test_readback_unavailable_without_ckr_xfails_deviation() -> None:
    """OK plus CK_UNAVAILABLE_INFORMATION with no CKR is a visible deviation."""
    fake = _ByteKdfFake(value_mode="no_ckr")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[3], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "honest_deviation"]
    assert all(record.outcome == "xfail" for record in records)


def test_readback_call_failure_xfails_with_original_rv() -> None:
    """A clean whole-call read failure xfails, preserving the RV."""
    fake = _ByteKdfFake(value_raise_rv=_CLEAN_REJECT)
    assert_xfails(_basekey, _rs(fake), "both", "matching", "both")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_readback_undefined_rv_fails_metadata() -> None:
    """An undefined read RV fails the return-value contract."""
    fake = _ByteKdfFake(value_raise_rv=_UNDEFINED_RV)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_wrap_unextractable_child_fails_policy() -> None:
    """Wrapping an unextractable child fails the wrap leg."""
    fake = _ByteKdfFake(wrap_mode="wrap_any")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[3], "both", "matching")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.operation == "C_WrapKey"


def test_wrap_refused_extractable_child_xfails_with_original_rv() -> None:
    """Refusing a proven-valid wrap of an extractable child xfails (S3).

    CKR_KEY_NOT_WRAPPABLE explicitly permits token-specific refusal
    despite EXTRACTABLE=true (§5.18.3); a clean refusal is evidence the
    wrap leg is unprovable, never a policy failure.
    """
    fake = _ByteKdfFake(wrap_mode="refuse_child")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "sensitive_only", "matching")
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_WrapKey"
    assert record.actual_ckr == "CKR_KEY_UNEXTRACTABLE"


def test_wrap_correct_refusal_passes_for_unextractable() -> None:
    """The same refusing token passes the unextractable-child wrap leg."""
    fake = _ByteKdfFake(wrap_mode="refuse_child")
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    assert C.get_records() == []


def test_wrap_alternate_rv_xfails_for_unextractable() -> None:
    """A clean non-canonical wrap refusal xfails, preserving the RV."""
    fake = _ByteKdfFake(wrap_mode="alternate")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[1], "both", "matching")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert record.expected_ckr == ["CKR_KEY_UNEXTRACTABLE"]


def test_wrap_alternate_rv_xfails_for_extractable() -> None:
    """Any clean refusal of an extractable child xfails (S3)."""
    fake = _ByteKdfFake(wrap_mode="alternate")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[1], "sensitive_only", "matching")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_wrap_undefined_rv_fails_metadata() -> None:
    """An undefined wrap RV fails the return-value contract."""
    fake = _ByteKdfFake(wrap_mode="undefined")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[2], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_wrap_empty_output_fails_metadata() -> None:
    """CKR_OK with zero wrapped bytes fails the output-shape check."""
    fake = _ByteKdfFake(wrap_mode="empty")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "sensitive_only", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_wrap_skipped_without_mechanism_passes() -> None:
    """No wrap mechanism skips only the wrap leg; flags still verify."""
    mechs = {
        "CONCATENATE_BASE_AND_DATA",
        "CONCATENATE_DATA_AND_BASE",
        "XOR_BASE_AND_DATA",
        "EXTRACT_KEY_FROM_KEY",
        "CONCATENATE_BASE_AND_KEY",
        "HKDF_DERIVE",
        "GENERIC_SECRET_KEY_GEN",
    }
    fake = _ByteKdfFake()
    _single(_rs(fake, mechs=mechs), _SINGLE_MECHS[0], "both", "matching")
    assert C.get_records() == []
    assert fake.wrap_calls == []


def test_strengthened_omitted_child_passes() -> None:
    """Over-sealing an omitted child passes: the oracle is one-sided."""
    for seal in _SEALS:
        fake = _ByteKdfFake(strengthen_omitted=True)
        _single(_rs(fake), _SINGLE_MECHS[3], seal, "omitted")
        assert C.get_records() == [], seal
        C.clear()


def test_unsealed_short_kat_detects_wrong_value() -> None:
    """The short-child KAT fails when the derived byte is wrong."""
    fake = _ByteKdfFake(extract_corrupt=True)
    _run_must_fail(_short_unsealed, _rs(fake))
    _assert_fail_record("wrong_result", "crypto")


def test_failing_cell_still_destroys_sources() -> None:
    """Cleanup survives a primary failure: all sources are destroyed."""
    fake = _ByteKdfFake(derive_mode="forward")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    _assert_cleaned_up(fake)


def test_short_sealed_value_leak_fails_policy() -> None:
    """A readable sealed short child fails; shortness never excuses leaks."""
    fake = _ByteKdfFake(value_mode="leak")
    _run_must_fail(_short_sealed, _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.operation == "C_GetAttributeValue"


def test_hkdf_downgrade_permitted_unsealed_passes() -> None:
    """An HKDF downgrade yielding a permitted unsealed child passes (S1).

    §6.62.3 lets the caller select the HKDF child's protection
    independently: accepting the downgrade with an unsealed child is
    conformant, and the readable value is consistent access evidence.
    """
    fake = _ByteKdfFake(derive_mode="forward")
    _hkdf(_rs(fake), "downgrade")
    assert C.get_records() == []
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_HOST_MEMORY, _CLEAN_REJECT], ids=["host_memory", "clean"])
def test_child_flag_read_clean_error_xfails_evidence(rv: int) -> None:
    """A defined clean child-flag read error is xfail evidence (S4)."""
    fake = _ByteKdfFake(flag_raise_rv=rv)
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_xfail_record("not_operational")


def test_child_flag_read_undefined_rv_fails_metadata() -> None:
    """An undefined child-flag read RV fails the RV contract (S9)."""
    fake = _ByteKdfFake(flag_raise_rv=_UNDEFINED_RV)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_child_history_read_failure_skips_histories_visibly() -> None:
    """A refused history read skips only the history check, visibly."""
    fake = _ByteKdfFake(history_raise_rv=_CLEAN_REJECT)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("not_operational")
    assert "history" in record.label.lower()


def test_child_history_hidden_skips_histories_visibly() -> None:
    """Hidden child histories skip only the history check, visibly (S8).

    Each hidden component is recorded (per-component evidence); the
    protection legs still carry the pass verdict.
    """
    fake = _ByteKdfFake(history_hide=True)
    _single(_rs(fake), _SINGLE_MECHS[1], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "honest_deviation"]
    assert all(record.outcome == "xfail" for record in records)
    assert all("history" in record.label.lower() for record in records)


def test_source_seal_read_failure_xfails_premise() -> None:
    """A refused source read voids the seal premise."""
    fake = _ByteKdfFake(source_raise_rv=_CLEAN_REJECT)
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_xfail_record("not_operational")


def test_source_history_contradiction_xfails_premise() -> None:
    """A source history contradicting its flags voids the premise."""
    fake = _ByteKdfFake(source_flip_histories=True)
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "unextractable_only", "matching")
    record = _assert_xfail_record("not_operational")
    assert "history" in record.label.lower()


def test_control_key_gen_refused_xfails_wrap_setup() -> None:
    """A refused control-key setup xfails the wrap leg."""
    fake = _ByteKdfFake(gen_script=[_OK, _OK, _CLEAN_REJECT])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_xfail_record("not_operational")


def test_unknown_placement_raises_harness_error() -> None:
    """An unknown seal placement is a harness bug, raised loudly."""
    with pytest.raises(ValueError, match="placement"):
        _basekey(_rs(_ByteKdfFake()), "both", "matching", "bogus")


def test_unknown_child_mode_raises_harness_error() -> None:
    """An unknown child-template mode is a harness bug, raised loudly."""
    with pytest.raises(ValueError, match="mode"):
        tmisc._child_mode_attrs("both", "bogus")


def test_downgrade_ok_with_zero_handle_fails_lifecycle() -> None:
    """CKR_OK with a zero handle fails on the downgrade path too."""
    fake = _ByteKdfFake(derive_script=[_OK])
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    _assert_fail_record("self_contradiction", "lifecycle")


def test_short_unsealed_refusal_xfails_permitted() -> None:
    """A clean refusal of the short KAT control xfails, preserving the RV."""
    fake = _ByteKdfFake(derive_script=[_CLEAN_REJECT])
    assert_xfails(_short_unsealed, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_short_unsealed_ok_with_zero_handle_fails_lifecycle() -> None:
    """CKR_OK with a zero handle fails the short KAT control."""
    fake = _ByteKdfFake(derive_script=[_OK])
    _run_must_fail(_short_unsealed, _rs(fake))
    _assert_fail_record("self_contradiction", "lifecycle")


def test_short_unsealed_read_refusal_xfails_control() -> None:
    """A clean refusal of the KAT readback xfails the control."""
    fake = _ByteKdfFake(value_raise_rv=_CLEAN_REJECT)
    assert_xfails(_short_unsealed, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_short_unsealed_read_undefined_rv_fails_metadata() -> None:
    """An undefined KAT-read RV fails the return-value contract."""
    fake = _ByteKdfFake(value_raise_rv=_UNDEFINED_RV)
    _run_must_fail(_short_unsealed, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_source_histories_hidden_skips_histories_visibly() -> None:
    """Hidden source histories skip only the history check, visibly (S8).

    Each hidden component voids its own premise visibly; the protection
    legs still carry the pass verdict.
    """
    fake = _ByteKdfFake(source_hide_histories=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert all(record.outcome == "xfail" for record in records)
    assert all("history" in record.label.lower() for record in records)


def test_child_histories_malformed_skips_histories_visibly() -> None:
    """Malformed child histories skip only the history check, visibly."""
    fake = _ByteKdfFake(child_malformed_histories=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("honest_deviation")
    assert "history" in record.label.lower()


def test_hidden_second_source_flag_xfails_premise() -> None:
    """A hidden EXTRACTABLE with readable SENSITIVE still voids the premise."""
    fake = _ByteKdfFake(source_mode="hide", hide_second_only=True)
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]


def test_hidden_second_child_flag_fails_metadata() -> None:
    """A hidden child EXTRACTABLE fails like a hidden SENSITIVE."""
    fake = _ByteKdfFake(child_hide_flags=True, hide_second_only=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "self_contradiction"]
    assert records[1].kind == "metadata"


def test_hidden_second_child_history_skips_visibly() -> None:
    """A hidden child NEVER alone skips only the history check."""
    fake = _ByteKdfFake(history_hide=True, hide_second_only=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("honest_deviation")
    assert "history" in record.label.lower()


def test_hidden_second_source_history_skips_visibly() -> None:
    """A hidden source NEVER alone skips only the history check."""
    fake = _ByteKdfFake(source_hide_histories=True, hide_second_only=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("not_operational")
    assert "history" in record.label.lower()


# ---------------------------------------------------------------------------
# Fix round 1: review findings S1–S10 + M1.
# ---------------------------------------------------------------------------


def test_hkdf_matching_forwarded_sealed_passes() -> None:
    """An HKDF matching request honored with a sealed child passes (S1)."""
    fake = _ByteKdfFake(derive_mode="forward")
    _hkdf(_rs(fake), "matching")
    assert C.get_records() == []
    _assert_cleaned_up(fake)


def test_hkdf_downgrade_accepted_sealed_fails_accepted_invalid() -> None:
    """An HKDF downgrade sealed against the request fails the template (S1)."""
    fake = _ByteKdfFake(derive_mode="accept_sealed")
    _run_must_fail(_hkdf, _rs(fake), "downgrade")
    _assert_fail_record("accepted_invalid", "metadata")


def test_hkdf_unsealed_value_hidden_fails_policy() -> None:
    """A hidden value on a permitted unsealed HKDF child fails access (S1)."""
    fake = _ByteKdfFake(derive_mode="forward", value_mode="refuse_unsealed")
    _run_must_fail(_hkdf, _rs(fake), "downgrade")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.operation == "C_GetAttributeValue"


def test_hkdf_downgrade_refusal_xfails_permitted() -> None:
    """Refusing a permitted HKDF downgrade xfails; nothing is proven (S1)."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT])
    assert_xfails(_hkdf, _rs(fake), "downgrade")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_TEMPLATE_INCONSISTENT"


def test_hkdf_omitted_unsealed_defaults_pass() -> None:
    """HKDF omitted attributes take unsealed defaults and pass (S1)."""
    fake = _ByteKdfFake()
    _hkdf(_rs(fake), "omitted")
    assert C.get_records() == []
    _assert_cleaned_up(fake)


def test_child_templates_carry_explicit_output_length() -> None:
    """Every row states CKA_VALUE_LEN: 64/64/64/32/16 concat/xor/extract (S2)."""
    expected_lens = {
        "CKM_CONCATENATE_BASE_AND_DATA": 64,
        "CKM_CONCATENATE_DATA_AND_BASE": 64,
        "CKM_XOR_BASE_AND_DATA": 32,
        "CKM_EXTRACT_KEY_FROM_KEY": 16,
    }
    for mech, expected in expected_lens.items():
        fake = _ByteKdfFake()
        _single(_rs(fake), mech, "both", "matching")
        assert [call["value_len"] for call in fake.derive_calls] == [expected]
        C.clear()
    fake = _ByteKdfFake()
    _basekey(_rs(fake), "both", "matching", "both")
    assert [call["value_len"] for call in fake.derive_calls] == [64]
    C.clear()
    fake = _ByteKdfFake()
    _hkdf(_rs(fake), "matching")
    assert [call["value_len"] for call in fake.derive_calls] == [32]


def test_fake_rejects_incomplete_template() -> None:
    """Fake capability pin: a derive template without length is refused (S2).

    White-box pin on the fake (not production behavior): it guards the
    production obligation above — an incomplete template must trip loudly
    instead of silently deriving a token-invented length.
    """
    fake = _ByteKdfFake()
    rs = _rs(fake)
    base = gen_generic_secret(rs, 256)
    try:
        rv, handle = tmisc._derive_byte_child(
            rs,
            "CKM_XOR_BASE_AND_DATA",
            [base],
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_TOKEN: False,
                CKA_LABEL: "tripwire-incomplete",
            },
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, base)
    assert rv == _TEMPLATE_INCOMPLETE
    assert handle == 0


def test_downgrade_incomplete_template_xfails_premise() -> None:
    """TEMPLATE_INCOMPLETE on downgrade voids the premise, not the rule (S2)."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCOMPLETE])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_TEMPLATE_INCOMPLETE"


def test_wrap_not_wrappable_extractable_child_xfails() -> None:
    """CKR_KEY_NOT_WRAPPABLE on an extractable child xfails with its RV (S3)."""
    fake = _ByteKdfFake(wrap_mode="not_wrappable")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[2], "sensitive_only", "matching")
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_WrapKey"
    assert record.actual_ckr == "CKR_KEY_NOT_WRAPPABLE"


def test_value_xfail_does_not_prevent_wrap_oracle() -> None:
    """A value-read xfail is collected; the wrap oracle still runs (S5)."""
    fake = _ByteKdfFake(value_mode="alternate", wrap_mode="wrap_any")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[2], "both", "matching")
    assert fake.wrap_calls, "the wrap oracle must run despite the value xfail"
    records = C.get_records()
    assert [record.reason for record in records] == [
        "nonspec_reject",
        "self_contradiction",
    ]
    assert records[0].outcome == "xfail"
    assert records[1].outcome == "fail"
    assert records[1].kind == "policy"


def test_accepted_downgrade_runs_full_checks_before_fallback() -> None:
    """Accepted downgrade children are fully checked before the fallback (S5)."""
    fake = _ByteKdfFake(derive_mode="accept_sealed", history_mode="drop")
    with pytest.raises(Failed) as exc_info:
        _single(_rs(fake), _SINGLE_MECHS[0], "sensitive_only", "downgrade")
    assert not isinstance(exc_info.value, XFailed), f"expected fail, got xfail: {exc_info.value}"
    assert "history" in str(exc_info.value).lower()
    records = C.get_records()
    assert [record.reason for record in records] == ["self_contradiction", "accepted_invalid"]
    assert records[0].kind == "metadata"


def test_refused_derive_creation_detected_before_cleanup() -> None:
    """A labelled survivor is found before the dirty handle is destroyed (S6)."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT], refusal_creates_child=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "self_contradiction"]
    assert records[1].kind == "lifecycle"
    children = [h for h in fake.created if fake.objects[h].role == "child"]
    assert children, "the fake must create the labelled child on refusal"
    assert all(h in fake.destroyed for h in children)


def test_permitted_refusal_creation_detected() -> None:
    """A refused permitted derive must also create no labelled object (S6)."""
    fake = _ByteKdfFake(derive_script=[_CLEAN_REJECT], refusal_creates_child=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[1], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "self_contradiction"]
    assert records[1].kind == "lifecycle"


def test_permitted_refusal_search_refused_xfails_effect() -> None:
    """A refused label search after a permitted refusal voids the effect (S6)."""
    fake = _ByteKdfFake(derive_script=[_CLEAN_REJECT], find_mode="refuse")
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[1], "both", "matching")
    record = _assert_xfail_record("not_operational")
    assert "search" in record.label.lower()


@pytest.mark.parametrize("seal", ["sensitive_only", "unextractable_only"])
def test_matching_strengthened_child_fails_template_contract(seal: str) -> None:
    """A matching child sealed harder than requested fails exactness (S7)."""
    fake = _ByteKdfFake(derive_mode="accept_sealed")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], seal, "matching")
    _assert_fail_record("accepted_invalid", "metadata")


def test_matching_weakened_child_fails_policy() -> None:
    """A matching child weakened below the request fails protection (S7)."""
    fake = _ByteKdfFake(derive_mode="strip")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.operation == "C_DeriveKey"


def test_malformed_source_history_recorded_and_partial_check_runs() -> None:
    """A malformed source ALWAYS is recorded; the NEVER leg still runs (S8)."""
    fake = _ByteKdfFake(source_malformed_always=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert len(records) == 1, [record.summary for record in records]
    assert records[0].reason == "not_operational"
    assert records[0].outcome == "xfail"
    assert "malformed" in records[0].summary.lower()


def test_malformed_source_history_provable_component_contradiction_fails() -> None:
    """The provable NEVER leg fails even when ALWAYS is malformed (S8)."""
    fake = _ByteKdfFake(source_malformed_always=True, history_mode="fabricate")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "sensitive_only", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "self_contradiction"]
    assert records[1].kind == "metadata"


def test_source_gen_undefined_rv_fails_metadata() -> None:
    """An undefined source-generation RV fails the RV contract (S9)."""
    fake = _ByteKdfFake(gen_script=[_UNDEFINED_RV])
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_source_readback_undefined_rv_fails_metadata() -> None:
    """An undefined source-readback RV fails the RV contract (S9)."""
    fake = _ByteKdfFake(source_raise_rv=_UNDEFINED_RV)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_child_history_readback_undefined_rv_fails_metadata() -> None:
    """An undefined child-history readback RV fails the RV contract (S9)."""
    fake = _ByteKdfFake(history_raise_rv=_UNDEFINED_RV)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_wrap_setup_undefined_rv_fails_metadata() -> None:
    """An undefined wrap-setup RV fails the RV contract (S9)."""
    fake = _ByteKdfFake(gen_script=[_OK, _UNDEFINED_RV])
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    _assert_fail_record("self_contradiction", "metadata")


def test_find_undefined_rv_fails_metadata() -> None:
    """An undefined label-search RV fails the RV contract (S9)."""
    fake = _ByteKdfFake(
        derive_script=[_TEMPLATE_INCONSISTENT],
        find_mode="refuse",
        find_refuse_rv=_UNDEFINED_RV,
    )
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    _assert_fail_record("self_contradiction", "metadata")


def test_short_unsealed_import_undefined_rv_fails_metadata() -> None:
    """An undefined KAT-import RV fails the RV contract (S9)."""
    fake = _ByteKdfFake(create_mode="refuse", create_refuse_rv=_UNDEFINED_RV)
    _run_must_fail(_short_unsealed, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_downgrade_always_refusing_token_xfails_vacuous() -> None:
    """A token refusing everything cannot pass downgrade legs (S10)."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT, _TEMPLATE_INCONSISTENT])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    record = _assert_xfail_record("not_operational")
    assert "vacuous" in record.summary.lower()
    assert len(fake.derive_calls) == 2, "downgrade plus the operability probe"


def test_downgrade_reuses_matching_operability_control() -> None:
    """A matching xfail establishes the control; downgrade reuses it (S10)."""
    fake = _ByteKdfFake(derive_script=[_CLEAN_REJECT, _TEMPLATE_INCONSISTENT])
    rs = _rs(fake)
    assert_xfails(_single, rs, _SINGLE_MECHS[0], "both", "matching")
    assert_xfails(_single, rs, _SINGLE_MECHS[0], "both", "downgrade")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert "vacuous" in records[1].summary.lower()
    assert len(fake.derive_calls) == 2, "no extra probe derive on a cache hit"


def test_downgrade_probe_undefined_rv_passes_standing() -> None:
    """An undefined probe RV never masks the downgrade pass (S10)."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT, _UNDEFINED_RV])
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    assert C.get_records() == []
    assert len(fake.derive_calls) == 2, "downgrade plus the operability probe"


def test_downgrade_probe_zero_handle_passes_standing() -> None:
    """A zero-handle probe never masks the downgrade pass (S10)."""
    fake = _ByteKdfFake(derive_script=[_TEMPLATE_INCONSISTENT, _OK])
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    assert C.get_records() == []
    assert len(fake.derive_calls) == 2, "downgrade plus the operability probe"


def test_source_gen_capability_missing_skips() -> None:
    """Legs skip when GENERIC_SECRET_KEY_GEN is not advertised (M1)."""
    assert_skips(
        _single,
        _rs(_ByteKdfFake(), mechs={"XOR_BASE_AND_DATA"}),
        _SINGLE_MECHS[2],
        "both",
        "matching",
    )
    assert_skips(
        _basekey,
        _rs(_ByteKdfFake(), mechs={"CONCATENATE_BASE_AND_KEY"}),
        "both",
        "matching",
        "both",
    )
    assert_skips(_hkdf, _rs(_ByteKdfFake(), mechs={"HKDF_DERIVE"}), "matching")
    assert_skips(_short_sealed, _rs(_ByteKdfFake(), mechs={"EXTRACT_KEY_FROM_KEY"}))


def test_wrap_aes_keygen_missing_skips_wrap_leg() -> None:
    """No AES_KEY_GEN skips only the wrap leg; flags still verify (M1)."""
    mechs = {"CONCATENATE_BASE_AND_DATA", "GENERIC_SECRET_KEY_GEN", "AES_KEY_WRAP"}
    fake = _ByteKdfFake()
    _single(_rs(fake, mechs=mechs), _SINGLE_MECHS[0], "both", "matching")
    assert C.get_records() == []
    assert fake.wrap_calls == []


def test_advertised_gen_mechanism_invalid_still_xfails() -> None:
    """An advertised keygen refusing MECHANISM_INVALID xfails setup (M1)."""
    fake = _ByteKdfFake(gen_script=[_MECHANISM_INVALID])
    assert_xfails(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_MECHANISM_INVALID"


# ---------------------------------------------------------------------------
# Fix round 1b: MISSING_ATTRIBUTE routing at the history readback sites (G1).
# ---------------------------------------------------------------------------


def test_source_histories_omitted_without_ckr_fails_metadata() -> None:
    """A source history omitted with no refusal CKR fails the premise (G1).

    CKR_OK plus CK_UNAVAILABLE_INFORMATION with no refusal is an omission,
    not a clean operational refusal: the history premise is unprovable
    through hiding (judgment (c)). The fail is immediate: the NEVER
    readback never runs.
    """
    fake = _ByteKdfFake(source_omit_histories=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "self_contradiction"]
    assert [record.outcome for record in records] == ["xfail", "fail"]
    assert records[1].kind == "metadata"
    assert "omitted" in records[1].summary.lower()
    assert "ALWAYS_SENSITIVE" in records[1].summary


def test_omitted_second_source_history_fails_metadata() -> None:
    """An omitted source NEVER fails after a healthy ALWAYS read (G1)."""
    fake = _ByteKdfFake(source_omit_histories=True, hide_second_only=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "self_contradiction"]
    assert records[1].kind == "metadata"
    assert "omitted" in records[1].summary.lower()
    assert "NEVER_EXTRACTABLE" in records[1].summary


def test_hidden_first_source_history_skips_visibly() -> None:
    """A refused source ALWAYS alone skips only that component (G1).

    Operational routing pin: a defined clean refusal
    (CKR_ATTRIBUTE_TYPE_INVALID) stays not_operational xfail evidence;
    the healthy NEVER leg still runs.
    """
    fake = _ByteKdfFake(source_hide_histories=True, history_first_only=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("not_operational")
    assert "history" in record.label.lower()


def test_child_histories_omitted_without_ckr_fails_metadata() -> None:
    """Child histories omitted with no refusal CKR fail the check (G1)."""
    fake = _ByteKdfFake(history_omit=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == [
        "honest_deviation",
        "honest_deviation",
        "self_contradiction",
        "self_contradiction",
    ]
    assert [record.outcome for record in records] == ["xfail", "xfail", "fail", "fail"]
    assert all(record.kind == "metadata" for record in records[2:])
    assert all("omitted" in record.summary.lower() for record in records[2:])


def test_omitted_second_child_history_fails_metadata() -> None:
    """An omitted child NEVER fails after a healthy ALWAYS check (G1)."""
    fake = _ByteKdfFake(history_omit=True, hide_second_only=True)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "self_contradiction"]
    assert records[1].kind == "metadata"
    assert "omitted" in records[1].summary.lower()
    assert "NEVER_EXTRACTABLE" in records[1].summary


def test_hidden_first_child_history_skips_visibly() -> None:
    """A refused child ALWAYS alone skips only that component (G1)."""
    fake = _ByteKdfFake(history_hide=True, history_first_only=True)
    _single(_rs(fake), _SINGLE_MECHS[0], "both", "matching")
    record = _assert_xfail_record("honest_deviation")
    assert "history" in record.label.lower()


def test_omitted_child_history_sibling_contradiction_still_checked() -> None:
    """An omitted ALWAYS does not discard the provable NEVER check (G1/S8).

    The fabricated NEVER contradicts its expectation while ALWAYS is
    omitted: both the omission and the contradiction are recorded, and the
    demonstrated contradiction is the raised verdict.
    """
    fake = _ByteKdfFake(history_omit=True, history_first_only=True, history_mode="fabricate")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "sensitive_only", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == [
        "honest_deviation",
        "self_contradiction",
        "self_contradiction",
    ]
    assert "ALWAYS_SENSITIVE" in records[1].summary
    assert "NEVER_EXTRACTABLE" in records[2].summary


# ---------------------------------------------------------------------------
# Fix round 2: re-review findings T1–T6.
# ---------------------------------------------------------------------------


def test_accepted_downgrade_flag_error_still_fails_accepted_invalid() -> None:
    """An accepted downgrade fails even when its flags are unreadable (T1).

    Acceptance of the forbidden template is established independently of
    flag readback: the clean flag-read error is collected as xfail
    evidence and the fallback template-contract failure is still emitted.
    """
    fake = _ByteKdfFake(derive_mode="accept_sealed", flag_raise_rv=_HOST_MEMORY)
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "accepted_invalid"]
    assert [record.outcome for record in records] == ["xfail", "fail"]
    assert records[1].kind == "metadata"


@pytest.mark.parametrize(
    ("rv", "name"),
    [(_HOST_MEMORY, "CKR_HOST_MEMORY"), (_CLEAN_REJECT, "CKR_FUNCTION_FAILED")],
    ids=["host_memory", "function_failed"],
)
def test_hkdf_readable_value_operational_error_xfails(rv: int, name: str) -> None:
    """A defined whole-call read error on a readable child xfails (T2).

    The operational error demonstrates no protection contradiction and is
    explicitly permitted for C_GetAttributeValue (§5.7.5): the original RV
    is preserved as not_operational evidence.
    """
    fake = _ByteKdfFake(derive_mode="forward", value_raise_rv=rv)
    assert_xfails(_hkdf, _rs(fake), "downgrade")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == name


def test_hkdf_readable_value_undefined_rv_fails_metadata() -> None:
    """An undefined read RV on a readable child still fails the RV contract (T2)."""
    fake = _ByteKdfFake(derive_mode="forward", value_raise_rv=_UNDEFINED_RV)
    _run_must_fail(_hkdf, _rs(fake), "downgrade")
    _assert_fail_record("self_contradiction", "metadata")


def test_permitted_undefined_derive_with_refused_search_fails_derive_rv() -> None:
    """An undefined derive RV is validated before the no-object search (T3).

    The clean search refusal is collected as xfail evidence, but the
    undefined C_DeriveKey RV is the raised fail verdict.
    """
    fake = _ByteKdfFake(derive_script=[_UNDEFINED_RV], find_mode="refuse")
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "matching")
    records = C.get_records()
    assert [record.reason for record in records] == ["self_contradiction", "not_operational"]
    assert [record.outcome for record in records] == ["fail", "xfail"]
    assert records[0].kind == "metadata"
    assert "search" in records[1].label.lower()


def test_short_unsealed_undefined_derive_with_refused_search_fails_derive_rv() -> None:
    """The short-child control also validates the derive RV first (T3-partial/U1).

    Same evidence-preservation contract as the matching row: the clean
    search refusal is collected as xfail evidence, but the undefined
    C_DeriveKey RV is the raised fail verdict, and the base is cleaned up.
    """
    fake = _ByteKdfFake(derive_script=[_UNDEFINED_RV], find_mode="refuse")
    _run_must_fail(_short_unsealed, _rs(fake))
    records = C.get_records()
    assert [record.reason for record in records] == ["self_contradiction", "not_operational"]
    assert [record.outcome for record in records] == ["fail", "xfail"]
    assert records[0].kind == "metadata"
    assert "search" in records[1].label.lower()
    _assert_cleaned_up(fake)


def test_short_unsealed_undefined_derive_dirty_handle_destroyed() -> None:
    """A dirty out-handle on the short-child path is destroyed, not leaked (U1)."""
    fake = _ByteKdfFake(derive_script=[_UNDEFINED_RV], find_mode="refuse", dirty_handle=True)
    _run_must_fail(_short_unsealed, _rs(fake))
    records = C.get_records()
    assert [record.reason for record in records] == [
        "honest_deviation",
        "self_contradiction",
        "not_operational",
    ]
    assert [record.outcome for record in records] == ["xfail", "fail", "xfail"]
    assert 999 in fake.destroyed
    _assert_cleaned_up(fake)


def test_refused_control_creation_detected_before_cleanup() -> None:
    """A refused inline control proves its no-object effect before cleanup (T4).

    The primary downgrade is cleanly rejected; the matching control then
    creates its labelled child while refusing. The control's
    ':operability' label is searched before its handle is destroyed,
    preserving the lifecycle contradiction.
    """
    fake = _ByteKdfFake(
        derive_script=[_TEMPLATE_INCONSISTENT, _CLEAN_REJECT],
        control_creates_on_refusal=True,
    )
    _run_must_fail(_single, _rs(fake), _SINGLE_MECHS[0], "both", "downgrade")
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "self_contradiction"]
    assert records[1].kind == "lifecycle"
    assert ":operability" in records[1].label


def test_hidden_source_histories_provable_child_contradiction_fails() -> None:
    """Unknown sources do not suppress a provable child-history failure (T5).

    A false factor establishes a false conjunction despite unknown
    factors: the unsealed child's fabricated histories must both be false
    regardless of the unavailable source histories.
    """
    fake = _ByteKdfFake(source_hide_histories=True, history_mode="fabricate")
    _run_must_fail(_hkdf, _rs(fake), "downgrade")
    records = C.get_records()
    assert [record.reason for record in records] == [
        "not_operational",
        "not_operational",
        "self_contradiction",
    ]
    assert records[2].kind == "metadata"


def test_two_source_false_factor_short_circuits_unknown() -> None:
    """A false child factor proves NEVER despite two unknown sources (T5).

    Both source histories are unavailable, but the extractable child's
    NEVER conjunction is already false; only the provable NEVER component
    is compared while ALWAYS stays skipped.
    """
    fake = _ByteKdfFake(source_hide_histories=True, history_mode="fabricate")
    _run_must_fail(_basekey, _rs(fake), "sensitive_only", "matching", "base")
    records = C.get_records()
    assert [record.reason for record in records] == [
        "not_operational",
        "not_operational",
        "not_operational",
        "not_operational",
        "self_contradiction",
    ]
    assert records[4].kind == "metadata"
    assert "NEVER_EXTRACTABLE" in records[4].summary
    assert "ALWAYS_SENSITIVE" not in records[4].summary


def test_hkdf_matching_weakened_child_fails_policy() -> None:
    """A weakened explicit HKDF matching child fails protection (T6).

    Absence of an inheritance floor does not remove the explicit request:
    weakening below it fails as policy, exactly as on byte rows.
    """
    fake = _ByteKdfFake(derive_mode="strip")
    _run_must_fail(_hkdf, _rs(fake), "matching")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.operation == "C_DeriveKey"
