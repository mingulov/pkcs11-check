"""QC8c contracts (#61.3): DES-family parity on byte/digest derives.

Drives ``TestDerivedDesParity`` in ``pkcs11_check.testcases.test_misc_kdf``
against a scriptable raw fake. Only ``import_secret_key_negotiated`` is
monkeypatched; derive, readback and the ECB KAT run against the fake at
the raw layer. The generic-secret twin is a control; expected bytes are
computed from the fake's actual stored inputs and mech params.
"""

from __future__ import annotations

import ctypes
import hashlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CK_KEY_DERIVATION_STRING_DATA,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_CDMF,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_GENERIC_SECRET,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_CONCATENATE_BASE_AND_KEY,
    CKM_CONCATENATE_DATA_AND_BASE,
    CKM_DES3_ECB,
    CKM_DES_ECB,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_HKDF_DERIVE,
    CKM_SHA1_KEY_DERIVATION,
    CKM_XOR_BASE_AND_DATA,
    CKR_FUNCTION_FAILED,
    CKR_OK,
)
from pkcs11_check.testcases import test_misc_kdf as tmisc

_OK = int(CKR_OK)
_UNDEFINED = 0x12345678
_DES_TYPES = {int(CKK_DES), int(CKK_DES2), int(CKK_DES3), int(CKK_CDMF)}
_BAK = int(CKM_CONCATENATE_BASE_AND_KEY)
_BAD = int(CKM_CONCATENATE_BASE_AND_DATA)
_DAB = int(CKM_CONCATENATE_DATA_AND_BASE)
_XOR = int(CKM_XOR_BASE_AND_DATA)
_EXT = int(CKM_EXTRACT_KEY_FROM_KEY)
_SHA1 = int(CKM_SHA1_KEY_DERIVATION)
_MECHS = [
    "CKM_CONCATENATE_BASE_AND_KEY",
    "CKM_CONCATENATE_BASE_AND_DATA",
    "CKM_CONCATENATE_DATA_AND_BASE",
    "CKM_XOR_BASE_AND_DATA",
    "CKM_EXTRACT_KEY_FROM_KEY",
]


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    classification.clear()
    yield
    classification.clear()


def _parity_adjust(raw: bytes) -> bytes:
    return bytes(b if b.bit_count() % 2 == 1 else b ^ 0x01 for b in raw)


def _fill(out: Any, value: int, ctype: Any = CK_ULONG) -> None:
    ctypes.cast(out, ctypes.POINTER(ctype)).contents.value = value


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    decoded: dict[int, bytes] = {}
    for i in range(int(count)):
        alen = int(tmpl[i].ulValueLen)
        addr = tmpl[i].pValue
        decoded[int(tmpl[i].type)] = (
            bytes(ctypes.string_at(addr, alen)) if addr and alen > 0 else b""
        )
    return decoded


def _ulong(raw: bytes) -> int:
    return int.from_bytes(raw, sys.byteorder)


def _mech_parts(mech: Any) -> tuple[int, int | None, bytes | None]:
    ck = mech._obj
    mech_id = int(ck.mechanism)
    addr = ck.pParameter
    plen = int(ck.ulParameterLen)
    if not addr or plen == 0:
        return mech_id, None, None
    if plen == ctypes.sizeof(CK_ULONG):
        return mech_id, int.from_bytes(ctypes.string_at(addr, plen), sys.byteorder), None
    if plen == ctypes.sizeof(CK_KEY_DERIVATION_STRING_DATA):
        struct = ctypes.cast(addr, ctypes.POINTER(CK_KEY_DERIVATION_STRING_DATA)).contents
        data = bytes(ctypes.string_at(struct.pData, int(struct.ulLen)))
        return mech_id, None, data
    return mech_id, None, None


class _Fake:
    def __init__(self, *, mode: str = "healthy", derive_rv: int | None = None) -> None:
        self.mode = mode
        self.derive_rv = derive_rv
        self.values: dict[int, bytes] = {}
        self.created: list[int] = []
        self.destroyed: list[int] = []
        self.derive_calls: list[dict[str, Any]] = []
        self._next = 100
        self._enc_key: int = 0
        self.session = SimpleNamespace(raw=self, sh=1, has_mechanism=lambda _n: True)

    def _issue(self, value: bytes) -> int:
        handle = self._next
        self._next += 1
        self.values[handle] = value
        self.created.append(handle)
        return handle

    def import_secret(self, *_a: Any, **_k: Any) -> int:
        # import_secret_key_negotiated(rs, key_type, value, attrs=...)
        return self._issue(bytes(_a[2]))

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        return _OK

    def _raw_output(self, mech_id: int, base: int, param: int | None, data: bytes | None) -> bytes:
        base_value = self.values[int(base)]
        if mech_id == _BAK:
            assert param is not None
            return base_value + self.values[int(param)]
        if mech_id == _BAD:
            assert data is not None
            return base_value + data
        if mech_id == _DAB:
            assert data is not None
            return data + base_value
        if mech_id == _XOR:
            assert data is not None
            return bytes(a ^ b for a, b in zip(base_value, data, strict=True))
        if mech_id == _EXT:
            assert param is not None
            return base_value[param // 8 :]
        if mech_id == _SHA1:
            return hashlib.sha1(base_value, usedforsecurity=False).digest()
        raise AssertionError(f"unexpected derive mech {mech_id:#x}")

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, mech: Any, base: int, tmpl: Any, count: int, out: Any
    ) -> int:
        mech_id, param, data = _mech_parts(mech)
        attrs = _decode_template(tmpl, int(count))
        key_type = _ulong(attrs[int(CKA_KEY_TYPE)])
        length = _ulong(attrs[int(CKA_VALUE_LEN)])
        self.derive_calls.append({"mech": mech_id, "key_type": key_type, "len": length})
        if self.derive_rv is not None:
            _fill(out, 0, CK_OBJECT_HANDLE)
            return self.derive_rv
        raw = self._raw_output(mech_id, int(base), param, data)[:length]
        is_des = key_type in _DES_TYPES
        if self.mode == "raw_no_parity":
            value = raw
        elif self.mode == "generic_flipped":
            value = _parity_adjust(raw)
        elif self.mode == "wrong_odd":
            value = _parity_adjust(b"\x5a\xc3\x0f\x96" * 8)[:length]
        else:
            value = _parity_adjust(raw) if is_des else raw
        _fill(out, self._issue(value), CK_OBJECT_HANDLE)
        return _OK

    def C_GetAttributeValue(  # noqa: N802
        self, _sh: int, handle: int, tmpl: Any, count: int
    ) -> int:
        value = self.values[int(handle)]
        for i in range(int(count)):
            assert int(tmpl[i].type) == int(CKA_VALUE)
            if tmpl[i].pValue:
                ctypes.memmove(tmpl[i].pValue, value, min(len(value), int(tmpl[i].ulValueLen)))
            tmpl[i].ulValueLen = len(value)
        return _OK

    def C_EncryptInit(self, _sh: int, mech: Any, key: int) -> int:  # noqa: N802
        mech_id, _p, _d = _mech_parts(mech)
        assert mech_id in (int(CKM_DES_ECB), int(CKM_DES3_ECB))
        self._enc_key = int(key)
        return _OK

    def C_Encrypt(  # noqa: N802
        self, _sh: int, data: Any, data_len: int, out: Any, out_len: Any
    ) -> int:
        plain = bytes(ctypes.string_at(ctypes.addressof(data), int(data_len)))
        key = self.values[self._enc_key]
        effective = key * 3 if len(key) == 8 else key + key[:8] if len(key) == 16 else key
        enc = Cipher(algorithms.TripleDES(effective), modes.ECB()).encryptor()  # nosec B305
        ct = enc.update(plain) + enc.finalize()
        ctypes.memmove(out, ct, len(ct))
        _fill(out_len, len(ct))
        return _OK


def _run(mp: pytest.MonkeyPatch, fake: _Fake, mech: str, type_name: str) -> None:
    mp.setattr(tmisc, "import_secret_key_negotiated", fake.import_secret)
    tmisc.TestDerivedDesParity().test_byte_derive_des_parity(fake.session, mech, type_name)


def _run_sha1(mp: pytest.MonkeyPatch, fake: _Fake) -> None:
    mp.setattr(tmisc, "import_secret_key_negotiated", fake.import_secret)
    tmisc.TestDerivedDesParity().test_sha1_derive_des_parity(fake.session)


def _must_fail(fn: Any, *args: Any, **kw: Any) -> Any:
    with pytest.raises(Failed) as ei:
        fn(*args, **kw)
    assert not isinstance(ei.value, XFailed), f"expected fail, got xfail: {ei.value}"
    return classification.get_records()[-1]


def _cleaned(fake: _Fake) -> None:
    assert sorted(set(fake.destroyed)) == sorted(set(fake.created)), (
        fake.created,
        fake.destroyed,
    )


def test_concat_des_parity_adjusted_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Conformant control across all five byte mechanisms (DES + DES3)."""
    for mech in _MECHS:
        for type_name in ("DES", "DES3"):
            fake = _Fake()
            _run(monkeypatch, fake, mech, type_name)
            assert classification.get_records() == [], (mech, type_name)
            _cleaned(fake)
            classification.clear()


@pytest.mark.parametrize("type_name", ["DES2", "CDMF"])
def test_des2_cdmf_parity_adjusted_passes(monkeypatch: pytest.MonkeyPatch, type_name: str) -> None:
    fake = _Fake()
    _run(monkeypatch, fake, "CKM_XOR_BASE_AND_DATA", type_name)
    assert classification.get_records() == []
    _cleaned(fake)


def test_sha1_des_parity_adjusted_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake()
    _run_sha1(monkeypatch, fake)
    assert classification.get_records() == []
    _cleaned(fake)


def test_xor_des3_raw_bytes_without_parity_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake(mode="raw_no_parity")
    rec = _must_fail(_run, monkeypatch, fake, "CKM_XOR_BASE_AND_DATA", "DES3")
    assert rec.reason == "wrong_result"
    assert "parity" in rec.label.lower()
    _cleaned(fake)


def test_generic_secret_parity_flipped_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake(mode="generic_flipped")
    rec = _must_fail(_run, monkeypatch, fake, "CKM_CONCATENATE_BASE_AND_DATA", "DES")
    assert rec.reason == "wrong_result"
    assert "generic" in rec.label.lower()
    # The DES leg passed; the flipped generic twin is the failing leg.
    assert fake.derive_calls[-1]["key_type"] == int(CKK_GENERIC_SECRET)
    _cleaned(fake)


def test_wrong_material_with_odd_parity_fails_kat(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake(mode="wrong_odd")
    rec = _must_fail(_run, monkeypatch, fake, "CKM_CONCATENATE_DATA_AND_BASE", "DES3")
    assert rec.reason == "wrong_result"
    assert "parity" not in rec.label.lower()  # parity alone would have passed
    _cleaned(fake)


def test_sha1_des3_is_not_asserted(monkeypatch: pytest.MonkeyPatch) -> None:
    assert tmisc._DES_PARITY_SHA1_TYPES == ("DES",)
    fake = _Fake()
    _run_sha1(monkeypatch, fake)
    sha1_calls = [c for c in fake.derive_calls if c["mech"] == _SHA1]
    assert sha1_calls
    assert all(c["key_type"] != int(CKK_DES3) for c in sha1_calls)
    assert any(c["key_type"] == int(CKK_DES) for c in sha1_calls)


def test_hkdf_scope_control_unchanged_or_absent() -> None:
    """HKDF carries no pinned parity sentence: no HKDF DES-parity row exists."""
    assert "CKM_HKDF_DERIVE" not in tmisc._DES_PARITY_MECH_NAMES
    assert int(CKM_HKDF_DERIVE) not in {
        tmisc._BYTE_KDF_MECH_IDS[name] for name in tmisc._DES_PARITY_MECH_NAMES
    }
    assert not any("hkdf" in name.lower() for name in vars(tmisc.TestDerivedDesParity))


def test_des_child_clean_refusal_xfails_not_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake(derive_rv=int(CKR_FUNCTION_FAILED))
    with pytest.raises(XFailed):
        _run(monkeypatch, fake, "CKM_XOR_BASE_AND_DATA", "DES")
    rec = classification.get_records()[-1]
    assert rec.reason == "not_operational"
    assert rec.actual_ckr == "CKR_FUNCTION_FAILED"


def test_des_child_undefined_refusal_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake(derive_rv=_UNDEFINED)
    rec = _must_fail(_run, monkeypatch, fake, "CKM_XOR_BASE_AND_DATA", "DES")
    assert rec.kind == "metadata"


def test_even_parity_premise_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake()
    all_odd = _parity_adjust(bytes(range(32)))
    assert all(b.bit_count() % 2 == 1 for b in all_odd)
    monkeypatch.setattr(
        tmisc,
        "_des_parity_materials",
        lambda _mech, n: (all_odd[:n], b"", all_odd[:n]),
    )
    rec = _must_fail(_run, monkeypatch, fake, "CKM_XOR_BASE_AND_DATA", "DES")
    assert rec.reason == "harness_error"
    assert fake.derive_calls == []  # never counted as provider evidence
