"""Contract for #72 readable-keypair templates.

ML-KEM helpers must not request CKA_SENSITIVE (the token chooses;
KEM legs never read the private value), while the RSA-OAEP helper
keeps its readable template and voids honestly when a module refuses
to make non-sensitive private keys.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.recipes import RSAUsage
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECAPSULATE,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    classification.clear()
    yield
    classification.clear()


def test_kem_helper_omits_sensitive_keeps_restrictive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test_kem helper: no SENSITIVE request; EXTRACTABLE/DECAPSULATE kept."""
    from pkcs11_check.testcases import test_kem as kem_mod

    seen: dict[str, Any] = {}

    def _capture(*args: Any, **kwargs: Any) -> tuple[int, int]:
        seen.update(kwargs)
        return (101, 102)

    monkeypatch.setattr(kem_mod, "gen_keypair", _capture)
    rs = SimpleNamespace(raw=object(), sh=1)
    assert kem_mod._generate_ml_kem_keypair(rs) == (101, 102)
    priv_attrs = seen["private_attrs"]
    assert CKA_SENSITIVE not in priv_attrs
    assert priv_attrs[CKA_EXTRACTABLE] is False
    assert priv_attrs[CKA_DECAPSULATE] is True


def test_ckr_kem_helper_omits_sensitive_keeps_restrictive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ckr KEM helper: no SENSITIVE attr; EXTRACTABLE/DECAPSULATE kept."""
    from pkcs11_check.testcases.ckr import test_ckr_kem as ckr_mod

    packed_seen: list[Any] = []

    def _capture(*packed: Any) -> Any:
        packed_seen.extend(packed)
        return SimpleNamespace(ptr=None, count=len(packed))

    class _Raw:
        def C_GenerateKeyPair(  # noqa: N802
            self,
            _sh: int,
            _mech: Any,
            _pub_tmpl: Any,
            _pub_count: int,
            _priv_tmpl: Any,
            _priv_count: int,
            pub_ptr: Any,
            priv_ptr: Any,
        ) -> int:
            ctypes.cast(pub_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 201
            ctypes.cast(priv_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 202
            return int(CKR_OK)

    monkeypatch.setattr(ckr_mod, "template", _capture)
    assert ckr_mod._generate_ml_kem_keypair(_Raw(), 1) == (201, 202)
    types = [int(item.attribute.type) for item in packed_seen]
    assert int(CKA_SENSITIVE) not in types
    assert int(CKA_EXTRACTABLE) in types
    assert int(CKA_DECAPSULATE) in types


class _GenStub:
    """Raw stub with a scripted C_GenerateKeyPair RV and stored flag readback."""

    def __init__(
        self,
        rv: int,
        *,
        stored: tuple[bool, bool] = (False, True),
        read_rv: int | None = None,
    ) -> None:
        self._rv = rv
        self._stored = stored
        self._read_rv = read_rv

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _pub_tmpl: Any,
        _pub_count: int,
        _priv_tmpl: Any,
        _priv_count: int,
        pub_ptr: Any,
        priv_ptr: Any,
    ) -> int:
        ctypes.cast(pub_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 301
        ctypes.cast(priv_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 302
        return self._rv

    def C_GetAttributeValue(self, _sh: int, _handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if self._read_rv is not None:
            return self._read_rv
        for i in range(int(count)):
            attr = int(tmpl[i].type)
            flag = self._stored[0] if attr == int(CKA_SENSITIVE) else self._stored[1]
            value = b"\x01" if flag else b"\x00"
            if tmpl[i].pValue is None:
                tmpl[i].ulValueLen = len(value)
            else:
                ctypes.memmove(tmpl[i].pValue, value, len(value))
                tmpl[i].ulValueLen = len(value)
        return int(CKR_OK)


def _gen_readable(rs_raw: Any, **kw: Any) -> Any:
    from pkcs11_check.testcases import test_crossverify_extended as xv_mod

    return xv_mod._gen_readable_rsa_or_xfail(
        SimpleNamespace(raw=rs_raw, sh=1), 2048, label="L", **kw
    )


def test_readable_rsa_ok_returns_handles() -> None:
    assert _gen_readable(_GenStub(int(CKR_OK))) == (301, 302)


def test_readable_rsa_template_inconsistent_xfails_named() -> None:
    from _pytest.outcomes import XFailed

    with pytest.raises(XFailed):
        _gen_readable(_GenStub(int(CKR_TEMPLATE_INCONSISTENT)))
    (record,) = classification.get_records()
    assert record.reason == "not_operational"
    assert "decrypt-purpose readable private-key template" in (record.summary or "")
    assert "CKR_TEMPLATE_INCONSISTENT" in (record.summary or "")
    assert "does not make" not in (record.summary or "")


def test_readable_rsa_read_only_xfails_named() -> None:
    from _pytest.outcomes import XFailed

    with pytest.raises(XFailed):
        _gen_readable(_GenStub(int(CKR_ATTRIBUTE_READ_ONLY)))
    (record,) = classification.get_records()
    assert record.reason == "not_operational"
    assert "decrypt-purpose readable private-key template" in (record.summary or "")
    assert "CKR_ATTRIBUTE_READ_ONLY" in (record.summary or "")
    assert "does not make" not in (record.summary or "")


def test_readable_rsa_other_refusal_reraises() -> None:
    with pytest.raises(CkrAssertionError):
        _gen_readable(_GenStub(int(CKR_FUNCTION_FAILED)))


def test_readable_rsa_keeps_readable_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The helper still asks SENSITIVE False + EXTRACTABLE True (needed to read)."""
    from pkcs11_check.raw.recipes import AttrReadResult
    from pkcs11_check.testcases import test_crossverify_extended as xv_mod

    seen: dict[str, Any] = {}

    def _capture(*args: Any, **kwargs: Any) -> tuple[int, int]:
        seen.update(kwargs)
        return (301, 302)

    def _flags(*args: Any) -> Any:
        result = AttrReadResult()
        result[int(CKA_SENSITIVE)] = False
        result[int(CKA_EXTRACTABLE)] = True
        return result

    monkeypatch.setattr(xv_mod, "gen_rsa_keypair", _capture)
    monkeypatch.setattr(xv_mod, "read_attributes", _flags)
    rs = SimpleNamespace(raw=object(), sh=1)
    assert xv_mod._gen_readable_rsa_or_xfail(rs, 2048, label="L") == (301, 302)
    assert seen["private_attrs"] == {CKA_SENSITIVE: False, CKA_EXTRACTABLE: True}
    assert seen["usage"] == RSAUsage.DECRYPT


def test_readable_rsa_normalized_flags_void() -> None:
    """C5: stored flags differing from the readable request void the leg."""
    from _pytest.outcomes import XFailed

    with pytest.raises(XFailed):
        _gen_readable(_GenStub(int(CKR_OK), stored=(True, False)))
    (record,) = classification.get_records()
    assert record.reason == "not_operational"
    assert "differ from the readable request" in (record.summary or "")


def test_readable_rsa_unreadable_flags_void() -> None:
    """C5: unreadable stored flags void the leg with the RV named."""
    from _pytest.outcomes import XFailed

    with pytest.raises(XFailed):
        _gen_readable(_GenStub(int(CKR_OK), read_rv=int(CKR_DEVICE_ERROR)))
    (record,) = classification.get_records()
    assert record.reason == "not_operational"
    assert "CKR_DEVICE_ERROR" in (record.summary or "")
