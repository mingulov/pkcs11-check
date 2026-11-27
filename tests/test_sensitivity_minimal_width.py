"""Minimal-width differential verdict pins (no provider needed).

A provider may return RSA integers in minimal width (leading zeros
stripped). The disclosure differential must never misclassify such
reads: the positional fragment matcher cannot see the shifted value,
so the length gate fail-closes to inconclusive instead of reaching
a verdict on unmatched fragments. These tests drive
_matrix_disclosure_verdict with a scripted fake session and assert
the verdict -- not the matcher output.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pkcs11_check.testcases.test_sensitivity as sens
from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKA_MODULUS, CKR_OK
from pkcs11_check.testcases import _import_negotiation as negot


class _MinimalWidthFakeRaw:
    """Fake PKCS#11 binding serving minimal-width reads.

    C_CreateObject mints handles; C_GetAttributeValue serves the
    scripted per-handle bytes with truthful short lengths;
    C_DestroyObject succeeds. Everything else is out of contract
    (AttributeError surfaces loudly).
    """

    def __init__(self, reads: dict[int, bytes]) -> None:
        self._reads = reads
        self._next_handle = 1001
        self.calls: list[str] = []

    def C_CreateObject(  # noqa: N802
        self, _sh: int, _tmpl: Any, _count: int, handle_ptr: Any
    ) -> int:
        handle = self._next_handle
        self._next_handle += 1
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = handle
        self.calls.append("create")
        return int(CKR_OK)

    def C_GetAttributeValue(  # noqa: N802
        self, _sh: int, handle: int, tmpl: Any, count: int
    ) -> Any:
        assert count == 1, "single-attribute reads only"
        assert handle in self._reads, f"unexpected handle {handle}"
        payload = self._reads[handle]
        addr = int(tmpl[0].pValue) if not isinstance(tmpl[0].pValue, int) else tmpl[0].pValue
        ctypes.memmove(addr, payload, len(payload))
        tmpl[0].ulValueLen = len(payload)
        self.calls.append(f"read:{len(payload)}")
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: int, _handle: int) -> int:  # noqa: N802
        self.calls.append("destroy")
        return int(CKR_OK)


def _rsa_family() -> Any:
    for family in sens._MATRIX_FAMILIES:
        if family.family == "rsa":
            return family
    raise AssertionError("no rsa matrix family")


def _alt_components_fixed() -> dict[str, bytes]:
    # Fixed alternate material with leading zeros (deterministic: no
    # real RSA generation, no 1/256 flake on the strip shape).
    return {
        "modulus": b"\x00" * 4 + bytes((i * 7 + 3) % 251 + 1 for i in range(252)),
        "public_exponent": b"\x01\x00\x01",
        "private_exponent": b"\x02" * 256,
        "prime_1": b"\x03" * 128,
        "prime_2": b"\x04" * 128,
        "exponent_1": b"\x05" * 128,
        "exponent_2": b"\x06" * 128,
        "coefficient": b"\x07" * 128,
    }


def test_minimal_width_refused_read_stays_inconclusive(monkeypatch: Any) -> None:
    """Minimal-width bytes never misclassify as independent disclosure."""
    secret = b"\x00" * 8 + bytes((i * 13 + 5) % 251 + 1 for i in range(248))
    assert len(secret) == 256
    minimal = secret.lstrip(b"\x00")
    assert 0 < len(minimal) < len(secret), "strip shape premise"
    cap = len(secret)
    observed = minimal + sens._matrix_sentinel_block(cap - len(minimal))
    fragment = sens._matrix_fragment(secret, observed)
    assert fragment is None, "positional miss is the premise under test"

    comp = _alt_components_fixed()
    monkeypatch.setattr(sens, "_matrix_rsa_components", lambda: comp)
    alt_secret = comp["modulus"]
    assert len(alt_secret.lstrip(b"\x00")) < len(alt_secret), "alt strip shape premise"
    winners = dict(negot._IMPORT_SHAPE_WINNERS)
    try:
        # The fake serves the stripped value; the buffer tail stays
        # sentinel because the provider only wrote the short bytes.
        # _matrix_data_read returns the full cap buffer.
        fake = _MinimalWidthFakeRaw({1001: alt_secret.lstrip(b"\x00")})
        rs = SimpleNamespace(raw=fake, sh=7)
        verdict = sens._matrix_disclosure_verdict(
            rs=rs,
            family=_rsa_family(),
            creation="import",
            sensitive=False,
            extractable=True,
            attr=int(CKA_MODULUS),
            secret=secret,
            observed=observed,
            fragment=fragment,
            shape="single",
            members=(),
            purpose="minimal-width differential pin",
            label="minimal-width",
            records=[],
            sealed_protected=False,
        )
    finally:
        negot._IMPORT_SHAPE_WINNERS.clear()
        negot._IMPORT_SHAPE_WINNERS.update(winners)
    assert verdict == "inconclusive"
    assert fake.calls[0] == "create", "alternate key imported (not setup-failed)"
    short = len(alt_secret.lstrip(b"\x00"))
    assert f"read:{short}" in fake.calls, "short alternate read reached the gate"
