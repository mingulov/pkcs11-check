"""Direct child tests for the field-size probes (valid premises, honest backing).

Each test drives one ``field_size`` sub-probe in-process with a fake ``raw``
module and asserts on the provider call shape (mechanism, template, cleanup),
the stdout evidence protocol, and the honeypot minimum-size contract.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_PRIME_BITS,
    CKA_VALUE_LEN,
    CKM_DH_PKCS_PARAMETER_GEN,
    CKM_DSA_PARAMETER_GEN,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._probes import field_size as field_size_probe
from pkcs11_check.testcases._probes.honeypot import HoneypotUnavailable
from pkcs11_check.testcases.security._boundary_values import TRUNCATION_LOW8


def _ctx(raw: object) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=9)


def _mech_id(mech: object) -> int:
    return int(ctypes.cast(mech, ctypes.POINTER(CK_MECHANISM)).contents.mechanism)


def _set_handle(out: object, value: int) -> None:
    ctypes.cast(out, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = value


def _template_pairs(tmpl: object, count: int) -> list[tuple[int, int, int]]:
    """Decode ``(type, ulValueLen, scalar)`` for ulong/bool template entries."""
    arr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE))
    pairs: list[tuple[int, int, int]] = []
    for idx in range(count):
        attr = arr[idx]
        scalar = ctypes.cast(attr.pValue, ctypes.POINTER(CK_ULONG)).contents.value
        pairs.append((int(attr.type), int(attr.ulValueLen), int(scalar)))
    return pairs


class _ParamGenRaw:
    """Fake proving C_GenerateKey domain-parameter generation premises."""

    def __init__(self) -> None:
        self.keygen_calls: list[tuple[int, list[tuple[int, int, int]]]] = []
        self.keypair_calls: int = 0
        self.destroyed: list[int] = []

    def C_GenerateKey(  # noqa: N802
        self, _session: int, mech: object, tmpl: object, count: int, out: object
    ) -> int:
        self.keygen_calls.append((_mech_id(mech), _template_pairs(tmpl, count)))
        _set_handle(out, 77)
        return int(CKR_OK)

    def C_GenerateKeyPair(  # noqa: N802
        self, *_args: object, **_kwargs: object
    ) -> int:
        self.keypair_calls += 1
        return int(CKR_GENERAL_ERROR)

    def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        return int(CKR_OK)


@pytest.mark.parametrize(
    ("which", "mechanism"),
    [
        ("dh_prime_bits", int(CKM_DH_PKCS_PARAMETER_GEN)),
        ("dsa_prime_bits", int(CKM_DSA_PARAMETER_GEN)),
    ],
)
def test_prime_bits_child_generates_domain_parameters(
    which: str, mechanism: int, capsys: pytest.CaptureFixture[str]
) -> None:
    """DH/DSA children call C_GenerateKey with the parameter-gen mechanism.

    CKA_PRIME_BITS applies to CKM_*_PARAMETER_GEN; the incomplete
    C_GenerateKeyPair templates prove no field-width property and must not be
    used. The returned domain-parameter object must be destroyed.
    """
    raw = _ParamGenRaw()
    prime_bits = (1 << 32) + 1024
    run = getattr(field_size_probe, f"_run_{which}")
    run(_ctx(raw), {"prime_bits": prime_bits})

    assert raw.keypair_calls == 0
    assert len(raw.keygen_calls) == 1
    used_mech, attrs = raw.keygen_calls[0]
    assert used_mech == mechanism
    assert (int(CKA_PRIME_BITS), ctypes.sizeof(CK_ULONG), prime_bits) in attrs
    assert raw.destroyed == [77]
    out = capsys.readouterr().out
    assert out.count("TARGET_RV:") == 1
    assert f"TARGET_RV:{int(CKR_OK):#010x}" in out


class _AesGenRaw:
    """Fake AES keygen with a controllable CKA_VALUE_LEN readback."""

    def __init__(self, *, readback: int | None) -> None:
        self.readback = readback
        self.value_len_seen: list[int] = []
        self.destroyed: list[int] = []

    def C_GenerateKey(  # noqa: N802
        self, _session: int, _mech: object, tmpl: object, count: int, out: object
    ) -> int:
        for attr_type, _ln, scalar in _template_pairs(tmpl, count):
            if attr_type == int(CKA_VALUE_LEN):
                self.value_len_seen.append(scalar)
        _set_handle(out, 55)
        return int(CKR_OK)

    def C_GetAttributeValue(  # noqa: N802
        self, _session: int, _handle: int, tmpl: object, _count: int
    ) -> int:
        if self.readback is None:
            return int(CKR_ATTRIBUTE_SENSITIVE)
        attr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)).contents
        ctypes.cast(attr.pValue, ctypes.POINTER(CK_ULONG)).contents.value = self.readback
        return int(CKR_OK)

    def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        return int(CKR_OK)


def test_aes_child_emits_value_len_readback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """On CKR_OK the AES child reads back CKA_VALUE_LEN for the oracle."""
    raw = _AesGenRaw(readback=16)
    field_size_probe._run_aes_value_len(_ctx(raw), {"value_len": (1 << 32) + 16})

    assert raw.value_len_seen == [(1 << 32) + 16]
    assert raw.destroyed == [55]
    out = capsys.readouterr().out
    assert out.count("TARGET_RV:") == 1
    assert "VALUE_LEN:16" in out


def test_aes_child_reports_unavailable_readback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed CKA_VALUE_LEN readback is explicit, not silent."""
    raw = _AesGenRaw(readback=None)
    field_size_probe._run_aes_value_len(_ctx(raw), {"value_len": (1 << 32) + 16})

    assert raw.destroyed == [55]
    out = capsys.readouterr().out
    assert "VALUE_LEN:unavailable" in out


class _FindRaw:
    """Fake C_FindObjects with controllable outcome and handle writes."""

    def __init__(self, *, target_rv: int, final_rv: int, handles: int = 0) -> None:
        self.target_rv = target_rv
        self.final_rv = final_rv
        self.handles = handles
        self.max_count_seen: list[int] = []
        self.buffer_seen: list[int] = []
        self.final_calls: int = 0

    def C_FindObjectsInit(self, _session: int, _tmpl: object, _count: int) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_FindObjects(  # noqa: N802
        self, _session: int, buf: object, max_count: int, count_out: object
    ) -> int:
        self.max_count_seen.append(int(max_count))
        self.buffer_seen.append(ctypes.cast(buf, ctypes.c_void_p).value or 0)
        arr = ctypes.cast(buf, ctypes.POINTER(CK_OBJECT_HANDLE))
        for idx in range(self.handles):
            arr[idx] = 1000 + idx
        ctypes.cast(count_out, ctypes.POINTER(CK_ULONG)).contents.value = self.handles
        return int(self.target_rv)

    def C_FindObjectsFinal(self, _session: int) -> int:  # noqa: N802
        self.final_calls += 1
        return int(self.final_rv)


def test_find_objects_child_requests_backing_for_declared_capacity(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The child backs max_count + guard slots before advertising max_count."""
    import pkcs11_check.testcases._probes.honeypot as honeypot

    seen: dict[str, int] = {}
    real = honeypot.demand_zero_buffer

    def _spy(min_size: int = 0) -> Any:
        seen["min_size"] = min_size
        return real(min_size=min_size)

    monkeypatch.setattr(field_size_probe, "demand_zero_buffer", _spy)
    raw = _FindRaw(target_rv=int(CKR_OK), final_rv=int(CKR_OK), handles=3)
    field_size_probe._run_find_objects_count(_ctx(raw), {"max_count": 64})

    assert seen["min_size"] >= (64 + 8) * ctypes.sizeof(CK_OBJECT_HANDLE)
    assert raw.max_count_seen == [64]
    assert raw.final_calls == 1
    out = capsys.readouterr().out
    for marker in ("TARGET_RV:", "COUNT_OUT:", "GUARD_OVERWRITE:", "FINAL_RV:"):
        assert out.count(marker) == 1, marker
    assert "COUNT_OUT:3" in out
    assert "GUARD_OVERWRITE:0" in out


def test_find_objects_child_always_finalizes_and_emits_final_rv(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """C_FindObjectsFinal runs (and FINAL_RV emits) even when refused."""
    raw = _FindRaw(target_rv=int(CKR_GENERAL_ERROR), final_rv=int(CKR_OK))
    field_size_probe._run_find_objects_count(_ctx(raw), {"max_count": 64})

    assert raw.final_calls == 1
    out = capsys.readouterr().out
    assert out.count("FINAL_RV:") == 1
    assert f"FINAL_RV:{int(CKR_OK):#010x}" in out


def test_find_objects_child_setup_xfails_without_backing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No honest backing -> setup-XFAIL protocol, no under-backed call."""

    def _unavailable(min_size: int = 0) -> Any:
        raise HoneypotUnavailable(f"no candidate satisfies minimum {min_size} bytes")

    monkeypatch.setattr(field_size_probe, "demand_zero_buffer", _unavailable)
    raw = _FindRaw(target_rv=int(CKR_OK), final_rv=int(CKR_OK))
    field_size_probe._run_find_objects_count(_ctx(raw), {"max_count": TRUNCATION_LOW8})

    assert raw.max_count_seen == []
    # The successful Init is still balanced with Final; no markers emit.
    assert raw.final_calls == 1
    out = capsys.readouterr().out
    assert "SETUP_XFAIL:" in out
    assert "TARGET_RV:" not in out


class _HkdfRaw:
    """Fake HKDF derive with scriptable probe/reference outcomes."""

    def __init__(
        self,
        *,
        probe_rv: int,
        ref_rv: int,
        probe_bytes: bytes,
        ref_bytes: bytes,
    ) -> None:
        self.probe_rv = probe_rv
        self.ref_rv = ref_rv
        self.probe_bytes = probe_bytes
        self.ref_bytes = ref_bytes
        self.derives: int = 0
        self.destroyed: list[int] = []
        self.lengths_seen: list[int] = []

    def C_CreateObject(  # noqa: N802
        self, _session: int, _tmpl: object, _count: int, out: object
    ) -> int:
        _set_handle(out, 5)
        return int(CKR_OK)

    def C_DeriveKey(  # noqa: N802
        self,
        _session: int,
        _mech: object,
        _base: int,
        _tmpl: object,
        _count: int,
        out: object,
    ) -> int:
        self.derives += 1
        _set_handle(out, 100 + self.derives)
        return int(self.probe_rv if self.derives == 1 else self.ref_rv)

    def C_GetAttributeValue(  # noqa: N802
        self, _session: int, handle: int, tmpl: object, _count: int
    ) -> int:
        data = self.probe_bytes if int(handle) == 101 else self.ref_bytes
        attr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)).contents
        ctypes.memmove(attr.pValue, data, len(data))
        return int(CKR_OK)

    def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        return int(CKR_OK)


@pytest.mark.parametrize("which", ["hkdf_salt_len", "hkdf_info_len"])
def test_hkdf_children_request_backing_for_oversize_len(
    which: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """HKDF children request min_size >= oversize_len before advertising it."""
    import pkcs11_check.testcases._probes.honeypot as honeypot

    seen: dict[str, int] = {}
    real = honeypot.demand_zero_buffer

    def _spy(min_size: int = 0) -> Any:
        seen["min_size"] = min_size
        return real(min_size=min_size)

    monkeypatch.setattr(field_size_probe, "demand_zero_buffer", _spy)
    raw = _HkdfRaw(
        probe_rv=int(CKR_MECHANISM_PARAM_INVALID),
        ref_rv=int(CKR_OK),
        probe_bytes=bytes(32),
        ref_bytes=bytes(32),
    )
    run = getattr(field_size_probe, f"_run_{which}")
    run(_ctx(raw), {"oversize_len": TRUNCATION_LOW8})

    assert seen["min_size"] >= TRUNCATION_LOW8
    out = capsys.readouterr().out
    assert out.count("PROBE_RV:") == 1


@pytest.mark.parametrize("which", ["hkdf_salt_len", "hkdf_info_len"])
def test_hkdf_child_emits_single_truncated_after_completion(
    which: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """After probe + reference complete, exactly one TRUNCATED:1 emits."""
    raw = _HkdfRaw(
        probe_rv=int(CKR_OK),
        ref_rv=int(CKR_OK),
        probe_bytes=bytes(range(32)),
        ref_bytes=bytes(range(32)),
    )
    run = getattr(field_size_probe, f"_run_{which}")
    run(_ctx(raw), {"oversize_len": TRUNCATION_LOW8})

    assert raw.derives == 2
    out = capsys.readouterr().out
    assert out.count("PROBE_RV:") == 1
    assert out.count("TRUNCATED:") == 1
    assert "TRUNCATED:1" in out
