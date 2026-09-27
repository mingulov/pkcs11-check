"""F12 (P11C-0198-013): alignment hostile routing + aligned controls.

The two ``ffi_alignment`` probes pass 1-byte-misaligned caller pointers: a
typed ``CK_MECHANISM*`` (undefined behavior on dereference) and scalar
encodings at ``CK_ATTRIBUTE.pValue`` (``CK_VOID_PTR``, ambiguous contract).
Whatever the provider does with such input -- crash, hang, reject, accept --
is a non-normative hostile-caller robustness observation (EXTENDED note),
never a conformance or memory-safety finding. The aligned controls in the
same product file prove the valid-input baseline with typed storage.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import compliance
from pkcs11_check.compliance import ComplianceNote
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases._probes import ffi_alignment as ffi_alignment_probe
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER
from pkcs11_check.testcases.security import test_ffi_alignment

_MECH_DESC = "1-byte-misaligned typed CK_MECHANISM_PTR (undefined behavior on dereference)"
_SCALAR_DESC = (
    "1-byte-misaligned CK_ATTRIBUTE.pValue scalar storage (CK_VOID_PTR, ambiguous contract)"
)


def _extended_notes() -> list[ComplianceNote]:
    """Drain and return EXTENDED compliance notes (F12-local)."""
    try:
        return [n for n in compliance.get_notes() if n.level is compliance.ComplianceLevel.EXTENDED]
    finally:
        compliance.clear_notes()


def _reset_notes() -> None:
    compliance.clear_notes()


class _Pin:
    def get_secret_value(self) -> str:
        return "1234"


class _RawSession:
    raw = object()
    sh = object()

    def has_mechanism(self, _name: str) -> bool:
        return True


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)


def _scalar_of(attr: CK_ATTRIBUTE) -> int:
    """Read a scalar attribute value without over-reading 1-byte bools."""
    if int(attr.ulValueLen) == 1:
        return int(ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ubyte)).contents.value)
    return int(ctypes.cast(attr.pValue, ctypes.POINTER(CK_ULONG)).contents.value)


class TestF12HostileCallerObservation:
    """The alignment observer records EXTENDED robustness notes and never fails."""

    def test_hostile_mech_crash_is_observation_not_finding(self) -> None:
        _reset_notes()
        test_ffi_alignment._observe_hostile_caller_robustness(
            -11,
            "HOSTILE_CALLER:C_EncryptInit(misaligned CK_MECHANISM_PTR)\n",
            "",
            context="C_EncryptInit with misaligned CK_MECHANISM_PTR",
            input_desc=_MECH_DESC,
            test_id="TestF12.test",
        )
        (note,) = _extended_notes()
        assert "hostile-caller" in note.description
        assert "non-normative" in note.description
        assert "not a conformance" in note.description
        assert "typed CK_MECHANISM_PTR" in note.description
        assert note.reference == "P11C-0198-013"

    def test_hostile_scalar_timeout_is_observation_not_hang_finding(self) -> None:
        _reset_notes()
        test_ffi_alignment._observe_hostile_caller_robustness(
            124,
            "HOSTILE_CALLER:C_GenerateKey(misaligned CK_ATTRIBUTE.pValue scalars)\n",
            f"partial\n{SUBPROCESS_TIMEOUT_MARKER}:10s\n",
            context="C_GenerateKey with misaligned CK_ATTRIBUTE.pValue scalars",
            input_desc=_SCALAR_DESC,
            test_id="TestF12.test",
        )
        (note,) = _extended_notes()
        assert "hostile-caller" in note.description
        assert "timed out" in note.description
        assert "CK_VOID_PTR" in note.description
        assert note.reference == "P11C-0198-013"

    def test_hostile_clean_reject_is_observation(self) -> None:
        _reset_notes()
        test_ffi_alignment._observe_hostile_caller_robustness(
            0,
            "HOSTILE_CALLER:C_GenerateKey(misaligned CK_ATTRIBUTE.pValue scalars)\n"
            "TARGET_RV:C_GenerateKey:0x00000007\n",
            "",
            context="C_GenerateKey with misaligned CK_ATTRIBUTE.pValue scalars",
            input_desc=_SCALAR_DESC,
            test_id="TestF12.test",
        )
        (note,) = _extended_notes()
        assert "hostile-caller" in note.description
        assert "CKR_ARGUMENTS_BAD" in note.description

    def test_hostile_ckr_ok_is_observation_not_accepted_invalid(self) -> None:
        _reset_notes()
        test_ffi_alignment._observe_hostile_caller_robustness(
            0,
            "HOSTILE_CALLER:C_EncryptInit(misaligned CK_MECHANISM_PTR)\n"
            "TARGET_RV:C_EncryptInit:0x00000000\n",
            "",
            context="C_EncryptInit with misaligned CK_MECHANISM_PTR",
            input_desc=_MECH_DESC,
            test_id="TestF12.test",
        )
        (note,) = _extended_notes()
        assert "hostile-caller" in note.description
        assert "CKR_OK" in note.description

    def test_hostile_prefers_target_rv_over_setup_rv(self) -> None:
        """SETUP_RV stays separate: the observation reports the hostile call."""
        _reset_notes()
        test_ffi_alignment._observe_hostile_caller_robustness(
            0,
            "SETUP_RV:C_GenerateKey:0\n"
            "HOSTILE_CALLER:C_EncryptInit(misaligned CK_MECHANISM_PTR)\n"
            "TARGET_RV:C_EncryptInit:0x00000007\n",
            "",
            context="C_EncryptInit with misaligned CK_MECHANISM_PTR",
            input_desc=_MECH_DESC,
            test_id="TestF12.test",
        )
        (note,) = _extended_notes()
        assert "CKR_ARGUMENTS_BAD" in note.description
        assert "CKR_OK" not in note.description

    def test_hostile_traceback_exit_stays_loud(self) -> None:
        _reset_notes()
        with pytest.raises(AssertionError, match="hostile-path probe bug"):
            test_ffi_alignment._observe_hostile_caller_robustness(
                1,
                "HOSTILE_CALLER:C_EncryptInit(misaligned CK_MECHANISM_PTR)\n",
                "Traceback (most recent call last):\nValueError: f12 probe bug\n",
                context="C_EncryptInit with misaligned CK_MECHANISM_PTR",
                input_desc=_MECH_DESC,
                test_id="TestF12.test",
            )
        assert _extended_notes() == []

    def test_is_hostile_caller_matches_marker_only(self) -> None:
        assert test_ffi_alignment._is_hostile_caller(
            "SETUP_RV:C_GenerateKey:0\nHOSTILE_CALLER:x\nTARGET_RV:C_EncryptInit:0\n"
        )
        assert not test_ffi_alignment._is_hostile_caller("TARGET_RV:C_GenerateKey:0\n")
        assert not test_ffi_alignment._is_hostile_caller("SETUP_XFAIL:keygen rejected\n")
        assert not test_ffi_alignment._is_hostile_caller("")


class TestF12HostileRouting:
    """Marker-first routing: hostile crashes observe, anything earlier still fails."""

    def test_mech_crash_with_marker_is_observation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _reset_notes()
        seen: dict[str, Any] = {}

        def _stub_probe(probe: str, params: dict[str, Any], **_kwargs: object) -> ProbeResult:
            seen["probe"] = probe
            seen["params"] = dict(params)
            return ProbeResult(
                returncode=-11,
                stdout="SETUP_RV:C_GenerateKey:0\n"
                "HOSTILE_CALLER:C_EncryptInit(misaligned CK_MECHANISM_PTR)\n",
                stderr="",
            )

        monkeypatch.setattr(test_ffi_alignment, "run_probe", _stub_probe)
        test_ffi_alignment.TestMisalignedMechanismPointer().test_encrypt_init_with_misaligned_mechanism_pointer(
            _RawSession(), _cfg()
        )
        assert seen["probe"] == "ffi_alignment"
        assert seen["params"]["probe"] == "misaligned_mechanism_ptr"
        (note,) = _extended_notes()
        assert "hostile-caller" in note.description
        assert note.reference == "P11C-0198-013"

    def test_scalar_crash_with_marker_is_observation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _reset_notes()
        seen: dict[str, Any] = {}

        def _stub_probe(probe: str, params: dict[str, Any], **_kwargs: object) -> ProbeResult:
            seen["probe"] = probe
            seen["params"] = dict(params)
            return ProbeResult(
                returncode=-11,
                stdout="HOSTILE_CALLER:C_GenerateKey(misaligned CK_ATTRIBUTE.pValue scalars)\n",
                stderr="",
            )

        monkeypatch.setattr(test_ffi_alignment, "run_probe", _stub_probe)
        test_ffi_alignment.TestMisalignedAttributeValues().test_generate_key_with_misaligned_scalar_attribute_values(
            _RawSession(), _cfg()
        )
        assert seen["probe"] == "ffi_alignment"
        assert seen["params"]["probe"] == "misaligned_scalar_attrs"
        (note,) = _extended_notes()
        assert "hostile-caller" in note.description
        assert note.reference == "P11C-0198-013"

    def test_crash_without_marker_stays_crash_finding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loudness pin: no marker means the child died before the hostile call."""

        def _stub_probe(_probe: str, _params: dict[str, Any], **_kwargs: object) -> ProbeResult:
            return ProbeResult(returncode=-11, stdout="", stderr="")

        monkeypatch.setattr(test_ffi_alignment, "run_probe", _stub_probe)
        with pytest.raises(pytest.fail.Exception, match="module crashed"):
            test_ffi_alignment.TestMisalignedMechanismPointer().test_encrypt_init_with_misaligned_mechanism_pointer(
                _RawSession(), _cfg()
            )
        assert _extended_notes() == []

    def test_setup_crash_before_marker_stays_crash_finding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loudness pin: a setup-keygen crash is valid-input evidence, not hostile."""

        def _stub_probe(_probe: str, _params: dict[str, Any], **_kwargs: object) -> ProbeResult:
            return ProbeResult(
                returncode=-11,
                stdout="",
                stderr="",
            )

        monkeypatch.setattr(test_ffi_alignment, "run_probe", _stub_probe)
        with pytest.raises(pytest.fail.Exception, match="module crashed"):
            test_ffi_alignment.TestMisalignedAttributeValues().test_generate_key_with_misaligned_scalar_attribute_values(
                _RawSession(), _cfg()
            )
        assert _extended_notes() == []


class _ProbeRaw:
    """CKR_OK provider double recording hostile-pointer addresses."""

    def __init__(self) -> None:
        self.attr_types: list[int] = []
        self.attr_pvalues: list[int] = []
        self.attr_scalars: list[int] = []
        self.mech_addrs: list[int] = []
        self.destroyed: list[int] = []

    def C_GenerateKey(  # noqa: N802
        self, _sh: Any, _mech: Any, tmpl: Any, count: Any, out: Any
    ) -> int:
        arr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE))
        for idx in range(int(count)):
            attr = arr[idx]
            self.attr_types.append(int(attr.type))
            self.attr_pvalues.append(int(attr.pValue))
            self.attr_scalars.append(_scalar_of(attr))
        ctypes.cast(out, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 0xB2
        return int(CKR_OK)

    def C_EncryptInit(self, _sh: Any, mech: Any, _key: Any) -> int:  # noqa: N802
        self.mech_addrs.append(ctypes.cast(mech, ctypes.c_void_p).value or 0)
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: Any, handle: Any) -> int:  # noqa: N802
        self.destroyed.append(int(getattr(handle, "value", handle)))
        return int(CKR_OK)


class TestF12ProbeMarkers:
    """Both hostile probes mark the wire before the target provider call."""

    def test_probe_marker_value_is_canonical(self) -> None:
        assert ffi_alignment_probe.HOSTILE_CALLER_PREFIX == "HOSTILE_CALLER:"

    def test_misaligned_helpers_use_plus_one_offset(self) -> None:
        """Loudness pin: hostile storage is exactly 1 byte past its backing."""
        storage, ptr = ffi_alignment_probe._misaligned_scalar(CK_ULONG, 16)
        assert ctypes.cast(ptr, ctypes.c_void_p).value - ctypes.addressof(storage) == 1
        mech = CK_MECHANISM()
        mech_storage, mech_ptr = ffi_alignment_probe._misaligned_ptr_to_struct(mech)
        assert ctypes.cast(mech_ptr, ctypes.c_void_p).value - ctypes.addressof(mech_storage) == 1

    def test_scalar_probe_prints_hostile_marker_before_target(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        raw = _ProbeRaw()
        ffi_alignment_probe._run_misaligned_scalar_attrs(SimpleNamespace(raw=raw, sh=9), {})
        out = capsys.readouterr().out
        assert "HOSTILE_CALLER:C_GenerateKey" in out
        assert out.index("HOSTILE_CALLER:") < out.index("TARGET_RV:C_GenerateKey:")
        assert raw.attr_types == [CKA_VALUE_LEN, CKA_ENCRYPT, CKA_DECRYPT, CKA_TOKEN]
        assert raw.attr_scalars == [16, 1, 1, 0]
        assert raw.destroyed == [0xB2]

    def test_mech_probe_prints_hostile_marker_after_setup(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        raw = _ProbeRaw()
        ffi_alignment_probe._run_misaligned_mechanism_ptr(SimpleNamespace(raw=raw, sh=9), {})
        out = capsys.readouterr().out
        assert "HOSTILE_CALLER:C_EncryptInit" in out
        assert (
            out.index("SETUP_RV:C_GenerateKey:")
            < out.index("HOSTILE_CALLER:")
            < out.index("TARGET_RV:C_EncryptInit:")
        )
        # Absolute-address parity is allocator luck; the +1 construction itself is
        # pinned deterministically by test_misaligned_helpers_use_plus_one_offset.
        assert len(raw.mech_addrs) == 1
        assert raw.destroyed == [0xB2]


class _ControlRaw:
    """CKR_OK provider double recording control-pointer alignment."""

    def __init__(
        self,
        *,
        keygen_rv: int = int(CKR_OK),
        init_rv: int = int(CKR_OK),
        corrupt_decrypt: bool = False,
    ) -> None:
        self.keygen_rv = keygen_rv
        self.init_rv = init_rv
        self.corrupt_decrypt = corrupt_decrypt
        self.attr_types: list[int] = []
        self.attr_pvalues: list[int] = []
        self.attr_scalars: list[int] = []
        self.mech_addrs: list[int] = []
        self.encrypt_init_calls = 0
        self.destroyed: list[int] = []
        self._last_plaintext = b""

    def C_GenerateKey(  # noqa: N802
        self, _sh: Any, _mech: Any, tmpl: Any, count: Any, out: Any
    ) -> int:
        arr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE))
        for idx in range(int(count)):
            attr = arr[idx]
            self.attr_types.append(int(attr.type))
            self.attr_pvalues.append(int(attr.pValue))
            self.attr_scalars.append(_scalar_of(attr))
        ctypes.cast(out, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 0xA1
        return int(self.keygen_rv)

    def C_EncryptInit(self, _sh: Any, mech: Any, _key: Any) -> int:  # noqa: N802
        self.encrypt_init_calls += 1
        self.mech_addrs.append(ctypes.cast(mech, ctypes.c_void_p).value or 0)
        return int(self.init_rv)

    def C_Encrypt(  # noqa: N802
        self,
        _sh: Any,
        in_buf: Any,
        in_len: Any,
        out_buf: Any,
        out_len: Any,
    ) -> int:
        outp = ctypes.cast(out_len, ctypes.POINTER(CK_ULONG))
        length = int(in_len)
        if out_buf is None:
            outp.contents.value = length
            return int(CKR_OK)
        data = bytes(ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_ubyte * length)).contents)
        self._last_plaintext = data
        ct = bytes(b ^ 0x5A for b in data)
        ctypes.memmove(out_buf, ct, len(ct))
        outp.contents.value = len(ct)
        return int(CKR_OK)

    def C_Decrypt(  # noqa: N802
        self,
        _sh: Any,
        in_buf: Any,
        in_len: Any,
        out_buf: Any,
        out_len: Any,
    ) -> int:
        outp = ctypes.cast(out_len, ctypes.POINTER(CK_ULONG))
        length = int(in_len)
        if out_buf is None:
            outp.contents.value = length
            return int(CKR_OK)
        pt = self._last_plaintext
        if self.corrupt_decrypt:
            pt = bytes(b ^ 0xFF for b in pt)
        ctypes.memmove(out_buf, pt, len(pt))
        outp.contents.value = len(pt)
        return int(CKR_OK)

    def C_DecryptInit(  # noqa: N802
        self, _sh: Any, _mech: Any, _key: Any
    ) -> int:
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: Any, handle: Any) -> int:  # noqa: N802
        self.destroyed.append(int(getattr(handle, "value", handle)))
        return int(CKR_OK)


class _ControlSession:
    def __init__(self, raw: _ControlRaw) -> None:
        self.raw = raw
        self.sh = 7

    def has_mechanism(self, _name: str) -> bool:
        return True


class TestF12AlignedControls:
    """Aligned controls pass on valid typed storage and separate setup/target."""

    def test_scalar_control_passes_with_aligned_storage(self) -> None:
        raw = _ControlRaw()
        test_ffi_alignment.TestAlignedAttributeValues().test_generate_key_with_aligned_scalar_attribute_values(
            _ControlSession(raw)
        )
        assert raw.attr_types == [
            CKA_VALUE_LEN,
            CKA_ENCRYPT,
            CKA_DECRYPT,
            CKA_KEY_TYPE,
            CKA_TOKEN,
        ]
        assert raw.attr_scalars == [16, 1, 1, int(CKK_AES), 0]
        assert raw.attr_pvalues[0] % ctypes.alignment(CK_ULONG) == 0
        assert raw.destroyed == [0xA1]

    def test_scalar_control_setup_reject_xfails_not_operational(self) -> None:
        raw = _ControlRaw(keygen_rv=int(CKR_FUNCTION_NOT_SUPPORTED))
        with pytest.raises(pytest.xfail.Exception, match="not operational"):
            test_ffi_alignment.TestAlignedAttributeValues().test_generate_key_with_aligned_scalar_attribute_values(
                _ControlSession(raw)
            )
        assert raw.encrypt_init_calls == 0

    def test_mech_control_passes_with_aligned_storage_and_roundtrip(self) -> None:
        raw = _ControlRaw()
        test_ffi_alignment.TestAlignedMechanismPointer().test_encrypt_init_with_aligned_mechanism_pointer(
            _ControlSession(raw)
        )
        assert raw.encrypt_init_calls == 1
        (mech_addr,) = raw.mech_addrs
        assert mech_addr % ctypes.alignment(CK_MECHANISM) == 0
        assert raw.destroyed == [0xA1]

    def test_mech_control_setup_reject_xfails_before_target(self) -> None:
        raw = _ControlRaw(keygen_rv=int(CKR_FUNCTION_NOT_SUPPORTED))
        with pytest.raises(pytest.xfail.Exception, match="not operational"):
            test_ffi_alignment.TestAlignedMechanismPointer().test_encrypt_init_with_aligned_mechanism_pointer(
                _ControlSession(raw)
            )
        assert raw.encrypt_init_calls == 0

    def test_mech_control_target_reject_xfails_not_operational(self) -> None:
        raw = _ControlRaw(init_rv=int(CKR_FUNCTION_NOT_SUPPORTED))
        with pytest.raises(pytest.xfail.Exception, match="not operational"):
            test_ffi_alignment.TestAlignedMechanismPointer().test_encrypt_init_with_aligned_mechanism_pointer(
                _ControlSession(raw)
            )

    def test_mech_control_wrong_effect_fails(self) -> None:
        raw = _ControlRaw(corrupt_decrypt=True)
        with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
            test_ffi_alignment.TestAlignedMechanismPointer().test_encrypt_init_with_aligned_mechanism_pointer(
                _ControlSession(raw)
            )
