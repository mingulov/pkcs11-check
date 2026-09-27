"""Pins for OTP registry key types (P11C-001, F16).

The HOTP/SecurID/ACTI registry entries must carry their CKK_* key type. With
``key_type=None`` the registry-driven wrong-key-type negative legs die on
``assert config.key_type is not None`` (the 2 HOTP hard fails on Haskoki),
and proper-key setup self-skips instead of reaching C_GenerateKey.

Six-row behavioral table: each row drives the real negative probe
(``_wrong_secret_key_type``) and the real proper-key path
(``generate_key_for_sign``) against a fake token, asserting per-case rc, CKK
code, and witness. Witnesses compare portably via int(), so an enum member
or an accepted legacy plain-int numeric both satisfy them. The SecurID/ACTI
rows expect their own distinct CKK values, proving no copy-paste repeats.
Placeholder recipes (param "none", empty key sizes) are asserted untouched
per the HSK-P11C-001 narrowing: positive-path OTP operation stays deferred.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_KEY_TYPE,
    CKA_VALUE_LEN,
    CKK_ACTI,
    CKK_GENERIC_SECRET,
    CKK_HOTP,
    CKK_SECURID,
    CKM_ACTI,
    CKM_ACTI_KEY_GEN,
    CKM_HOTP,
    CKM_HOTP_KEY_GEN,
    CKM_SECURID,
    CKM_SECURID_KEY_GEN,
    CKR_OK,
)
from pkcs11_check.testcases import test_mech_negative
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import generate_key_for_sign
from pkcs11_check.testcases.mechanism_registry import get_config


@dataclass(frozen=True)
class _OtpCase:
    case_id: str
    mech: int
    keygen_mech: int
    key_type: int  # enum member (int subclass)
    legacy: int  # accepted legacy plain-int numeric for the same code
    rc: int  # per-case fake-token rc for C_GenerateKey


_OTP_CASES: tuple[_OtpCase, ...] = (
    _OtpCase("hotp-keygen-entry", CKM_HOTP_KEY_GEN, CKM_HOTP_KEY_GEN, CKK_HOTP, 0x23, CKR_OK),
    _OtpCase("hotp-op-entry", CKM_HOTP, CKM_HOTP_KEY_GEN, CKK_HOTP, 0x23, CKR_OK),
    _OtpCase(
        "securid-keygen-entry",
        CKM_SECURID_KEY_GEN,
        CKM_SECURID_KEY_GEN,
        CKK_SECURID,
        0x22,
        CKR_OK,
    ),
    _OtpCase("securid-op-entry", CKM_SECURID, CKM_SECURID_KEY_GEN, CKK_SECURID, 0x22, CKR_OK),
    _OtpCase("acti-keygen-entry", CKM_ACTI_KEY_GEN, CKM_ACTI_KEY_GEN, CKK_ACTI, 0x24, CKR_OK),
    _OtpCase("acti-op-entry", CKM_ACTI, CKM_ACTI_KEY_GEN, CKK_ACTI, 0x24, CKR_OK),
)


def _assert_code_equal(witness: Any, expected: int, legacy: int, label: str) -> None:
    """Assert a CKK/CKR witness portably (enum member or legacy numeric)."""
    assert int(expected) == int(legacy), f"{label}: pin table inconsistent ({expected!r})"
    assert witness is not None, f"{label}: witness is None, expected {expected!r} ({legacy:#x})"
    got = int(witness)
    assert got == int(legacy), f"{label}: witness {witness!r} != {expected!r} ({legacy:#x})"


def _template_ulongs(tmpl: Any, count: int) -> dict[int, int]:
    """Decode ulong-sized template entries to {CKA_*: value}."""
    arr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE))
    decoded: dict[int, int] = {}
    for idx in range(count):
        attr = arr[idx]
        if int(attr.ulValueLen) == ctypes.sizeof(CK_ULONG):
            scalar = ctypes.cast(attr.pValue, ctypes.POINTER(CK_ULONG)).contents.value
            decoded[int(attr.type)] = int(scalar)
    return decoded


class _KeygenCaptureRaw:
    """Fake token capturing the C_GenerateKey mechanism id and template."""

    def __init__(self, rc: int) -> None:
        self._rc = rc
        self.calls: list[tuple[int, int, dict[int, int]]] = []

    def C_GenerateKey(  # noqa: N802
        self,
        _session: int,
        mech: Any,
        tmpl: Any,
        count: int,
        out: Any,
    ) -> int:
        mech_id = int(ctypes.cast(mech, ctypes.POINTER(CK_MECHANISM)).contents.mechanism)
        self.calls.append((mech_id, self._rc, _template_ulongs(tmpl, count)))
        ctypes.cast(out, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 77
        return self._rc


@pytest.mark.parametrize("case", _OTP_CASES, ids=[c.case_id for c in _OTP_CASES])
def test_otp_registry_key_type(case: _OtpCase) -> None:
    config = get_config(case.mech)
    assert config is not None, f"{case.case_id}: no registry config for 0x{case.mech:08x}"
    entry = MechEntry(
        mech_id=case.mech,
        mech_name=case.case_id,
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )

    # 1. Negative probe: the wrong-key-type leg must resolve a concrete wrong type.
    wrong = test_mech_negative._wrong_secret_key_type(entry)
    _assert_code_equal(wrong, CKK_GENERIC_SECRET, 0x10, f"{case.case_id}: wrong-key probe type")

    # 2. Proper-key setup must reach C_GenerateKey with the correct CKA_KEY_TYPE.
    raw = _KeygenCaptureRaw(case.rc)
    rs = SimpleNamespace(raw=raw, sh=1)
    try:
        handle, _verify = generate_key_for_sign(rs, entry, config)
    except pytest.skip.Exception as exc:
        pytest.fail(f"{case.case_id}: proper-key setup skipped ({exc}); expected C_GenerateKey")
    assert handle == 77, f"{case.case_id}: unexpected key handle {handle}"
    assert len(raw.calls) == 1, f"{case.case_id}: expected 1 C_GenerateKey call, saw {raw.calls}"
    seen_mech, seen_rc, attrs = raw.calls[0]
    _assert_code_equal(seen_rc, CKR_OK, 0x0, f"{case.case_id}: C_GenerateKey rc")
    assert int(seen_mech) == int(case.keygen_mech), (
        f"{case.case_id}: keygen mech 0x{int(seen_mech):08x} != 0x{int(case.keygen_mech):08x}"
    )
    witness = attrs.get(int(CKA_KEY_TYPE))
    assert witness is not None, f"{case.case_id}: CKA_KEY_TYPE missing from keygen template"
    _assert_code_equal(witness, case.key_type, case.legacy, f"{case.case_id}: CKA_KEY_TYPE")
    assert attrs.get(int(CKA_VALUE_LEN)) == 32, (
        f"{case.case_id}: CKA_VALUE_LEN {attrs.get(int(CKA_VALUE_LEN))} != 32"
    )

    # 3. Registry anchors + scope boundary (placeholder recipes untouched).
    _assert_code_equal(
        config.key_type, case.key_type, case.legacy, f"{case.case_id}: registry key_type"
    )
    assert config.keygen_mech is not None, f"{case.case_id}: keygen_mech is None"
    assert int(config.keygen_mech) == int(case.keygen_mech), (
        f"{case.case_id}: keygen_mech 0x{int(config.keygen_mech):08x}"
        f" != 0x{int(case.keygen_mech):08x}"
    )
    assert config.param_recipe.style == "none", (
        f"{case.case_id}: param recipe {config.param_recipe.style!r} != 'none'"
    )
    assert config.key_sizes == (), f"{case.case_id}: key sizes {config.key_sizes} != ()"
