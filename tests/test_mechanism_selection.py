from __future__ import annotations

from pkcs11_check.raw.types_std import CKF_DECRYPT, CKF_ENCRYPT, CKF_WRAP
from pkcs11_check.testcases import mechanism_selection as selection
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig


def _entry(*, flags: int = 0, multi_part_supported: bool = True) -> MechEntry:
    return MechEntry(
        mech_id=1,
        mech_name="DUMMY",
        flags=flags,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(multi_part_supported=multi_part_supported),
    )


def test_wrap_roundtrip_rejects_wrap_only_mechanism() -> None:
    decision = selection.wrap_roundtrip(_entry(flags=int(CKF_WRAP)))

    assert not decision.selected
    assert decision.reasons[0].code == "missing_flags"
    assert decision.reasons[0].field == "flags"
    assert decision.reasons[0].expected == ("CKF_WRAP", "CKF_UNWRAP")
    assert decision.reasons[0].actual == ("CKF_WRAP",)


def test_encrypt_roundtrip_rejects_encrypt_only_mechanism() -> None:
    decision = selection.encrypt_roundtrip(_entry(flags=int(CKF_ENCRYPT)))

    assert not decision.selected
    assert decision.reasons[0].code == "missing_flags"
    assert decision.reasons[0].expected == ("CKF_ENCRYPT", "CKF_DECRYPT")
    assert decision.reasons[0].actual == ("CKF_ENCRYPT",)


def test_multipart_encrypt_rejects_disabled_multi_part_support() -> None:
    decision = selection.multipart_encrypt_roundtrip(
        _entry(flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT), multi_part_supported=False)
    )

    assert not decision.selected
    assert decision.reasons[0].code == "unsupported_multi_part"
    assert decision.reasons[0].field == "multi_part_supported"
    assert decision.reasons[0].expected is True
    assert decision.reasons[0].actual is False


def test_select_for_scenario_returns_machine_readable_reasons() -> None:
    decision = selection.select_for_scenario(_entry(flags=int(CKF_WRAP)), "wrap_roundtrip")

    assert decision.scenario == "wrap_roundtrip"
    assert decision.reasons
    assert decision.reasons[0].code == "missing_flags"
    assert isinstance(decision.reasons[0].expected, tuple)
    assert isinstance(decision.reasons[0].actual, tuple)
