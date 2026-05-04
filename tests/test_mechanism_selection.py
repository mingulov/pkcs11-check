from __future__ import annotations

from typing import cast

import pytest

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKF_SIGN,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_WRAP,
    CKM_EDDSA,
    CKM_XEDDSA,
)
from pkcs11_check.testcases import mechanism_selection as selection
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog, MechEntry
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY, MechConfig

_UNSET = object()


def _entry(
    *,
    flags: int = 0,
    multi_part_supported: bool = True,
    config: MechConfig | None | object = _UNSET,
) -> MechEntry:
    resolved_config = (
        MechConfig(multi_part_supported=multi_part_supported) if config is _UNSET else config
    )
    return MechEntry(
        mech_id=1,
        mech_name="DUMMY",
        flags=flags,
        min_key_size=0,
        max_key_size=0,
        config=cast(MechConfig | None, resolved_config),
    )


def test_wrap_roundtrip_rejects_wrap_only_mechanism() -> None:
    decision = selection.wrap_roundtrip(_entry(flags=int(CKF_WRAP)))

    assert not decision.selected
    assert decision.reasons[0].code == "missing_flags"
    assert decision.reasons[0].field == "flags"
    assert decision.reasons[0].expected == ("CKF_WRAP", "CKF_UNWRAP")
    assert decision.reasons[0].actual == ("CKF_WRAP",)
    assert decision.reasons[0].missing == ("CKF_UNWRAP",)


def test_wrap_roundtrip_accepts_wrap_and_unwrap_mechanism() -> None:
    decision = selection.wrap_roundtrip(_entry(flags=int(CKF_WRAP) | int(CKF_UNWRAP)))

    assert decision.selected
    assert decision.reasons == ()


def test_encrypt_roundtrip_rejects_encrypt_only_mechanism() -> None:
    decision = selection.encrypt_roundtrip(_entry(flags=int(CKF_ENCRYPT)))

    assert not decision.selected
    assert decision.reasons[0].code == "missing_flags"
    assert decision.reasons[0].expected == ("CKF_ENCRYPT", "CKF_DECRYPT")
    assert decision.reasons[0].actual == ("CKF_ENCRYPT",)


def test_encrypt_roundtrip_accepts_encrypt_and_decrypt_mechanism() -> None:
    decision = selection.encrypt_roundtrip(_entry(flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT)))

    assert decision.selected
    assert decision.reasons == ()


def test_encrypt_roundtrip_rejects_input_constraint_none_mechanism() -> None:
    decision = selection.encrypt_roundtrip(
        _entry(
            flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT),
            config=MechConfig(input_constraint="none"),
        )
    )

    assert not decision.selected
    assert decision.reasons[0].code == "unsupported_input_constraint"
    assert decision.reasons[0].field == "input_constraint"
    assert decision.reasons[0].expected == "data-capable"
    assert decision.reasons[0].actual == "none"


def test_sign_verify_roundtrip_accepts_sign_and_verify_mechanism() -> None:
    decision = selection.sign_verify_roundtrip(_entry(flags=int(CKF_SIGN) | int(CKF_VERIFY)))

    assert decision.selected
    assert decision.reasons == ()


def test_multipart_encrypt_rejects_disabled_multi_part_support() -> None:
    decision = selection.multipart_encrypt_roundtrip(
        _entry(flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT), multi_part_supported=False)
    )

    assert not decision.selected
    assert decision.reasons[0].code == "unsupported_multi_part"
    assert decision.reasons[0].field == "multi_part_supported"
    assert decision.reasons[0].expected is True
    assert decision.reasons[0].actual is False


def test_multipart_encrypt_roundtrip_accepts_multi_part_supported_mechanism() -> None:
    decision = selection.multipart_encrypt_roundtrip(
        _entry(flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT), multi_part_supported=True)
    )

    assert decision.selected
    assert decision.reasons == ()


def test_multipart_sign_verify_rejects_disabled_multi_part_support() -> None:
    decision = selection.select_for_scenario(
        _entry(flags=int(CKF_SIGN) | int(CKF_VERIFY), multi_part_supported=False),
        selection.MULTIPART_SIGN_VERIFY_ROUNDTRIP,
    )

    assert decision.scenario == selection.MULTIPART_SIGN_VERIFY_ROUNDTRIP
    assert not decision.selected
    assert decision.reasons[0].code == "unsupported_multi_part"
    assert decision.reasons[0].field == "multi_part_supported"
    assert decision.reasons[0].expected is True
    assert decision.reasons[0].actual is False


def test_multipart_sign_verify_roundtrip_accepts_multi_part_supported_mechanism() -> None:
    decision = selection.select_for_scenario(
        _entry(flags=int(CKF_SIGN) | int(CKF_VERIFY), multi_part_supported=True),
        selection.MULTIPART_SIGN_VERIFY_ROUNDTRIP,
    )

    assert decision.selected
    assert decision.reasons == ()


def test_multipart_sign_verify_uses_real_eddsa_and_xeddsa_registry_config() -> None:
    eddsa_config = MECHANISM_REGISTRY[CKM_EDDSA]
    xeddsa_config = MECHANISM_REGISTRY[CKM_XEDDSA]
    assert eddsa_config.multi_part_supported is True
    assert xeddsa_config.multi_part_supported is False

    eddsa = selection.select_for_scenario(
        _entry(
            flags=int(CKF_SIGN) | int(CKF_VERIFY),
            config=eddsa_config,
        ),
        selection.MULTIPART_SIGN_VERIFY_ROUNDTRIP,
    )
    xeddsa = selection.select_for_scenario(
        _entry(
            flags=int(CKF_SIGN) | int(CKF_VERIFY),
            config=xeddsa_config,
        ),
        selection.MULTIPART_SIGN_VERIFY_ROUNDTRIP,
    )

    assert eddsa.selected
    assert xeddsa.rejected
    assert xeddsa.reasons[0].code == "unsupported_multi_part"


def test_select_for_scenario_returns_machine_readable_reasons() -> None:
    decision = selection.select_for_scenario(
        _entry(flags=int(CKF_WRAP)),
        selection.WRAP_ROUNDTRIP,
    )

    assert decision.scenario == selection.WRAP_ROUNDTRIP
    assert decision.reasons
    assert decision.reasons[0].code == "missing_flags"
    assert isinstance(decision.reasons[0].expected, tuple)
    assert isinstance(decision.reasons[0].actual, tuple)


def test_missing_registry_config_is_reported_as_rejection() -> None:
    decision = selection.encrypt_roundtrip(
        _entry(flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT), config=None),
    )

    assert not decision.selected
    assert decision.reasons[0].code == "missing_registry_config"
    assert decision.reasons[0].field == "config"


def test_select_for_scenario_rejects_unknown_scenario() -> None:
    with pytest.raises(ValueError, match="unknown scenario"):
        selection.select_for_scenario(
            _entry(flags=int(CKF_WRAP) | int(CKF_UNWRAP)),
            "nope",
        )


def test_filter_for_scenario_keeps_only_matching_entries() -> None:
    wrap_ok = _entry(flags=int(CKF_WRAP) | int(CKF_UNWRAP))
    wrap_only = _entry(flags=int(CKF_WRAP))
    encrypt_ok = _entry(flags=int(CKF_ENCRYPT) | int(CKF_DECRYPT))
    catalog = MechanismCatalog(
        {
            1: wrap_ok,
            2: wrap_only,
            3: encrypt_ok,
        }
    )

    selected = catalog.filter_for_scenario(selection.WRAP_ROUNDTRIP)

    assert selected == [wrap_ok]
