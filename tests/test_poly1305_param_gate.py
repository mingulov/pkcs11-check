"""P11C-009: CKM_POLY1305 registry entry must not contradict its param recipe."""

from __future__ import annotations

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.types_std import (
    CKM_POLY1305,
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    build_test_params,
    make_mech_param,
    make_mech_param_or_skip,
)
from pkcs11_check.testcases.mechanism_registry import get_config
from pkcs11_check.testcases.test_mech_negative import (
    _MALFORMED_REQUIRED_PARAM_RVS,
    _skip_if_not_required_param_registry_case,
)
from tests._skip_assert import assert_skips


def _poly1305_entry() -> MechEntry:
    config = get_config(int(CKM_POLY1305))
    assert config is not None
    return MechEntry(
        mech_id=int(CKM_POLY1305),
        mech_name="CKM_POLY1305",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )


def test_poly1305_param_flag_matches_none_recipe() -> None:
    """param_required must be False: the "none" recipe builds NULL params."""
    config = get_config(int(CKM_POLY1305))
    assert config is not None
    assert config.param_recipe.style == "none"
    assert config.param_required is False


def test_poly1305_null_param_roundtrip_path() -> None:
    """Roundtrip builders must resolve POLY1305 to NULL params (the accepted form)."""
    entry = _poly1305_entry()
    assert entry.config is not None
    assert build_test_params(entry.mech_id, entry.config.param_recipe) is None
    assert make_mech_param(entry) is None
    assert make_mech_param_or_skip(entry) is None


def test_poly1305_skips_required_param_negatives() -> None:
    """Sign/verify missing-required-param nodes must skip POLY1305: NULL is valid."""
    assert_skips(
        _skip_if_not_required_param_registry_case,
        _poly1305_entry(),
        match="params are not required",
    )


def test_poly1305_explicit_param_rejection_classifies() -> None:
    """Explicit non-NULL params on POLY1305 must classify as a spec rejection."""
    explicit = mech_bytes(int(CKM_POLY1305), b"\x00")
    assert explicit.ck.mechanism == int(CKM_POLY1305)
    assert explicit.ck.pParameter is not None
    assert explicit.ck.ulParameterLen == 1

    assert CKR_MECHANISM_PARAM_INVALID in _MALFORMED_REQUIRED_PARAM_RVS
    assert CKR_ARGUMENTS_BAD in _MALFORMED_REQUIRED_PARAM_RVS
    classify_negative_rv(
        CKR_MECHANISM_PARAM_INVALID,
        _MALFORMED_REQUIRED_PARAM_RVS,
        label="CKM_POLY1305 C_SignInit with explicit non-NULL params",
    )
    classify_negative_rv(
        CKR_ARGUMENTS_BAD,
        _MALFORMED_REQUIRED_PARAM_RVS,
        label="CKM_POLY1305 C_VerifyInit with explicit non-NULL params",
    )
