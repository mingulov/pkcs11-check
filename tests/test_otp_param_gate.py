"""fw#40: OTP registry entries must not contradict their param recipe.

CKM_SECURID / CKM_HOTP / CKM_ACTI claim param_required=True with the
default "none" recipe: the missing/malformed-param negatives demand NULL
rejection while every positive path sends NULL. The "none" recipe is pinned
by test_hotp_registry_key_type (positive-path OTP operation stays deferred),
so the flag must match the recipe (POLY1305 precedent, P11C-009): NULL is the
probed form and refusal xfails; there is no provider-general static recipe
for CK_OTP_PARAMS (content is per-token runtime data).
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.types_std import (
    CKM_ACTI,
    CKM_HOTP,
    CKM_SECURID,
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

_OTP_OP_MECHS: tuple[tuple[int, str], ...] = (
    (int(CKM_SECURID), "CKM_SECURID"),
    (int(CKM_HOTP), "CKM_HOTP"),
    (int(CKM_ACTI), "CKM_ACTI"),
)


def _otp_entry(mech_id: int, mech_name: str) -> MechEntry:
    config = get_config(mech_id)
    assert config is not None
    return MechEntry(
        mech_id=mech_id,
        mech_name=mech_name,
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )


@pytest.mark.parametrize(("mech_id", "mech_name"), _OTP_OP_MECHS)
def test_otp_param_flag_matches_none_recipe(mech_id: int, mech_name: str) -> None:
    """param_required must be False: the "none" recipe builds NULL params."""
    config = get_config(mech_id)
    assert config is not None
    assert config.param_recipe.style == "none", mech_name
    assert config.param_required is False, mech_name


@pytest.mark.parametrize(("mech_id", "mech_name"), _OTP_OP_MECHS)
def test_otp_null_param_roundtrip_path(mech_id: int, mech_name: str) -> None:
    """Roundtrip builders must resolve OTP mechs to NULL params (the probed form)."""
    entry = _otp_entry(mech_id, mech_name)
    assert entry.config is not None
    assert build_test_params(entry.mech_id, entry.config.param_recipe) is None
    assert make_mech_param(entry) is None
    assert make_mech_param_or_skip(entry) is None


@pytest.mark.parametrize(("mech_id", "mech_name"), _OTP_OP_MECHS)
def test_otp_skips_required_param_negatives(mech_id: int, mech_name: str) -> None:
    """Missing-required-param nodes must skip OTP mechs: NULL is the valid probe."""
    assert_skips(
        _skip_if_not_required_param_registry_case,
        _otp_entry(mech_id, mech_name),
        match="params are not required",
    )


@pytest.mark.parametrize(("mech_id", "mech_name"), _OTP_OP_MECHS)
def test_otp_explicit_param_rejection_classifies(mech_id: int, mech_name: str) -> None:
    """Explicit non-NULL params on OTP mechs must classify as a spec rejection."""
    explicit = mech_bytes(mech_id, b"\x00")
    assert explicit.ck.mechanism == mech_id
    assert explicit.ck.pParameter is not None
    assert explicit.ck.ulParameterLen == 1

    assert CKR_MECHANISM_PARAM_INVALID in _MALFORMED_REQUIRED_PARAM_RVS
    assert CKR_ARGUMENTS_BAD in _MALFORMED_REQUIRED_PARAM_RVS
    classify_negative_rv(
        CKR_MECHANISM_PARAM_INVALID,
        _MALFORMED_REQUIRED_PARAM_RVS,
        label=f"{mech_name} C_SignInit with explicit non-NULL params",
    )
    classify_negative_rv(
        CKR_ARGUMENTS_BAD,
        _MALFORMED_REQUIRED_PARAM_RVS,
        label=f"{mech_name} C_VerifyInit with explicit non-NULL params",
    )
