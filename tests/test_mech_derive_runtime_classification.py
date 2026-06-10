"""Regression tests for mechanism-driven derive runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_HKDF_DERIVE,
    CKM_XOR_BASE_AND_DATA,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_mech_derive
from pkcs11_check.testcases.mechanism_catalog import MechEntry


def _entry(mech_id: int, name: str) -> MechEntry:
    return MechEntry(
        mech_id=mech_id,
        mech_name=name,
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=object(),
    )


def _session() -> Any:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
    )


def _session_with_keygen_reject(reject_rv: int) -> Any:
    """Return a fake session whose C_GenerateKey always returns *reject_rv*.

    Used to drive the base-keygen precondition through the real assert path
    (C-level return, not a monkeypatched helper) and verify the claim-layer
    classifies the refusal as "advertised but not operational".
    """
    raw = SimpleNamespace(
        C_GenerateKey=lambda *_args, **_kwargs: reject_rv,
    )
    return SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda _name: True,
    )


def test_extract_key_from_key_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean CkrAssertionError derive reject -> claim-layer xfail (shared wording)."""

    def _derive_reject(*_args: Any, **_kwargs: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    monkeypatch.setattr(test_mech_derive, "_derive_extract", _derive_reject)

    with pytest.raises(
        pytest.xfail.Exception,
        match="advertised but not operational",
    ):
        test_mech_derive.TestMechDerive().test_derive_produces_key(
            _session(),
            _entry(int(CKM_EXTRACT_KEY_FROM_KEY), "CKM_EXTRACT_KEY_FROM_KEY"),
        )


def test_hkdf_base_keygen_non_ckr_assert_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Allowlist retired: a plain (non-CkrAssertionError) keygen assert no longer
    matches on message substring -- the claim layer re-raises it as a real failure.

    Previously ``xfail_if_known_ckr`` substring-matched the CKR name in the
    message and xfailed. The claim layer classifies only ``CkrAssertionError``,
    so a plain assert (potential harness/contradiction signal) propagates.
    """

    def _derive_reject(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("HKDF base key gen failed: CKR_MECHANISM_INVALID")

    monkeypatch.setattr(test_mech_derive, "_derive_hkdf", _derive_reject)

    with pytest.raises(AssertionError, match="HKDF base key gen failed") as ei:
        test_mech_derive.TestMechDerive().test_derive_produces_key(
            _session(),
            _entry(int(CKM_HKDF_DERIVE), "CKM_HKDF_DERIVE"),
        )
    assert not isinstance(ei.value, pytest.xfail.Exception)


def test_hkdf_base_keygen_mech_invalid_is_xfail() -> None:
    """R1 regression: HKDF base-keygen CKR_MECHANISM_INVALID -> xfail not-operational.

    When CKM_HKDF_KEY_GEN returns CKR_MECHANISM_INVALID (NSS genuinely lacks it),
    the assert in _gen_hkdf_base_key must raise CkrAssertionError (via expect_rv)
    so the claim layer can classify it as not-operational and xfail.

    RED before fix: plain assert -> bare AssertionError escapes claim layer -> hard FAIL.
    GREEN after fix: expect_rv raises CkrAssertionError -> claim_refusal_passes -> xfail.

    Hard-pin: an unexpected skip instead of xfail is a regression -> pytest.fail.
    """
    rs = _session_with_keygen_reject(int(CKR_MECHANISM_INVALID))
    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            test_mech_derive.TestMechDerive().test_derive_produces_key(
                rs,
                _entry(int(CKM_HKDF_DERIVE), "CKM_HKDF_DERIVE"),
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_xor_base_keygen_mech_invalid_is_xfail() -> None:
    """R1 regression: XOR/generic-secret base-keygen CKR_MECHANISM_INVALID -> xfail.

    When CKM_GENERIC_SECRET_KEY_GEN returns CKR_MECHANISM_INVALID (pkcs11-mock),
    gen_generic_secret's assert must raise CkrAssertionError (via expect_rv)
    so the claim layer classifies it as not-operational and xfails.

    RED before fix: plain assert -> bare AssertionError escapes claim layer -> hard FAIL.
    GREEN after fix: expect_rv raises CkrAssertionError -> claim_refusal_passes -> xfail.

    Hard-pin: an unexpected skip instead of xfail is a regression -> pytest.fail.
    """
    rs = _session_with_keygen_reject(int(CKR_MECHANISM_INVALID))
    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            test_mech_derive.TestMechDerive().test_derive_produces_key(
                rs,
                _entry(int(CKM_XOR_BASE_AND_DATA), "CKM_XOR_BASE_AND_DATA"),
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")
