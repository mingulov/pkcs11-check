"""Meta-test: ProvisioningProfile._probe_private verdict routing (no real module needed).

Uses monkeypatch to stub import_ec_private_key and destroy_quietly so all three
create-availability verdicts can be exercised without a real PKCS#11 module.
Mirrors tests/test_provisioning_profile.py pattern for the secret-key probe.
"""

from __future__ import annotations

import pytest

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCONSISTENT,
)


def _make_rs(sh: int, *, has_mech: bool) -> object:
    """Synthetic RS object: no real module; has_mechanism always returns has_mech."""
    return type(
        "RS",
        (),
        {
            "raw": object(),
            "sh": sh,
            "slot_id": 0,
            "has_mechanism": lambda self, n: has_mech,
        },
    )()


def _reset_cache() -> None:
    _prov._PROFILE_CACHE.clear()


# ---------------------------------------------------------------------------
# create_available: import_ec_private_key returns a valid handle; destroy_quietly called
# ---------------------------------------------------------------------------


def test_private_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []

    def fake_import(
        raw: object,
        sh: int,
        *,
        ec_params: bytes,
        value: bytes,
        attrs: object = None,
    ) -> int:
        return 42

    def fake_destroy(raw: object, sh: int, handle: int) -> None:
        destroyed.append(handle)

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_private_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    rs = _make_rs(sh=101, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("private") == "create_available"
    assert destroyed == [42], "handle must be destroyed after successful probe"


# ---------------------------------------------------------------------------
# create_absent: import_ec_private_key raises CkrAssertionError(CKR_FUNCTION_NOT_SUPPORTED)
# ---------------------------------------------------------------------------


def test_private_create_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(
        raw: object,
        sh: int,
        *,
        ec_params: bytes,
        value: bytes,
        attrs: object = None,
    ) -> int:
        raise CkrAssertionError("not supported", int(CKR_FUNCTION_NOT_SUPPORTED))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_private_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=102, has_mech=False)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("private") == "create_absent"


# ---------------------------------------------------------------------------
# create_prohibited: import_ec_private_key raises a code in _CREATE_PROHIBITED_RVS
# ---------------------------------------------------------------------------


def test_private_create_prohibited(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(
        raw: object,
        sh: int,
        *,
        ec_params: bytes,
        value: bytes,
        attrs: object = None,
    ) -> int:
        raise CkrAssertionError("template inconsistent", int(CKR_TEMPLATE_INCONSISTENT))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_private_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=103, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("private") == "create_prohibited"


# ---------------------------------------------------------------------------
# unexpected CKR re-raises (not silently swallowed)
# ---------------------------------------------------------------------------


def test_private_unexpected_ckr_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(
        raw: object,
        sh: int,
        *,
        ec_params: bytes,
        value: bytes,
        attrs: object = None,
    ) -> int:
        raise CkrAssertionError("device error", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_private_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=104, has_mech=True)
    prof = _prov.profile_for(rs)
    with pytest.raises(CkrAssertionError):
        prof.create_verdict("private")
