"""Meta-tests: ProvisioningProfile probes for public/cert/data object classes.

Uses monkeypatch to stub the underlying recipe (import_ec_public_key / create_object)
in the pkcs11_check.raw.recipes namespace so all three create-availability verdicts
can be exercised without a real PKCS#11 module.
Mirrors tests/test_provisioning_profile_private.py.
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
# Helpers shared across classes
# ---------------------------------------------------------------------------


def _make_fake_import_ec_public_key(rv: int | None, *, handle: int = 99) -> object:
    """Return a fake import_ec_public_key that raises CkrAssertionError(rv) or returns handle."""
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake(raw: object, sh: int, *, ec_params: bytes, ec_point: bytes, **kw: object) -> int:
        if rv is not None:
            raise CkrAssertionError("fake", int(rv))
        return handle

    return fake


def _make_fake_create_object(rv: int | None, *, handle: int = 77) -> object:
    """Return a fake create_object that raises CkrAssertionError(rv) or returns handle."""
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake(raw: object, sh: int, template: object) -> int:
        if rv is not None:
            raise CkrAssertionError("fake", int(rv))
        return handle

    return fake


# ===========================================================================
# _probe_public
# ===========================================================================


def test_public_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.import_ec_public_key",
        _make_fake_import_ec_public_key(None, handle=99),
    )
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.destroy_quietly",
        lambda raw, sh, h: destroyed.append(h),
    )
    _reset_cache()

    rs = _make_rs(sh=201, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("public") == "create_available"
    assert destroyed == [99], "handle must be destroyed after successful probe"


def test_public_create_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.import_ec_public_key",
        _make_fake_import_ec_public_key(int(CKR_FUNCTION_NOT_SUPPORTED)),
    )
    _reset_cache()

    rs = _make_rs(sh=202, has_mech=False)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("public") == "create_absent"


def test_public_create_prohibited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.import_ec_public_key",
        _make_fake_import_ec_public_key(int(CKR_TEMPLATE_INCONSISTENT)),
    )
    _reset_cache()

    rs = _make_rs(sh=203, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("public") == "create_prohibited"


def test_public_unexpected_ckr_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.import_ec_public_key",
        _make_fake_import_ec_public_key(int(CKR_DEVICE_ERROR)),
    )
    _reset_cache()

    rs = _make_rs(sh=204, has_mech=True)
    prof = _prov.profile_for(rs)
    with pytest.raises(CkrAssertionError):
        prof.create_verdict("public")


# ===========================================================================
# _probe_cert
# ===========================================================================


def test_cert_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(None, handle=77),
    )
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.destroy_quietly",
        lambda raw, sh, h: destroyed.append(h),
    )
    _reset_cache()

    rs = _make_rs(sh=211, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("cert") == "create_available"
    assert destroyed == [77], "handle must be destroyed after successful probe"


def test_cert_create_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_FUNCTION_NOT_SUPPORTED)),
    )
    _reset_cache()

    rs = _make_rs(sh=212, has_mech=False)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("cert") == "create_absent"


def test_cert_create_prohibited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_TEMPLATE_INCONSISTENT)),
    )
    _reset_cache()

    rs = _make_rs(sh=213, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("cert") == "create_prohibited"


def test_cert_unexpected_ckr_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_DEVICE_ERROR)),
    )
    _reset_cache()

    rs = _make_rs(sh=214, has_mech=True)
    prof = _prov.profile_for(rs)
    with pytest.raises(CkrAssertionError):
        prof.create_verdict("cert")


# ===========================================================================
# _probe_data
# ===========================================================================


def test_data_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(None, handle=55),
    )
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.destroy_quietly",
        lambda raw, sh, h: destroyed.append(h),
    )
    _reset_cache()

    rs = _make_rs(sh=221, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("data") == "create_available"
    assert destroyed == [55], "handle must be destroyed after successful probe"


def test_data_create_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_FUNCTION_NOT_SUPPORTED)),
    )
    _reset_cache()

    rs = _make_rs(sh=222, has_mech=False)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("data") == "create_absent"


def test_data_create_prohibited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_TEMPLATE_INCONSISTENT)),
    )
    _reset_cache()

    rs = _make_rs(sh=223, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("data") == "create_prohibited"


def test_data_unexpected_ckr_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_DEVICE_ERROR)),
    )
    _reset_cache()

    rs = _make_rs(sh=224, has_mech=True)
    prof = _prov.profile_for(rs)
    with pytest.raises(CkrAssertionError):
        prof.create_verdict("data")
