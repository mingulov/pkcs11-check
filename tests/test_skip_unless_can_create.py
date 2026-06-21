"""Meta-tests: skip_unless_can_create per-class robust guard.

Uses monkeypatch to stub the underlying create_object / import_ec_public_key recipes
so all three create-availability verdicts can be exercised without a real PKCS#11 module.
Mirrors tests/test_provisioning_profile_classes.py for the fake-rs + monkeypatch recipe.
"""

from __future__ import annotations

import pytest

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCONSISTENT,
)


def _make_rs(sh: int) -> object:
    """Synthetic RS object: no real module."""
    return type(
        "RS",
        (),
        {
            "raw": object(),
            "sh": sh,
            "slot_id": 0,
            "has_mechanism": lambda self, n: True,
        },
    )()


def _reset_cache() -> None:
    _prov._PROFILE_CACHE.clear()


def _make_fake_create_object(rv: int | None, *, handle: int = 77) -> object:
    """Return a fake create_object that raises CkrAssertionError(rv) or returns handle."""
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake(raw: object, sh: int, template: object) -> int:
        if rv is not None:
            raise CkrAssertionError("fake", int(rv))
        return handle

    return fake


# ===========================================================================
# create_available: skip_unless_can_create returns normally (no skip raised)
# ===========================================================================


def test_skip_unless_can_create_available_data(monkeypatch: pytest.MonkeyPatch) -> None:
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
    _prov.clear_provisioning_events()

    rs = _make_rs(sh=301)
    # Must not raise pytest.skip.Exception
    _prov.skip_unless_can_create(rs, "data")
    # No skipped_no_path event should be recorded
    events = _prov.get_provisioning_events()
    assert not any(e.method == "skipped_no_path" for e in events)


def test_skip_unless_can_create_available_public(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.import_ec_public_key",
        lambda raw, sh, *, ec_params, ec_point, **kw: destroyed.append(99) or 99,
    )
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.destroy_quietly",
        lambda raw, sh, h: destroyed.append(h),
    )
    _reset_cache()
    _prov.clear_provisioning_events()

    rs = _make_rs(sh=302)
    _prov.skip_unless_can_create(rs, "public")
    events = _prov.get_provisioning_events()
    assert not any(e.method == "skipped_no_path" for e in events)


# ===========================================================================
# create_absent: raises pytest.skip.Exception AND records skipped_no_path event
# ===========================================================================


def test_skip_unless_can_create_absent_data(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_FUNCTION_NOT_SUPPORTED)),
    )
    _reset_cache()
    _prov.clear_provisioning_events()

    rs = _make_rs(sh=303)
    with pytest.raises(pytest.skip.Exception):
        _prov.skip_unless_can_create(rs, "data")

    events = _prov.get_provisioning_events()
    assert any(e.obj_class == "data" and e.method == "skipped_no_path" for e in events), (
        "skipped_no_path event must be recorded for create_absent"
    )


# ===========================================================================
# create_prohibited: raises pytest.skip.Exception
# ===========================================================================


def test_skip_unless_can_create_prohibited_data(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object",
        _make_fake_create_object(int(CKR_TEMPLATE_INCONSISTENT)),
    )
    _reset_cache()
    _prov.clear_provisioning_events()

    rs = _make_rs(sh=304)
    with pytest.raises(pytest.skip.Exception):
        _prov.skip_unless_can_create(rs, "data")

    events = _prov.get_provisioning_events()
    assert any(e.obj_class == "data" and e.method == "skipped_no_path" for e in events), (
        "skipped_no_path event must be recorded for create_prohibited"
    )


def test_skip_unless_can_create_prohibited_public(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.import_ec_public_key",
        lambda raw, sh, *, ec_params, ec_point, **kw: (_ for _ in ()).throw(
            CkrAssertionError("template inconsistent", int(CKR_TEMPLATE_INCONSISTENT))
        ),
    )
    _reset_cache()
    _prov.clear_provisioning_events()

    rs = _make_rs(sh=305)
    with pytest.raises(pytest.skip.Exception):
        _prov.skip_unless_can_create(rs, "public")
