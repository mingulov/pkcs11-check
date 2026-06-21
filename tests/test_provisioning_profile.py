"""Meta-test: ProvisioningProfile verdict routing and supports_unwrap_mech (no real module needed).

Uses monkeypatch to stub import_secret_key and destroy_quietly so all three
create-availability verdicts can be exercised without a real PKCS#11 module.
Follows the pattern of tests/test_import_ec_private_key_negotiated.py.
"""

from __future__ import annotations

import pytest

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_UNEXTRACTABLE,
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
# create_available: import_secret_key returns a valid handle; destroy_quietly called
# ---------------------------------------------------------------------------


def test_create_available_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        return 77

    def fake_destroy(raw: object, sh: int, handle: int) -> None:
        destroyed.append(handle)

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    rs = _make_rs(sh=1, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("secret") == "create_available"
    assert destroyed == [77], "handle must be destroyed after successful probe"


# ---------------------------------------------------------------------------
# create_absent: import_secret_key raises CkrAssertionError(CKR_FUNCTION_NOT_SUPPORTED)
# ---------------------------------------------------------------------------


def test_create_absent_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        raise CkrAssertionError("not supported", int(CKR_FUNCTION_NOT_SUPPORTED))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=2, has_mech=False)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("secret") == "create_absent"


# ---------------------------------------------------------------------------
# create_prohibited: import_secret_key raises a code in _CREATE_PROHIBITED_RVS
# ---------------------------------------------------------------------------


def test_create_prohibited_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        raise CkrAssertionError("template inconsistent", int(CKR_TEMPLATE_INCONSISTENT))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=3, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("secret") == "create_prohibited"


def test_create_prohibited_via_attribute_value_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        raise CkrAssertionError("attr invalid", int(CKR_ATTRIBUTE_VALUE_INVALID))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=4, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("secret") == "create_prohibited"


def test_create_prohibited_via_key_function_not_permitted(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        raise CkrAssertionError("function not permitted", int(CKR_KEY_FUNCTION_NOT_PERMITTED))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=10, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("secret") == "create_prohibited"


def test_create_prohibited_via_key_unextractable(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        raise CkrAssertionError("key unextractable", int(CKR_KEY_UNEXTRACTABLE))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=11, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.create_verdict("secret") == "create_prohibited"


# ---------------------------------------------------------------------------
# unexpected CKR re-raises (not silently swallowed)
# ---------------------------------------------------------------------------


def test_unexpected_ckr_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        raise CkrAssertionError("general error", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    _reset_cache()

    rs = _make_rs(sh=5, has_mech=True)
    prof = _prov.profile_for(rs)
    with pytest.raises(CkrAssertionError):
        prof.create_verdict("secret")


# ---------------------------------------------------------------------------
# supports_unwrap_mech reflects has_mechanism on the RS
# ---------------------------------------------------------------------------


def test_supports_unwrap_mech_true() -> None:
    from pkcs11_check.raw.types_std import CKM_RSA_AES_KEY_WRAP

    _reset_cache()

    rs = _make_rs(sh=6, has_mech=True)
    prof = _prov.profile_for(rs)
    assert prof.supports_unwrap_mech(int(CKM_RSA_AES_KEY_WRAP)) is True


def test_supports_unwrap_mech_false() -> None:
    from pkcs11_check.raw.types_std import CKM_AES_KEY_WRAP_KWP

    _reset_cache()

    rs = _make_rs(sh=7, has_mech=False)
    prof = _prov.profile_for(rs)
    assert prof.supports_unwrap_mech(int(CKM_AES_KEY_WRAP_KWP)) is False


# ---------------------------------------------------------------------------
# caching: profile_for returns same object for same sh
# ---------------------------------------------------------------------------


def test_profile_cached_by_sh(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        return 99

    def fake_destroy(raw: object, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    rs = _make_rs(sh=8, has_mech=True)
    prof1 = _prov.profile_for(rs)
    rs2 = _make_rs(sh=8, has_mech=True)
    prof2 = _prov.profile_for(rs2)
    assert prof1 is prof2, "profile_for must cache by rs.sh"


# ---------------------------------------------------------------------------
# verdict cached: second call does not re-probe (create_verdict returns cached)
# ---------------------------------------------------------------------------


def test_verdict_cached_on_second_call(monkeypatch: pytest.MonkeyPatch) -> None:
    call_count: list[int] = []

    def fake_import(raw: object, sh: int, key_type: object, value: bytes, attrs: object) -> int:
        call_count.append(1)
        return 20

    def fake_destroy(raw: object, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    rs = _make_rs(sh=9, has_mech=True)
    prof = _prov.profile_for(rs)
    prof.create_verdict("secret")
    prof.create_verdict("secret")  # second call
    assert len(call_count) == 1, "probe must only run once; verdict is cached"
