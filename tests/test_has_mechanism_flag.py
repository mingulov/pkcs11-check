"""Meta-tests for RawSession.has_mechanism_flag (no real module needed)."""

from __future__ import annotations

from pkcs11_check import fixtures
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKF_SIGN, CKF_VERIFY, CKM_RSA_PKCS


def _session(monkeypatch, *, flags: int, mechanisms=("CKM_RSA_PKCS", "RSA_PKCS"), raises=False):
    """Build a RawSession without a real module and stub C_GetMechanismInfo."""
    fixtures._MECH_INFO_CACHE.clear()
    rs = fixtures.RawSession.__new__(fixtures.RawSession)
    object.__setattr__(rs, "raw", object())
    object.__setattr__(rs, "sh", 0)
    object.__setattr__(rs, "slot_id", 0)
    object.__setattr__(rs, "_mechanisms", frozenset(mechanisms))

    calls = {"n": 0}

    def fake_get_mechanism_info(raw, slot_id, mech):
        calls["n"] += 1
        if raises:
            raise CkrAssertionError("C_GetMechanismInfo failed", 0)
        return {"min_key_size": 0, "max_key_size": 0, "flags": flags}

    monkeypatch.setattr("pkcs11_check.raw.recipes.get_mechanism_info", fake_get_mechanism_info)
    return rs, calls


def test_flag_present_by_name(monkeypatch):
    rs, _ = _session(monkeypatch, flags=int(CKF_SIGN) | int(CKF_VERIFY))
    assert rs.has_mechanism_flag("RSA_PKCS", int(CKF_VERIFY)) is True


def test_flag_absent_by_name(monkeypatch):
    rs, _ = _session(monkeypatch, flags=int(CKF_SIGN))  # no CKF_VERIFY
    assert rs.has_mechanism_flag("CKM_RSA_PKCS", int(CKF_VERIFY)) is False


def test_int_mechanism_accepted(monkeypatch):
    rs, _ = _session(monkeypatch, flags=int(CKF_VERIFY))
    assert rs.has_mechanism_flag(int(CKM_RSA_PKCS), int(CKF_VERIFY)) is True


def test_unadvertised_mechanism_returns_false(monkeypatch):
    rs, calls = _session(monkeypatch, flags=int(CKF_VERIFY), mechanisms=())
    assert rs.has_mechanism_flag("RSA_PKCS", int(CKF_VERIFY)) is False
    assert calls["n"] == 0  # never queried C_GetMechanismInfo


def test_unknown_name_returns_false(monkeypatch):
    rs, _ = _session(monkeypatch, flags=int(CKF_VERIFY), mechanisms=("NOT_A_REAL_MECH",))
    assert rs.has_mechanism_flag("NOT_A_REAL_MECH", int(CKF_VERIFY)) is False


def test_getmechinfo_error_returns_false(monkeypatch):
    rs, _ = _session(monkeypatch, flags=int(CKF_VERIFY), raises=True)
    assert rs.has_mechanism_flag("RSA_PKCS", int(CKF_VERIFY)) is False


def test_result_is_cached(monkeypatch):
    rs, calls = _session(monkeypatch, flags=int(CKF_VERIFY))
    rs.has_mechanism_flag("RSA_PKCS", int(CKF_VERIFY))
    rs.has_mechanism_flag("RSA_PKCS", int(CKF_SIGN))
    assert calls["n"] == 1  # second call served from _MECH_INFO_CACHE
