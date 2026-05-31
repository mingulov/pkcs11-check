"""Regression tests for PC-3 remainder: tpm2 SHA-1 RSA-PSS "valid sig
rejected" must classify as ``xfail`` (advertised but not operational)
when the provider cannot itself produce a verifying signature for the
same (mech, hash, mgf, sLen) combo.

A `verified=False` return from ``C_Verify`` carries no exception, so
the existing ``xfail_if_known_ckr`` path does not apply. The new
``_pss_combo_operational`` self-roundtrip probe answers the only
question that distinguishes "real provider bug" from "advertised but
not operational" in this shape: can the provider sign+verify a fresh
message with the same PSS params? If not, the combo is xfail; if yes,
the rejection of the known-valid vector is a real ``fail``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_pss as twrp


def _clear_cache() -> None:
    twrp._PSS_COMBO_OPERATIONAL.clear()


def test_combo_probe_returns_true_when_roundtrip_succeeds(monkeypatch: Any) -> None:
    _clear_cache()
    rs = SimpleNamespace(raw=object(), sh=1)
    monkeypatch.setattr(twrp, "gen_rsa_keypair", lambda *_a, **_kw: (10, 11))
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: True)
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)

    assert twrp._pss_combo_operational(rs, 1, 2, 3, 20) is True


def test_combo_probe_returns_false_when_roundtrip_verify_false(monkeypatch: Any) -> None:
    """The SHA-1 PSS tpm2 case: own roundtrip fails -> combo not operational."""
    _clear_cache()
    rs = SimpleNamespace(raw=object(), sh=1)
    monkeypatch.setattr(twrp, "gen_rsa_keypair", lambda *_a, **_kw: (10, 11))
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: False)
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)

    assert twrp._pss_combo_operational(rs, 1, 2, 3, 20) is False


def test_combo_probe_returns_false_when_keygen_rejects(monkeypatch: Any) -> None:
    _clear_cache()
    rs = SimpleNamespace(raw=object(), sh=1)

    def _bad(*_a: Any, **_kw: Any) -> tuple[int, int]:
        raise AssertionError("Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID")

    monkeypatch.setattr(twrp, "gen_rsa_keypair", _bad)
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)

    assert twrp._pss_combo_operational(rs, 1, 2, 3, 20) is False


def test_combo_probe_caches_result_per_combo(monkeypatch: Any) -> None:
    _clear_cache()
    rs = SimpleNamespace(raw=object(), sh=1)

    calls: list[int] = []

    def _keygen(*_a: Any, **_kw: Any) -> tuple[int, int]:
        calls.append(1)
        return (10, 11)

    monkeypatch.setattr(twrp, "gen_rsa_keypair", _keygen)
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: True)
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)

    twrp._pss_combo_operational(rs, 1, 2, 3, 20)
    twrp._pss_combo_operational(rs, 1, 2, 3, 20)
    twrp._pss_combo_operational(rs, 1, 2, 3, 20)
    assert len(calls) == 1  # second + third call use the cache

    twrp._pss_combo_operational(rs, 1, 2, 3, 32)  # different sLen -> re-probe
    assert len(calls) == 2


def test_rsa_pss_valid_rejected_xfails_when_combo_not_operational(monkeypatch: Any) -> None:
    """End-to-end: valid-vector rejected + roundtrip-fails => xfail, not fail."""
    import pytest as _pytest

    _clear_cache()
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _n: True)
    monkeypatch.setattr(twrp, "import_rsa_public_key", lambda *_a, **_kw: 99)
    # The wycheproof verify of the test vector -> False (provider rejects).
    # The probe verify -> False (provider can't verify its own sig either).
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: False)
    monkeypatch.setattr(twrp, "gen_rsa_keypair", lambda *_a, **_kw: (10, 11))
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)
    monkeypatch.setattr(twrp, "generate_random", lambda *_a, **_kw: b"\x00" * 64)

    vec = {
        "msg": "00",
        "sig": "00",
        "result": "valid",
        "_mechanism": 0x0D,  # CKM_RSA_PKCS_PSS
        "_hash_mech": 0x0220,  # CKM_SHA_1
        "_mgf": 1,  # CKG_MGF1_SHA1
        "_sLen": 20,
        "_group": {"publicKey": {"modulus": "00" * 256, "publicExponent": "010001"}},
    }
    with _pytest.raises(_pytest.xfail.Exception):
        twrp.test_rsa_pss(rs, "rsa_pss_2048_sha1_mgf1_20_params:tc1-valid", vec)


def test_rsa_pss_valid_rejected_fails_when_combo_operational(monkeypatch: Any) -> None:
    """End-to-end: valid-vector rejected + roundtrip-succeeds => real fail."""
    import pytest as _pytest

    _clear_cache()
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _n: True)
    monkeypatch.setattr(twrp, "import_rsa_public_key", lambda *_a, **_kw: 99)
    # Drive vector-verify = False but probe-verify = True (operational).
    verify_results = iter([False, True])
    monkeypatch.setattr(twrp, "verify_single", lambda *_a, **_kw: next(verify_results))
    monkeypatch.setattr(twrp, "gen_rsa_keypair", lambda *_a, **_kw: (10, 11))
    monkeypatch.setattr(twrp, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(twrp, "destroy_quietly", lambda *_a, **_kw: None)
    monkeypatch.setattr(twrp, "generate_random", lambda *_a, **_kw: b"\x00" * 64)

    vec = {
        "msg": "00",
        "sig": "00",
        "result": "valid",
        "_mechanism": 0x0D,
        "_hash_mech": 0x0250,
        "_mgf": 2,
        "_sLen": 32,
        "_group": {"publicKey": {"modulus": "00" * 256, "publicExponent": "010001"}},
    }
    with _pytest.raises(_pytest.fail.Exception):
        twrp.test_rsa_pss(rs, "rsa_pss_2048_sha256_mgf1_32_params:tc1-valid", vec)
