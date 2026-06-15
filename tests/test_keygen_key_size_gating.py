"""Meta-tests for the advertised-key-size keygen/siggen gate.

``keygen_key_size_supported`` / ``require_keygen_key_size`` (in
``testcases/conftest.py``) gate ACVP keygen/siggen on the module's advertised
``C_GetMechanismInfo`` min/max for the keygen mechanism. A size inside the
advertised range proceeds; a size outside it is a genuine capability absence
(``pytest.skip``). The EC field-bits trap matters: P-521's compared value is
521 (curve field bits), NOT 528 (coord_len*8), so a module advertising max=521
must accept P-521.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases.conftest import (
    keygen_key_size_supported,
    require_keygen_key_size,
)


def _patch_info(monkeypatch: pytest.MonkeyPatch, *, min_key: int, max_key: int) -> None:
    """Make the conftest helper see an advertised [min_key, max_key] range."""

    def _fake(_raw: Any, _slot: int, _mech: int) -> dict[str, int]:
        return {"min_key_size": min_key, "max_key_size": max_key, "flags": 0}

    monkeypatch.setattr("pkcs11_check.raw.recipes.get_mechanism_info", _fake)


def _rs(*, advertised: bool) -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        slot_id=0,
        has_mechanism=lambda _name: advertised,
    )


# --- RSA: modulus bits compared against advertised range -----------------------


def test_rsa_in_range_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_info(monkeypatch, min_key=2048, max_key=4096)
    rs = _rs(advertised=True)
    assert keygen_key_size_supported(rs, "RSA_PKCS_KEY_PAIR_GEN", 2048) is True
    assert keygen_key_size_supported(rs, "RSA_PKCS_KEY_PAIR_GEN", 4096) is True
    # require_* must return (not skip) for an in-range size.
    require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", 3072, label="rsa-in")


def test_rsa_below_min_not_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_info(monkeypatch, min_key=2048, max_key=2048)
    rs = _rs(advertised=True)
    assert keygen_key_size_supported(rs, "RSA_PKCS_KEY_PAIR_GEN", 1024) is False
    with pytest.raises(pytest.skip.Exception):
        require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", 1024, label="rsa-below")


def test_rsa_above_max_not_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    # jcardsim: RSA_PKCS_KEY_PAIR_GEN min=max=2048 -> 3072/4096 out of range.
    _patch_info(monkeypatch, min_key=2048, max_key=2048)
    rs = _rs(advertised=True)
    assert keygen_key_size_supported(rs, "RSA_PKCS_KEY_PAIR_GEN", 3072) is False
    assert keygen_key_size_supported(rs, "RSA_PKCS_KEY_PAIR_GEN", 4096) is False
    with pytest.raises(pytest.skip.Exception):
        require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", 4096, label="rsa-above")


def test_mechanism_not_advertised_not_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    # has_mechanism False short-circuits before the info query is even consulted.
    _patch_info(monkeypatch, min_key=2048, max_key=4096)
    rs = _rs(advertised=False)
    assert keygen_key_size_supported(rs, "RSA_PKCS_KEY_PAIR_GEN", 2048) is False
    with pytest.raises(pytest.skip.Exception):
        require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", 2048, label="rsa-absent")


def test_info_error_not_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    # C_GetMechanismInfo erroring -> False (never raises).
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED

    def _raise(_raw: Any, _slot: int, _mech: int) -> dict[str, int]:
        raise CkrAssertionError("boom", rv=int(CKR_FUNCTION_FAILED))

    monkeypatch.setattr("pkcs11_check.raw.recipes.get_mechanism_info", _raise)
    rs = _rs(advertised=True)
    assert keygen_key_size_supported(rs, "RSA_PKCS_KEY_PAIR_GEN", 2048) is False
    with pytest.raises(pytest.skip.Exception):
        require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", 2048, label="rsa-info-err")


# --- EC: field-bits trap (P-521 == 521, not 528) -------------------------------


def test_ec_p521_in_range_when_max_521(monkeypatch: pytest.MonkeyPatch) -> None:
    """P-521's compared value is 521 (field bits) -- in range when max=521.

    The trap: coord_len*8 = 66*8 = 528 would wrongly mark P-521 out of range.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    assert ec.SECP521R1().key_size == 521  # the value the gate must use
    _patch_info(monkeypatch, min_key=256, max_key=521)
    rs = _rs(advertised=True)
    assert keygen_key_size_supported(rs, "EC_KEY_PAIR_GEN", 521) is True
    require_keygen_key_size(rs, "EC_KEY_PAIR_GEN", 521, label="p521-in")


def test_ec_p521_out_of_range_when_max_384(monkeypatch: pytest.MonkeyPatch) -> None:
    # jcardsim: EC_KEY_PAIR_GEN 192-384 -> P-521 (521) out of range.
    _patch_info(monkeypatch, min_key=192, max_key=384)
    rs = _rs(advertised=True)
    assert keygen_key_size_supported(rs, "EC_KEY_PAIR_GEN", 521) is False
    assert keygen_key_size_supported(rs, "EC_KEY_PAIR_GEN", 256) is True
    assert keygen_key_size_supported(rs, "EC_KEY_PAIR_GEN", 384) is True
    with pytest.raises(pytest.skip.Exception):
        require_keygen_key_size(rs, "EC_KEY_PAIR_GEN", 521, label="p521-out")
