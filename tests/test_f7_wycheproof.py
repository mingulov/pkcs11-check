"""Regression tests for the remaining Wycheproof suites' attribute-readback
classification (F7 slice 11).

Exercises the migrated call sites in ``src/pkcs11_check/testcases/wycheproof/``
directly (not through pytest collection of those files, which needs a real
PKCS#11 module) by monkeypatching each file's collaborator functions and
invoking the parametrized test function with a synthetic session and vector.
Each test proves a specific behavior contract from
``.superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/f7-migration-contract.md``:
a missing ``CKA_VALUE`` produces a structured, mechanism-free record instead of
a ``KeyError``/crash; independent work in the same test still runs (including a
crypto self-contradiction that does not depend on the missing value); handles
are still destroyed; and a present-but-wrong value still fails hard.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as aes_mod
from pkcs11_check.testcases.wycheproof import test_wycheproof_ecdh as ecdh_mod
from pkcs11_check.testcases.wycheproof import test_wycheproof_hkdf as hkdf_mod
from pkcs11_check.testcases.wycheproof import test_wycheproof_mlkem as mlkem_mod
from pkcs11_check.testcases.wycheproof import test_wycheproof_pbkdf2 as pbkdf2_mod
from pkcs11_check.testcases.wycheproof import test_wycheproof_x25519 as xdh_mod

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name in advertised)


def _boom(label: str) -> Any:
    def _f(*_a: Any, **_k: Any) -> Any:
        raise AssertionError(f"{label} must not run when the readback value is missing")

    return _f


def _call_expecting_no_xfail_escape(fn: Any, *args: Any, **kwargs: Any) -> None:
    """Call ``fn`` and hard-fail if a ``pytest.xfail`` escapes it.

    The migrated call site records the missing-attribute observation via
    ``attr_or_record()`` -- which only appends a record, it never raises -- and
    returns normally. The pre-migration site called ``classify()`` directly, which
    raises ``pytest.xfail`` (``_pytest.outcomes.XFailed``) internally; because ``fn``
    is invoked directly rather than collected as its own pytest item, that exception
    would otherwise propagate straight through this wrapper test and pytest would
    report *this* regression test as xfailed, not failed -- exactly the silent-green
    reversion this suite exists to catch (outcome-class hard-pin, e0340c2d pattern:
    see ``tests/test_acvp_ecdh_runtime.py``). Convert it to a hard failure instead.
    """
    try:
        fn(*args, **kwargs)
    except pytest.xfail.Exception as exc:
        pytest.fail(
            "reverted to a raw classify()-based pytest.xfail instead of the "
            f"structured, non-raising attr_or_record() readback path: {exc}"
        )


# --- AES-KW: test_wycheproof_aes.test_aes_key_wrap -------------------------------------


def _patch_aes_kw(
    monkeypatch: pytest.MonkeyPatch, *, attrs: dict[Any, Any], destroyed: list[int]
) -> None:
    monkeypatch.setattr(aes_mod, "import_secret_key_negotiated", lambda *_a, **_k: 10)
    monkeypatch.setattr(aes_mod, "_unwrap_aes_kw_adaptive", lambda *_a, **_k: 11)
    monkeypatch.setattr(aes_mod, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(aes_mod, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))


def test_aes_kw_missing_value_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing unwrapped CKA_VALUE must not KeyError; it records honest_deviation."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    _patch_aes_kw(monkeypatch, attrs={}, destroyed=destroyed)
    monkeypatch.setattr(aes_mod, "assert_correct", _boom("assert_correct"))

    vec = {"key": "00" * 16, "msg": "11" * 8, "ct": "22" * 16, "result": "valid"}
    _call_expecting_no_xfail_escape(
        aes_mod.test_aes_key_wrap, _rs("AES_KEY_WRAP"), "tc1-valid", vec
    )

    # Both the wrap-key and the unwrapped-key handles are destroyed before the
    # readback is even inspected -- cleanup never depends on attribute presence.
    assert destroyed == [10, 11]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "honest_deviation"
    assert rec.outcome == "xfail"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_aes_kw_present_but_wrong_value_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-wrong unwrapped CKA_VALUE must still fail hard (wrong_result)."""
    destroyed: list[int] = []
    _patch_aes_kw(monkeypatch, attrs={CKA_VALUE: b"\x00" * 8}, destroyed=destroyed)

    vec = {"key": "00" * 16, "msg": "11" * 8, "ct": "22" * 16, "result": "valid"}
    with pytest.raises(pytest.fail.Exception):
        aes_mod.test_aes_key_wrap(_rs("AES_KEY_WRAP"), "tc1-valid", vec)

    assert destroyed == [10, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# --- ECDH: test_wycheproof_ecdh.test_ecdh -----------------------------------------------


def _patch_ecdh(
    monkeypatch: pytest.MonkeyPatch,
    *,
    attrs: dict[Any, Any],
    destroyed: list[int],
    point_on_base_curve: bool | None,
) -> None:
    monkeypatch.setattr(ecdh_mod, "_UNSUPPORTED_CURVES", set())
    monkeypatch.setattr(ecdh_mod, "ec_params_for_curve", lambda _curve: b"oid")
    monkeypatch.setattr(
        ecdh_mod, "decode_ec_public_point", lambda *_a, **_k: b"\x04" + b"\x01" * 64
    )
    monkeypatch.setattr(ecdh_mod, "decode_ec_private_scalar", lambda *_a, **_k: b"\x02" * 32)
    monkeypatch.setattr(ecdh_mod, "ec_key_bits", lambda _curve: 256)
    monkeypatch.setattr(ecdh_mod, "provision_ec_private_key", lambda *_a, **_k: 20)
    monkeypatch.setattr(ecdh_mod, "derive_key", lambda *_a, **_k: 21)
    monkeypatch.setattr(ecdh_mod, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(ecdh_mod, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    monkeypatch.setattr(ecdh_mod, "_point_on_base_curve", lambda *_a, **_k: point_on_base_curve)


def _ecdh_vec(result: str) -> dict[str, Any]:
    return {
        "_curve": "secp256r1",
        "_encoding": "raw",
        "public": "unused",
        "private": "unused",
        "shared": "aa" * 32,
        "result": result,
    }


def test_ecdh_valid_missing_value_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing derived CKA_VALUE on a valid vector must skip the KAT compare only."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    _patch_ecdh(monkeypatch, attrs={}, destroyed=destroyed, point_on_base_curve=None)
    monkeypatch.setattr(ecdh_mod, "assert_correct", _boom("assert_correct"))

    ecdh_mod.test_ecdh(_rs("ECDH1_DERIVE"), object(), "tc1-valid", _ecdh_vec("valid"))

    assert destroyed == [21, 20]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_ecdh_invalid_offcurve_still_flags_even_with_missing_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The off-base-curve crypto contradiction must fire even when CKA_VALUE is missing.

    This is the rule-4/5 case: a missing readback must never suppress an independent
    self-contradiction oracle that does not itself need the value's bytes.
    """
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    _patch_ecdh(monkeypatch, attrs={}, destroyed=destroyed, point_on_base_curve=False)

    with pytest.raises(pytest.fail.Exception):
        ecdh_mod.test_ecdh(_rs("ECDH1_DERIVE"), object(), "tc2-invalid", _ecdh_vec("invalid"))

    assert destroyed == [21, 20]
    records = C.get_records()
    assert len(records) == 2
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert records[1].reason == "accepted_invalid"
    assert records[1].kind == "crypto"


def test_ecdh_valid_present_but_wrong_value_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-wrong derived CKA_VALUE must still fail hard (wrong_result)."""
    destroyed: list[int] = []
    _patch_ecdh(
        monkeypatch,
        attrs={CKA_VALUE: b"\x00" * 32},
        destroyed=destroyed,
        point_on_base_curve=None,
    )

    with pytest.raises(pytest.fail.Exception):
        ecdh_mod.test_ecdh(_rs("ECDH1_DERIVE"), object(), "tc1-valid", _ecdh_vec("valid"))

    assert destroyed == [21, 20]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# --- HKDF: test_wycheproof_hkdf.test_hkdf -----------------------------------------------


def _patch_hkdf(
    monkeypatch: pytest.MonkeyPatch, *, attrs: dict[Any, Any], destroyed: list[int]
) -> None:
    monkeypatch.setattr(hkdf_mod, "import_secret_key_negotiated", lambda *_a, **_k: 30)
    monkeypatch.setattr(hkdf_mod, "derive_key", lambda *_a, **_k: 31)
    monkeypatch.setattr(hkdf_mod, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(hkdf_mod, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))


def _hkdf_vec(result: str) -> dict[str, Any]:
    return {
        "ikm": "00" * 16,
        "salt": "01" * 16,
        "info": "",
        "okm": "aa" * 32,
        "size": 32,
        "result": result,
        "_sha": "SHA-256",
    }


def test_hkdf_missing_value_is_structured_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing derived HKDF CKA_VALUE must not KeyError; it records not_operational."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    _patch_hkdf(monkeypatch, attrs={}, destroyed=destroyed)
    monkeypatch.setattr(hkdf_mod, "assert_correct", _boom("assert_correct"))

    _call_expecting_no_xfail_escape(
        hkdf_mod.test_hkdf, _rs("HKDF_DERIVE"), "tc1-valid", _hkdf_vec("valid")
    )

    assert destroyed == [31, 30]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_hkdf_present_but_wrong_value_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-wrong derived HKDF CKA_VALUE must still fail hard (wrong_result)."""
    destroyed: list[int] = []
    _patch_hkdf(monkeypatch, attrs={CKA_VALUE: b"\x00" * 32}, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        hkdf_mod.test_hkdf(_rs("HKDF_DERIVE"), "tc1-valid", _hkdf_vec("valid"))

    assert destroyed == [31, 30]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# --- ML-KEM: test_wycheproof_mlkem.test_mlkem_decaps ------------------------------------


def _patch_mlkem(
    monkeypatch: pytest.MonkeyPatch, *, attrs: dict[Any, Any], destroyed: list[int]
) -> None:
    monkeypatch.setattr(mlkem_mod, "import_pqc_private_key", lambda *_a, **_k: 40)
    monkeypatch.setattr(mlkem_mod, "decapsulate_key", lambda *_a, **_k: 41)
    monkeypatch.setattr(mlkem_mod, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(mlkem_mod, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))


def _mlkem_vec(result: str) -> dict[str, Any]:
    return {
        "_group": {},
        "dk": "00" * 32,
        "ct": "11" * 32,
        "K": "aa" * 32,
        "result": result,
        "_parameter_set": 512,
    }


def test_mlkem_missing_value_is_structured_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing decapsulated CKA_VALUE must not KeyError; it records honest_deviation."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    _patch_mlkem(monkeypatch, attrs={}, destroyed=destroyed)
    monkeypatch.setattr(mlkem_mod, "assert_correct", _boom("assert_correct"))

    _call_expecting_no_xfail_escape(
        mlkem_mod.test_mlkem_decaps, "tc1-valid", _mlkem_vec("valid"), _rs("ML_KEM")
    )

    assert destroyed == [41, 40]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "honest_deviation"
    assert rec.outcome == "xfail"
    assert rec.kind == "lifecycle"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_mlkem_present_but_wrong_value_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-wrong decapsulated CKA_VALUE must still fail hard (wrong_result)."""
    destroyed: list[int] = []
    _patch_mlkem(monkeypatch, attrs={CKA_VALUE: b"\x00" * 32}, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        mlkem_mod.test_mlkem_decaps("tc1-valid", _mlkem_vec("valid"), _rs("ML_KEM"))

    assert destroyed == [41, 40]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# --- PBKDF2: test_wycheproof_pbkdf2.test_pbkdf2 -----------------------------------------


def _patch_pbkdf2(
    monkeypatch: pytest.MonkeyPatch, *, attrs: dict[Any, Any], destroyed: list[int]
) -> None:
    monkeypatch.setattr(pbkdf2_mod, "_generate_key_with_mech", lambda *_a, **_k: 50)
    monkeypatch.setattr(pbkdf2_mod, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(pbkdf2_mod, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))


def _pbkdf2_vec(result: str) -> dict[str, Any]:
    from pkcs11_check.raw.types_std import CKP_PKCS5_PBKD2_HMAC_SHA256

    return {
        "password": "70617373776f7264",
        "salt": "73616c74",
        "iterationCount": 2,
        "dkLen": 32,
        "dk": "aa" * 32,
        "result": result,
        "_prf": CKP_PKCS5_PBKD2_HMAC_SHA256,
        "_prf_name": "hmacsha256",
    }


def test_pbkdf2_missing_value_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing derived PBKDF2 CKA_VALUE must not KeyError; it records not_operational.

    Handle cleanup must not depend on the readback: ``destroy_quietly`` runs
    unconditionally right after the presence check, in the same try block.
    """
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    _patch_pbkdf2(monkeypatch, attrs={}, destroyed=destroyed)
    monkeypatch.setattr(pbkdf2_mod, "assert_correct", _boom("assert_correct"))

    pbkdf2_mod.test_pbkdf2(_rs("PKCS5_PBKD2"), "tc1-valid", _pbkdf2_vec("valid"))

    assert destroyed == [50]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_pbkdf2_present_value_flows_through_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: a present CKA_VALUE still reaches the KAT compare and records nothing
    when it matches, proving the presence helper does not alter the success path."""
    destroyed: list[int] = []
    dk = bytes.fromhex("aa" * 32)
    _patch_pbkdf2(monkeypatch, attrs={CKA_VALUE: dk}, destroyed=destroyed)

    pbkdf2_mod.test_pbkdf2(_rs("PKCS5_PBKD2"), "tc1-valid", _pbkdf2_vec("valid"))

    assert destroyed == [50]
    assert C.get_records() == []


def test_pbkdf2_present_but_wrong_value_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-wrong derived PBKDF2 CKA_VALUE must still fail hard (wrong_result).

    Sibling regression to the other five wycheproof suites in this slice: a readback
    that is present but does not match the KAT expectation is a crypto/metadata
    self-contradiction, never an honest omission, and must not be downgraded by the
    presence helper (rule 7 of the migration contract).
    """
    destroyed: list[int] = []
    _patch_pbkdf2(monkeypatch, attrs={CKA_VALUE: b"\x00" * 32}, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        pbkdf2_mod.test_pbkdf2(_rs("PKCS5_PBKD2"), "tc1-valid", _pbkdf2_vec("valid"))

    assert destroyed == [50]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# --- X25519/X448: test_wycheproof_x25519.test_xdh ---------------------------------------


def _patch_xdh(
    monkeypatch: pytest.MonkeyPatch, *, attrs: dict[Any, Any], destroyed: list[int]
) -> None:
    monkeypatch.setattr(xdh_mod, "_UNSUPPORTED_CURVE_OIDS", set())
    monkeypatch.setattr(xdh_mod, "decode_xdh_private_bytes", lambda *_a, **_k: b"\x02" * 32)
    monkeypatch.setattr(xdh_mod, "decode_xdh_public_bytes", lambda *_a, **_k: b"\x03" * 32)
    monkeypatch.setattr(xdh_mod, "provision_ec_private_key", lambda *_a, **_k: 60)
    monkeypatch.setattr(xdh_mod, "derive_key", lambda *_a, **_k: 61)
    monkeypatch.setattr(xdh_mod, "read_attributes", lambda *_a, **_k: attrs)
    monkeypatch.setattr(xdh_mod, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))


def _xdh_vec(result: str) -> dict[str, Any]:
    return {
        "_oid": xdh_mod.X25519_OID,
        "_key_size": 32,
        "_encoding": "raw",
        "public": "unused",
        "private": "unused",
        "shared": "aa" * 32,
        "result": result,
    }


def test_xdh_missing_value_is_structured_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing derived X25519 CKA_VALUE must not KeyError; it records not_operational."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    _patch_xdh(monkeypatch, attrs={}, destroyed=destroyed)
    monkeypatch.setattr(xdh_mod, "assert_correct", _boom("assert_correct"))

    _call_expecting_no_xfail_escape(
        xdh_mod.test_xdh, _rs("ECDH1_DERIVE"), object(), "tc1-valid", _xdh_vec("valid")
    )

    assert destroyed == [61, 60]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF
    assert rec.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_xdh_present_but_wrong_value_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-wrong derived X25519 CKA_VALUE must still fail hard (wrong_result)."""
    destroyed: list[int] = []
    _patch_xdh(monkeypatch, attrs={CKA_VALUE: b"\x00" * 32}, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        xdh_mod.test_xdh(_rs("ECDH1_DERIVE"), object(), "tc1-valid", _xdh_vec("valid"))

    assert destroyed == [61, 60]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
