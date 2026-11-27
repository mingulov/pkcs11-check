"""Readback-attribution regression: shared-helper readbacks must never inherit a caller's mechanism.

``_provisioning.py``, ``_ec_export.py``, ``_rsa_export.py`` and ``_aes_operability.py``
are reached from ACVP/Wycheproof tests *after* those tests call ``set_mechanism()``.
A plain ``C_GetAttributeValue`` readback performed inside one of these helpers must be
attributed to the read itself -- ``operation="C_GetAttributeValue"``, ``mechanism=None``
-- never to whatever signing/derive/decrypt mechanism the calling test made active.

Before the fix, ``record_as()``'s ``if mechanism is None and inherit_mechanism: mechanism
= _active_mechanism`` silently inherited the caller's mechanism whenever a site passed
``mechanism=None`` without also passing ``inherit_mechanism=False``. Because
``wrap_context_for()`` memoises per session handle, *which* mechanism got stamped onto a
readback depended on test ordering / ``-k`` selection -- the same record could carry
different ``spec_ref`` values across runs. That non-determinism is the release-blocking
defect; test 2 below (``test_determinism_*``) is the direct proof of it.

Each helper test wraps the call in ``pytest.raises(pytest.xfail.Exception, ...)``: several
of these helpers escape via ``pytest.xfail``, and pytest exits 0 on an xfail, so a test
that merely let it propagate would report "xfailed" (a false pass) rather than failing on
a bad assertion. Capturing it explicitly turns any assertion failure back into a hard
test failure.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw import recipes
from pkcs11_check.raw.types_std import CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE, CKK_AES
from pkcs11_check.testcases import _aes_operability as aes
from pkcs11_check.testcases import _ec_export as ec_export
from pkcs11_check.testcases import _provisioning as provisioning
from pkcs11_check.testcases import _rsa_export as rsa_export
from pkcs11_check.testcases._operability import Operability, reset_operability_cache

_BARE_C_GET_ATTRIBUTE_VALUE = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _isolated() -> Generator[None, None, None]:
    C.clear()
    provisioning._PROFILE_CACHE.clear()
    provisioning.clear_provisioning_events()
    reset_operability_cache()
    yield
    C.clear()
    provisioning._PROFILE_CACHE.clear()
    provisioning.clear_provisioning_events()
    reset_operability_cache()


def _rs(sh: int = 1) -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=sh)


# ---------------------------------------------------------------------------
# Helper invocations that each drive exactly one readback record.
# ---------------------------------------------------------------------------


def _run_provisioning_readback() -> None:
    """Drive `_build_configured_wrap_context`'s CKA_CLASS readback (site ~925).

    `attr_or_record()` records without raising (unlike the xfail_as/fail_as paths in
    the other three helpers): the missing attribute is recorded, the context build
    then fails through its own non-classification `_fail()` path and returns None.
    """

    def _read(_raw: Any, _sh: int, _handle: int, attrs: Any) -> dict[int, Any]:
        return {} if attrs == (CKA_CLASS,) else {CKA_KEY_TYPE: CKK_AES}

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(recipes, "read_attributes", _read)
        result = provisioning._build_configured_wrap_context(
            _rs(), SimpleNamespace(wrap_key_handle=12)
        )
    assert result is None


def _run_ec_export_readback() -> None:
    """Drive `read_conventional_ec_point_or_xfail`'s missing-CKA_EC_POINT readback."""
    from cryptography.hazmat.primitives.asymmetric import ec

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ec_export, "read_attributes", lambda *_a, **_kw: {})
        with pytest.raises(pytest.xfail.Exception, match="CKA_EC_POINT attribute unavailable"):
            ec_export.read_conventional_ec_point_or_xfail(
                _rs(), 2, ec.SECP256R1(), label="ACVP ECDSA public key"
            )


def _run_rsa_export_readback() -> None:
    """Drive `_rsa_int_attr`'s missing CKA_MODULUS readback (site ~55)."""
    with pytest.raises(pytest.xfail.Exception, match="missing RSA public attribute"):
        rsa_export.rsa_public_key_from_attrs_or_xfail({}, label="ACVP RSA public key")


def _run_aes_operability_readback() -> tuple[Operability, list[int]]:
    """Drive `kw_unwrap_operability`'s missing recovered-CKA_VALUE readback (site ~328)."""
    handles = iter([10, 11])
    destroyed: list[int] = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_kw: next(handles))
        mp.setattr(aes, "wrap_key", lambda *_a, **_kw: b"wrapped")
        mp.setattr(aes, "unwrap_key", lambda *_a, **_kw: 12)
        mp.setattr(aes, "read_attributes", lambda *_a, **_kw: {})
        mp.setattr(aes, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
        result = aes.kw_unwrap_operability(_rs())
    return result.status, destroyed


# ---------------------------------------------------------------------------
# 1. Per-helper: a readback after set_mechanism() is mechanism-free.
# ---------------------------------------------------------------------------


def test_provisioning_readback_after_set_mechanism_is_mechanism_free() -> None:
    C.set_mechanism("CKM_SHA256_HMAC", operation="C_Verify")

    _run_provisioning_readback()

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE


def test_ec_export_readback_after_set_mechanism_is_mechanism_free() -> None:
    C.set_mechanism("ECDSA_SHA256", operation="C_Sign")

    _run_ec_export_readback()

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE


def test_rsa_export_readback_after_set_mechanism_is_mechanism_free() -> None:
    C.set_mechanism("RSA_PKCS", operation="C_Sign")

    _run_rsa_export_readback()

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE


def test_aes_operability_readback_after_set_mechanism_is_mechanism_free() -> None:
    # Deliberately a *different* active mechanism than the wrap/unwrap this probe itself
    # performs, so an inheriting record would be caught even if it happened to coincide
    # with CKM_AES_KEY_WRAP.
    C.set_mechanism("CKM_AES_CBC_PAD", operation="C_Decrypt")

    status, destroyed = _run_aes_operability_readback()

    assert status is Operability.INCONCLUSIVE
    assert destroyed == [10, 11, 12]
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE


# ---------------------------------------------------------------------------
# 2. The determinism regression -- the highest-value test in this file.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "run_readback",
    [_run_provisioning_readback, _run_ec_export_readback, _run_rsa_export_readback],
    ids=["provisioning", "ec_export", "rsa_export"],
)
def test_determinism_spec_ref_does_not_depend_on_active_mechanism(
    run_readback: Any,
) -> None:
    """The same readback, run under two different active mechanisms, must be identical.

    Before the fix this reproduces the release-blocking defect directly: the first run
    (active mechanism CKM_SHA256_HMAC / C_Verify) stamps `spec_ref` with
    "... C_GetAttributeValue . CKM_SHA256_HMAC", the second (active mechanism RSA_PKCS /
    C_Decrypt) stamps "... C_GetAttributeValue . RSA_PKCS" -- two different spec_ref
    strings for the exact same readback, differing only by which unrelated test ran
    first and left its mechanism active. After the fix both runs must produce the same,
    mechanism-free record.
    """
    C.set_mechanism("CKM_SHA256_HMAC", operation="C_Verify")
    run_readback()
    first = C.get_records()
    assert len(first) == 1
    first_record = first[0]

    C.clear()

    C.set_mechanism("RSA_PKCS", operation="C_Decrypt")
    run_readback()
    second = C.get_records()
    assert len(second) == 1
    second_record = second[0]

    assert first_record.mechanism is None
    assert second_record.mechanism is None
    assert first_record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE
    assert second_record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE
    assert first_record == second_record


def test_aes_operability_determinism_spec_ref_does_not_depend_on_active_mechanism() -> None:
    """Same regression, exercised through the AES-KW helper (kept separate: its readback
    also carries `mechanism=` state internal to the probe cache, so it is not parametrized
    alongside the pure attribute-readback helpers above)."""
    C.set_mechanism("CKM_SHA256_HMAC", operation="C_Verify")
    status1, _ = _run_aes_operability_readback()
    first = C.get_records()
    assert len(first) == 1
    first_record = first[0]

    C.clear()
    reset_operability_cache()

    C.set_mechanism("RSA_PKCS", operation="C_Decrypt")
    status2, _ = _run_aes_operability_readback()
    second = C.get_records()
    assert len(second) == 1
    second_record = second[0]

    assert status1 is Operability.INCONCLUSIVE
    assert status2 is Operability.INCONCLUSIVE
    assert first_record.mechanism is None
    assert second_record.mechanism is None
    assert first_record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE
    assert second_record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE
    assert first_record == second_record


# ---------------------------------------------------------------------------
# 3. Producer context, where it existed before the fix, still survives.
# ---------------------------------------------------------------------------


def test_aes_operability_readback_keeps_producer_mechanism_in_label_and_detail() -> None:
    """Before the fix this site carried an explicit (wrong) `mechanism="CKM_AES_KEY_WRAP"`.

    The producer context -- that this readback follows a CKM_AES_KEY_WRAP wrap/unwrap
    roundtrip -- is genuine and must not vanish; it is carried in the record's label
    (and therefore its summary), not fabricated into `mechanism`. The structured
    `detail` (attribute name/id) that existed before the fix must also be unchanged.
    """
    C.set_mechanism("CKM_AES_CBC_PAD", operation="C_Decrypt")

    _run_aes_operability_readback()

    record = C.get_records()[0]
    assert record.mechanism is None
    assert record.label == "CKM_AES_KEY_WRAP:recovered CKA_VALUE readback"
    assert "CKM_AES_KEY_WRAP" in record.summary
    assert record.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_ec_export_readback_keeps_curve_detail() -> None:
    """The curve context recorded in `detail` before the fix must be unaffected."""
    from cryptography.hazmat.primitives.asymmetric import ec

    C.set_mechanism("ECDSA_SHA256", operation="C_Sign")

    _run_ec_export_readback()

    record = C.get_records()[0]
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["curve"] == ec.SECP256R1().name
