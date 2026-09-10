"""F7 slice 08 regressions: security crypto/parameters attribute-presence migration.

Covers the six migrated ``read_attributes()`` readback sites in
``security/test_curve_oid_confusion.py``, ``security/test_dh_param_validation.py``,
``security/test_padding_oracle.py`` and ``security/test_parameter_validation.py``.

Each site previously indexed or ``.get()``-ed a provider-backed attribute mapping
directly, turning a provider omission into either an uncaught ``KeyError`` (raw
subscript) or a silently-``None`` value that skipped a check without leaving any
evidence.  These tests drive that omission at runtime and assert:

- a structured classification record is emitted (correct ``reason``,
  ``operation == "C_GetAttributeValue"``, ``mechanism is None`` despite an active
  stale mechanism, and the exact PKCS#11 v3.2 spec_ref),
- independent work in the same test still runs and handles are still destroyed,
- a present-but-malformed value is unaffected and still hard-fails/xfails exactly
  as before the migration.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_BASE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_VALUE,
    CKR_ARGUMENTS_BAD,
)
from pkcs11_check.testcases.security import test_curve_oid_confusion as coc
from pkcs11_check.testcases.security import test_dh_param_validation as dhp
from pkcs11_check.testcases.security import test_padding_oracle as po
from pkcs11_check.testcases.security import test_parameter_validation as pv

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classification() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


# ---------------------------------------------------------------------------
# test_curve_oid_confusion.py: reference CKA_EC_POINT readback
# ---------------------------------------------------------------------------


def test_curve_oid_ec_point_missing_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider that omits CKA_EC_POINT on the reference keypair is recorded as
    an honest not_operational deviation; the probe is skipped (it cannot construct
    a candidate object without a point) but both reference handles are destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    label, malformed_params = coc._make_malformed_params()[0]
    destroyed: list[int] = []
    probe_calls: list[Any] = []

    monkeypatch.setattr(coc, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(coc, "gen_ec_keypair_or_xfail", lambda *_a, **_k: (301, 302))
    monkeypatch.setattr(coc, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(coc, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    monkeypatch.setattr(coc, "_probe_malformed_ec_params", lambda *a, **_k: probe_calls.append(a))

    coc.TestCurveOidConfusion().test_short_ec_params_oid_rejected(
        _session(), label, malformed_params
    )

    # Continuation: cleanup of both reference handles still ran despite the
    # omission, and the (now unconstructable) dependent probe never fired.
    assert destroyed == [301, 302]
    assert probe_calls == []

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _SPEC_REF


# ---------------------------------------------------------------------------
# test_dh_param_validation.py: base=0 readback of CKA_BASE / CKA_VALUE
# ---------------------------------------------------------------------------


def test_dh_value_missing_is_not_operational_skips_derive_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_VALUE omitted (CKA_BASE present and un-substituted): the derive-based
    usability oracle cannot run and is skipped, but both keypair handles are
    still destroyed and no bogus CKR is invented for the omission."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    derive_calls: list[Any] = []

    monkeypatch.setattr(dhp, "_try_gen_dh_keypair", lambda *_a, **_k: (0, 601, 602))
    monkeypatch.setattr(dhp, "read_attributes", lambda *_a, **_k: {CKA_BASE: b"\x00"})
    monkeypatch.setattr(dhp, "derive_key", lambda *a, **k: derive_calls.append((a, k)))
    monkeypatch.setattr(dhp, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    dhp.TestDHDomainParameterValidation().test_dh_rejects_zero_generator(_session())

    assert derive_calls == []  # dependent oracle skipped, not silently "passed"
    assert destroyed == [601, 602]

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _SPEC_REF
    assert record.actual_ckr is None  # rule 3: an omission invents no CKR


def test_dh_base_missing_continues_to_derive_check_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_BASE omitted must not silence the (independent) substitution check nor
    block the (independent) CKA_VALUE-driven derive-usability oracle: the derive
    still runs and its own clean rejection is recorded, and handles still clean up.
    """
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []

    def _reject_derive(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(dhp, "_try_gen_dh_keypair", lambda *_a, **_k: (0, 701, 702))
    monkeypatch.setattr(dhp, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\x00"})
    monkeypatch.setattr(dhp, "derive_key", _reject_derive)
    monkeypatch.setattr(dhp, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    # The derive-usability oracle's own clean-rejection outcome (xfail_as) is what
    # terminates this test -- unrelated to the CKA_BASE omission, and proof that
    # the omission did not block it from running at all.
    with pytest.raises(pytest.xfail.Exception):
        dhp.TestDHDomainParameterValidation().test_dh_rejects_zero_generator(_session())

    assert destroyed == [701, 702]

    records = C.get_records()
    assert len(records) == 2
    missing = records[0]
    assert missing.reason == "not_operational"
    assert missing.operation == "C_GetAttributeValue"
    assert missing.mechanism is None
    assert missing.spec_ref == _SPEC_REF
    # Independent work continued: the derive-usability oracle still ran and
    # recorded its own (unrelated) clean-rejection xfail.
    assert records[1].reason == "not_operational"


def test_dh_value_present_but_not_bytes_still_hard_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-malformed CKA_VALUE (not the omission this slice targets)
    must keep failing exactly as before the migration: self_contradiction, fail."""
    monkeypatch.setattr(dhp, "_try_gen_dh_keypair", lambda *_a, **_k: (0, 801, 802))
    monkeypatch.setattr(
        dhp, "read_attributes", lambda *_a, **_k: {CKA_BASE: b"\x00", CKA_VALUE: 12345}
    )
    monkeypatch.setattr(dhp, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        dhp.TestDHDomainParameterValidation().test_dh_rejects_zero_generator(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"


# ---------------------------------------------------------------------------
# test_padding_oracle.py: RSA public-number readback (CKA_MODULUS / CKA_PUBLIC_EXPONENT)
# ---------------------------------------------------------------------------


def test_rsa_modulus_missing_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKA_MODULUS omitted after an advertised-successful keygen: no structured-oracle
    construction is possible, so the helper terminates with a structured xfail record
    instead of the pre-migration bare KeyError crash."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(
        po, "read_attributes", lambda *_a, **_k: {CKA_PUBLIC_EXPONENT: b"\x01\x00\x01"}
    )

    with pytest.raises(pytest.xfail.Exception):
        po._read_rsa_public_numbers_or_xfail(_session(), 42)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _SPEC_REF


def test_rsa_public_numbers_present_but_not_bytes_still_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Present-but-malformed (not the omission this slice targets) is unaffected
    by the migration: still an xfail, with the pre-existing "not bytes" summary."""
    monkeypatch.setattr(
        po,
        "read_attributes",
        lambda *_a, **_k: {CKA_MODULUS: 12345, CKA_PUBLIC_EXPONENT: b"\x01\x00\x01"},
    )

    with pytest.raises(pytest.xfail.Exception):
        po._read_rsa_public_numbers_or_xfail(_session(), 42)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert "not bytes" in (records[0].summary or "")


# ---------------------------------------------------------------------------
# test_parameter_validation.py: X25519/X448 low-order-point shared-secret readback
# ---------------------------------------------------------------------------


def test_montgomery_shared_secret_missing_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_VALUE omitted after a CKR_OK derive: the zero/non-zero effect cannot be
    verified, so the test xfails with a structured record instead of the
    pre-migration bare KeyError crash; every handle is still destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []

    monkeypatch.setattr(pv, "gen_keypair", lambda *_a, **_k: (901, 902))
    monkeypatch.setattr(pv, "derive_key", lambda *_a, **_k: 903)
    monkeypatch.setattr(pv, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(pv, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    pv.TestEcPointValidation().test_ecdh_montgomery_low_order_point(
        _session(), "x25519", b"\x00" * 32, 32
    )

    # Continuation: the derive already ran (independent of the readback) and
    # every handle -- derived secret, private, public -- is still destroyed.
    assert destroyed == [903, 902, 901]

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _SPEC_REF
