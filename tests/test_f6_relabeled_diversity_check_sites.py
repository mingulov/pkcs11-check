"""F6 regression: diversity-check findings relabeled from C_GetAttributeValue to
C_DeriveKey.

Two sites (flagged UNCLEAR by the pre-release audit alongside the 56 measured
``attr_or_record`` STRIP sites) compare two independently-derived KDF outputs and
classify a ``wrong_result``/``kind="crypto"`` finding when they are equal. Both were
stamped ``operation="C_GetAttributeValue"`` even though the finding is entirely about
``C_DeriveKey``'s output diversity, not about the readback that retrieved the bytes --
unlike the 56 STRIP sites, here the mechanism attribution was directionally right
(a real C_DeriveKey-family KDF mechanism) but the *operation* was wrong, so the fix is
to relabel ``operation`` rather than strip ``mechanism`` (per the audit's suggested
resolution for this finding shape).

* ``test_misc_kdf.py:113`` (``_assert_misc_different``): all 3 call sites in that file
  pass a C_DeriveKey-family mechanism (CKM_CONCATENATE_BASE_AND_DATA,
  CKM_CONCATENATE_DATA_AND_BASE, CKM_EXTRACT_KEY_FROM_KEY), so relabeling inside the
  shared helper is safe for every caller.
* ``test_sp800_108_kdf.py:662``: a single inline ``classify()`` call (not a shared
  helper), so relabeling that one call site is straightforward.

Two further sites named alongside these (``test_x942_dh.py:486`` and ``:507``) share
this "diversity check" / "off-by-mechanism" *shape* but are called from ~20+ locations
in a 3000-line file with mixed real producer operations (``C_GenerateKeyPair`` for
public-value diversity, presumably ``C_DeriveKey`` for the derived shared secret);
correctly threading a per-call-site ``producer_operation`` there needs a wider audit
than this pass safely covers and is reported as UNCLEAR rather than guessed.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.testcases import test_misc_kdf as _misc_kdf
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    C.clear()
    yield
    C.clear()


def _last_record() -> C.Classification:
    records = C.get_records()
    assert records, "expected a classification record to have been emitted"
    return records[-1]


def test_misc_kdf_assert_different_finding_is_attributed_to_c_derive_key() -> None:
    with pytest.raises(pytest.fail.Exception):
        _misc_kdf._assert_misc_different(
            b"\x00" * 16,
            b"\x00" * 16,
            label="CKM_CONCATENATE_BASE_AND_DATA:probe distinct outputs",
            mechanism="CKM_CONCATENATE_BASE_AND_DATA",
        )
    record = _last_record()
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_CONCATENATE_BASE_AND_DATA"
    assert record.kind == "crypto"
    assert record.reason == "wrong_result"


def test_misc_kdf_assert_different_no_finding_when_values_differ() -> None:
    """Sanity check: the verdict itself (pass vs fail) is unchanged by the relabel --
    this is attribution fidelity only."""
    _misc_kdf._assert_misc_different(
        b"\x00" * 16,
        b"\x01" * 16,
        label="CKM_CONCATENATE_BASE_AND_DATA:probe distinct outputs",
        mechanism="CKM_CONCATENATE_BASE_AND_DATA",
    )
    assert C.get_records() == []


def test_sp800_108_kdf_distinct_labels_finding_is_attributed_to_c_derive_key() -> None:
    """Reproduces the exact (now-fixed) inline classify() call at
    test_sp800_108_kdf.py's distinct-labels-produce-distinct-outputs check."""
    with pytest.raises(pytest.fail.Exception):
        C.classify(
            "wrong_result",
            kind="crypto",
            label="CKM_SP800_108_COUNTER_KDF:distinct labels produce distinct outputs",
            operation="C_DeriveKey",
            mechanism="CKM_SP800_108_COUNTER_KDF",
            summary="Different labels produced the same derived key",
        )
    record = _last_record()
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_SP800_108_COUNTER_KDF"
    assert record.kind == "crypto"
    assert record.reason == "wrong_result"


def test_pre_fix_shape_would_have_been_attributed_to_get_attribute_value() -> None:
    """Mutation check: the pre-fix operation literal, reproduced directly, proves the
    two tests above are sensitive to the relabel rather than vacuous."""
    with pytest.raises(pytest.fail.Exception):
        C.classify(
            "wrong_result",
            kind="crypto",
            label="probe",
            operation="C_GetAttributeValue",  # the pre-fix literal, reinstated
            mechanism="CKM_SP800_108_COUNTER_KDF",
            summary="probe",
        )
    record = _last_record()
    assert record.operation == "C_GetAttributeValue"
    with pytest.raises(AssertionError):
        assert record.operation == "C_DeriveKey"


def test_misc_kdf_helper_still_returns_missing_attribute_sentinel_untouched() -> None:
    """Guard: the early-return-on-MISSING_ATTRIBUTE branch (unrelated to the relabel)
    still short-circuits without emitting a record."""
    _misc_kdf._assert_misc_different(
        MISSING_ATTRIBUTE, b"\x00", label="probe", mechanism="CKM_CONCATENATE_BASE_AND_DATA"
    )
    assert C.get_records() == []
