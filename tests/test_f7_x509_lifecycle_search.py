"""F7 slice 13 runtime-behavior regressions: x509/test_lifecycle.py, x509/test_limbo_import.py,
x509/test_limbo_stress.py, x509/test_search.py routed through ``attr_or_record()``.

These are *behavior* tests, not analyzer-count tests: each proves that an omitted provider
attribute now produces a structured, mechanism-free classification record (never a
``KeyError`` crash and never a silently degraded value feeding a comparison/oracle), that
independent work in the same test still runs and handles are still destroyed (the
aggregate-oracle hazard), and that a genuinely present-but-wrong value still hard-fails (the
migration must not soften an existing hard finding).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ID,
    CKA_ISSUER,
    CKA_LABEL,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_TOKEN,
    CKA_VALUE,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases.x509 import test_lifecycle as x509_test_lifecycle
from pkcs11_check.testcases.x509 import test_limbo_import as x509_test_limbo_import
from pkcs11_check.testcases.x509 import test_limbo_stress as x509_test_limbo_stress
from pkcs11_check.testcases.x509 import test_search as x509_test_search

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _make_read_attributes(values: dict[Any, Any], omit: set[Any] | None = None) -> Any:
    """A fake ``read_attributes()`` that always CKR_OK's but omits from ``values`` (or
    ``omit``) -- exactly the provider behavior F7 must turn into evidence instead of a
    KeyError crash or a silently degraded default."""
    omit = omit or set()

    def _read(_raw: Any, _sh: Any, _handle: Any, attrs: list[Any]) -> dict[Any, Any]:
        return {a: values[a] for a in attrs if a in values and a not in omit}

    return _read


def _assert_missing_attribute_record(rec: C.Classification, reason: str) -> None:
    assert rec.reason == reason
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF


# --------------------------------------------------------------------------------
# x509/test_lifecycle.py :: TestCertificateLifecycle (2 sites)
# --------------------------------------------------------------------------------


def test_lifecycle_token_missing_is_honest_deviation_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_TOKEN] -> attr_or_record: an omitted CKA_TOKEN readback is recorded as
    an honest omission (not a KeyError crash), and the handle is still destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 71
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_lifecycle, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_lifecycle, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(x509_test_lifecycle, "read_attributes", _make_read_attributes({}))

    x509_test_lifecycle.TestCertificateLifecycle().test_cert_token_persistence(
        _session(), b"der-bytes", "3.0"
    )

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "honest_deviation")


def test_lifecycle_token_present_wrong_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present-but-wrong CKA_TOKEN (module accepted CKA_TOKEN=True but the readback
    reports False) must stay a hard ``wrong_result`` fail -- the migration must never
    downgrade an actual metadata mismatch into an omission."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 72
    monkeypatch.setattr(x509_test_lifecycle, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(x509_test_lifecycle, "destroy_quietly", lambda *a: None)
    monkeypatch.setattr(
        x509_test_lifecycle, "read_attributes", _make_read_attributes({CKA_TOKEN: False})
    )

    with pytest.raises(pytest.fail.Exception):
        x509_test_lifecycle.TestCertificateLifecycle().test_cert_token_persistence(
            _session(), b"der-bytes", "3.0"
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].outcome == "fail"


def test_lifecycle_id_missing_is_honest_deviation_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_ID] -> attr_or_record: an omitted CKA_ID readback after a successful
    set is recorded as an honest omission, and the handle is still destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 73
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_lifecycle, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_lifecycle, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(x509_test_lifecycle, "read_attributes", _make_read_attributes({}))

    x509_test_lifecycle.TestCertificateLifecycle().test_cert_id_assignment(
        _session(), b"der-bytes", "3.0"
    )

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "honest_deviation")


def test_lifecycle_id_present_wrong_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present-but-wrong CKA_ID (module returns a different value than the one set)
    must stay a hard ``wrong_result`` fail."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 74
    monkeypatch.setattr(x509_test_lifecycle, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(x509_test_lifecycle, "destroy_quietly", lambda *a: None)
    monkeypatch.setattr(
        x509_test_lifecycle,
        "read_attributes",
        _make_read_attributes({CKA_ID: b"not-the-id-we-set"}),
    )

    with pytest.raises(pytest.fail.Exception):
        x509_test_lifecycle.TestCertificateLifecycle().test_cert_id_assignment(
            _session(), b"der-bytes", "3.0"
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].outcome == "fail"


# --------------------------------------------------------------------------------
# x509/test_limbo_import.py (2 sites)
# --------------------------------------------------------------------------------


def test_peer_cert_label_missing_is_not_operational_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_LABEL] -> attr_or_record: an omitted CKA_LABEL round-trip readback is
    recorded (not_operational) instead of crashing before the ``needed_attrs`` note and
    cleanup run."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 81
    monkeypatch.setattr(x509_test_limbo_import, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_limbo_import, "pem_to_der", lambda *a, **k: b"original-der-bytes")
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_limbo_import, "import_cert_raw", lambda *a, **k: (handle, True))
    monkeypatch.setattr(
        x509_test_limbo_import, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(x509_test_limbo_import, "read_attributes", _make_read_attributes({}))

    tc = {"id": "f7-s13-tc-label", "peer_certificate": "irrelevant"}
    x509_test_limbo_import.TestLimboCertImport().test_import_peer_cert(tc, _session(), None)

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")


def test_peer_cert_label_present_wrong_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present-but-wrong CKA_LABEL (round-trip mismatch, and not the known
    Pkcs11Interop-rewrite quirk) must stay a hard ``wrong_result`` fail."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 82
    monkeypatch.setattr(x509_test_limbo_import, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_limbo_import, "pem_to_der", lambda *a, **k: b"original-der-bytes")
    monkeypatch.setattr(x509_test_limbo_import, "import_cert_raw", lambda *a, **k: (handle, False))
    monkeypatch.setattr(x509_test_limbo_import, "destroy_quietly", lambda *a: None)
    monkeypatch.setattr(
        x509_test_limbo_import,
        "read_attributes",
        _make_read_attributes({CKA_LABEL: "a-completely-different-label"}),
    )

    tc = {"id": "f7-s13-tc-label-wrong", "peer_certificate": "irrelevant"}
    with pytest.raises(pytest.fail.Exception):
        x509_test_limbo_import.TestLimboCertImport().test_import_peer_cert(tc, _session(), None)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].outcome == "fail"


def test_failure_cert_value_missing_is_not_operational_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_VALUE] -> attr_or_record: an omitted CKA_VALUE round-trip readback on a
    stored FAILURE-corpus cert is recorded (not_operational) instead of crashing before
    cleanup runs, and does NOT fabricate a self_contradiction against the missing value."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 83
    monkeypatch.setattr(x509_test_limbo_import, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_limbo_import, "pem_to_der", lambda *a, **k: b"original-der-bytes")
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_limbo_import, "import_cert_raw", lambda *a, **k: (handle, False))
    monkeypatch.setattr(
        x509_test_limbo_import, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(x509_test_limbo_import, "read_attributes", _make_read_attributes({}))

    tc = {"id": "f7-s13-tc-value", "peer_certificate": "irrelevant"}
    x509_test_limbo_import.test_import_limbo_failure_cert_raw(tc, _session(), None)

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")


def test_failure_cert_value_present_wrong_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present-but-modified CKA_VALUE (module stored different bytes than sent) must
    stay a hard ``self_contradiction`` fail."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 84
    monkeypatch.setattr(x509_test_limbo_import, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_limbo_import, "pem_to_der", lambda *a, **k: b"original-der-bytes")
    monkeypatch.setattr(x509_test_limbo_import, "import_cert_raw", lambda *a, **k: (handle, False))
    monkeypatch.setattr(x509_test_limbo_import, "destroy_quietly", lambda *a: None)
    monkeypatch.setattr(
        x509_test_limbo_import,
        "read_attributes",
        _make_read_attributes({CKA_VALUE: b"corrupted-bytes"}),
    )

    tc = {"id": "f7-s13-tc-value-wrong", "peer_certificate": "irrelevant"}
    with pytest.raises(pytest.fail.Exception):
        x509_test_limbo_import.test_import_limbo_failure_cert_raw(tc, _session(), None)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].outcome == "fail"


# --------------------------------------------------------------------------------
# x509/test_limbo_stress.py (2 sites: cert-import and CRL-import unsafe_get)
# --------------------------------------------------------------------------------


def test_stress_cert_value_missing_is_not_operational_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs.get(CKA_VALUE, b"") -> attr_or_record: an omitted CKA_VALUE (module
    returned CKR_OK but silently dropped the attribute from the response) is recorded
    (not_operational), and the module is still forced to parse the DER (computed
    attributes + C_GetObjectSize) before the handle is destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 91
    monkeypatch.setattr(x509_test_limbo_stress, "skip_unless_cert_storage", lambda *a: None)
    destroyed: list[int] = []
    calls: list[list[Any]] = []

    def _read(_raw: Any, _sh: Any, _handle: Any, attrs: list[Any]) -> dict[Any, Any]:
        calls.append(list(attrs))
        # CKA_VALUE is never in the returned mapping: a genuine silent omission.
        values = {CKA_SUBJECT: b"s", CKA_ISSUER: b"i", CKA_SERIAL_NUMBER: b"\x01"}
        return {a: values[a] for a in attrs if a in values}

    monkeypatch.setattr(x509_test_limbo_stress, "create_object", lambda *a, **k: handle)
    monkeypatch.setattr(x509_test_limbo_stress, "read_attributes", _read)
    monkeypatch.setattr(x509_test_limbo_stress, "get_object_size", lambda *a, **k: 123)
    monkeypatch.setattr(
        x509_test_limbo_stress, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    x509_test_limbo_stress.test_exhaustive_cert_import_no_crash(
        "f7-s13-stress-cert", b"der-bytes", _session(), None
    )

    assert destroyed == [handle]
    # The CKA_VALUE read AND the computed-attributes read must both have happened --
    # the missing-CKA_VALUE oracle disable must not short-circuit the rest of the probe.
    assert [CKA_VALUE] in calls
    assert [CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER] in calls
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")


def test_stress_cert_value_read_failure_records_no_extra_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the CKA_VALUE read itself raises a clean, defined CK_RV (not a silent
    omission), that is already handled by ``_accept_clean_crash_probe_rejection``: the
    migration must NOT additionally fabricate a MISSING_ATTRIBUTE record for the same
    event (the aggregate-oracle double-count hazard)."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 92
    monkeypatch.setattr(x509_test_limbo_stress, "skip_unless_cert_storage", lambda *a: None)

    def _read(_raw: Any, _sh: Any, _handle: Any, attrs: list[Any]) -> dict[Any, Any]:
        if attrs == [CKA_VALUE]:
            raise CkrAssertionError("boom", CKR_GENERAL_ERROR)
        return {}

    monkeypatch.setattr(x509_test_limbo_stress, "create_object", lambda *a, **k: handle)
    monkeypatch.setattr(x509_test_limbo_stress, "read_attributes", _read)
    monkeypatch.setattr(x509_test_limbo_stress, "get_object_size", lambda *a, **k: 123)
    monkeypatch.setattr(x509_test_limbo_stress, "destroy_quietly", lambda *a: None)

    x509_test_limbo_stress.test_exhaustive_cert_import_no_crash(
        "f7-s13-stress-cert-readfail", b"der-bytes", _session(), None
    )

    # CKR_GENERAL_ERROR is a standard CK_RV -> _accept_clean_crash_probe_rejection is
    # silent -> zero records, not one.
    assert C.get_records() == []


def test_stress_cert_value_present_wrong_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present-but-modified CKA_VALUE (module corrupted stored cert bytes) must stay a
    hard ``self_contradiction`` fail."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 93
    monkeypatch.setattr(x509_test_limbo_stress, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_limbo_stress, "create_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_limbo_stress,
        "read_attributes",
        _make_read_attributes({CKA_VALUE: b"corrupted"}),
    )
    monkeypatch.setattr(x509_test_limbo_stress, "get_object_size", lambda *a, **k: 123)
    monkeypatch.setattr(x509_test_limbo_stress, "destroy_quietly", lambda *a: None)

    with pytest.raises(pytest.fail.Exception):
        x509_test_limbo_stress.test_exhaustive_cert_import_no_crash(
            "f7-s13-stress-cert-wrong", b"der-bytes", _session(), None
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].outcome == "fail"


def test_stress_crl_value_missing_is_not_operational_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs.get(CKA_VALUE, b"") -> attr_or_record on the CRL variant: an omitted
    CKA_VALUE is recorded (not_operational) and C_GetObjectSize still runs before the
    handle is destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 94
    destroyed: list[int] = []
    size_calls: list[int] = []
    monkeypatch.setattr(x509_test_limbo_stress, "create_object", lambda *a, **k: handle)
    monkeypatch.setattr(x509_test_limbo_stress, "read_attributes", _make_read_attributes({}))
    monkeypatch.setattr(
        x509_test_limbo_stress,
        "get_object_size",
        lambda _raw, _sh, h: size_calls.append(h),
    )
    monkeypatch.setattr(
        x509_test_limbo_stress, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )

    x509_test_limbo_stress.test_exhaustive_crl_import_no_crash(
        "f7-s13-stress-crl", b"der-bytes", _session(), None
    )

    assert destroyed == [handle]
    assert size_calls == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")


# --------------------------------------------------------------------------------
# x509/test_search.py :: TestCertificateSearchExtended (3 sites)
# --------------------------------------------------------------------------------


def _patch_search_common(
    monkeypatch: pytest.MonkeyPatch,
    handle: int,
    read_values: dict[Any, Any],
    destroyed: list[int],
    find_calls: list[Any],
) -> None:
    monkeypatch.setattr(x509_test_search, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_search, "pem_to_der", lambda *a, **k: b"der-bytes")
    monkeypatch.setattr(x509_test_search, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_search, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(x509_test_search, "read_attributes", _make_read_attributes(read_values))

    def _find_objects(_raw: Any, _sh: Any, tmpl: Any) -> list[int]:
        find_calls.append(tmpl)
        return [handle]

    monkeypatch.setattr(x509_test_search, "find_objects", _find_objects)


def test_search_subject_missing_is_honest_deviation_and_other_searches_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """a[CKA_SUBJECT] -> attr_or_record: an omitted CKA_SUBJECT is recorded
    (honest_deviation) and disables ONLY the subject-derived searches -- the
    independent issuer and serial searches in the same test still run."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 101
    destroyed: list[int] = []
    find_calls: list[Any] = []
    _patch_search_common(
        monkeypatch,
        handle,
        {CKA_ISSUER: b"issuer-bytes", CKA_SERIAL_NUMBER: b"\x01"},
        destroyed,
        find_calls,
    )

    tc = {"id": "f7-s13-search-tc", "peer_certificate": "irrelevant"}
    x509_test_search.TestCertificateSearchExtended().test_search_by_attributes_extracted(
        tc, _session(), None, "3.0"
    )

    assert destroyed == [handle]
    # issuer-only and serial-only searches ran; subject-only and subject+serial did not.
    assert len(find_calls) == 2
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "honest_deviation")


def test_search_issuer_missing_and_other_searches_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """a[CKA_ISSUER] -> attr_or_record: an omitted CKA_ISSUER is recorded
    (honest_deviation) and the independent subject and serial searches still run."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 102
    destroyed: list[int] = []
    find_calls: list[Any] = []
    _patch_search_common(
        monkeypatch,
        handle,
        {CKA_SUBJECT: b"subject-bytes", CKA_SERIAL_NUMBER: b"\x01"},
        destroyed,
        find_calls,
    )

    tc = {"id": "f7-s13-search-tc", "peer_certificate": "irrelevant"}
    x509_test_search.TestCertificateSearchExtended().test_search_by_attributes_extracted(
        tc, _session(), None, "3.0"
    )

    assert destroyed == [handle]
    # subject-only, serial-only, and subject+serial combined searches all ran.
    assert len(find_calls) == 3
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "honest_deviation")


def test_search_serial_missing_and_subject_search_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """a[CKA_SERIAL_NUMBER] -> attr_or_record: an omitted CKA_SERIAL_NUMBER is recorded
    (honest_deviation) and disables only the serial-derived searches, while the
    independent subject search still runs and the handle is still destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 103
    destroyed: list[int] = []
    find_calls: list[Any] = []
    _patch_search_common(
        monkeypatch,
        handle,
        {CKA_SUBJECT: b"subject-bytes", CKA_ISSUER: b"issuer-bytes"},
        destroyed,
        find_calls,
    )

    tc = {"id": "f7-s13-search-tc", "peer_certificate": "irrelevant"}
    x509_test_search.TestCertificateSearchExtended().test_search_by_attributes_extracted(
        tc, _session(), None, "3.0"
    )

    assert destroyed == [handle]
    # subject-only and issuer-only searches ran; serial-only and subject+serial did not.
    assert len(find_calls) == 2
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "honest_deviation")


def test_search_all_present_runs_all_four_searches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanity: with all three attributes present, all four search probes run and no
    classification record is produced -- proves the guard does not fire on genuine
    presence."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 104
    destroyed: list[int] = []
    find_calls: list[Any] = []
    _patch_search_common(
        monkeypatch,
        handle,
        {
            CKA_SUBJECT: b"subject-bytes",
            CKA_ISSUER: b"issuer-bytes",
            CKA_SERIAL_NUMBER: b"\x01",
        },
        destroyed,
        find_calls,
    )

    tc = {"id": "f7-s13-search-tc", "peer_certificate": "irrelevant"}
    x509_test_search.TestCertificateSearchExtended().test_search_by_attributes_extracted(
        tc, _session(), None, "3.0"
    )

    assert destroyed == [handle]
    assert len(find_calls) == 4
    assert C.get_records() == []
