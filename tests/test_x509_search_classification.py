"""Classification meta-tests for x509/test_search by-attribute (Phase 5 P1a).

If the module extracted a derived cert attribute (CKA_SUBJECT/ISSUER/SERIAL) but
search-by-that-attribute does not return the object, that is search-by-derived-
attribute provider-incompleteness -> ``xfail``, not a bare ``assert`` ``fail``.
A successful search still passes.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases.x509 import test_search as ts


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0


def test_search_miss_xfails() -> None:
    with pytest.raises(XFailed):
        ts._xfail_if_search_miss([2, 3], 7, by="CKA_SUBJECT")


def test_search_hit_passes() -> None:
    ts._xfail_if_search_miss([2, 7, 3], 7, by="CKA_SUBJECT")


def test_search_does_not_swallow_harness_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Python assertion during certificate import must remain visible."""
    monkeypatch.setattr(ts, "skip_unless_cert_storage", lambda _rs: None)
    monkeypatch.setattr(ts, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(
        ts,
        "import_cert_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("harness bug")),
    )

    with pytest.raises(AssertionError, match="harness bug"):
        ts.TestCertificateSearchExtended().test_search_by_attributes_extracted(
            {"id": "tc", "peer_certificate": "pem"},
            _RawSession(),
            object(),
            "v3.0",
        )


def test_supported_storage_then_selected_import_refusal_is_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ts, "skip_unless_cert_storage", lambda _rs: None)
    monkeypatch.setattr(ts, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(
        ts,
        "import_cert_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("function unavailable", int(CKR_FUNCTION_NOT_SUPPORTED))
        ),
    )

    with pytest.raises(XFailed):
        ts.TestCertificateSearchExtended().test_search_by_attributes_extracted(
            {"id": "tc", "peer_certificate": "pem"},
            _RawSession(),
            object(),
            "v3.0",
        )
