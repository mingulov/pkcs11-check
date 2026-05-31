"""Classification meta-tests for x509/test_attributes valid-cert reject (Phase 5 P1a).

A clean rejection of a Limbo-valid cert on import is provider-incompleteness ->
``xfail``, not a hard ``fail``.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID
from pkcs11_check.testcases.x509 import test_attributes as ta


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0


def test_valid_cert_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID))

    monkeypatch.setattr(ta, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(ta, "import_cert_object", _raise_import)
    monkeypatch.setattr(ta, "destroy_quietly", lambda *_a, **_k: None)

    tc = {"id": "tc-valid", "peer_certificate": "pem", "expected_result": "SUCCESS"}
    with pytest.raises(XFailed):
        ta.TestCertificateAttributes().test_verify_attributes(tc, _RawSession(), object(), "v3.0")
