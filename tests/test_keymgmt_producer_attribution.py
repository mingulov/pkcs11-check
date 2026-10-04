"""Producer attribution for keymgmt mismatch verdicts.

``_record_wrong_attribute`` is shared by bare readback observations (imported/
copied attribute checks with no producer mechanism) and crypto-producer
mismatch verdicts (RSA keygen output, unwrap output). The former must stay
bare readbacks (``operation="C_GetAttributeValue"``, ``mechanism=None``); the
latter must attribute the failure to the producer operation + mechanism,
following the ``test_access_levels`` precedent for fail verdicts on
mechanism-produced values. Ambient mechanisms must leak into neither shape.

Each test sets a stale active mechanism first: with ``classification.clear()``
zeroing the ambient context, a ``mechanism is None`` assertion would hold
vacuously, and an explicit-mechanism assertion would pass even if the helper
re-enabled inheritance. The stale marker makes both directions load-bearing.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import (
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
)
from pkcs11_check.testcases import test_keymgmt as keymgmt

_STALE_MECHANISM = "CKM_STALE"


@pytest.fixture(autouse=True)
def _isolated() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda *a: True)


def _last_record() -> C.Classification:
    records = C.get_records()
    assert records, "expected a classification record to have been emitted"
    return records[-1]


def test_unwrap_mismatch_attributes_producer_operation_and_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism(_STALE_MECHANISM, operation="C_Stale")
    monkeypatch.setattr(keymgmt, "skip_unless_create_object_supported", lambda rs: None)
    monkeypatch.setattr(keymgmt, "_aes_keymgmt_key", lambda rs, **kw: 11)
    monkeypatch.setattr(keymgmt, "import_secret_key_negotiated", lambda *a, **k: 12)
    monkeypatch.setattr(keymgmt, "wrap_key", lambda *a, **k: b"wrapped")
    monkeypatch.setattr(keymgmt, "unwrap_key_for_mechanism_roundtrip", lambda *a, **k: 13)
    monkeypatch.setattr(
        keymgmt, "read_attributes", lambda *a, **k: {CKA_VALUE: b"wrong-bytes-1234"}
    )
    monkeypatch.setattr(keymgmt, "destroy_quietly", lambda *a, **k: None)
    with pytest.raises(pytest.fail.Exception):
        keymgmt.TestKeyWrapUnwrap().test_wrap_unwrap_roundtrip(_rs(), SimpleNamespace())
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.outcome == "fail"
    assert record.operation == "C_UnwrapKey"
    assert record.mechanism == "CKM_AES_KEY_WRAP"


def test_rsa_export_mismatch_attributes_keygen_producer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism(_STALE_MECHANISM, operation="C_Stale")
    monkeypatch.setattr(keymgmt, "gen_rsa_keypair_or_xfail", lambda *a, **k: (21, 22))
    monkeypatch.setattr(
        keymgmt,
        "read_attributes",
        lambda *a, **k: {CKA_MODULUS: b"short", CKA_PUBLIC_EXPONENT: b"\x01\x00\x01"},
    )
    monkeypatch.setattr(keymgmt, "destroy_quietly", lambda *a, **k: None)
    with pytest.raises(pytest.fail.Exception):
        keymgmt.TestKeyExport().test_rsa_modulus_export(_rs())
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.outcome == "fail"
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_RSA_PKCS_KEY_PAIR_GEN"


def test_import_mismatch_stays_a_bare_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    C.set_mechanism(_STALE_MECHANISM, operation="C_Stale")
    monkeypatch.setattr(keymgmt, "import_secret_key", lambda *a, **k: 31)
    monkeypatch.setattr(
        keymgmt, "read_attributes", lambda *a, **k: {CKA_KEY_TYPE: int(CKK_GENERIC_SECRET)}
    )
    monkeypatch.setattr(keymgmt, "destroy_quietly", lambda *a, **k: None)
    with pytest.raises(pytest.fail.Exception):
        keymgmt.TestKeyImport().test_import_aes_key(_rs())
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
