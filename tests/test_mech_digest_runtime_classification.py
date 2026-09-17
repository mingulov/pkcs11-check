"""Regression tests for mechanism-driven digest runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_DIGEST,
    CKM_AES_GCM,
    CKM_SHA224,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases import test_mech_digest
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig
from tests._skip_assert import assert_skips


def _digest_entry(
    *,
    vector_file: str | None = None,
    input_constraint: str = "digest_only",
    mech_id: int = int(CKM_SHA224),
    mech_name: str = "SHA224",
    flags: int = 0,
) -> MechEntry:
    return MechEntry(
        mech_id=mech_id,
        mech_name=mech_name,
        flags=flags,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(vector_file=vector_file, input_constraint=input_constraint),
    )


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _digest_reject(*_args: Any, **_kwargs: Any) -> bytes:
    raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))


def test_mech_digest_empty_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_mech_digest, "digest_single", _digest_reject)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        test_mech_digest.TestMechDigest().test_known_empty(_session(), _digest_entry())


def test_mech_digest_kat_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_mech_digest, "digest_single", _digest_reject)

    from pkcs11_check.testcases import mechanism_vectors

    monkeypatch.setattr(
        mechanism_vectors,
        "load_positive_vectors",
        lambda _path: [{"input_hex": "00", "digest_hex": "00"}],
    )

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        test_mech_digest.TestMechDigestKAT().test_kat_vector(
            _session(),
            _digest_entry(vector_file="dummy.json"),
        )


def test_aes_gcm_digest_advertisement_does_not_load_digest_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.testcases import mechanism_vectors

    monkeypatch.setattr(
        mechanism_vectors,
        "load_positive_vectors",
        lambda _path: [{"id": "gcm-1", "plaintext_hex": "00", "ciphertext_hex": "00"}],
    )

    def _unexpected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("AEAD vector must not be sent to digest provider")

    monkeypatch.setattr(test_mech_digest, "digest_single", _unexpected_digest)
    entry = _digest_entry(
        vector_file="aes_gcm.json",
        input_constraint="any",
        mech_id=int(CKM_AES_GCM),
        mech_name="AES_GCM",
        flags=int(CKF_DIGEST),
    )

    assert_skips(
        test_mech_digest.TestMechDigestKAT().test_kat_vector, _session(), entry, match="not digest"
    )
    assert get_records() == []


def test_incompatible_digest_advertisement_is_retained() -> None:
    from pkcs11_check.testcases.test_mech_flags import TestMechFlagBehavioralConformance

    def _digest_init(*_args: Any) -> int:
        return int(CKR_FUNCTION_NOT_SUPPORTED)

    session = SimpleNamespace(raw=SimpleNamespace(C_DigestInit=_digest_init), sh=1)
    entry = _digest_entry(
        input_constraint="any",
        mech_id=int(CKM_AES_GCM),
        mech_name="AES_GCM",
        flags=int(CKF_DIGEST),
    )

    with pytest.raises(pytest.fail.Exception, match="advertises CKF_DIGEST"):
        TestMechFlagBehavioralConformance().test_digest_flag_callable(session, entry)

    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].mechanism == "AES_GCM"
    assert records[0].actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"
