"""Regression tests for mechanism-driven digest runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKM_SHA224, CKR_ARGUMENTS_BAD
from pkcs11_check.testcases import test_mech_digest
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig


def _digest_entry(*, vector_file: str | None = None) -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_SHA224),
        mech_name="SHA224",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(vector_file=vector_file),
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
