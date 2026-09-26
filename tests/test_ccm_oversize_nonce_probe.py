"""Meta-tests: standalone CCM 16-byte-nonce negative probe.

The ECMA KATs are positive vectors (their B_0 embeds a 13-byte nonce); the
invalid-input case for a genuine 16-byte CCM nonce lives in its own retained
product node. Canonical rejection (CKR_MECHANISM_PARAM_INVALID) is PASS;
another defined/vendor clean rejection is XFAIL; acceptance, undefined CK_RV,
crash, or hang is FAIL; missing AES-CCM is capability SKIP.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.security import test_parameter_validation as pv
from tests._skip_assert import assert_skips


def _run_probe(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    seen: dict[str, int] = {}

    class _Raw:
        def C_EncryptInit(  # noqa: N802 - mirrors the PKCS#11 C function name
            self, _sh: int, _mech: Any, _key: int
        ) -> int:
            return rv

    session = SimpleNamespace(raw=_Raw(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(pv, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(pv, "destroy_quietly", lambda *_a, **_k: None)

    def _capture_nonce(mechanism_type: Any, nonce: bytes, **kwargs: Any) -> Any:
        seen["nonce_len"] = len(nonce)
        return _real_mech_ccm(mechanism_type, nonce, **kwargs)

    from pkcs11_check.raw import pack_mechanisms as pm

    _real_mech_ccm = pm.mech_ccm
    monkeypatch.setattr(pv, "mech_ccm", _capture_nonce, raising=False)
    pv.TestCcmOversizeNonce().test_ccm_16byte_nonce_rejected(session)
    assert seen.get("nonce_len") == 16


def test_canonical_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_probe(monkeypatch, int(CKR_MECHANISM_PARAM_INVALID))


def test_other_defined_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_probe(monkeypatch, int(CKR_ARGUMENTS_BAD))


def test_vendor_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_probe(monkeypatch, int(CKR_VENDOR_DEFINED))


def test_acceptance_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed, match="accepted invalid"):
        _run_probe(monkeypatch, int(CKR_OK))


def test_undefined_ckr_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed, match="undefined CK_RV"):
        _run_probe(monkeypatch, 0x7FFFFFFF)


def test_missing_ccm_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: False)
    assert_skips(pv.TestCcmOversizeNonce().test_ccm_16byte_nonce_rejected, session, match="AES_CCM")
