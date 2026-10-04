"""fw#43: TestRSAX931 must feed digest || trailer-ID and run the oracle.

Runs the real TestRSAX931 methods with a fake token: sign captures the fed
input (must be the transformer output, not a bare digest) and returns an
all-zero block, so the oracle stage must reject it with the oracle label.
The tampered/wrong-input negatives must complete with their oracle
discrimination assertions holding.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
)
from pkcs11_check.testcases import _x931, test_rsa_extended

_TOY_N = bytes.fromhex(
    "c45f90ebd7fc4eaace356e7775a8098a251be970f0976a1810fa347a437373f6b5e544b93"
    "2e720c2fa7a0e1cf0a916115f1235be65e6497610e3def20c707efd"
)
_TOY_E = bytes.fromhex("010001")

_SHA256_MESSAGE = b"test data for X9.31 signing"
_SHA1_MESSAGE = b"test data for X9.31 SHA-1"


class _X931CaptureRaw:
    """Capture sign input; return zero blocks; refuse verification."""

    def __init__(self) -> None:
        self.sign_inputs: list[bytes] = []

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _pub_tmpl: Any,
        _pub_n: int,
        _priv_tmpl: Any,
        _priv_n: int,
        pub_out: Any,
        priv_out: Any,
    ) -> int:
        # Must match the PKCS#11 entry-point name the helper calls.
        pub_out._obj.value = 41
        priv_out._obj.value = 42
        return int(CKR_OK)

    def C_SignInit(self, _sh: int, _mech: Any, _key: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        return int(CKR_OK)

    def C_Sign(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out_buf: Any, out_len: Any
    ) -> int:
        # Must match the PKCS#11 entry-point name the recipe calls.
        self.sign_inputs.append(bytes(in_buf[:in_len]))
        if out_buf is None:
            out_len._obj.value = 256
        else:
            for i in range(min(256, len(out_buf))):
                out_buf[i] = 0
            out_len._obj.value = 256
        return int(CKR_OK)

    def C_VerifyInit(self, _sh: int, _mech: Any, _key: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        return int(CKR_OK)

    def C_Verify(  # noqa: N802
        self, _sh: int, _in_buf: Any, _in_len: int, _sig: Any, _sig_len: int
    ) -> int:
        # Must match the PKCS#11 entry-point name the recipe calls.
        return int(CKR_SIGNATURE_INVALID)

    def C_DestroyObject(self, _sh: int, _h: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the helper calls.
        return int(CKR_OK)


def _run(method: str, raw: _X931CaptureRaw, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        test_rsa_extended,
        "read_attributes",
        lambda *_a, **_k: {CKA_MODULUS: _TOY_N, CKA_PUBLIC_EXPONENT: _TOY_E},
    )
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=raw, sh=1)
    getattr(test_rsa_extended.TestRSAX931(), method)(rs)


def test_sha256_leg_feeds_trailer_input(monkeypatch: Any) -> None:
    """The SHA-256 leg must sign digest || 0x34, not a bare digest (fw#43)."""
    raw = _X931CaptureRaw()
    with pytest.raises(pytest.fail.Exception, match="(?i)oracle"):
        _run("test_sign_verify_sha256", raw, monkeypatch)
    assert raw.sign_inputs
    for fed in raw.sign_inputs:
        assert fed == _x931.x931_sign_input(_SHA256_MESSAGE, "sha256")


def test_sha1_leg_feeds_trailer_input(monkeypatch: Any) -> None:
    """The SHA-1 leg must sign digest || 0x33, not a bare digest (fw#43)."""
    raw = _X931CaptureRaw()
    with pytest.raises(pytest.fail.Exception, match="(?i)oracle"):
        _run("test_sign_verify_sha1", raw, monkeypatch)
    assert raw.sign_inputs
    for fed in raw.sign_inputs:
        assert fed == _x931.x931_sign_input(_SHA1_MESSAGE, "sha1")


def test_tampered_signature_negative_oracle_runs(monkeypatch: Any) -> None:
    """The tampered leg completes with oracle discrimination holding (fw#43)."""
    _run("test_tampered_signature_fails", _X931CaptureRaw(), monkeypatch)


def test_wrong_input_negative_oracle_runs(monkeypatch: Any) -> None:
    """The wrong-input leg completes with oracle discrimination holding."""
    _run("test_wrong_digest_fails", _X931CaptureRaw(), monkeypatch)
