"""Behavioral regressions for the output-length probe dispatch and verdict metadata."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CK_CHACHA20_PARAMS,
    CKM_AES_CFB8,
    CKM_AES_CFB128,
    CKM_AES_CTR,
    CKM_AES_OFB,
    CKM_CHACHA20,
)
from pkcs11_check.testcases._probes import output_length
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases.security import test_output_length_truncation
from pkcs11_check.testcases.security._boundary_values import OVERSIZE_WRITE_LEN, PROBE_OFFSET

_ROUTES = [
    pytest.param(
        "TestEncryptOutputLengthTruncation",
        "test_encrypt_oversized_length_rejects_or_honors",
        "aes_ctr_encrypt",
        CKM_AES_CTR,
        "CKM_AES_CTR",
        "C_EncryptInit",
        "C_Encrypt",
        id="aes-ctr-encrypt",
    ),
    pytest.param(
        "TestDecryptOutputLengthTruncation",
        "test_decrypt_oversized_length_rejects_or_honors",
        "aes_ctr_decrypt",
        CKM_AES_CTR,
        "CKM_AES_CTR",
        "C_DecryptInit",
        "C_Decrypt",
        id="aes-ctr-decrypt",
    ),
    pytest.param(
        "TestAesOFBOutputLengthTruncation",
        "test_encrypt_oversized_length_rejects_or_honors",
        "aes_ofb_encrypt",
        CKM_AES_OFB,
        "CKM_AES_OFB",
        "C_EncryptInit",
        "C_Encrypt",
        id="aes-ofb-encrypt",
    ),
    pytest.param(
        "TestAesOFBOutputLengthTruncation",
        "test_decrypt_oversized_length_rejects_or_honors",
        "aes_ofb_decrypt",
        CKM_AES_OFB,
        "CKM_AES_OFB",
        "C_DecryptInit",
        "C_Decrypt",
        id="aes-ofb-decrypt",
    ),
    pytest.param(
        "TestAesCFB128OutputLengthTruncation",
        "test_encrypt_oversized_length_rejects_or_honors",
        "aes_cfb128_encrypt",
        CKM_AES_CFB128,
        "CKM_AES_CFB128",
        "C_EncryptInit",
        "C_Encrypt",
        id="aes-cfb128-encrypt",
    ),
    pytest.param(
        "TestAesCFB128OutputLengthTruncation",
        "test_decrypt_oversized_length_rejects_or_honors",
        "aes_cfb128_decrypt",
        CKM_AES_CFB128,
        "CKM_AES_CFB128",
        "C_DecryptInit",
        "C_Decrypt",
        id="aes-cfb128-decrypt",
    ),
    pytest.param(
        "TestAesCFB8OutputLengthTruncation",
        "test_encrypt_oversized_length_rejects_or_honors",
        "aes_cfb8_encrypt",
        CKM_AES_CFB8,
        "CKM_AES_CFB8",
        "C_EncryptInit",
        "C_Encrypt",
        id="aes-cfb8-encrypt",
    ),
    pytest.param(
        "TestAesCFB8OutputLengthTruncation",
        "test_decrypt_oversized_length_rejects_or_honors",
        "aes_cfb8_decrypt",
        CKM_AES_CFB8,
        "CKM_AES_CFB8",
        "C_DecryptInit",
        "C_Decrypt",
        id="aes-cfb8-decrypt",
    ),
    pytest.param(
        "TestChaCha20OutputLengthTruncation",
        "test_encrypt_oversized_length_rejects_or_honors",
        "chacha20_encrypt",
        CKM_CHACHA20,
        "CKM_CHACHA20",
        "C_EncryptInit",
        "C_Encrypt",
        id="chacha20-encrypt",
    ),
    pytest.param(
        "TestChaCha20OutputLengthTruncation",
        "test_decrypt_oversized_length_rejects_or_honors",
        "chacha20_decrypt",
        CKM_CHACHA20,
        "CKM_CHACHA20",
        "C_DecryptInit",
        "C_Decrypt",
        id="chacha20-decrypt",
    ),
]


def test_chacha20_probe_uses_canonical_32_bit_counter_with_96_bit_nonce() -> None:
    mechanism, references = output_length._make_chacha20_mech()

    assert references
    params = ctypes.cast(
        mechanism.pParameter,
        ctypes.POINTER(CK_CHACHA20_PARAMS),
    ).contents
    assert mechanism.mechanism == CKM_CHACHA20
    assert params.blockCounterBits == 32
    assert ctypes.string_at(params.pBlockCounter, 4) == b"\x00" * 4
    assert params.ulNonceBits == 96
    assert ctypes.string_at(params.pNonce, 12) == bytes(range(12))


@pytest.mark.parametrize(
    "_class_name,_method_name,which,mechanism_id,_mechanism_name,init_fn,op_fn",
    _ROUTES,
)
def test_each_child_dispatch_reaches_the_intended_mechanism_and_operation(
    monkeypatch: pytest.MonkeyPatch,
    _class_name: str,
    _method_name: str,
    which: str,
    mechanism_id: int,
    _mechanism_name: str,
    init_fn: str,
    op_fn: str,
) -> None:
    calls: list[tuple[int, str, str]] = []
    ctx = SimpleNamespace(raw=object(), sh=7)

    monkeypatch.setattr(output_length, "_setup_aes_key", lambda *_args: 41)
    monkeypatch.setattr(output_length, "_setup_chacha20_key", lambda *_args: 42)
    monkeypatch.setattr(output_length, "destroy_quietly", lambda *_args: None)

    def _record_oracle(
        _raw: Any,
        _sh: int,
        *,
        init_fn: str,
        op_fn: str,
        mech: Any,
        key: int,
    ) -> None:
        assert key in {41, 42}
        calls.append((int(mech.mechanism), init_fn, op_fn))

    monkeypatch.setattr(output_length, "_run_oracle", _record_oracle)

    output_length._main(ctx, {"which": which})

    assert calls == [(int(mechanism_id), init_fn, op_fn)]


class _AdvertisesEveryRoute:
    def has_mechanism(self, _name: str) -> bool:
        return True


@pytest.mark.parametrize(
    "class_name,method_name,which,_mechanism_id,mechanism_name,_init_fn,operation",
    _ROUTES,
)
def test_each_successful_underfill_emits_identified_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
    class_name: str,
    method_name: str,
    which: str,
    _mechanism_id: int,
    mechanism_name: str,
    _init_fn: str,
    operation: str,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def _underfill_probe(
        probe: str,
        params: dict[str, object],
        **_kwargs: object,
    ) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout=(f"TARGET_RV:0x00000000\nUNDERFILL:1\nOUT_LEN:0x{OVERSIZE_WRITE_LEN:016x}\n"),
            stderr="",
        )

    monkeypatch.setattr(test_output_length_truncation, "run_probe", _underfill_probe)
    monkeypatch.setattr(
        test_output_length_truncation,
        "gen_aes_key_or_xfail",
        lambda *_args, **_kwargs: 1,
    )
    monkeypatch.setattr(
        test_output_length_truncation,
        "destroy_returned_handles",
        lambda *_args: None,
    )
    classification.clear()
    method = getattr(getattr(test_output_length_truncation, class_name)(), method_name)

    try:
        with pytest.raises(pytest.fail.Exception):
            method(
                _AdvertisesEveryRoute(),
                SimpleNamespace(module="/tmp/module.so", pin=None),
            )

        assert calls == [("output_length", {"module_path": "/tmp/module.so", "which": which})]
        record = classification.get_records()[-1]
        assert record.reason == "wrong_result"
        assert record.kind == "crypto"
        assert record.operation == operation
        assert record.mechanism == mechanism_name
        assert record.expected_ckr == [
            f"nonzero output at offset 0x{PROBE_OFFSET:x} after successful "
            f"0x{OVERSIZE_WRITE_LEN:x}-byte operation"
        ]
        assert record.actual_ckr == (
            f"all-zero output at offset 0x{PROBE_OFFSET:x}; "
            f"reported output length 0x{OVERSIZE_WRITE_LEN:x}"
        )
    finally:
        classification.clear()
