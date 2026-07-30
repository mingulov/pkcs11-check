"""Hygiene checks for ACVP AES runtime-result classification."""

from __future__ import annotations

import ast
import ctypes
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_AES_CFB8,
    CKM_AES_CFB128,
    CKM_AES_OFB,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE
from pkcs11_check.testcases.acvp.aes import base_cts, base_runner_simple

_ACVP_AES_ROOT = Path("src/pkcs11_check/testcases/acvp/aes")


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return ""


def _literal_strings(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


class _AesSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name in {"AES_CFB128", "AES_CFB8", "AES_OFB"}


def _session_with_raw(raw: object) -> _AesSession:
    session = _AesSession()
    session.raw = raw
    return session


def _raise_general_error(*_args: Any, **_kwargs: Any) -> bytes:
    raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))


def test_advertised_acvp_aes_runtime_rejections_are_not_skips() -> None:
    """After has_mechanism passes, runtime mechanism rejection is a finding."""
    offenders: list[str] = []
    for path in sorted(_ACVP_AES_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            strings = _literal_strings(node)
            if any("not supported:" in text or "module errors" in text for text in strings):
                offenders.append(f"{path}:{node.lineno}: {strings!r}")

    assert offenders == []


def test_advertised_acvp_aes_simple_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic runtime rejection after advertised AES support is an xfail finding."""
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "encrypt_single", _raise_general_error)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)

    vec = {
        "key": b"0" * 16,
        "iv": b"1" * 16,
        "pt": b"2" * 16,
        "ct_expected": b"3" * 16,
    }

    with pytest.raises(pytest.xfail.Exception, match="advertised but encrypt is not operational"):
        base_runner_simple.run_simple_encrypt_test(
            _AesSession(),
            "cfb128-general-error",
            vec,
            "AES_CFB128",
            CKM_AES_CFB128,
        )


def test_advertised_acvp_aes_mct_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCT runtime rejection is classified like simple encrypt/decrypt rejection."""
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "encrypt_single", _raise_general_error)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)

    vec = {
        "blocks": [
            {
                "block_index": 0,
                "key": b"0" * 16,
                "iv": b"1" * 16,
                "pt": b"2" * 16,
                "ct_expected": b"3" * 16,
            }
        ],
    }

    with pytest.raises(
        pytest.xfail.Exception,
        match="advertised but MCT encrypt is not operational",
    ):
        base_runner_simple.run_multiblock_encrypt_test(
            _AesSession(),
            "cfb128-mct-general-error",
            vec,
            "AES_CFB128",
            CKM_AES_CFB128,
        )


class _MctEncryptRaw:
    def __init__(self, outputs: list[bytes], *, update_rv: int = int(CKR_OK)) -> None:
        self.outputs = list(outputs)
        self.update_rv = update_rv
        self.init_calls = 0
        self.update_calls = 0
        self.final_calls = 0
        self.cancel_calls = 0

    def C_EncryptInit(self, *_args: Any) -> int:  # noqa: N802
        self.init_calls += 1
        return int(CKR_OK)

    def C_EncryptUpdate(  # noqa: N802
        self,
        _session: int,
        _in_buf: Any,
        _in_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        return self._update(out, out_len)

    def C_EncryptFinal(self, _session: int, _out: Any, out_len: Any) -> int:  # noqa: N802
        self.final_calls += 1
        out_len._obj.value = 0
        return int(CKR_OK)

    def C_DecryptInit(self, *_args: Any) -> int:  # noqa: N802
        self.init_calls += 1
        return int(CKR_OK)

    def C_DecryptUpdate(  # noqa: N802
        self,
        _session: int,
        _in_buf: Any,
        _in_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        return self._update(out, out_len)

    def C_DecryptFinal(self, _session: int, _out: Any, out_len: Any) -> int:  # noqa: N802
        self.final_calls += 1
        out_len._obj.value = 0
        return int(CKR_OK)

    def C_SessionCancel(self, *_args: Any) -> int:  # noqa: N802
        self.cancel_calls += 1
        return int(CKR_OK)

    def _update(self, out: Any, out_len: Any) -> int:
        self.update_calls += 1
        if self.update_rv != int(CKR_OK):
            return self.update_rv
        data = self.outputs.pop(0)
        for index, value in enumerate(data):
            out[index] = value
        out_len._obj.value = len(data)
        return int(CKR_OK)


class _CryptoAesMctRaw:
    def __init__(self, mechanism: int) -> None:
        self.mechanism = mechanism
        self._encryptor: Any | None = None
        self._decryptor: Any | None = None

    def C_EncryptInit(self, _session: int, mechanism: Any, key: bytes) -> int:  # noqa: N802
        self._encryptor = self._cipher(key, _iv_from_mechanism(mechanism)).encryptor()
        return int(CKR_OK)

    def C_EncryptUpdate(  # noqa: N802
        self,
        _session: int,
        data: Any,
        data_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        assert self._encryptor is not None
        return _copy_update(self._encryptor.update(bytes(data[:data_len])), out, out_len)

    def C_EncryptFinal(self, _session: int, _out: Any, out_len: Any) -> int:  # noqa: N802
        assert self._encryptor is not None
        tail = self._encryptor.finalize()
        assert tail == b""
        out_len._obj.value = 0
        return int(CKR_OK)

    def C_DecryptInit(self, _session: int, mechanism: Any, key: bytes) -> int:  # noqa: N802
        self._decryptor = self._cipher(key, _iv_from_mechanism(mechanism)).decryptor()
        return int(CKR_OK)

    def C_DecryptUpdate(  # noqa: N802
        self,
        _session: int,
        data: Any,
        data_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        assert self._decryptor is not None
        return _copy_update(self._decryptor.update(bytes(data[:data_len])), out, out_len)

    def C_DecryptFinal(self, _session: int, _out: Any, out_len: Any) -> int:  # noqa: N802
        assert self._decryptor is not None
        tail = self._decryptor.finalize()
        assert tail == b""
        out_len._obj.value = 0
        return int(CKR_OK)

    def _cipher(self, key: bytes, iv: bytes) -> Any:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        mode = (
            modes.CFB8(iv)
            if self.mechanism == int(CKM_AES_CFB8)
            else modes.OFB(iv)
            if self.mechanism == int(CKM_AES_OFB)
            else modes.CFB(iv)
        )
        return Cipher(algorithms.AES(key), mode)


def _iv_from_mechanism(mechanism: Any) -> bytes:
    ck_mechanism = mechanism._obj
    return ctypes.string_at(ck_mechanism.pParameter, ck_mechanism.ulParameterLen)


def _copy_update(data: bytes, out: Any, out_len: Any) -> int:
    for index, value in enumerate(data):
        out[index] = value
    out_len._obj.value = len(data)
    return int(CKR_OK)


def test_acvp_aes_mct_encrypt_uses_multipart_update_fast_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(base_runner_simple, "_MCT_ITERATIONS", 3)
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        base_runner_simple,
        "encrypt_single",
        lambda *_args, **_kwargs: pytest.fail("single-part fallback should not run"),
    )
    raw = _MctEncryptRaw([b"\x01" * 16, b"\x02" * 16, b"\x03" * 16])
    vec = {
        "blocks": [
            {
                "block_index": 0,
                "key": b"0" * 16,
                "iv": b"1" * 16,
                "pt": b"2" * 16,
                "ct_expected": b"\x03" * 16,
            }
        ],
    }

    base_runner_simple.run_multiblock_encrypt_test(
        _session_with_raw(raw),
        "cfb128-mct-fast",
        vec,
        "AES_CFB128",
        CKM_AES_CFB128,
    )

    assert raw.init_calls == 1
    assert raw.update_calls == 3
    assert raw.final_calls == 1


@pytest.mark.skipif(not ACVP_AVAILABLE, reason="ACVP vectors not cloned")
@pytest.mark.parametrize(
    ("vector_name", "mech_name", "mech_constant"),
    [
        ("ACVP-AES-CFB128-1.0", "AES_CFB128", CKM_AES_CFB128),
        ("ACVP-AES-CFB8-1.0", "AES_CFB8", CKM_AES_CFB8),
        ("ACVP-AES-OFB-1.0", "AES_OFB", CKM_AES_OFB),
    ],
)
def test_acvp_aes_mct_multipart_fast_path_matches_official_vectors(
    monkeypatch: pytest.MonkeyPatch,
    vector_name: str,
    mech_name: str,
    mech_constant: Any,
) -> None:
    pytest.importorskip("cryptography")
    from pkcs11_check.testcases.acvp.aes.base_loader import _load_simple_vectors

    encrypt_vectors, decrypt_vectors = _load_simple_vectors(vector_name)
    encrypt_vec = next((vec for _vec_id, vec in encrypt_vectors if vec.get("is_multiblock")), None)
    decrypt_vec = next((vec for _vec_id, vec in decrypt_vectors if vec.get("is_multiblock")), None)
    if encrypt_vec is None or decrypt_vec is None:
        pytest.skip(f"{vector_name} MCT vectors not available")
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda _rs, key, **_kwargs: key)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)

    session = _session_with_raw(_CryptoAesMctRaw(int(mech_constant)))
    base_runner_simple.run_multiblock_encrypt_test(
        session,
        f"{mech_name}-mct-official-enc",
        encrypt_vec,
        mech_name,
        mech_constant,
    )

    session = _session_with_raw(_CryptoAesMctRaw(int(mech_constant)))
    base_runner_simple.run_multiblock_decrypt_test(
        session,
        f"{mech_name}-mct-official-dec",
        decrypt_vec,
        mech_name,
        mech_constant,
    )


def test_acvp_aes_mct_encrypt_falls_back_when_update_is_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(base_runner_simple, "_MCT_ITERATIONS", 2)
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)
    outputs = [b"\x01" * 16, b"\x02" * 16]

    def encrypt_single_fallback(*_args: Any, **_kwargs: Any) -> bytes:
        return outputs.pop(0)

    monkeypatch.setattr(base_runner_simple, "encrypt_single", encrypt_single_fallback)
    raw = _MctEncryptRaw([], update_rv=int(CKR_FUNCTION_NOT_SUPPORTED))
    vec = {
        "blocks": [
            {
                "block_index": 0,
                "key": b"0" * 16,
                "iv": b"1" * 16,
                "pt": b"2" * 16,
                "ct_expected": b"\x02" * 16,
            }
        ],
    }

    base_runner_simple.run_multiblock_encrypt_test(
        _session_with_raw(raw),
        "cfb128-mct-fallback",
        vec,
        "AES_CFB128",
        CKM_AES_CFB128,
    )

    assert raw.init_calls == 1
    assert raw.update_calls == 1
    assert raw.cancel_calls == 1


def test_acvp_aes_mct_decrypt_uses_multipart_update_fast_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(base_runner_simple, "_MCT_ITERATIONS", 3)
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        base_runner_simple,
        "decrypt_single",
        lambda *_args, **_kwargs: pytest.fail("single-part fallback should not run"),
    )
    raw = _MctEncryptRaw([b"\x01" * 16, b"\x02" * 16, b"\x03" * 16])
    vec = {
        "blocks": [
            {
                "block_index": 0,
                "key": b"0" * 16,
                "iv": b"1" * 16,
                "ct": b"2" * 16,
                "pt_expected": b"\x03" * 16,
            }
        ],
    }

    base_runner_simple.run_multiblock_decrypt_test(
        _session_with_raw(raw),
        "cfb128-mct-decrypt-fast",
        vec,
        "AES_CFB128",
        CKM_AES_CFB128,
    )

    assert raw.init_calls == 1
    assert raw.update_calls == 3
    assert raw.final_calls == 1


def test_acvp_aes_mct_decrypt_falls_back_when_update_is_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(base_runner_simple, "_MCT_ITERATIONS", 2)
    monkeypatch.setattr(base_runner_simple, "_import_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(base_runner_simple, "destroy_quietly", lambda *_args: None)
    outputs = [b"\x01" * 16, b"\x02" * 16]

    def decrypt_single_fallback(*_args: Any, **_kwargs: Any) -> bytes:
        return outputs.pop(0)

    monkeypatch.setattr(base_runner_simple, "decrypt_single", decrypt_single_fallback)
    raw = _MctEncryptRaw([], update_rv=int(CKR_FUNCTION_NOT_SUPPORTED))
    vec = {
        "blocks": [
            {
                "block_index": 0,
                "key": b"0" * 16,
                "iv": b"1" * 16,
                "ct": b"2" * 16,
                "pt_expected": b"\x02" * 16,
            }
        ],
    }

    base_runner_simple.run_multiblock_decrypt_test(
        _session_with_raw(raw),
        "cfb128-mct-decrypt-fallback",
        vec,
        "AES_CFB128",
        CKM_AES_CFB128,
    )

    assert raw.init_calls == 1
    assert raw.update_calls == 1
    assert raw.cancel_calls == 1


def test_advertised_aes_cts_device_error_is_xfail() -> None:
    """CKR_DEVICE_ERROR from advertised CTS is a provider finding, not a raw failure."""
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    with pytest.raises(pytest.xfail.Exception, match="CKM_AES_CTS advertised"):
        base_cts._handle_cts_error(_AesSession(), exc, "CBC-CS1-AES-enc-tc285", "encrypt")
