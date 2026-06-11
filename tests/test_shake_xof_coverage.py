"""Guardrails for SHAKE/XOF KAT-backed product tests."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases import test_extended_mechanisms as tem


class _FakeXofRaw:
    def __init__(self, output: bytes) -> None:
        self._output = output
        self._offset = 0
        self.calls: list[Any] = []

    def C_DigestXofInit(self, session: int, _mechanism: Any) -> int:  # noqa: N802
        self.calls.append(("init", session))
        self._offset = 0
        return int(CKR_OK)

    def C_DigestXof(  # noqa: N802
        self,
        _session: int,
        data: Any,
        data_len: int,
        output: Any,
        output_len: int,
    ) -> int:
        self.calls.append(("single", bytes(data[:data_len]), output_len))
        self._write(output, self._output[:output_len])
        return int(CKR_OK)

    def C_DigestXofUpdate(self, _session: int, data: Any, data_len: int) -> int:  # noqa: N802
        self.calls.append(("update", bytes(data[:data_len])))
        return int(CKR_OK)

    def C_DigestXofExtract(self, _session: int, output: Any, output_len: int) -> int:  # noqa: N802
        self.calls.append(("extract", output_len))
        chunk = self._output[self._offset : self._offset + output_len]
        self._offset += output_len
        self._write(output, chunk)
        return int(CKR_OK)

    def C_DigestXofFinal(self, _session: int, output: Any, output_len: int) -> int:  # noqa: N802
        self.calls.append(("final", output_len))
        chunk = self._output[self._offset : self._offset + output_len]
        self._offset += output_len
        self._write(output, chunk)
        return int(CKR_OK)

    @staticmethod
    def _write(output: Any, data: bytes) -> None:
        for index, value in enumerate(data):
            output[index] = value


def _session(raw: Any) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=7, has_mechanism=lambda _name: True)


def test_shake_xof_case_table_has_hashlib_reference_outputs() -> None:
    cases = tem._SHAKE_XOF_CASES

    assert [case.name for case in cases] == ["SHAKE_128", "SHAKE_256"]
    assert cases[0].reference(b"abc", 16) == hashlib.shake_128(b"abc").digest(16)
    assert cases[1].reference(b"abc", 32) == hashlib.shake_256(b"abc").digest(32)


def test_shake_xof_single_shot_helper_detects_wrong_output() -> None:
    case = tem._SHAKE_XOF_CASE_BY_NAME["SHAKE_128"]
    raw = _FakeXofRaw(b"\x00" * 16)

    with pytest.raises(AssertionError, match="CKM_SHAKE_128 XOF single-shot"):
        tem._shake_xof_single_shot_matches_reference(_session(raw), case, b"abc", 16)


def test_shake_xof_multipart_helper_uses_update_extract_and_final() -> None:
    case = tem._SHAKE_XOF_CASE_BY_NAME["SHAKE_256"]
    data_parts = (b"abc", b"def")
    expected = case.reference(b"".join(data_parts), 32)
    raw = _FakeXofRaw(expected)

    tem._shake_xof_multipart_matches_reference(
        _session(raw),
        case,
        data_parts,
        extract_len=13,
        final_len=19,
    )

    assert raw.calls == [
        ("init", 7),
        ("update", b"abc"),
        ("update", b"def"),
        ("extract", 13),
        ("final", 19),
    ]
