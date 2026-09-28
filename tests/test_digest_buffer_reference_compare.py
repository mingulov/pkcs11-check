"""Pins for reference-digest comparison in the digest buffer tests.

Every digest output-buffer node that ends with a successful C_DigestFinal
must compare the produced bytes against hashlib -- size checks alone cannot
catch state corruption or wrong output. These tests drive the real nodes
with a fake token: a correct token passes quietly, a token returning
corrupt bytes must fail the node.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_BUFFER_TOO_SMALL, CKR_OK
from pkcs11_check.testcases import test_buffers as buffers

_NODES = (
    "test_digest_final_buffer_too_small_then_correct",
    "test_digest_final_preserves_state_across_multiple_retries",
    "test_digest_final_probe_null_buffer_returns_size",
    "test_digest_final_with_oversize_buffer_writes_actual_size",
)


class _DigestFakeRaw:
    """Fake token emulating C_Digest* with an optional corrupt final."""

    def __init__(self, *, corrupt: bool = False) -> None:
        self._corrupt = corrupt
        self._msg = b""

    def C_DigestInit(self, _sh: int, _mech: Any) -> int:  # noqa: N802
        self._msg = b""
        return int(CKR_OK)

    def C_DigestUpdate(self, _sh: int, buf: Any, buf_len: int) -> int:  # noqa: N802
        self._msg += bytes(buf[: int(buf_len)])
        return int(CKR_OK)

    def C_DigestFinal(self, _sh: int, buf: Any, len_ptr: Any) -> int:  # noqa: N802
        if buf is None:
            len_ptr._obj.value = 32
            return int(CKR_OK)
        capacity = len(buf)
        if capacity < 32:
            len_ptr._obj.value = 32
            return int(CKR_BUFFER_TOO_SMALL)
        digest = hashlib.sha256(self._msg).digest()
        if self._corrupt:
            digest = bytes(b ^ 0xFF for b in digest)
        for index, byte in enumerate(digest):
            buf[index] = byte
        len_ptr._obj.value = 32
        return int(CKR_OK)


def _rs(corrupt: bool) -> SimpleNamespace:
    return SimpleNamespace(
        raw=_DigestFakeRaw(corrupt=corrupt),
        sh=1,
        has_mechanism=lambda _name: True,
    )


@pytest.mark.parametrize("node", _NODES)
def test_digest_buffer_node_accepts_correct_output(node: str) -> None:
    """A correct token passes each digest buffer node quietly."""
    getattr(buffers.TestOutputBufferEdgeCases(), node)(_rs(corrupt=False))


@pytest.mark.parametrize("node", _NODES)
def test_digest_buffer_node_rejects_corrupt_output(node: str) -> None:
    """A token returning corrupt digest bytes fails each node."""
    with pytest.raises(AssertionError, match="digest mismatch"):
        getattr(buffers.TestOutputBufferEdgeCases(), node)(_rs(corrupt=True))
