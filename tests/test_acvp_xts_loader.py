"""Regression tests for ACVP AES-XTS vector loading."""

from __future__ import annotations

import pytest

from pkcs11_check.testcases.acvp.aes.test_xts import (
    _XTS_1_0_ENCRYPT_VECTORS,
    _XTS_2_0_ENCRYPT_VECTORS,
    _increment_xts_tweak,
    _require_byte_aligned_xts_vector,
    _xts_data_unit_chunks,
)


def _vector_by_id(rows: list[tuple[str, dict[str, object]]], vec_id: str) -> dict[str, object]:
    return dict(rows)[vec_id]


def test_xts_v1_number_mode_uses_little_endian_sequence_number() -> None:
    vec = _vector_by_id(_XTS_1_0_ENCRYPT_VECTORS, "XTS-1.0-AES-enc-tc51")

    assert vec["sequence_number"] == 255
    assert vec["tweak"] == (255).to_bytes(16, "little")


def test_xts_v2_number_mode_uses_little_endian_sequence_number() -> None:
    vec = _vector_by_id(_XTS_2_0_ENCRYPT_VECTORS, "XTS-2.0-AES-enc-tc101")

    assert vec["sequence_number"] == 245
    assert vec["tweak"] == (245).to_bytes(16, "little")


def test_xts_v1_group_payload_len_is_preserved() -> None:
    vec = _vector_by_id(_XTS_1_0_ENCRYPT_VECTORS, "XTS-1.0-AES-enc-tc22")

    assert vec["payload_len_bits"] == 26574
    assert vec["data_unit_len_bits"] == 26574


def test_xts_non_byte_aligned_vectors_skip_at_runtime() -> None:
    vec = _vector_by_id(_XTS_1_0_ENCRYPT_VECTORS, "XTS-1.0-AES-enc-tc22")

    with pytest.raises(pytest.skip.Exception, match="not byte-aligned"):
        _require_byte_aligned_xts_vector("XTS-1.0-AES-enc-tc22", vec)


def test_xts_data_unit_chunks_increment_tweak_little_endian() -> None:
    vec = {
        "payload_len_bits": 384,
        "data_unit_len_bits": 128,
        "tweak": bytes.fromhex("ffffffffffffffffffffffffffffffff"),
    }
    data = bytes(range(48))

    chunks = list(_xts_data_unit_chunks(data, vec))

    assert [chunk for chunk, _tweak in chunks] == [
        bytes(range(0, 16)),
        bytes(range(16, 32)),
        bytes(range(32, 48)),
    ]
    assert [tweak for _chunk, tweak in chunks] == [
        bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        bytes.fromhex("00000000000000000000000000000000"),
        bytes.fromhex("01000000000000000000000000000000"),
    ]


def test_increment_xts_tweak_uses_128_bit_little_endian_wraparound() -> None:
    tweak = bytes.fromhex("ffffffffffffffffffffffffffffffff")

    assert _increment_xts_tweak(tweak, 1) == bytes(16)
