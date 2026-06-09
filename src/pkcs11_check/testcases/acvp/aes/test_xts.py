"""NIST ACVP AES-XTS tests.

XEX-based Tweaked Codebook with Ciphertext Stealing -- sector-based
disk encryption mode.  Uses double-length keys (data key + tweak key).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES_XTS,
    CKM_AES_XTS,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    classify_kat_clean_error,
    probe_operability,
)
from pkcs11_check.testcases.acvp.acvp_loader import load_acvp_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_XTS"]

# --- Canonical operability probe (triage H2) ---------------------------------
# One canonical XTS known answer per direction per process decides how clean
# vector errors classify (testcases/_operability.py). Expected output comes
# from `cryptography` (AES-128-XTS, spec-derived truth).
PROBE_XTS_KEY = bytes(range(32))
PROBE_XTS_TWEAK = bytes(range(16))
PROBE_XTS_PT = bytes(range(32))


def _probe_expected_xts_ct() -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    enc = Cipher(algorithms.AES(PROBE_XTS_KEY), modes.XTS(PROBE_XTS_TWEAK)).encryptor()
    return enc.update(PROBE_XTS_PT) + enc.finalize()


def _canonical_xts_probe(rs: Any, direction: str) -> OperabilityResult:
    expected_ct = _probe_expected_xts_ct()
    key = 0
    try:
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES_XTS,
                PROBE_XTS_KEY,
                attrs={
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
        except CkrAssertionError as exc:
            return OperabilityResult(
                Operability.INCONCLUSIVE, f"canonical AES_XTS key import failed: {exc}"
            )
        mech = mech_bytes(CKM_AES_XTS, PROBE_XTS_TWEAK)
        try:
            if direction == "encrypt":
                got = encrypt_single(
                    rs.raw, rs.sh, key, CKM_AES_XTS, PROBE_XTS_PT, mech_param=mech
                )
                want = expected_ct
            else:
                got = decrypt_single(
                    rs.raw, rs.sh, key, CKM_AES_XTS, expected_ct, mech_param=mech
                )
                want = PROBE_XTS_PT
        except CkrAssertionError as exc:
            return OperabilityResult(
                Operability.NOT_OPERATIONAL,
                f"canonical AES_XTS {direction} rejected: {exc}",
            )
        if got != want:
            return OperabilityResult(
                Operability.WRONG_OUTPUT,
                f"canonical AES_XTS {direction} output mismatch: "
                f"got {got.hex()}, want {want.hex()}",
            )
        return OperabilityResult(Operability.OPERATIONAL, f"canonical AES_XTS {direction} OK")
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def _xts_operability(rs: Any, direction: str) -> OperabilityResult:
    return probe_operability(
        f"AES_XTS:{direction}", lambda: _canonical_xts_probe(rs, direction)
    )


def _load_xts_vectors(
    version: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-XTS ACVP vectors for specified version (1.0 or 2.0)."""
    encrypt_vecs: list[tuple[str, dict[str, Any]]] = []
    decrypt_vecs: list[tuple[str, dict[str, Any]]] = []

    for raw_vec in load_acvp_vectors(f"ACVP-AES-XTS-{version}"):
        group = raw_vec["group"]
        inp = raw_vec["input"]
        exp = raw_vec["expected"]
        direction = group.get("direction", "")
        tc_id = inp.get("tcId", 0)
        payload_len_bits = inp.get("payloadLen", group.get("payloadLen"))
        data_unit_len_bits = inp.get("dataUnitLen", payload_len_bits)

        common = {
            "tc_id": tc_id,
            "key": bytes.fromhex(inp["key"]) if inp.get("key") else b"",
            "tweak": _xts_tweak_from_input(inp),
            "sequence_number": inp.get("sequenceNumber"),
            "payload_len_bits": payload_len_bits,
            "data_unit_len_bits": data_unit_len_bits,
            "tweak_mode": group.get("tweakMode"),
        }

        if direction == "encrypt":
            encrypt_vecs.append(
                (
                    f"XTS-{version}-AES-enc-tc{tc_id}",
                    {
                        **common,
                        "pt": bytes.fromhex(inp["pt"]) if inp.get("pt") else b"",
                        "ct_expected": bytes.fromhex(exp["ct"]) if exp.get("ct") else b"",
                    },
                )
            )
        elif direction == "decrypt":
            decrypt_vecs.append(
                (
                    f"XTS-{version}-AES-dec-tc{tc_id}",
                    {
                        **common,
                        "ct": bytes.fromhex(inp["ct"]) if inp.get("ct") else b"",
                        "pt_expected": bytes.fromhex(exp["pt"]) if exp.get("pt") else b"",
                    },
                )
            )

    return encrypt_vecs, decrypt_vecs


def _xts_tweak_from_input(inp: dict[str, Any]) -> bytes:
    if "tweakValue" in inp:
        return bytes.fromhex(inp["tweakValue"])
    sequence_number = inp.get("sequenceNumber")
    if sequence_number is None:
        return b""
    return int(sequence_number).to_bytes(16, "little")


def _increment_xts_tweak(tweak: bytes, increment: int) -> bytes:
    value = (int.from_bytes(tweak, "little") + increment) % (1 << 128)
    return value.to_bytes(16, "little")


def _require_byte_aligned_xts_vector(vec_id: str, vec: dict[str, Any]) -> None:
    payload_len_bits = vec.get("payload_len_bits")
    data_unit_len_bits = vec.get("data_unit_len_bits")
    for label, bit_len in (
        ("payloadLen", payload_len_bits),
        ("dataUnitLen", data_unit_len_bits),
    ):
        if bit_len is not None and int(bit_len) % 8 != 0:
            pytest.skip(
                f"{vec_id}: ACVP AES-XTS {label}={bit_len} is not byte-aligned; "
                "PKCS#11 CKM_AES_XTS accepts byte strings"
            )


def _xts_data_unit_chunks(data: bytes, vec: dict[str, Any]) -> list[tuple[bytes, bytes]]:
    _require_byte_aligned_xts_vector(str(vec.get("tc_id", "unknown")), vec)
    payload_len_bits = vec.get("payload_len_bits")
    data_unit_len_bits = vec.get("data_unit_len_bits")
    payload_len = len(data) if payload_len_bits is None else int(payload_len_bits) // 8
    data_unit_len = payload_len if data_unit_len_bits is None else int(data_unit_len_bits) // 8
    tweak = vec["tweak"]

    if not tweak or len(tweak) != 16:
        pytest.skip("ACVP AES-XTS vector does not provide a 16-byte data-unit sequence number")
    if payload_len != len(data):
        pytest.skip(
            f"ACVP AES-XTS payloadLen={payload_len_bits} does not match {len(data)} input bytes"
        )
    if data_unit_len <= 0:
        pytest.skip("ACVP AES-XTS dataUnitLen is empty")

    chunks = []
    for index, offset in enumerate(range(0, len(data), data_unit_len)):
        chunk = data[offset : offset + data_unit_len]
        if len(chunk) < 16:
            pytest.skip(
                "ACVP AES-XTS data unit shorter than the PKCS#11 CKM_AES_XTS minimum input length"
            )
        chunks.append((chunk, _increment_xts_tweak(tweak, index)))
    return chunks


_XTS_1_0_ENCRYPT_VECTORS, _XTS_1_0_DECRYPT_VECTORS = _load_xts_vectors("1.0")
_XTS_2_0_ENCRYPT_VECTORS, _XTS_2_0_DECRYPT_VECTORS = _load_xts_vectors("2.0")


@pytest.mark.parametrize(
    "vec_id,vec",
    _XTS_1_0_ENCRYPT_VECTORS + _XTS_2_0_ENCRYPT_VECTORS,
    ids=[v[0] for v in _XTS_1_0_ENCRYPT_VECTORS + _XTS_2_0_ENCRYPT_VECTORS],
)
def test_acvp_aes_xts_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XTS encryption from NIST ACVP vectors (v1.0 and v2.0)."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_XTS"):
        pytest.skip("AES_XTS not supported by module")

    chunks = _xts_data_unit_chunks(vec["pt"], vec)
    key = 0
    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES_XTS,
            vec["key"],
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_ENCRYPT: True,
            },
        )
        try:
            ct_parts = []
            for chunk, tweak in chunks:
                mech = mech_bytes(CKM_AES_XTS, tweak)
                ct_parts.append(
                    encrypt_single(
                        rs.raw,
                        rs.sh,
                        key,
                        CKM_AES_XTS,
                        chunk,
                        mech_param=mech,
                    )
                )
            ct = b"".join(ct_parts)
        except AssertionError as exc:
            classify_kat_clean_error(
                exc, result=_xts_operability(rs, "encrypt"), label="AES_XTS encrypt"
            )

        assert ct == vec["ct_expected"], (
            f"{vec_id}: ciphertext mismatch: got {ct.hex()}, expected {vec['ct_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.parametrize(
    "vec_id,vec",
    _XTS_1_0_DECRYPT_VECTORS + _XTS_2_0_DECRYPT_VECTORS,
    ids=[v[0] for v in _XTS_1_0_DECRYPT_VECTORS + _XTS_2_0_DECRYPT_VECTORS],
)
def test_acvp_aes_xts_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XTS decryption from NIST ACVP vectors (v1.0 and v2.0)."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_XTS"):
        pytest.skip("AES_XTS not supported by module")

    chunks = _xts_data_unit_chunks(vec["ct"], vec)
    key = 0
    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES_XTS,
            vec["key"],
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_DECRYPT: True,
            },
        )
        try:
            pt_parts = []
            for chunk, tweak in chunks:
                mech = mech_bytes(CKM_AES_XTS, tweak)
                pt_parts.append(
                    decrypt_single(
                        rs.raw,
                        rs.sh,
                        key,
                        CKM_AES_XTS,
                        chunk,
                        mech_param=mech,
                    )
                )
            pt = b"".join(pt_parts)
        except AssertionError as exc:
            classify_kat_clean_error(
                exc, result=_xts_operability(rs, "decrypt"), label="AES_XTS decrypt"
            )

        assert pt == vec["pt_expected"], (
            f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
