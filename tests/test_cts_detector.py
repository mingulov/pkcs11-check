"""Focused tests for the AES-CTS variant detector."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_AES_CTS,
    CKR_FUNCTION_FAILED,
    CKR_KEY_SIZE_RANGE,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.acvp.aes import base_cts

_EXPECTED_OUTPUTS = {
    128: (
        bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a3cf456b4ca488aa383c79c98b34797cb"),
        bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a805a979c08338ad33b5ab497158f41bf3c"),
    ),
    192: (
        bytes.fromhex("0060bffe46834bb8da5cf9a61ff220aeb9770009a06cb2d7f6f296be878bb327"),
        bytes.fromhex("0060bffe46834bb8da5cf9a61ff220aee38155f278d601ee52b3993bedbbbecfb9"),
    ),
    256: (
        bytes.fromhex("5a6e045708fb7196f02e553d02c3a692c77147ebd5121de8d0fae7762423b6bf"),
        bytes.fromhex("5a6e045708fb7196f02e553d02c3a6927701c065cbc2b06542c46d328514483ec7"),
    ),
}


class _FakeSession:
    raw = object()
    sh = 7

    def has_mechanism(self, name: str) -> bool:
        return name == "AES_CTS"


def _fake_encryptor(
    outputs: dict[int, dict[bytes, bytes]],
    calls: list[tuple[int, bytes]],
):
    def encrypt(
        _raw: Any,
        _session: int,
        key: int,
        mechanism: int,
        plaintext: bytes,
        **_kwargs: Any,
    ) -> bytes:
        calls.append((key, plaintext))
        if mechanism != CKM_AES_CTS:
            raise AssertionError("detector must not use provider CBC as its oracle")
        return outputs[key][plaintext]

    return encrypt


def _all_variant_outputs(variant: str) -> dict[int, dict[bytes, bytes]]:
    expected = _EXPECTED_OUTPUTS
    aligned = {
        "1": {
            128: bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a3cf456b4ca488aa383c79c98b34797cb"),
            192: expected[192][0],
            256: expected[256][0],
        },
        "2": {
            128: expected[128][0],
            192: expected[192][0],
            256: expected[256][0],
        },
        "3": {
            128: bytes.fromhex("3cf456b4ca488aa383c79c98b34797cb0a940bb5416ef045f1c39458c653ea5a"),
            192: bytes.fromhex("b9770009a06cb2d7f6f296be878bb3270060bffe46834bb8da5cf9a61ff220ae"),
            256: bytes.fromhex("c77147ebd5121de8d0fae7762423b6bf5a6e045708fb7196f02e553d02c3a692"),
        },
    }[variant]
    unaligned = {
        "1": {
            128: bytes.fromhex(
                "0a940bb5416ef045f1c39458c653ea5a3c805a979c08338ad33b5ab497158f41bf"
            ),
            192: bytes.fromhex(
                "0060bffe46834bb8da5cf9a61ff220aeb9e38155f278d601ee52b3993bedbbbecf"
            ),
            256: bytes.fromhex(
                "5a6e045708fb7196f02e553d02c3a692c77701c065cbc2b06542c46d328514483e"
            ),
        },
        "2": {bits: expected[bits][1] for bits in (128, 192, 256)},
        "3": {bits: expected[bits][1] for bits in (128, 192, 256)},
    }[variant]
    return {
        bits // 8: {
            bytes(range(32)): aligned[bits],
            bytes(range(33)): unaligned[bits],
        }
        for bits in (128, 192, 256)
    }


@pytest.mark.parametrize("variant", ["1", "2", "3"])
def test_cts_detector_uses_fixed_exact_kat_pair(
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    """The detector must classify independent fixed-key 32/33-byte KAT outputs."""
    calls: list[tuple[int, bytes]] = []
    imported: list[bytes] = []
    packed: list[tuple[int, bytes]] = []
    outputs = _all_variant_outputs(variant)
    monkeypatch.setattr(
        base_cts,
        "_import_aes_key",
        lambda _rs, key, **_kwargs: imported.append(key) or len(key),
    )
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    real_mech_bytes = base_cts.mech_bytes

    def pack_mechanism(mechanism: int, iv: bytes) -> Any:
        packed.append((mechanism, iv))
        return real_mech_bytes(mechanism, iv)

    monkeypatch.setattr(base_cts, "mech_bytes", pack_mechanism)
    monkeypatch.setattr(
        base_cts,
        "encrypt_single",
        _fake_encryptor(outputs, calls),
    )
    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert result.variant == variant
    assert imported == [bytes(range(32)), bytes(range(24)), bytes(range(16))]
    assert all(
        len(outputs[bits // 8][bytes(range(32))]) == 32
        and len(outputs[bits // 8][bytes(range(33))]) == 33
        for bits in (128, 192, 256)
    )
    assert packed == [(CKM_AES_CTS, bytes(16))] * 6
    assert calls == [
        (32, bytes(range(32))),
        (32, bytes(range(33))),
        (24, bytes(range(32))),
        (24, bytes(range(33))),
        (16, bytes(range(32))),
        (16, bytes(range(33))),
    ]


def test_cts_detector_supports_256_bit_only_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clean key-size refusals fall through to a supported fixed-key size."""
    imported: list[bytes] = []
    calls: list[tuple[int, bytes]] = []

    def import_key(_rs: Any, key: bytes, **_kwargs: Any) -> int:
        imported.append(key)
        if len(key) != 32:
            raise CkrAssertionError("size unavailable", int(CKR_KEY_SIZE_RANGE))
        return len(key)

    monkeypatch.setattr(base_cts, "_import_aes_key", import_key)
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        base_cts,
        "encrypt_single",
        _fake_encryptor(_all_variant_outputs("2"), calls),
    )

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert result.variant == "2"
    assert [len(key) for key in imported] == [32, 24, 16]
    assert [key_size for key_size, _payload in calls] == [32, 32]


def test_cts_detector_wrong_aligned_output_survives_later_clean_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong CKR_OK aligned answer cannot be erased by an unaligned CKR."""
    outputs = _all_variant_outputs("1")
    wrong_aligned = bytearray(outputs[32][bytes(range(32))])
    wrong_aligned[0] ^= 1
    calls: list[tuple[int, bytes]] = []

    def import_key(_rs: Any, key: bytes, **_kwargs: Any) -> int:
        if len(key) != 32:
            raise CkrAssertionError("size unavailable", int(CKR_KEY_SIZE_RANGE))
        return len(key)

    def encrypt(
        _raw: Any,
        _session: int,
        key: int,
        mechanism: int,
        plaintext: bytes,
        **_kwargs: Any,
    ) -> bytes:
        calls.append((key, plaintext))
        assert mechanism == CKM_AES_CTS
        if plaintext == bytes(range(32)):
            return bytes(wrong_aligned)
        raise CkrAssertionError("unaligned refusal", int(CKR_FUNCTION_FAILED))

    monkeypatch.setattr(base_cts, "_import_aes_key", import_key)
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(base_cts, "encrypt_single", encrypt)

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.WRONG_RESULT
    assert result.key_bits == 256
    assert result.detail["output"]["aligned"]["actual"] == bytes(wrong_aligned).hex()
    assert calls == [(32, bytes(range(32)))]


def test_cts_detector_wrong_unaligned_cs3_evidence_uses_viable_variant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CS3 aligned match must make the later mismatch evidence say CS3."""
    outputs = _all_variant_outputs("3")
    wrong_unaligned = bytearray(outputs[32][bytes(range(33))])
    wrong_unaligned[-1] ^= 1
    outputs[32][bytes(range(33))] = bytes(wrong_unaligned)

    monkeypatch.setattr(base_cts, "_import_aes_key", lambda _rs, key, **_kwargs: len(key))
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(base_cts, "encrypt_single", _fake_encryptor(outputs, []))

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.WRONG_RESULT
    detail = result.detail
    assert detail["viable_variants"] == ["CS3"]
    assert detail["output"]["aligned"]["expected"] == outputs[32][bytes(range(32))].hex()
    assert detail["output"]["unaligned"]["expected"] == (
        _all_variant_outputs("3")[32][bytes(range(33))].hex()
    )


def test_cts_detector_distinguishes_unavailable_setup_from_import_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine C_CreateObject capability skip is not an import CKR result."""

    def unavailable(_rs: Any, _key: bytes, **_kwargs: Any) -> int:
        raise pytest.skip.Exception("Module does not implement C_CreateObject")

    monkeypatch.setattr(base_cts, "_import_aes_key", unavailable)

    try:
        result = base_cts._detect_cts_variant(_FakeSession())
    except pytest.skip.Exception as exc:
        pytest.fail(f"setup capability skip was not retained as structured evidence: {exc}")

    assert result.status.value == "setup_unavailable"
    assert all(
        attempt["stage"] == "setup"
        and attempt["operation"] == "C_CreateObject"
        and attempt["case"] is None
        and attempt["ckr"] is None
        for attempt in result.detail["attempts"]
    )
    with pytest.raises(pytest.skip.Exception):
        base_cts.report_cts_detection(result)


def test_cts_detector_attributes_clean_import_reject_to_create_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clean fixed-key import CKRs remain setup evidence, not C_Encrypt evidence."""

    def reject(_rs: Any, _key: bytes, **_kwargs: Any) -> int:
        raise CkrAssertionError("import refusal", int(CKR_FUNCTION_FAILED))

    monkeypatch.setattr(base_cts, "_import_aes_key", reject)

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status.value == "setup_rejected"
    attempts = result.detail["attempts"]
    assert len(attempts) == 3
    assert all(
        attempt["stage"] == "setup"
        and attempt["operation"] == "C_CreateObject"
        and attempt["case"] is None
        and attempt["ckr"] == int(CKR_FUNCTION_FAILED)
        for attempt in attempts
    )
    with pytest.raises(pytest.xfail.Exception):
        base_cts.report_cts_detection(result)
    record = classification.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_CreateObject"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_cts_detector_contains_unlisted_setup_ckr_as_setup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An off-contract CKR from the detection import must not crash collection.

    Round-0197 evidence: wolf answers the detector's C_CreateObject with
    CKR_USER_NOT_LOGGED_IN, which is not in AES_KEYGEN_RUNTIME_REJECT_RVS.
    Re-raising it became a pytest INTERNALERROR (exit 3) that deleted all
    7,500 collected tests and left the provider unpublished. The detector
    must gather every key size and return a structured error instead.
    """
    assert not base_cts.is_known_error(
        CkrAssertionError("premise", int(CKR_USER_NOT_LOGGED_IN)),
        base_cts.AES_KEYGEN_RUNTIME_REJECT_RVS,
    )

    def reject(_rs: Any, _key: bytes, **_kwargs: Any) -> int:
        raise CkrAssertionError("import refusal", int(CKR_USER_NOT_LOGGED_IN))

    monkeypatch.setattr(base_cts, "_import_aes_key", reject)

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status.value == "setup_error"
    assert result.error_rv == int(CKR_USER_NOT_LOGGED_IN)
    attempts = result.detail["attempts"]
    assert len(attempts) == 3
    assert all(
        attempt["stage"] == "setup"
        and attempt["operation"] == "C_CreateObject"
        and attempt["case"] is None
        and attempt["ckr"] == int(CKR_USER_NOT_LOGGED_IN)
        for attempt in attempts
    )
    with pytest.raises(CkrAssertionError) as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == int(CKR_USER_NOT_LOGGED_IN)
    assert "CKR_USER_NOT_LOGGED_IN" in str(excinfo.value)


def test_cts_detector_contains_unlisted_operation_ckr_as_setup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An off-contract CKR from the detection encrypt must not crash collection."""
    assert not base_cts.is_known_error(
        CkrAssertionError("premise", int(CKR_USER_NOT_LOGGED_IN)),
        base_cts.CIPHER_OP_RUNTIME_REJECT_RVS,
    )
    monkeypatch.setattr(base_cts, "_import_aes_key", lambda _rs, key, **_kwargs: len(key))
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)

    def explode(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("encrypt refusal", int(CKR_USER_NOT_LOGGED_IN))

    monkeypatch.setattr(base_cts, "encrypt_single", explode)

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status.value == "setup_error"
    assert result.error_rv == int(CKR_USER_NOT_LOGGED_IN)
    attempts = result.detail["attempts"]
    assert len(attempts) == 3
    assert all(
        attempt["stage"] == "operation"
        and attempt["operation"] == "C_Encrypt"
        and attempt["ckr"] == int(CKR_USER_NOT_LOGGED_IN)
        for attempt in attempts
    )


def test_cts_setup_error_message_names_the_priority_operation_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sentinel message must name the attempt that produced error_rv.

    error_rv carries operation priority (an operation-stage unlisted CKR wins
    over later setup attempts), so the message must cite that attempt -- not
    the chronologically last one.
    """
    assert not base_cts.is_known_error(
        CkrAssertionError("premise", int(CKR_USER_NOT_LOGGED_IN)),
        base_cts.CIPHER_OP_RUNTIME_REJECT_RVS,
    )
    assert base_cts.is_known_error(
        CkrAssertionError("premise", int(CKR_KEY_SIZE_RANGE)),
        base_cts.AES_KEYGEN_RUNTIME_REJECT_RVS,
    )

    def import_256_only(_rs: Any, key: bytes, **_kwargs: Any) -> int:
        if len(key) == 32:
            return 11
        raise CkrAssertionError("unsupported size", int(CKR_KEY_SIZE_RANGE))

    def explode(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("encrypt refusal", int(CKR_USER_NOT_LOGGED_IN))

    monkeypatch.setattr(base_cts, "_import_aes_key", import_256_only)
    monkeypatch.setattr(base_cts, "encrypt_single", explode)
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status.value == "setup_error"
    assert result.error_rv == int(CKR_USER_NOT_LOGGED_IN)
    attempts = result.detail["attempts"]
    assert [attempt["stage"] for attempt in attempts] == [
        "operation",
        "setup",
        "setup",
    ]
    with pytest.raises(CkrAssertionError) as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == int(CKR_USER_NOT_LOGGED_IN)
    assert "operation C_Encrypt" in str(excinfo.value)
    assert "setup C_CreateObject" not in str(excinfo.value)


def test_cts_setup_error_without_ckr_is_a_harness_bug() -> None:
    """SETUP_ERROR without the offending CKR means the detector misbuilt it."""
    result = base_cts.CtsDetectionResult(status=base_cts.CtsDetectionStatus.SETUP_ERROR)
    with pytest.raises(RuntimeError, match="without a CKR"):
        base_cts.report_cts_detection(result)


@pytest.mark.parametrize(
    "status",
    [
        "setup_unavailable",
        "setup_rejected",
        "setup_error",
    ],
)
def test_cts_setup_outcomes_are_inconclusive_operability(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    """Setup-only outcomes must not claim CTS operation was exercised."""
    result = SimpleNamespace(status=SimpleNamespace(value=status))
    monkeypatch.setattr(base_cts, "get_cts_detection", lambda _rs: result)

    operability = base_cts._cts_operability(_FakeSession())

    assert operability.status is base_cts.Operability.INCONCLUSIVE


def test_cts_detector_wrong_output_is_structured_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OK with a wrong byte/length is a crypto wrong-result finding."""
    outputs = _all_variant_outputs("1")
    wrong = bytearray(outputs[16][bytes(range(33))])
    wrong[-1] ^= 1
    outputs[16][bytes(range(33))] = bytes(wrong)
    monkeypatch.setattr(base_cts, "_import_aes_key", lambda _rs, key, **_kwargs: len(key))
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(base_cts, "encrypt_single", _fake_encryptor(outputs, []))

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.WRONG_RESULT
    assert result.key_bits == 128
    assert result.detail["output"]["unaligned"]["actual"] == bytes(wrong).hex()
    with pytest.raises(pytest.fail.Exception):
        base_cts.report_cts_detection(result)
    record = classification.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.detail == result.detail


def test_cts_wrong_output_stays_wrong_output_in_operability_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A detector crypto mismatch must not let clean vector CKRs become xfails."""
    result = base_cts.CtsDetectionResult(
        base_cts.CtsDetectionStatus.WRONG_RESULT,
        key_bits=128,
        detail={"output": {}},
    )
    # Bypass provider calls but exercise the shared operability adapter.
    monkeypatch.setattr(base_cts, "get_cts_detection", lambda _rs: result)
    operability = base_cts._cts_operability(_FakeSession())
    assert operability.status is base_cts.Operability.WRONG_OUTPUT


def test_cts_detector_rejects_wrong_length_as_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CKR_OK output with the wrong length is never an operationality xfail."""
    outputs = _all_variant_outputs("1")
    outputs[16][bytes(range(33))] = b"wrong-length"
    monkeypatch.setattr(base_cts, "_import_aes_key", lambda _rs, key, **_kwargs: len(key))
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(base_cts, "encrypt_single", _fake_encryptor(outputs, []))

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.WRONG_RESULT
    assert result.detail["output"]["unaligned"]["actual_length"] == len(b"wrong-length")
    with pytest.raises(pytest.fail.Exception):
        base_cts.report_cts_detection(result)
    assert classification.get_records()[0].reason == "wrong_result"


def test_cts_detector_clean_ckr_is_not_operational_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A clean advertised-operation CKR remains a not-operational xfail."""
    monkeypatch.setattr(base_cts, "_import_aes_key", lambda *_args, **_kwargs: 23)
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        base_cts,
        "encrypt_single",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("clean refusal", int(CKR_FUNCTION_FAILED))
        ),
    )

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.NOT_OPERATIONAL
    assert result.error_rv == int(CKR_FUNCTION_FAILED)
    assert all(
        attempt["stage"] == "operation"
        and attempt["operation"] == "C_Encrypt"
        and attempt["case"] == "aligned"
        and attempt["ckr"] == int(CKR_FUNCTION_FAILED)
        for attempt in result.detail["attempts"]
    )
    with pytest.raises(pytest.xfail.Exception):
        base_cts.report_cts_detection(result)
    assert classification.get_records()[0].reason == "not_operational"


def test_cts_detector_missing_mechanism_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A genuinely absent AES_CTS mechanism stays a capability skip."""
    rs = type("NoCts", (), {"has_mechanism": lambda _self, _name: False})()

    result = base_cts._detect_cts_variant(rs)

    assert result.status is base_cts.CtsDetectionStatus.ABSENT
    with pytest.raises(pytest.skip.Exception):
        base_cts.report_cts_detection(result)
    assert classification.get_records() == []


def test_cts_detection_result_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """The structured detector result is cached once per isolated test process."""
    expected = base_cts.CtsDetectionResult(
        base_cts.CtsDetectionStatus.DETECTED,
        variant="1",
    )
    calls = 0

    def detect(_rs: Any) -> base_cts.CtsDetectionResult:
        nonlocal calls
        calls += 1
        return expected

    base_cts.reset_cts_detection_cache()
    monkeypatch.setattr(base_cts, "_detect_cts_variant", detect)
    rs = _FakeSession()

    assert base_cts.get_cts_detection(rs) is expected
    assert base_cts.get_cts_detection(rs) is expected
    assert calls == 1
    base_cts.reset_cts_detection_cache()
