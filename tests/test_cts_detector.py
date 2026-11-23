"""Focused tests for the AES-CTS variant detector."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.recipes import ImplausibleModuleLengthError
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKM_AES_CTS,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_KEY_SIZE_RANGE,
    CKR_OK,
    CKR_USER_NOT_LOGGED_IN,
    CKU_USER,
)
from pkcs11_check.testcases.acvp.aes import base_cts
from tests._skip_assert import assert_skips

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
    assert_skips(base_cts.report_cts_detection, result)


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
    assert_skips(base_cts.report_cts_detection, result)
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


def _stub_config() -> Any:
    return SimpleNamespace(
        getoption=lambda name, default=None: "/fake/module.so" if name == "p11_module" else default
    )


def test_cts_probe_contains_hostile_length_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hostile module length report must not INTERNALERROR collection.

    The encrypt probe sizes its output buffer from a module-reported length;
    an absurd report raises out of detection. The collection probe contains
    it as setup-unavailable (with the honest reason) so the file survives;
    the unprimed process cache makes the runtime guard re-probe, keeping the
    failure fail-visible per test.
    """
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    def hostile(_config: Any) -> base_cts.CtsDetectionResult:
        raise ImplausibleModuleLengthError(
            "C_Encrypt: module reported an implausible output length (2**63 bytes)"
        )

    monkeypatch.setattr(aes_conftest, "_detect_variant_via_pkcs11", hostile)

    result = aes_conftest._probe_cts_variant(_stub_config())

    assert result.status is base_cts.CtsDetectionStatus.SETUP_UNAVAILABLE
    assert "implausible output length" in result.detail["reason"]


def test_cts_probe_reraises_ordinary_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the typed length signal is contained; harness bugs stay visible."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    def buggy(_config: Any) -> base_cts.CtsDetectionResult:
        raise ValueError("harness bug")

    monkeypatch.setattr(aes_conftest, "_detect_variant_via_pkcs11", buggy)

    with pytest.raises(ValueError, match="harness bug"):
        aes_conftest._probe_cts_variant(_stub_config())


def test_cts_probe_coerces_missing_interface_to_auto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An omitted --p11-interface must not crash module loading.

    The plugin default is None ("auto" is only documentation); the probe
    coerces None like every other consumer instead of letting load_module
    raise "Unknown interface None" into collection.
    """
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    captured: dict[str, object] = {}

    def fake_load_module(path: object, interface: object = None) -> Any:
        captured["interface"] = interface
        return SimpleNamespace(raw=object())

    monkeypatch.setattr("pkcs11_check.core.loader.load_module", fake_load_module)
    monkeypatch.setattr("pkcs11_check.raw.bootstrap.get_slot_ids", lambda raw: [7])
    monkeypatch.setattr("pkcs11_check.raw.recipes.get_mechanism_list", lambda raw, slot: [])
    # Mirror the real plugin: known options return their plugin defaults
    # (--p11-interface defaults to None); the `default` kwarg only applies
    # to unknown options.
    plugin_defaults = {
        "p11_module": "/fake/module.so",
        "p11_key_inject": "off",
        "p11_wrap_key_source": "bootstrap",
        "p11_wrap_rsa_bits": 2048,
        "p11_wrap_oaep_hash": "auto",
    }
    config = SimpleNamespace(
        getoption=lambda name, default=None: plugin_defaults.get(name, default)
    )

    result = aes_conftest._detect_variant_via_pkcs11(config)

    assert captured["interface"] == "auto"
    assert result.status is base_cts.CtsDetectionStatus.ABSENT


def _install_collection_probe_stubs(
    monkeypatch: pytest.MonkeyPatch, captured: dict[str, Any], *, stub_detection: bool = True
) -> None:
    """Stub the provider surface behind the collection CTS probe."""

    def fake_load_module(path: object, interface: object = None) -> Any:
        captured["module"] = path
        captured["interface"] = interface
        return SimpleNamespace(raw=object())

    def fake_open_session(raw: Any, slot: int, flags: int) -> int:
        captured["slot"] = slot
        return 1234

    def fake_login(raw: Any, sh: int, user: int, pin: bytes) -> None:
        captured.setdefault("logins", []).append((sh, user, pin))

    def fake_detected(rs: Any, **kwargs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(base_cts.CtsDetectionStatus.DETECTED, variant="1")

    monkeypatch.setattr("pkcs11_check.core.loader.load_module", fake_load_module)
    monkeypatch.setattr("pkcs11_check.raw.bootstrap.get_slot_ids", lambda raw: [7, 8])
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_list", lambda raw, slot: [CKM_AES_CTS]
    )
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_info",
        lambda raw, slot, mech: {"flags": int(CKF_ENCRYPT) | int(CKF_DECRYPT)},
    )
    monkeypatch.setattr("pkcs11_check.raw.bootstrap.open_session", fake_open_session)
    monkeypatch.setattr("pkcs11_check.raw.bootstrap.login_user", fake_login)
    monkeypatch.setattr("pkcs11_check.raw.bootstrap.logout_quietly", lambda *a: None)
    monkeypatch.setattr("pkcs11_check.raw.bootstrap.close_session_quietly", lambda *a: None)
    if stub_detection:
        monkeypatch.setattr(base_cts, "get_cts_detection", fake_detected)


def _collection_config(opts: dict[str, Any]) -> Any:
    values = {"p11_module": "/fake/module.so", **opts}
    return SimpleNamespace(getoption=lambda name, default=None: values.get(name, default))


def _isolate_pin_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Drop ambient pin/slot/interface layers; TOML reads from an empty dir."""
    monkeypatch.delenv("P11TEST_PIN", raising=False)
    monkeypatch.delenv("P11TEST_SLOT", raising=False)
    monkeypatch.delenv("P11TEST_INTERFACE", raising=False)
    monkeypatch.chdir(tmp_path)


def test_cts_collection_probe_logs_in_with_env_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#89: a P11TEST_PIN env pin must log the collection probe in, like runtime."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_PIN", "envpin")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("logins") == [(1234, CKU_USER, b"envpin")]


@pytest.fixture
def _fresh_detection_cache() -> Any:
    base_cts.reset_cts_detection_cache()
    yield
    base_cts.reset_cts_detection_cache()


def test_cts_collection_probe_env_pin_yields_detection_not_setup_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """#89 end-to-end: env pin logs in, so a login-enforcing module detects."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_PIN", "envpin")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def login_enforcing_inner(rs: Any) -> base_cts.CtsDetectionResult:
        if not captured.get("logins"):
            return base_cts.CtsDetectionResult(
                base_cts.CtsDetectionStatus.SETUP_ERROR,
                error_rv=int(CKR_USER_NOT_LOGGED_IN),
                detail={"attempts": [{"ckr": int(CKR_USER_NOT_LOGGED_IN)}]},
            )
        return base_cts.CtsDetectionResult(base_cts.CtsDetectionStatus.DETECTED, variant="1")

    monkeypatch.setattr(base_cts, "_detect_cts_variant", login_enforcing_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("logins") == [(1234, CKU_USER, b"envpin")]


def test_cts_collection_probe_without_pin_surfaces_not_operational(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """S2: logged-out login refusal is not-operational (xfail), not a FAIL."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}
    inner_calls: list[Any] = []
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def login_enforcing_inner(rs: Any) -> base_cts.CtsDetectionResult:
        inner_calls.append(rs)
        if not captured.get("logins"):
            return base_cts.CtsDetectionResult(
                base_cts.CtsDetectionStatus.SETUP_ERROR,
                error_rv=int(CKR_USER_NOT_LOGGED_IN),
                detail={"attempts": [{"ckr": int(CKR_USER_NOT_LOGGED_IN)}]},
            )
        return base_cts.CtsDetectionResult(base_cts.CtsDetectionStatus.DETECTED, variant="1")

    monkeypatch.setattr(base_cts, "_detect_cts_variant", login_enforcing_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.NOT_OPERATIONAL
    assert result.error_rv == int(CKR_USER_NOT_LOGGED_IN)
    assert "logged-out" in result.detail.get("reason", "")
    assert not captured.get("logins")
    # The converted result is what the cache holds: the sentinel and the
    # standalone vector guard consume it converted, not as setup-error.
    again = base_cts.get_cts_detection(SimpleNamespace())
    assert again.status is base_cts.CtsDetectionStatus.NOT_OPERATIONAL
    assert len(inner_calls) == 1


def test_cts_collection_probe_logged_in_login_refusal_stays_loud(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """S2 control: logged-in meetings with the same RV stay SETUP_ERROR (loud)."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_PIN", "envpin")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def always_refusing_inner(rs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.SETUP_ERROR,
            error_rv=int(CKR_USER_NOT_LOGGED_IN),
            detail={"attempts": [{"ckr": int(CKR_USER_NOT_LOGGED_IN)}]},
        )

    monkeypatch.setattr(base_cts, "_detect_cts_variant", always_refusing_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == int(CKR_USER_NOT_LOGGED_IN)
    assert captured.get("logins") == [(1234, CKU_USER, b"envpin")]


def test_cts_mixed_refusal_reports_off_contract_rv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """R4-7: mixed attempts report the off-contract RV+operation, not the login RV."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def mixed_inner(rs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.SETUP_ERROR,
            error_rv=int(CKR_USER_NOT_LOGGED_IN),
            detail={
                "attempts": [
                    {"ckr": 0x00FFFFFF, "operation": "C_Encrypt", "stage": "operation"},
                    {
                        "ckr": int(CKR_USER_NOT_LOGGED_IN),
                        "operation": "C_Login",
                        "stage": "setup",
                    },
                    {
                        "ckr": int(CKR_USER_NOT_LOGGED_IN),
                        "operation": "C_Login",
                        "stage": "setup",
                    },
                ]
            },
        )

    monkeypatch.setattr(base_cts, "_detect_cts_variant", mixed_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == 0x00FFFFFF
    with pytest.raises(CkrAssertionError, match="C_Encrypt") as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == 0x00FFFFFF


def test_cts_mixed_refusal_logged_in_reports_off_contract_rv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """R4-7: reselection is login-independent (mixed while logged in)."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_PIN", "envpin")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def mixed_inner(rs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.SETUP_ERROR,
            error_rv=int(CKR_USER_NOT_LOGGED_IN),
            detail={
                "attempts": [
                    {"ckr": 0x00FFFFFF, "operation": "C_Encrypt", "stage": "operation"},
                    {"ckr": int(CKR_USER_NOT_LOGGED_IN)},
                ]
            },
        )

    monkeypatch.setattr(base_cts, "_detect_cts_variant", mixed_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == 0x00FFFFFF
    assert captured.get("logins") == [(1234, CKU_USER, b"envpin")]


def test_cts_mixed_success_reports_off_contract_rv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """R5-2: successes never win selection; the off-contract attempt does."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def mixed_inner(rs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.SETUP_ERROR,
            error_rv=int(CKR_USER_NOT_LOGGED_IN),
            detail={
                "attempts": [
                    {
                        "ckr": 0x00FFFFFF,
                        "operation": "C_CreateObject",
                        "stage": "setup",
                        "key_bits": 256,
                        "case": None,
                    },
                    {
                        "ckr": int(CKR_OK),
                        "operation": "C_Encrypt",
                        "stage": "operation",
                        "key_bits": 128,
                        "case": "aligned",
                    },
                    {"ckr": int(CKR_USER_NOT_LOGGED_IN)},
                    {"ckr": int(CKR_USER_NOT_LOGGED_IN)},
                ]
            },
        )

    monkeypatch.setattr(base_cts, "_detect_cts_variant", mixed_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == 0x00FFFFFF
    with pytest.raises(CkrAssertionError, match="C_CreateObject") as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == 0x00FFFFFF


def test_cts_mixed_listed_refusal_keeps_primary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """R5-2: listed clean refusals are not candidates; the primary stands."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def mixed_inner(rs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.SETUP_ERROR,
            error_rv=int(CKR_USER_NOT_LOGGED_IN),
            detail={
                "attempts": [
                    {
                        "ckr": int(CKR_ARGUMENTS_BAD),
                        "operation": "C_Encrypt",
                        "stage": "operation",
                        "key_bits": 256,
                        "case": "aligned",
                    },
                    {"ckr": int(CKR_USER_NOT_LOGGED_IN)},
                ]
            },
        )

    monkeypatch.setattr(base_cts, "_detect_cts_variant", mixed_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == int(CKR_USER_NOT_LOGGED_IN)


def test_cts_mixed_off_contract_prefers_operation_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """R5-2: operation-stage off-contract wins over setup (detector priority)."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def mixed_inner(rs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.SETUP_ERROR,
            error_rv=0x00FFFFFE,
            detail={
                "attempts": [
                    {
                        "ckr": 0x00FFFFFF,
                        "operation": "C_Encrypt",
                        "stage": "operation",
                        "key_bits": 192,
                        "case": "aligned",
                    },
                    {
                        "ckr": 0x00FFFFFE,
                        "operation": "C_CreateObject",
                        "stage": "setup",
                        "key_bits": 128,
                        "case": None,
                    },
                ]
            },
        )

    monkeypatch.setattr(base_cts, "_detect_cts_variant", mixed_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == 0x00FFFFFF
    with pytest.raises(CkrAssertionError, match="C_Encrypt") as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == 0x00FFFFFF


def test_cts_mixed_same_rv_names_operation_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _fresh_detection_cache: Any
) -> None:
    """R6-3: the same RV in both stages names the operation attempt."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured, stub_detection=False)

    def mixed_inner(rs: Any) -> base_cts.CtsDetectionResult:
        return base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.SETUP_ERROR,
            error_rv=int(CKR_USER_NOT_LOGGED_IN),
            detail={
                "attempts": [
                    {
                        "ckr": 0x00FFFFFF,
                        "operation": "C_Encrypt",
                        "stage": "operation",
                        "key_bits": 192,
                        "case": "aligned",
                    },
                    {
                        "ckr": 0x00FFFFFF,
                        "operation": "C_CreateObject",
                        "stage": "setup",
                        "key_bits": 128,
                        "case": None,
                    },
                    {"ckr": int(CKR_USER_NOT_LOGGED_IN)},
                ]
            },
        )

    monkeypatch.setattr(base_cts, "_detect_cts_variant", mixed_inner)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == 0x00FFFFFF
    with pytest.raises(CkrAssertionError, match="C_Encrypt") as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == 0x00FFFFFF
    assert "C_CreateObject" not in str(excinfo.value)


def test_cts_detector_captures_encrypt_stage_operation(monkeypatch: pytest.MonkeyPatch) -> None:
    """R7-2: operation attempts carry the failing C_* stage, not bare C_Encrypt."""

    def _import(_rs: Any, _key: bytes, **_kwargs: Any) -> int:
        return 99

    def _refuse_init(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("init refused", 0x00FFFFFF, "C_EncryptInit")

    monkeypatch.setattr(base_cts, "_import_aes_key", _import)
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(base_cts, "encrypt_single", _refuse_init)

    result = base_cts._detect_cts_variant(_FakeSession())

    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == 0x00FFFFFF
    operations = [
        attempt["operation"]
        for attempt in result.detail["attempts"]
        if attempt["stage"] == "operation"
    ]
    assert operations and all(op == "C_EncryptInit" for op in operations)


def test_cts_reporter_passes_selected_operation() -> None:
    """R7-2: the setup-error raise carries the selected attempt's operation."""
    result = base_cts.CtsDetectionResult(
        base_cts.CtsDetectionStatus.SETUP_ERROR,
        error_rv=0x00FFFFFF,
        detail={
            "attempts": [
                {
                    "ckr": 0x00FFFFFF,
                    "operation": "C_EncryptInit",
                    "stage": "operation",
                    "key_bits": 256,
                    "case": "aligned",
                },
            ],
            "primary_attempt": {"operation": "C_EncryptInit", "stage": "operation"},
        },
    )

    with pytest.raises(CkrAssertionError, match="C_EncryptInit") as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == 0x00FFFFFF
    assert excinfo.value.operation == "C_EncryptInit"


def test_cts_not_operational_names_supplying_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R8-2: clean-refusal xfails name the refusing call, not bare C_Encrypt."""

    def _import(_rs: Any, _key: bytes, **_kwargs: Any) -> int:
        return 99

    def _refuse_init(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("init refused", int(CKR_ARGUMENTS_BAD), "C_EncryptInit")

    monkeypatch.setattr(base_cts, "_import_aes_key", _import)
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(base_cts, "encrypt_single", _refuse_init)

    result = base_cts._detect_cts_variant(_FakeSession())
    assert result.status is base_cts.CtsDetectionStatus.NOT_OPERATIONAL

    captured: dict[str, Any] = {}

    def _capture(_reason: str, **kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(base_cts, "classify", _capture)
    base_cts.report_cts_detection(result)
    assert captured["operation"] == "C_EncryptInit"


def test_detection_skip_reason_names_logged_out_login_refusal() -> None:
    """S2: logged-out skips tell the operator to configure a PIN."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    detection = base_cts.CtsDetectionResult(
        base_cts.CtsDetectionStatus.NOT_OPERATIONAL,
        error_rv=int(CKR_USER_NOT_LOGGED_IN),
    )
    reason = aes_conftest._detection_skip_reason(detection)
    assert "logged out" in reason
    assert "PIN" in reason


def test_cts_collection_probe_cli_pin_wins_over_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CLI > env for the collection probe pin, matching runtime precedence."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_PIN", "envpin")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({"p11_pin": "clipin"}))

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("logins") == [(1234, CKU_USER, b"clipin")]


def test_cts_collection_probe_logs_in_with_toml_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#89: a TOML pin must log the collection probe in, like runtime."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    (tmp_path / "pkcs11_check.toml").write_text('pin = "tomlpin"\n', encoding="utf-8")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("logins") == [(1234, CKU_USER, b"tomlpin")]


def test_cts_collection_probe_no_pin_no_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No pin on any layer: the probe stays logged out (unchanged behavior)."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("logins") is None


def test_cts_collection_probe_uses_merged_slot_and_interface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#89: slot/interface resolve through the same layers as runtime."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_SLOT", "1")
    monkeypatch.setenv("P11TEST_INTERFACE", "3.1")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    result = aes_conftest._detect_variant_via_pkcs11(_collection_config({}))

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("slot") == 8
    assert captured.get("interface") == "3.1"


def test_cts_collection_probe_cli_wins_over_env_for_slot_and_interface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CLI > env for collection slot/interface, matching runtime precedence."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_SLOT", "1")
    monkeypatch.setenv("P11TEST_INTERFACE", "3.1")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    config = _collection_config({"p11_slot": 0, "p11_interface": "auto"})
    result = aes_conftest._detect_variant_via_pkcs11(config)

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("slot") == 7
    assert captured.get("interface") == "auto"


def test_cts_collection_probe_rejects_invalid_slot_like_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R32-5: an out-of-range slot fails cleanly instead of silently remapping."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    for bad_slot in ("-1", "2"):
        _isolate_pin_env(monkeypatch, tmp_path)
        monkeypatch.setenv("P11TEST_SLOT", bad_slot)
        captured: dict[str, Any] = {}
        _install_collection_probe_stubs(monkeypatch, captured)
        with pytest.raises(pytest.UsageError, match="slot"):
            aes_conftest._detect_variant_via_pkcs11(_collection_config({}))
        assert "slot" not in captured, "no session opens on a rejected slot"
        assert captured.get("logins") is None, "no login on a rejected slot"


def test_cts_collection_probe_shares_full_cli_precedence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R32-6: CLI settings beyond pin/slot reach the probe (no env leak)."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_KEY_INJECT", "bogus")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    config = _collection_config({"p11_key_inject": "unwrap"})
    result = aes_conftest._detect_variant_via_pkcs11(config)

    assert result.status is base_cts.CtsDetectionStatus.DETECTED


def test_cts_collection_probe_surfaces_invalid_config_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R32-6: genuinely invalid settings fail as config errors, not tracebacks."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_KEY_INJECT", "bogus")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    with pytest.raises(pytest.UsageError, match="key_inject|configuration"):
        aes_conftest._detect_variant_via_pkcs11(_collection_config({}))


def test_cts_collection_probe_honors_explicit_empty_interface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R32-6: an explicit empty CLI override wins over env, like runtime."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_INTERFACE", "3.1")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    config = _collection_config({"p11_interface": ""})
    result = aes_conftest._detect_variant_via_pkcs11(config)

    assert result.status is base_cts.CtsDetectionStatus.DETECTED
    assert captured.get("interface") == "auto"


def test_resolve_cli_settings_normalizes_and_validates_interface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R33-5: the shared resolver owns interface values for both paths."""
    from pkcs11_check.fixtures import resolve_cli_settings

    _isolate_pin_env(monkeypatch, tmp_path)
    assert (
        resolve_cli_settings(tmp_path / "fixture.so", _collection_config({}).getoption).interface
        == "auto"
    )
    monkeypatch.setenv("P11TEST_INTERFACE", "3.1")
    assert (
        resolve_cli_settings(
            tmp_path / "fixture.so", _collection_config({"p11_interface": ""}).getoption
        ).interface
        == "auto"
    )
    assert (
        resolve_cli_settings(tmp_path / "fixture.so", _collection_config({}).getoption).interface
        == "3.1"
    )
    monkeypatch.setenv("P11TEST_INTERFACE", "typo")
    with pytest.raises(pytest.UsageError, match="Unknown interface"):
        resolve_cli_settings(tmp_path / "fixture.so", _collection_config({}).getoption)


def test_cts_collection_probe_rejects_unknown_interface_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R33-5: an unknown interface fails as a config error, pre-load."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_INTERFACE", "typo")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    with pytest.raises(pytest.UsageError, match="Unknown interface"):
        aes_conftest._detect_variant_via_pkcs11(_collection_config({}))
    assert "module" not in captured, "nothing loads on a rejected interface"


def test_runtime_config_rejects_unknown_interface_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R33-5: runtime shares the collection interface verdict, pre-load."""
    from pkcs11_check import fixtures

    _isolate_pin_env(monkeypatch, tmp_path)
    monkeypatch.setenv("P11TEST_INTERFACE", "typo")
    request = SimpleNamespace(config=_collection_config({}))
    with pytest.raises(pytest.UsageError, match="Unknown interface"):
        fixtures.p11_config.__wrapped__(request)


def test_cts_collection_probe_surfaces_malformed_toml_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#88R33-5: malformed TOML fails as a config error, not a traceback."""
    from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest

    _isolate_pin_env(monkeypatch, tmp_path)
    (tmp_path / "pkcs11_check.toml").write_text('pin = "unterminated', encoding="utf-8")
    captured: dict[str, Any] = {}
    _install_collection_probe_stubs(monkeypatch, captured)

    with pytest.raises(pytest.UsageError, match="configuration"):
        aes_conftest._detect_variant_via_pkcs11(_collection_config({}))


def test_cts_detector_propagates_hostile_length_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detection itself still raises: the runtime re-probe must stay fail-visible."""
    monkeypatch.setattr(base_cts, "_import_aes_key", lambda _rs, key, **_kwargs: len(key))
    monkeypatch.setattr(base_cts, "destroy_quietly", lambda *_args: None)

    def hostile_length(*_args: Any, **_kwargs: Any) -> bytes:
        raise ImplausibleModuleLengthError(
            "C_Encrypt: module reported an implausible output length (2**63 bytes)"
        )

    monkeypatch.setattr(base_cts, "encrypt_single", hostile_length)

    with pytest.raises(ImplausibleModuleLengthError, match="implausible output length"):
        base_cts._detect_cts_variant(_FakeSession())
