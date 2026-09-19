"""Focused EC setup protocol and operational point regressions."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pkcs11_check.classification import get_records
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases._ec_export import (
    InvalidProviderECPointError,
    ProviderECPointEncodingError,
)
from pkcs11_check.testcases._probes import _attribute_facts
from pkcs11_check.testcases._probes import ckr_raw_buffer as raw_probe
from pkcs11_check.testcases.ckr import test_ckr_raw_buffer as raw_buffer


def _raw_p256_point() -> bytes:
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    return private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _setup(event: str, **fields: object) -> str:
    return "EC_SETUP:" + json.dumps(
        {
            "schema": 1,
            "probe": "ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "event": event,
            **fields,
        },
        separators=(",", ":"),
    )


def _cleanup(role: str, rv: int) -> str:
    return "EC_CLEANUP:" + json.dumps(
        {
            "schema": 1,
            "probe": "ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "object": role,
            "operation": "C_DestroyObject",
            "rv": rv,
        },
        separators=(",", ":"),
    )


def _check_ec(*args: object, **kwargs: object) -> None:
    kwargs["probe"] = "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    raw_buffer._check_buffer_probe(*args, **kwargs)  # type: ignore[arg-type]


def _complete_unavailable_setup() -> str:
    return (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\n"
    )


@pytest.mark.parametrize(
    ("selected_probe", "payload_probe"),
    [
        (None, None),
        ("digest_buffer_too_small", "ecdh_aes_wrap_compressed_public_key_buffer_too_small"),
        ("ecdh_aes_wrap_compressed_public_key_buffer_too_small", "other_probe"),
        ("ecdh_aes_wrap_compressed_public_key_buffer_too_small", 7),
    ],
)
def test_ec_semantics_require_literal_string_probe_binding(
    selected_probe: str | None, payload_probe: object
) -> None:
    """Null, non-EC, and non-string selections cannot authorize EC semantics."""
    output = _complete_unavailable_setup()
    if payload_probe is None:
        output = output.replace(
            '"probe":"ecdh_aes_wrap_compressed_public_key_buffer_too_small"',
            '"probe":null',
        )
    elif payload_probe != "ecdh_aes_wrap_compressed_public_key_buffer_too_small":
        output = output.replace(
            '"probe":"ecdh_aes_wrap_compressed_public_key_buffer_too_small"',
            f'"probe":{json.dumps(payload_probe)}',
        )
    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        raw_buffer._check_buffer_probe(
            0,
            output,
            "",
            context="EC setup",
            probe=selected_probe,
        )

    records = get_records()
    assert records
    assert all(record.reason == "harness_error" for record in records)
    assert all(record.mechanism != "CKM_ECDH_AES_KEY_WRAP" for record in records)


def test_read_error_after_done_retains_exact_reader_evidence() -> None:
    """A first post-DONE read error is contradictory but remains exact evidence."""
    output = (
        _complete_unavailable_setup()
        + _setup(
            "read_error",
            operation="C_GetAttributeValue",
            requested_attributes=[
                {"name": "CKA_EC_POINT", "id": 385},
                {"name": "CKA_EC_PARAMS", "id": 384},
            ],
            rv=0x06,
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert sum(record.actual_ckr == "CKR_FUNCTION_FAILED" for record in records) == 1
    assert any(record.reason == "harness_error" for record in records)


def test_cleanup_before_setup_is_protocol_but_recorded() -> None:
    """Cleanup-only output retains lifecycle evidence and reports phase mixing."""
    output = _cleanup("target_key", 6) + "\n"

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "harness_error"]
    assert records[0].detail is not None
    assert records[0].detail["object"] == "target_key"


def test_cleanup_roles_must_be_in_strict_child_order() -> None:
    """Out-of-order cleanup roles remain lifecycle records plus a harness defect."""
    output = _complete_unavailable_setup() + _cleanup("pub", 6) + "\n" + _cleanup("target_key", 7)

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == [
        "not_operational",
        "not_operational",
        "not_operational",
        "not_operational",
        "harness_error",
    ]


def test_setup_after_cleanup_is_protocol_and_keeps_setup_fact() -> None:
    """A setup event after cleanup is rejected without discarding its fact."""
    output = (
        _cleanup("target_key", 6)
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records[:3]] == [
        "not_operational",
        "not_operational",
        "not_operational",
    ]
    assert records[-1].reason == "harness_error"


def test_ec_facts_without_selected_probe_are_harness_only() -> None:
    """A wrapper that did not select this probe cannot inherit EC semantics."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        raw_buffer._check_buffer_probe(0, output, "", context="C_Digest wrapper")

    records = get_records()
    assert records
    assert all(record.reason == "harness_error" for record in records)
    assert all(record.mechanism != "CKM_ECDH_AES_KEY_WRAP" for record in records)


def test_point_event_requires_both_attribute_events_first() -> None:
    """Point facts cannot be accepted between the point and params attributes."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="raw_uncompressed",
            diagnostic="",
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    assert [record.reason for record in get_records()] == ["harness_error"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_deep_ec_marker_is_bounded_and_crash_survives() -> None:
    """Hostile nesting becomes one bounded protocol fact without hiding a crash."""
    nested = "[" * 10_000 + "0" + "]" * 10_000
    output = (
        'EC_SETUP:{"schema":1,"probe":"ecdh_aes_wrap_compressed_public_key_buffer_too_small",'
        '"event":"done","status":' + nested + "}\n"
    )

    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        _check_ec(-11, output, "segmentation fault", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "crash"]
    assert len(records[0].summary) < 512


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_unexpected_read_error_survives_prior_malformed_line_and_crash() -> None:
    """The exact reader CKR is retained once even when parsing then crashes."""
    output = (
        'EC_SETUP:{"schema":1,"probe":"ecdh_aes_wrap_compressed_public_key_buffer_too_small",'
        '"event":"attribute","operation":}\n'
        + _setup(
            "read_error",
            operation="C_GetAttributeValue",
            requested_attributes=[
                {"name": "CKA_EC_POINT", "id": 385},
                {"name": "CKA_EC_PARAMS", "id": 384},
            ],
            rv=0x06,
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        _check_ec(-11, output, "segmentation fault", context="EC setup")

    records = get_records()
    exact = [
        record for record in records if record.actual_ckr and "FUNCTION_FAILED" in record.actual_ckr
    ]
    assert len(exact) == 1
    assert [record.reason for record in records] == ["harness_error", "harness_error", "crash"]


def test_hostile_cleanup_role_is_a_bounded_protocol_error() -> None:
    """A JSON container cleanup role cannot escape schema validation."""
    output = (
        "EC_CLEANUP:"
        + json.dumps(
            {
                "schema": 1,
                "probe": "ecdh_aes_wrap_compressed_public_key_buffer_too_small",
                "object": [],
                "operation": "C_DestroyObject",
                "rv": 6,
            },
            separators=(",", ":"),
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_raw_p256_point_with_der_length_collision_is_operational() -> None:
    """A raw point beginning 04 40 is not reinterpreted as malformed DER."""
    raw_point = bytearray(_raw_p256_point())
    raw_point[1] = 0x40
    # Keep this test's point mathematically valid while forcing the collision.
    for scalar in range(1, 10_000):
        candidate = (
            ec.derive_private_key(scalar, ec.SECP256R1())
            .public_key()
            .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        )
        if candidate[1] == 0x40:
            raw_point = bytearray(candidate)
            break
    else:
        pytest.fail("could not find a P-256 point whose x coordinate starts with 0x40")

    compressed = raw_probe._compress_p256_ec_point(bytes(raw_point))

    assert compressed[0] == 0x04
    assert compressed[1] == 33
    assert compressed[2] in (0x02, 0x03)


@pytest.mark.parametrize("wrapped", [False, True])
def test_valid_uncompressed_and_compressed_der_points_are_operational(wrapped: bool) -> None:
    """Canonical DER-wrapped SEC1 points remain usable for the import path."""
    raw_point = _raw_p256_point()
    point = raw_point
    if wrapped:
        point = bytes([0x04, len(raw_point)]) + raw_point

    compressed = raw_probe._compress_p256_ec_point(point)

    assert compressed[2] in (0x02, 0x03)
    assert len(compressed) == 35


def test_valid_wrapped_compressed_point_is_preserved() -> None:
    """A DER-wrapped compressed SEC1 point remains usable and unchanged."""
    raw_point = _raw_p256_point()
    compressed_point = bytes([0x02 | (raw_point[-1] & 1)]) + raw_point[1:33]
    wrapped = bytes([0x04, len(compressed_point)]) + compressed_point

    result = raw_probe._compress_p256_ec_point(wrapped)

    assert result == wrapped


def test_off_curve_point_is_hard_crypto_evidence() -> None:
    """A shape-correct but off-curve point must not become operational."""
    with pytest.raises(InvalidProviderECPointError):
        raw_probe._compress_p256_ec_point(b"\x04" + b"\x00" * 64)


def test_valid_alternate_curve_point_is_hard_crypto_evidence() -> None:
    """A valid raw P-384 point is wrong-curve evidence, not an encoding xfail."""
    point = (
        ec.derive_private_key(1, ec.SECP384R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    )

    with pytest.raises(InvalidProviderECPointError):
        raw_probe._compress_p256_ec_point(point)


def test_raw_compressed_p256_is_encoding_unavailable_not_wrong_curve() -> None:
    """A raw compressed P-256 point cannot be promoted via secp256k1 coincidence."""
    point = (
        ec.derive_private_key(1, ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    )

    with pytest.raises(ProviderECPointEncodingError):
        raw_probe._compress_p256_ec_point(point)


def test_invalid_wrapped_compressed_point_retains_der_compressed_provenance() -> None:
    """Invalid points still identify their actual DER inner SEC1 encoding."""
    wrapped = b"\x04\x21\x02" + b"\x00" * 32

    assert raw_probe._ec_point_encoding_provenance(wrapped) == "der_compressed"


def test_alternate_curve_raw_point_retains_raw_provenance() -> None:
    """Positive alternate-curve evidence still identifies raw SEC1 provenance."""
    point = (
        ec.derive_private_key(1, ec.SECP384R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    )

    assert raw_probe._ec_point_encoding_provenance(point) == "raw_uncompressed"


@pytest.mark.parametrize("compressed", [False, True])
def test_der_wrapped_p384_provenance_uses_inner_sec1_prefix(compressed: bool) -> None:
    """DER provenance is width-independent for valid P-384 SEC1 prefixes."""
    public = ec.derive_private_key(1, ec.SECP384R1()).public_key()
    point = public.public_bytes(
        Encoding.X962,
        PublicFormat.CompressedPoint if compressed else PublicFormat.UncompressedPoint,
    )
    wrapped = bytes([0x04, len(point)]) + point

    assert raw_probe._ec_point_encoding_provenance(wrapped) == (
        "der_compressed" if compressed else "der_uncompressed"
    )


def test_valid_raw_p384_compressed_point_is_hard_wrong_curve_evidence() -> None:
    """A valid raw-compressed P-384 point is positive alternate-curve evidence."""
    point = (
        ec.derive_private_key(1, ec.SECP384R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    )

    with pytest.raises(InvalidProviderECPointError):
        raw_probe._compress_p256_ec_point(point)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_ec_child_emits_ready_before_import_and_flushes_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual EC child emits ready before import and flushes facts before retry."""
    raw_point = _raw_p256_point()
    emitted: list[tuple[tuple[object, ...], dict[str, object]]] = []
    timeline: list[str] = []

    def capture(*args: object, **kwargs: object) -> None:
        emitted.append((args, kwargs))
        timeline.append(f"emit:{args[0]}")

    class FakeRaw:
        wrap_calls = 0

        def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
            _args[-2]._obj.value = 1  # type: ignore[attr-defined]
            _args[-1]._obj.value = 2  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_CreateObject(self, *_args: object) -> int:  # noqa: N802
            timeline.append("call:C_CreateObject")
            _args[-1]._obj.value = 3  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_GenerateKey(self, *_args: object) -> int:  # noqa: N802
            _args[-1]._obj.value = 4  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_WrapKey(self, *_args: object) -> int:  # noqa: N802
            self.wrap_calls += 1
            output_len = _args[-1]
            if self.wrap_calls == 1:
                output_len._obj.value = 16  # type: ignore[attr-defined]
                return int(raw_probe.CKR_OK)
            if self.wrap_calls == 2:
                output_len._obj.value = 1  # type: ignore[attr-defined]
                return int(raw_probe.CKR_BUFFER_TOO_SMALL)
            output_len._obj.value = 16  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_DestroyObject(self, *_args: object) -> int:  # noqa: N802
            return int(raw_probe.CKR_OK)

    monkeypatch.setattr(raw_probe, "print", capture, raising=False)
    monkeypatch.setattr(_attribute_facts, "print", capture, raising=False)
    monkeypatch.setattr(
        raw_probe,
        "read_attributes",
        lambda *_args: {
            raw_probe.CKA_EC_POINT: raw_point,
            raw_probe.CKA_EC_PARAMS: b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        },
    )

    raw_probe._ecdh_aes_wrap_compressed_public_key_buffer_too_small(
        raw_probe.ProbeContext(FakeRaw(), 9, 1, lambda: None, "module")
    )

    lines = [str(args[0]) for args, _kwargs in emitted if args]
    ready_index = next(index for index, line in enumerate(timeline) if '"status":"ready"' in line)
    import_index = timeline.index("call:C_CreateObject")
    assert ready_index < import_index
    ok_index = lines.index("OK")
    assert emitted[ok_index][1].get("flush") is True
    for index in range(ok_index):
        if any(
            marker in lines[index] for marker in ("CKR:", "GUARD_OVERWRITTEN:", "INITIAL_COUNT:")
        ):
            assert emitted[index][1].get("flush") is True

    child_output = "\n".join(lines) + "\n"
    _check_ec(0, child_output, "", context="EC setup")
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        _check_ec(-11, child_output, "segmentation fault", context="EC setup")


@pytest.mark.parametrize(
    ("point_case", "params_case"),
    [
        ("missing", "missing"),
        ("unusable", "missing"),
        ("missing", "unusable"),
        ("unusable", "unusable"),
    ],
    ids=["both-missing", "point-unusable", "params-unusable", "both-unusable"],
)
def test_ec_child_observes_missing_and_unusable_attributes_in_order(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    point_case: str,
    params_case: str,
) -> None:
    """The actual child routes each requested EC attribute through the observer."""
    attributes: dict[object, object] = {}
    if point_case == "unusable":
        attributes[raw_probe.CKA_EC_POINT] = None
    if params_case == "unusable":
        attributes[raw_probe.CKA_EC_PARAMS] = False
    observer_calls: list[tuple[int, str]] = []
    original_observer = _attribute_facts.observe_ec_attribute

    def record_observation(
        values: Mapping[object, object], attribute: int, *, context: str
    ) -> bytes | None:
        observer_calls.append((attribute, context))
        return original_observer(values, attribute, context=context)

    class FakeRaw:
        def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
            _args[-2]._obj.value = 1  # type: ignore[attr-defined]
            _args[-1]._obj.value = 2  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_DestroyObject(self, *_args: object) -> int:  # noqa: N802
            return int(raw_probe.CKR_OK)

    monkeypatch.setattr(_attribute_facts, "observe_ec_attribute", record_observation)
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_args: attributes)

    raw_probe._ecdh_aes_wrap_compressed_public_key_buffer_too_small(
        raw_probe.ProbeContext(FakeRaw(), 9, 1, lambda: None, "module")
    )

    context = "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    assert observer_calls == [
        (raw_probe.CKA_EC_POINT, context),
        (raw_probe.CKA_EC_PARAMS, context),
    ]
    events = [
        json.loads(line.removeprefix("EC_SETUP:"))
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("EC_SETUP:")
    ]
    attribute_events = [event for event in events if event["event"] == "attribute"]
    assert [event["attribute"]["name"] for event in attribute_events] == [
        "CKA_EC_POINT",
        "CKA_EC_PARAMS",
    ]
    assert [event["state"] for event in attribute_events] == [point_case, params_case]


def test_ec_child_validates_present_point_before_unavailable_with_missing_params(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A malformed point remains visible even when the sibling params are absent."""
    malformed_point = b"\x04\x01"
    attributes: dict[object, object] = {raw_probe.CKA_EC_POINT: malformed_point}
    observer_calls: list[tuple[int, str]] = []
    original_observer = _attribute_facts.observe_ec_attribute

    def record_observation(
        values: Mapping[object, object], attribute: int, *, context: str
    ) -> bytes | None:
        observer_calls.append((attribute, context))
        return original_observer(values, attribute, context=context)

    class FakeRaw:
        def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
            _args[-2]._obj.value = 1  # type: ignore[attr-defined]
            _args[-1]._obj.value = 2  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_DestroyObject(self, *_args: object) -> int:  # noqa: N802
            return int(raw_probe.CKR_OK)

    monkeypatch.setattr(_attribute_facts, "observe_ec_attribute", record_observation)
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_args: attributes)

    raw_probe._ecdh_aes_wrap_compressed_public_key_buffer_too_small(
        raw_probe.ProbeContext(FakeRaw(), 9, 1, lambda: None, "module")
    )

    context = "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    assert observer_calls == [
        (raw_probe.CKA_EC_POINT, context),
        (raw_probe.CKA_EC_PARAMS, context),
    ]
    events = [
        json.loads(line.removeprefix("EC_SETUP:"))
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("EC_SETUP:")
    ]
    assert [(event["event"], event.get("state", event.get("status"))) for event in events] == [
        ("attribute", "present"),
        ("attribute", "missing"),
        ("point", "encoding_error"),
        ("done", "unavailable"),
    ]


def test_ec_child_classifies_raw_compressed_p256_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual child does not promote raw compressed P-256 via another curve."""
    point = (
        ec.derive_private_key(1, ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    )
    emitted: list[str] = []

    class FakeRaw:
        def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
            _args[-2]._obj.value = 1  # type: ignore[attr-defined]
            _args[-1]._obj.value = 2  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_DestroyObject(self, *_args: object) -> int:  # noqa: N802
            return int(raw_probe.CKR_OK)

    monkeypatch.setattr(
        raw_probe,
        "print",
        lambda value, **_kwargs: emitted.append(str(value)),
        raising=False,
    )
    monkeypatch.setattr(
        raw_probe,
        "read_attributes",
        lambda *_args: {
            raw_probe.CKA_EC_POINT: point,
            raw_probe.CKA_EC_PARAMS: b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        },
    )

    raw_probe._ecdh_aes_wrap_compressed_public_key_buffer_too_small(
        raw_probe.ProbeContext(FakeRaw(), 9, 1, lambda: None, "module")
    )

    point_events = [
        line for line in emitted if line.startswith("EC_SETUP:") and '"event":"point"' in line
    ]
    assert len(point_events) == 1
    assert '"state":"encoding_error"' in point_events[0]
    assert '"encoding":"unrecognized"' in point_events[0]


def test_ec_child_classifies_raw_compressed_p384_as_wrong_curve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual child promotes raw-compressed alternate evidence only after P-256 rejects."""
    point = (
        ec.derive_private_key(1, ec.SECP384R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    )
    emitted: list[str] = []

    class FakeRaw:
        def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
            _args[-2]._obj.value = 1  # type: ignore[attr-defined]
            _args[-1]._obj.value = 2  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_DestroyObject(self, *_args: object) -> int:  # noqa: N802
            return int(raw_probe.CKR_OK)

    monkeypatch.setattr(
        raw_probe,
        "print",
        lambda value, **_kwargs: emitted.append(str(value)),
        raising=False,
    )
    monkeypatch.setattr(
        _attribute_facts,
        "print",
        lambda value, **_kwargs: emitted.append(str(value)),
        raising=False,
    )
    monkeypatch.setattr(
        raw_probe,
        "read_attributes",
        lambda *_args: {
            raw_probe.CKA_EC_POINT: point,
            raw_probe.CKA_EC_PARAMS: b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        },
    )

    raw_probe._ecdh_aes_wrap_compressed_public_key_buffer_too_small(
        raw_probe.ProbeContext(FakeRaw(), 9, 1, lambda: None, "module")
    )
    child_output = "\n".join(emitted) + "\n"

    with pytest.raises(pytest.fail.Exception, match="invalid EC point"):
        _check_ec(0, child_output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == ["wrong_result"]
    assert records[0].detail is not None
    assert records[0].detail["encoding"] == "unrecognized"


def test_ec_child_ready_then_import_refusal_reaches_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    """A later import refusal remains visible after the flushed ready fact."""
    emitted: list[str] = []

    class RefusingRaw:
        def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
            _args[-2]._obj.value = 1  # type: ignore[attr-defined]
            _args[-1]._obj.value = 2  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_CreateObject(self, *_args: object) -> int:  # noqa: N802
            return int(CKR_GENERAL_ERROR)

        def C_DestroyObject(self, *_args: object) -> int:  # noqa: N802
            return int(raw_probe.CKR_OK)

    monkeypatch.setattr(
        raw_probe,
        "print",
        lambda value, **_kwargs: emitted.append(str(value)),
        raising=False,
    )
    monkeypatch.setattr(
        _attribute_facts,
        "print",
        lambda value, **_kwargs: emitted.append(str(value)),
        raising=False,
    )
    monkeypatch.setattr(
        raw_probe,
        "read_attributes",
        lambda *_args: {
            raw_probe.CKA_EC_POINT: _raw_p256_point(),
            raw_probe.CKA_EC_PARAMS: b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        },
    )

    raw_probe._ecdh_aes_wrap_compressed_public_key_buffer_too_small(
        raw_probe.ProbeContext(RefusingRaw(), 9, 1, lambda: None, "module")
    )
    child_output = "\n".join(emitted) + "\n"

    with pytest.raises(pytest.xfail.Exception, match="compressed EC public-key import rejected"):
        _check_ec(0, child_output, "", context="EC setup")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
@pytest.mark.parametrize(
    ("refusal", "marker"),
    [
        ("import", "compressed EC public-key import rejected"),
        ("keygen", "C_GenerateKey for ECDH-AES target key failed"),
        ("size", "ECDH-AES C_WrapKey size query failed"),
    ],
)
def test_each_post_ready_refusal_is_flushed_before_cleanup_crash(
    monkeypatch: pytest.MonkeyPatch, refusal: str, marker: str
) -> None:
    """Import, keygen, and size-query refusals survive a native cleanup fault."""
    emitted: list[tuple[str, dict[str, object]]] = []

    class RefusingRaw:
        def C_GenerateKeyPair(self, *_args: object) -> int:  # noqa: N802
            _args[-2]._obj.value = 1  # type: ignore[attr-defined]
            _args[-1]._obj.value = 2  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_CreateObject(self, *_args: object) -> int:  # noqa: N802
            if refusal == "import":
                return int(CKR_GENERAL_ERROR)
            _args[-1]._obj.value = 3  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_GenerateKey(self, *_args: object) -> int:  # noqa: N802
            if refusal == "keygen":
                return int(CKR_GENERAL_ERROR)
            _args[-1]._obj.value = 4  # type: ignore[attr-defined]
            return int(raw_probe.CKR_OK)

        def C_WrapKey(self, *_args: object) -> int:  # noqa: N802
            assert refusal == "size"
            return int(CKR_GENERAL_ERROR)

        def C_DestroyObject(self, *_args: object) -> int:  # noqa: N802
            raise OSError("native cleanup fault")

    def capture(value: object, **kwargs: object) -> None:
        emitted.append((str(value), kwargs))

    monkeypatch.setattr(raw_probe, "print", capture, raising=False)
    monkeypatch.setattr(_attribute_facts, "print", capture, raising=False)
    monkeypatch.setattr(
        raw_probe,
        "read_attributes",
        lambda *_args: {
            raw_probe.CKA_EC_POINT: _raw_p256_point(),
            raw_probe.CKA_EC_PARAMS: b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        },
    )

    with pytest.raises(OSError, match="native cleanup fault"):
        raw_probe._ecdh_aes_wrap_compressed_public_key_buffer_too_small(
            raw_probe.ProbeContext(RefusingRaw(), 9, 1, lambda: None, "module")
        )

    refusal_index = next(index for index, (line, _) in enumerate(emitted) if marker in line)
    assert emitted[refusal_index][1].get("flush") is True
    child_output = "\n".join(line for line, _ in emitted) + "\n"
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        _check_ec(-11, child_output, "segmentation fault", context="EC setup")

    assert [record.reason for record in get_records()] == ["not_operational", "crash"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_interrupted_ec_prefix_does_not_invent_missing_events() -> None:
    """A crashed child retains its valid prefix without synthetic protocol errors."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        _check_ec(-11, output, "segmentation fault", context="EC setup")

    assert [record.reason for record in get_records()] == ["not_operational", "crash"]


def test_present_point_without_point_event_is_protocol_error() -> None:
    """A present point cannot complete as unavailable without its point fact."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\n"
        + "CKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")


def test_terminal_ec_setup_with_buffer_facts_is_incompatible() -> None:
    """Unavailable setup plus a buffer measurement is an additive harness defect."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="terminal EC setup"):
        _check_ec(0, output, "", context="EC setup")


@pytest.mark.parametrize(
    "event,field",
    [("attribute", "state"), ("point", "encoding"), ("done", "status")],
)
def test_hostile_list_protocol_values_become_bounded_harness_errors(event: str, field: str) -> None:
    """List/dict state values never escape the parser as a TypeError."""
    fields: dict[str, object]
    if event == "attribute":
        fields = {
            "operation": "C_GetAttributeValue",
            "attribute": {"name": "CKA_EC_POINT", "id": 385},
            field: [],
        }
    elif event == "point":
        fields = {
            "operation": "C_GetAttributeValue",
            "attribute": {"name": "CKA_EC_POINT", "id": 385},
            "curve": "secp256r1",
            "state": "usable",
            field: {},
            "diagnostic": "",
        }
    else:
        fields = {field: {}}
    output = _setup(event, **fields) + "\n"

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")


def test_cleanup_only_is_not_ec_setup() -> None:
    """Cleanup without completed setup is a phase defect, not setup cardinality."""
    output = (
        _cleanup("target_key", 6)
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "harness_error"]
    assert records[0].kind == "lifecycle"


def test_read_error_with_attributes_retains_exact_ckr_and_contradiction() -> None:
    """Contradictory read_error facts retain both the CKR and protocol defect."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
        + _setup(
            "read_error",
            operation="C_GetAttributeValue",
            requested_attributes=[
                {"name": "CKA_EC_POINT", "id": 385},
                {"name": "CKA_EC_PARAMS", "id": 384},
            ],
            rv=0x11,
        )
        + "\n"
        + _setup("done", status="read_refused")
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert any(record.actual_ckr and record.actual_ckr.endswith("SENSITIVE") for record in records)
    assert any(record.reason == "harness_error" for record in records)


def test_usable_point_cannot_finish_as_invalid_point() -> None:
    """DONE status must agree with the point state, not merely its presence."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="der_compressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="invalid_point")
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")


def test_cleanup_harness_error_does_not_hide_guard_failure() -> None:
    """Normal-process cleanup harness evidence joins strongest selection."""
    output = (
        "CKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        "GUARD_OVERWRITTEN:1\nOK\nHARNESS_ERROR:cleanup failed\n"
    )

    with pytest.raises(pytest.fail.Exception, match="guard"):
        _check_ec(0, output, "", context="EC setup")


def test_two_omitted_ec_attributes_are_independent_and_ordered() -> None:
    """Missing point and params each produce one metadata observation."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\n"
    )

    with pytest.raises(pytest.xfail.Exception):
        _check_ec(
            0,
            output,
            "",
            context="ECDH-AES C_WrapKey compressed public key undersized output buffer guard",
        )

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert [record.detail["attribute"]["name"] for record in records if record.detail] == [
        "CKA_EC_POINT",
        "CKA_EC_PARAMS",
    ]


@pytest.mark.parametrize(
    ("point_state", "params_state", "point_event", "done_status"),
    [
        ("missing", "missing", None, "unavailable"),
        ("present", "missing", "usable", "unavailable"),
        ("missing", "present", None, "unavailable"),
        ("present", "present", "usable", "ready"),
    ],
    ids=["neither", "point-only", "params-only", "both"],
)
def test_parent_parser_accepts_each_ec_presence_combination_in_wire_order(
    point_state: str,
    params_state: str,
    point_event: str | None,
    done_status: str,
) -> None:
    """The parent parser consumes point then params facts without synthetic protocol errors."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state=point_state,
            **({"value_len": 65} if point_state == "present" else {}),
            **({"value_type": "bool", "value_len": None} if point_state == "unusable" else {}),
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state=params_state,
            **({"value_len": 10} if params_state == "present" else {}),
            **({"value_type": "NoneType", "value_len": None} if params_state == "unusable" else {}),
        )
        + "\n"
    )
    if point_event is not None:
        output += (
            _setup(
                "point",
                operation="C_GetAttributeValue",
                attribute={"name": "CKA_EC_POINT", "id": 385},
                curve="secp256r1",
                state=point_event,
                encoding="raw_uncompressed",
                diagnostic="",
            )
            + "\n"
        )
    output += _setup("done", status=done_status) + "\n"
    if done_status == "ready":
        output += "CKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        output += "GUARD_OVERWRITTEN:0\nOK\n"

    if done_status == "ready":
        _check_ec(0, output, "", context="EC setup")
    else:
        with pytest.raises(pytest.xfail.Exception):
            _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert all(record.reason != "harness_error" for record in records)
    assert all("ordering" not in (record.summary or "").lower() for record in records)


@pytest.mark.parametrize(
    ("value_type", "value_len"),
    [("bool", None), ("int", None), ("NoneType", None), ("bytes", 0)],
)
def test_unusable_attribute_facts_are_not_treated_as_missing(
    value_type: str, value_len: int | None
) -> None:
    """False, zero, None, and empty bytes retain unusable-state evidence."""
    fields: dict[str, object] = {
        "operation": "C_GetAttributeValue",
        "attribute": {"name": "CKA_EC_POINT", "id": 385},
        "state": "unusable",
        "value_type": value_type,
        "value_len": value_len,
    }
    output = (
        _setup("attribute", **fields)
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\n"
    )

    with pytest.raises(pytest.xfail.Exception):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert records[0].reason == "not_operational"
    assert records[0].detail is not None
    assert records[0].detail["state"] == "unusable"
    assert records[0].detail["value_type"] == value_type
    assert records[0].detail["value_len"] == value_len


def test_missing_params_does_not_hide_off_curve_point() -> None:
    """Point validation still emits hard crypto evidence when params are absent."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="invalid_point",
            encoding="raw_uncompressed",
            diagnostic="not on secp256r1",
        )
        + "\n"
        + _setup("done", status="invalid_point")
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="invalid EC point"):
        _check_ec(0, output, "", context="EC setup")

    assert [record.reason for record in get_records()] == ["not_operational", "wrong_result"]
    assert get_records()[-1].kind == "crypto"


@pytest.mark.parametrize("rv", [0x11, 0x12])
def test_accepted_direct_attribute_ckr_is_one_aggregate_observation(rv: int) -> None:
    """Sensitive/type-invalid direct reads retain one exact aggregate CKR."""
    output = (
        _setup(
            "read_error",
            operation="C_GetAttributeValue",
            requested_attributes=[
                {"name": "CKA_EC_POINT", "id": 385},
                {"name": "CKA_EC_PARAMS", "id": 384},
            ],
            rv=rv,
        )
        + "\n"
        + _setup("done", status="read_refused")
        + "\n"
    )

    with pytest.raises(pytest.xfail.Exception):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert len(records) == 1
    assert records[0].actual_ckr is not None
    assert records[0].actual_ckr.endswith("SENSITIVE") or records[0].actual_ckr.endswith(
        "TYPE_INVALID"
    )
    assert records[0].detail is not None
    assert "requested_attributes" in records[0].detail


def test_unexpected_direct_attribute_ckr_is_exact_harness_evidence() -> None:
    """An unexpected reader CKR is not converted into a provider setup xfail."""
    output = (
        _setup(
            "read_error",
            operation="C_GetAttributeValue",
            requested_attributes=[
                {"name": "CKA_EC_POINT", "id": 385},
                {"name": "CKA_EC_PARAMS", "id": 384},
            ],
            rv=0x06,
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="unexpected C_GetAttributeValue"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "harness_error"
    assert records[0].actual_ckr is not None
    assert records[0].actual_ckr.endswith("FUNCTION_FAILED")


def test_cleanup_events_are_exact_and_continue_across_roles() -> None:
    """A cleanup CKR for one handle does not suppress later handle observations."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="missing",
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\n"
        + _cleanup("target_key", 6)
        + "\n"
        + _cleanup("pub", 7)
        + "\n"
    )

    with pytest.raises(pytest.xfail.Exception):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == [
        "not_operational",
        "not_operational",
        "not_operational",
        "not_operational",
    ]
    assert [record.detail["object"] for record in records[2:] if record.detail] == [
        "target_key",
        "pub",
    ]
    assert all(record.kind == "lifecycle" for record in records[2:])


def test_duplicate_ec_attribute_event_is_harness_error() -> None:
    """Duplicate setup slots do not create duplicate provider records."""
    event = _setup(
        "attribute",
        operation="C_GetAttributeValue",
        attribute={"name": "CKA_EC_POINT", "id": 385},
        state="missing",
    )
    output = event + "\n" + event + "\n" + _setup("done", status="unavailable") + "\n"

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "harness_error"]


def test_ec_protocol_rejects_boolean_integer_fields() -> None:
    """JSON booleans must not satisfy integer schema or attribute-ID fields."""
    output = (
        'EC_SETUP:{"schema":true,"probe":"ecdh_aes_wrap_compressed_public_key_buffer_too_small",'
        '"event":"attribute","operation":"C_GetAttributeValue",'
        '"attribute":{"name":"CKA_EC_POINT","id":true},"state":"missing"}\n'
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert "invalid schema" in records[0].summary


def test_ready_ec_setup_requires_a_complete_buffer_measurement() -> None:
    """A ready setup disposition cannot terminate the probe by itself."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="raw_uncompressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="ready")
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="complete OK measurement"):
        _check_ec(0, output, "", context="EC setup")


def test_ready_ec_setup_accepts_complete_buffer_measurement() -> None:
    """A ready setup plus complete buffer facts reaches normal classification."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="der_compressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="ready")
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
    )

    _check_ec(0, output, "", context="EC setup")
    assert not get_records()


def test_premature_done_retains_first_invalid_point_fact() -> None:
    """A premature DONE cannot erase a later hard point observation."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup("done", status="unavailable")
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="invalid_point",
            encoding="raw_uncompressed",
            diagnostic="off curve",
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="invalid EC point"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert [record.reason for record in records].count("wrong_result") == 1
    assert any(record.reason == "harness_error" for record in records)


def test_premature_done_retains_first_attribute_omission_and_rejects_sibling() -> None:
    """A first post-DONE omission is retained once; its duplicate is protocol-only."""
    first = _setup(
        "attribute",
        operation="C_GetAttributeValue",
        attribute={"name": "CKA_EC_POINT", "id": 385},
        state="missing",
    )
    output = (
        _setup("done", status="unavailable")
        + "\n"
        + first
        + "\n"
        + first
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="missing",
        )
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert (
        sum(
            record.reason == "not_operational"
            and record.detail is not None
            and record.detail.get("attribute", {}).get("name") == "CKA_EC_POINT"
            for record in records
        )
        == 1
    )
    assert (
        sum(
            record.reason == "not_operational"
            and record.detail is not None
            and record.detail.get("attribute", {}).get("name") == "CKA_EC_PARAMS"
            for record in records
        )
        == 1
    )
    assert any(record.reason == "harness_error" for record in records)


@pytest.mark.parametrize(
    ("returncode", "stderr"),
    [(0, ""), (-11, "segmentation fault"), (0, "PKCS11_CHECK_SUBPROCESS_TIMEOUT")],
)
def test_legacy_setup_cleanup_does_not_require_ec_done(returncode: int, stderr: str) -> None:
    """Legacy setup terminal/abnormal exits retain cleanup without EC-DONE noise."""
    output = "SETUP_XFAIL:legacy key setup refused\n" + _cleanup("target_key", 6) + "\n"

    with pytest.raises((pytest.xfail.Exception, pytest.fail.Exception)):
        _check_ec(returncode, output, stderr, context="EC setup")

    records = get_records()
    assert [record.reason for record in records].count("not_operational") == 2
    assert not any(
        record.reason == "harness_error" and "cleanup requires completed EC setup" in record.summary
        for record in records
    )


def test_legacy_setup_after_cleanup_does_not_transfer_ownership_backwards() -> None:
    """A legacy marker after cleanup cannot retroactively authorize that cleanup."""
    output = _cleanup("target_key", 6) + "\nSETUP_XFAIL:late setup marker\n"

    with pytest.raises(pytest.fail.Exception, match="applicable EC setup ownership"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert sum(record.reason == "not_operational" for record in records) == 2
    assert sum(record.reason == "harness_error" for record in records) == 1


def test_unexpected_reader_exception_cleanup_keeps_exact_ckr_without_done_noise() -> None:
    """Reader propagation may clean up before DONE; exact CKR and cleanup survive."""
    output = (
        _setup(
            "read_error",
            operation="C_GetAttributeValue",
            requested_attributes=[
                {"name": "CKA_EC_POINT", "id": 385},
                {"name": "CKA_EC_PARAMS", "id": 384},
            ],
            rv=6,
        )
        + "\n"
        + _cleanup("target_key", 7)
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception):
        _check_ec(1, output, "traceback", context="EC setup")

    records = get_records()
    assert sum(record.actual_ckr == "CKR_FUNCTION_FAILED" for record in records) == 1
    assert sum(record.actual_ckr == "CKR_OK" for record in records) == 0
    assert any(
        record.reason == "not_operational"
        and record.detail is not None
        and record.detail.get("object") == "target_key"
        for record in records
    )
    assert not any(
        record.reason == "harness_error" and "cleanup requires completed EC setup" in record.summary
        for record in records
    )


def test_ready_cleanup_then_measurement_is_phase_invalid() -> None:
    """No buffer measurement may start after EC object cleanup begins."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="raw_uncompressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="ready")
        + "\n"
        + _cleanup("target_key", 6)
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="measurement begins after cleanup"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert any(
        record.reason == "not_operational" and record.kind == "lifecycle" for record in records
    )
    assert any(record.reason == "harness_error" for record in records)


def test_ready_cleanup_without_terminal_measurement_is_probe_incomplete() -> None:
    """Cleanup lifecycle xfails cannot make ready-without-measurement complete."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="raw_uncompressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="ready")
        + "\n"
        + _cleanup("target_key", 6)
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="complete OK measurement"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert any(
        record.reason == "not_operational" and record.kind == "lifecycle" for record in records
    )
    assert any(record.reason == "probe_incomplete" for record in records)


def test_ready_cleanup_then_setup_refusal_is_phase_invalid() -> None:
    """A legacy refusal after cleanup cannot complete the ready phase."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="raw_uncompressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="ready")
        + "\n"
        + _cleanup("target_key", 6)
        + "\nSETUP_XFAIL:late import refusal\n"
    )

    with pytest.raises(pytest.fail.Exception, match="setup refusal follows cleanup"):
        _check_ec(0, output, "", context="EC setup")


def test_invalid_cleanup_prefixes_do_not_move_phase_boundary() -> None:
    """Only a valid selected cleanup may make later measurement phase-invalid."""
    wrong_probe = _cleanup("target_key", 6).replace(
        "ecdh_aes_wrap_compressed_public_key_buffer_too_small", "other_probe"
    )
    output = (
        "SETUP_XFAIL:legacy setup refusal\n"
        + wrong_probe
        + "\nEC_CLEANUP:{not-json\n"
        + "CKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\n"
        + _cleanup("target_key", 6)
        + "\n"
    )

    with pytest.raises(pytest.fail.Exception, match="malformed EC protocol"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert sum(record.reason == "harness_error" for record in records) == 1
    assert (
        sum(
            record.reason == "not_operational"
            and record.detail is not None
            and record.detail.get("object") == "target_key"
            and record.actual_ckr == "CKR_FUNCTION_FAILED"
            for record in records
        )
        == 1
    )
    assert not any("measurement begins after cleanup" in record.summary for record in records)


def test_legacy_cleanup_then_measurement_is_phase_invalid() -> None:
    """Legacy setup ownership cannot bypass post-cleanup measurement validation."""
    output = (
        "SETUP_XFAIL:legacy setup refusal\n"
        + _cleanup("target_key", 6)
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:0\nOK\nSETUP_XFAIL:late setup refusal\n"
    )

    with pytest.raises(pytest.fail.Exception, match="measurement begins after cleanup"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert any(record.reason == "not_operational" and record.kind is None for record in records)
    assert any(
        record.reason == "not_operational"
        and record.kind == "lifecycle"
        and record.detail is not None
        and record.detail.get("object") == "target_key"
        for record in records
    )
    assert any(record.reason == "harness_error" for record in records)
    assert any("setup refusal follows cleanup" in record.summary for record in records)


def test_measurement_continuation_after_cleanup_is_phase_invalid() -> None:
    """A measurement stream cannot continue emitting facts after cleanup."""
    output = (
        "SETUP_XFAIL:legacy setup refusal\n"
        + "CKR:0x00000150\n"
        + _cleanup("target_key", 6)
        + "\nINITIAL_COUNT:16\nRETURNED_COUNT:16\nGUARD_OVERWRITTEN:0\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="measurement begins after cleanup"):
        _check_ec(0, output, "", context="EC setup")


def test_deep_marker_before_ready_preserves_guard_evidence() -> None:
    """Bounded parsing must retain a later hard guard finding without recursion escape."""
    nested = "[" * 10_000 + "0" + "]" * 10_000
    ready = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=65,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="raw_uncompressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="ready")
        + "\n"
    )
    output = (
        'EC_SETUP:{"schema":1,"probe":"ecdh_aes_wrap_compressed_public_key_buffer_too_small",'
        '"event":"done","status":'
        + nested
        + "}\n"
        + ready
        + "CKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:1\nSETUP_XFAIL:late setup refusal\n"
    )

    with pytest.raises(pytest.fail.Exception, match="overwrote"):
        _check_ec(0, output, "", context="EC setup")

    records = get_records()
    assert any(
        record.reason == "harness_error"
        and (
            "event exceeds bounded transport limit" in record.summary
            or "bounded JSON parse failure" in record.summary
        )
        for record in records
    )
    assert any(
        record.reason == "self_contradiction"
        and record.kind == "policy"
        and "overwrote" in record.summary
        for record in records
    )
    assert not any("RecursionError" in record.summary for record in records)


def test_usable_point_encoding_is_attached_to_buffer_findings() -> None:
    """Later EC buffer findings retain the validated point representation."""
    output = (
        _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            state="present",
            value_len=35,
        )
        + "\n"
        + _setup(
            "attribute",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_PARAMS", "id": 384},
            state="present",
            value_len=10,
        )
        + "\n"
        + _setup(
            "point",
            operation="C_GetAttributeValue",
            attribute={"name": "CKA_EC_POINT", "id": 385},
            curve="secp256r1",
            state="usable",
            encoding="der_compressed",
            diagnostic="",
        )
        + "\n"
        + _setup("done", status="ready")
        + "\nCKR:0x00000150\nINITIAL_COUNT:16\nRETURNED_COUNT:16\n"
        + "GUARD_OVERWRITTEN:1\nOK\n"
    )

    with pytest.raises(pytest.fail.Exception, match="guard"):
        _check_ec(0, output, "", context="EC setup")

    assert get_records()[-1].detail is not None
    assert get_records()[-1].detail["ec_point_encoding"] == "der_compressed"


def test_host_unsupported_curve_backend_is_not_reclassified() -> None:
    """A host cryptography limitation propagates instead of becoming provider evidence."""
    original = raw_probe.decode_provider_ec_point

    def unsupported(*_args: object, **_kwargs: object) -> bytes:
        raise UnsupportedAlgorithm("backend unavailable")

    raw_probe.decode_provider_ec_point = unsupported
    try:
        with pytest.raises(UnsupportedAlgorithm):
            raw_probe._compress_p256_ec_point(_raw_p256_point())
    finally:
        raw_probe.decode_provider_ec_point = original


def test_cleanup_harness_exception_continues_to_later_handles(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An ordinary cleanup exception is visible and later handles are attempted."""

    class Raw:
        def C_DestroyObject(self, _sh: int | None, handle: int) -> int:  # noqa: N802
            if handle == 1:
                raise RuntimeError("cleanup failed")
            return 7

    raw_probe._destroy_ec_object(Raw(), 9, raw_probe.CK_OBJECT_HANDLE(1), "target_key")
    raw_probe._destroy_ec_object(Raw(), 9, raw_probe.CK_OBJECT_HANDLE(2), "pub")

    captured = capsys.readouterr().out
    assert "HARNESS_ERROR:EC cleanup role=target_key" in captured
    assert '"object":"pub"' in captured


def test_cleanup_provider_fault_stops_later_handles() -> None:
    """A provider memory fault during cleanup is allowed to terminate the child."""

    class Raw:
        def C_DestroyObject(self, _sh: int | None, _handle: int) -> int:  # noqa: N802
            raise OSError("provider access violation")

    with pytest.raises(OSError):
        raw_probe._destroy_ec_object(Raw(), 9, raw_probe.CK_OBJECT_HANDLE(1), "target_key")
