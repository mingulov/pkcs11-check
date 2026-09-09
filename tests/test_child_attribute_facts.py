"""Provider-free tests for the child missing-attribute wire adapter."""

from __future__ import annotations

import inspect
import json
from typing import Any, cast

import pytest

from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.types_std import CKA_EC_PARAMS, CKA_EC_POINT, CKA_MODULUS


def _payload(capsys: pytest.CaptureFixture[str], marker: str) -> dict[str, object]:
    line = capsys.readouterr().out.strip()
    assert line.startswith(f"{marker}:")
    value = json.loads(line.removeprefix(f"{marker}:"))
    assert isinstance(value, dict)
    return value


def test_rsa_missing_fact_has_exact_parent_wire_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

    emit_missing_attribute(
        CKA_MODULUS,
        protocol="RSA_ATTRIBUTE",
        context="decrypt:pkcs:random",
    )

    assert _payload(capsys, "RSA_ATTRIBUTE") == {
        "schema": 1,
        "case": "decrypt:pkcs:random",
        "operation": "C_GetAttributeValue",
        "attribute": {"name": ATTR_NAMES[int(CKA_MODULUS)], "id": int(CKA_MODULUS)},
        "state": "missing",
    }


@pytest.mark.parametrize(
    ("attribute", "context", "expected"),
    [
        (
            CKA_EC_POINT,
            "ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        ),
        (
            CKA_EC_PARAMS,
            "ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            {"name": "CKA_EC_PARAMS", "id": int(CKA_EC_PARAMS)},
        ),
    ],
)
def test_ec_missing_fact_has_exact_parent_wire_shape(
    capsys: pytest.CaptureFixture[str],
    attribute: int,
    context: str,
    expected: dict[str, object],
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

    emit_missing_attribute(attribute, protocol="EC_SETUP", context=context)

    assert _payload(capsys, "EC_SETUP") == {
        "schema": 1,
        "probe": context,
        "event": "attribute",
        "operation": "C_GetAttributeValue",
        "attribute": expected,
        "state": "missing",
    }


def test_uaf_missing_fact_has_exact_parent_wire_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

    emit_missing_attribute(CKA_EC_POINT, protocol="UAF", context="derive")

    assert _payload(capsys, "UAF") == {
        "schema": 1,
        "probe": "derive",
        "event": "SETUP_ATTRIBUTE",
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "state": "missing",
        "value_type": None,
        "value_len": None,
    }


@pytest.mark.parametrize(
    ("attribute", "protocol", "context"),
    [
        (True, "EC_SETUP", "ecdh_aes_wrap_compressed_public_key_buffer_too_small"),
        (0x7FFFFFFF, "EC_SETUP", "ecdh_aes_wrap_compressed_public_key_buffer_too_small"),
        (CKA_MODULUS, "EC_SETUP", "ecdh_aes_wrap_compressed_public_key_buffer_too_small"),
        (CKA_EC_POINT, "UAF", "derive-other"),
        (CKA_EC_POINT, "RSA_ATTRIBUTE", "decrypt:pkcs:random"),
        (CKA_MODULUS, "RSA_ATTRIBUTE", "verify:sha256_rsa_pkcs:bitflip"),
        (CKA_MODULUS, "RSA_ATTRIBUTE", "decrypt:bogus:random"),
        (CKA_EC_POINT, "EC_SETUP", "dynamic"),
    ],
)
def test_invalid_adapter_combinations_raise_without_output(
    capsys: pytest.CaptureFixture[str],
    attribute: int,
    protocol: str,
    context: str,
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

    with pytest.raises((TypeError, ValueError)):
        emit_missing_attribute(attribute, protocol=protocol, context=context)  # type: ignore[arg-type]
    assert capsys.readouterr().out == ""


def test_helper_does_not_import_classification_or_pytest() -> None:
    from pkcs11_check.testcases._probes import _attribute_facts

    source = inspect.getsource(_attribute_facts)
    assert "import pytest" not in source
    assert "pkcs11_check.classification" not in source


def test_serialization_failures_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases._probes import _attribute_facts

    def fail(*_args: object, **_kwargs: object) -> str:
        raise OSError("broken stdout")

    monkeypatch.setattr(_attribute_facts, "print", fail, raising=False)
    with pytest.raises(OSError, match="broken stdout"):
        _attribute_facts.emit_missing_attribute(
            CKA_EC_POINT,
            protocol="UAF",
            context="derive",
        )


@pytest.mark.parametrize(
    ("attribute", "value", "expected_type", "expected_len"),
    [
        (CKA_EC_POINT, None, "NoneType", None),
        (CKA_EC_PARAMS, False, "bool", None),
        (CKA_EC_POINT, 0, "int", None),
        (CKA_EC_PARAMS, "curve", "str", None),
        (CKA_EC_POINT, bytearray(b"point"), "bytearray", None),
        (CKA_EC_PARAMS, b"", "bytes", 0),
    ],
)
def test_observe_ec_attribute_emits_unusable_for_every_nonusable_value(
    capsys: pytest.CaptureFixture[str],
    attribute: int,
    value: object,
    expected_type: str,
    expected_len: int | None,
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute

    result = observe_ec_attribute(
        {attribute: value},
        attribute,
        context="ecdh_aes_wrap_compressed_public_key_buffer_too_small",
    )

    assert result is None
    assert _payload(capsys, "EC_SETUP") == {
        "schema": 1,
        "probe": "ecdh_aes_wrap_compressed_public_key_buffer_too_small",
        "event": "attribute",
        "operation": "C_GetAttributeValue",
        "attribute": {
            "name": "CKA_EC_PARAMS" if attribute == CKA_EC_PARAMS else ATTR_NAMES[int(attribute)],
            "id": int(attribute),
        },
        "state": "unusable",
        "value_type": expected_type,
        "value_len": expected_len,
    }


def test_observe_ec_attribute_emits_present_and_preserves_bytes_identity(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute

    value = b"point"
    result = observe_ec_attribute(
        {CKA_EC_POINT: value},
        CKA_EC_POINT,
        context="ecdh_aes_wrap_compressed_public_key_buffer_too_small",
    )

    assert result is value
    assert _payload(capsys, "EC_SETUP") == {
        "schema": 1,
        "probe": "ecdh_aes_wrap_compressed_public_key_buffer_too_small",
        "event": "attribute",
        "operation": "C_GetAttributeValue",
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "state": "present",
        "value_len": len(value),
    }


def test_observe_ec_attribute_missing_reuses_existing_missing_fact(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute

    assert (
        observe_ec_attribute(
            {},
            CKA_EC_POINT,
            context="ecdh_aes_wrap_compressed_public_key_buffer_too_small",
        )
        is None
    )
    assert _payload(capsys, "EC_SETUP")["state"] == "missing"


@pytest.mark.parametrize(
    ("attributes", "attribute", "context"),
    [
        ({}, True, "ecdh_aes_wrap_compressed_public_key_buffer_too_small"),
        ({}, CKA_MODULUS, "ecdh_aes_wrap_compressed_public_key_buffer_too_small"),
        ({}, CKA_EC_POINT, "other"),
        ({}, CKA_EC_POINT, 1),
    ],
)
def test_observe_ec_attribute_rejects_invalid_key_context_without_output(
    capsys: pytest.CaptureFixture[str],
    attributes: object,
    attribute: object,
    context: object,
) -> None:
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute

    with pytest.raises((TypeError, ValueError)):
        observe_ec_attribute(attributes, attribute, context=context)  # type: ignore[arg-type]
    assert capsys.readouterr().out == ""


def test_observe_ec_attribute_flushes_each_event_and_preserves_first_on_second_failure(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.testcases._probes import _attribute_facts

    original_print = print
    calls = 0

    def fail_second(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("broken stdout")
        cast(Any, original_print)(*args, **kwargs)

    monkeypatch.setattr(_attribute_facts, "print", fail_second, raising=False)
    context = "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    _attribute_facts.observe_ec_attribute({}, CKA_EC_POINT, context=context)
    with pytest.raises(OSError, match="broken stdout"):
        _attribute_facts.observe_ec_attribute({}, CKA_EC_PARAMS, context=context)

    output = capsys.readouterr().out
    assert output.count("EC_SETUP:") == 1
