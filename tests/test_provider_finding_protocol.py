"""Regression tests for terminal provider observations from crash-safe probes."""

from __future__ import annotations

import ctypes
import inspect
import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.types_std import _CK_ULONG_MAX, CK_ULONG
from pkcs11_check.testcases._probes._emit import (
    PROVIDER_FINDING_MARKER,
    emit_provider_finding,
    parse_provider_finding,
)
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.security.conftest import (
    assert_subprocess_no_crash,
    handle_child_provider_finding,
)
from pkcs11_check.testcases.security.test_error_path_kwp import (
    _handle_corrupted_provider_finding,
)


@pytest.fixture(autouse=True)
def _clear_records() -> None:
    classification.clear()


def _marker(**overrides: object) -> str:
    payload: dict[str, object] = {
        "schema": 1,
        "reason": "self_contradiction",
        "kind": "policy",
        "operation": "C_Decrypt",
        "mechanism": "CKM_AES_KEY_WRAP_KWP",
        "detail": "provider overwrote the output guard",
    }
    payload.update(overrides)
    return PROVIDER_FINDING_MARKER + json.dumps(payload, separators=(",", ":"))


def test_provider_finding_marker_round_trips_without_classification_import(
    capsys: pytest.CaptureFixture[str],
) -> None:
    emit_provider_finding(
        reason="self_contradiction",
        kind="policy",
        operation="C_Decrypt",
        mechanism="CKM_AES_KEY_WRAP_KWP",
        detail="provider overwrote the output guard",
    )

    payload, error = parse_provider_finding(capsys.readouterr().out)
    assert error is None
    assert payload == {
        "schema": 1,
        "reason": "self_contradiction",
        "kind": "policy",
        "operation": "C_Decrypt",
        "mechanism": "CKM_AES_KEY_WRAP_KWP",
        "detail": "provider overwrote the output guard",
    }
    source = inspect.getsource(emit_provider_finding)
    assert "pkcs11_check.classification" not in source


@pytest.mark.parametrize(
    "relative_path",
    [
        "src/pkcs11_check/testcases/_probes/error_path_kwp.py",
        "src/pkcs11_check/testcases/_probes/secret_key_value_len.py",
    ],
)
def test_terminal_child_probes_only_emit_facts(relative_path: str) -> None:
    source = Path(relative_path).read_text(encoding="utf-8")
    assert "pkcs11_check.classification" not in source
    assert "classify(" not in source


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema": 2},
        {"reason": "probe_incomplete"},
        {"kind": "other"},
        {"operation": "decrypt"},
        {"mechanism": "AES_KEY_WRAP_KWP"},
        {"detail": ""},
        {"detail": "line\nbreak"},
        {"extra": "not allowed"},
    ],
)
def test_provider_finding_parser_rejects_malformed_payload(
    overrides: dict[str, object],
) -> None:
    payload, error = parse_provider_finding(_marker(**overrides))
    assert payload is None
    assert error


def test_provider_finding_parser_rejects_duplicate_json_keys() -> None:
    payload = (
        '{"schema":1,"reason":"self_contradiction","kind":"policy",'
        '"operation":"C_Decrypt","mechanism":"CKM_AES_KEY_WRAP_KWP",'
        '"detail":"first","detail":"second"}'
    )
    parsed, error = parse_provider_finding(PROVIDER_FINDING_MARKER + payload)
    assert parsed is None
    assert error


@pytest.mark.parametrize(
    "detail",
    [
        "a" * 2048,
        "é" * 1024,
        "\x7f",
        "\x80",
        "\u061c",
        "\u200e",
        "\u202e",
        "\u200b",
        "\n",
        "\ud800",
    ],
)
def test_provider_finding_parser_enforces_utf8_and_printable_detail(detail: str) -> None:
    parsed, error = parse_provider_finding(_marker(detail=detail))
    if detail in {"a" * 2048, "é" * 1024}:
        assert parsed is not None
        assert error is None
    else:
        assert parsed is None
        assert error


@pytest.mark.parametrize("detail", ["é" * 1025, 1, None, [], {}])
def test_provider_finding_parser_rejects_oversized_or_non_string_detail(
    detail: object,
) -> None:
    parsed, error = parse_provider_finding(_marker(detail=detail))
    assert parsed is None
    assert error


def test_missing_marker_is_not_interpreted_as_provider_evidence() -> None:
    assert parse_provider_finding("TARGET_RV:0x00000000\n") == (None, None)


def test_terminal_finding_outanks_clean_refusal_and_positive_exit() -> None:
    stdout = _marker() + "\ndecrypt_rv=CKR_GENERAL_ERROR\n"
    with pytest.raises(pytest.fail.Exception, match="provider terminal evidence"):
        handle_child_provider_finding(
            1,
            stdout,
            "traceback after provider observation",
            context="CKM_AES_KEY_WRAP_KWP decrypt: corruption=padding",
            expected_reason="self_contradiction",
            expected_kind="policy",
            operation="C_Decrypt",
            mechanism="CKM_AES_KEY_WRAP_KWP",
        )

    records = classification.get_records()
    assert [item.reason for item in records] == ["self_contradiction"]
    assert records[0].operation == "C_Decrypt"
    assert records[0].mechanism == "CKM_AES_KEY_WRAP_KWP"
    assert records[0].kind == "policy"


def test_missing_marker_with_positive_exit_remains_probe_incomplete() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        assert_subprocess_completed(
            1,
            "decrypt_rv=CKR_GENERAL_ERROR\n",
            "traceback before terminal marker",
            context="CKM_AES_KEY_WRAP_KWP decrypt",
        )

    assert [item.reason for item in classification.get_records()] == ["probe_incomplete"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_crash_before_marker_remains_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        assert_subprocess_completed(
            -11,
            "decrypt_init_rv=CKR_OK\n",
            "segmentation fault",
            context="CKM_AES_KEY_WRAP_KWP decrypt",
        )

    assert [item.reason for item in classification.get_records()] == ["crash"]


def test_terminal_finding_survives_later_cleanup_marker() -> None:
    with pytest.raises(pytest.fail.Exception, match="provider terminal evidence"):
        handle_child_provider_finding(
            0,
            _marker() + "\nHARNESS_ERROR:cleanup failed after measurement\n",
            "",
            context="CKM_AES_KEY_WRAP_KWP decrypt",
            expected_reason="self_contradiction",
            expected_kind="policy",
            operation="C_Decrypt",
            mechanism="CKM_AES_KEY_WRAP_KWP",
        )

    assert [item.reason for item in classification.get_records()] == [
        "self_contradiction",
        "harness_error",
    ]


def test_toxic_length_marker_keeps_producer_operation_in_label_and_detail() -> None:
    payload = _marker(
        kind="metadata",
        operation="C_GetAttributeValue",
        mechanism="CKM_HKDF_DERIVE",
        detail=(
            "C_DeriveKey accepted CKA_VALUE_LEN=0xffffffffffffffff; "
            "C_GetAttributeValue returned the same toxic length"
        ),
    )
    with pytest.raises(pytest.fail.Exception):
        handle_child_provider_finding(
            1,
            payload,
            "",
            context="C_DeriveKey(HKDF_SHA256, CKA_VALUE_LEN=0xffffffffffffffff)",
            expected_reason="self_contradiction",
            expected_kind="metadata",
            operation="C_GetAttributeValue",
            mechanism="CKM_HKDF_DERIVE",
        )

    finding = classification.get_records()[0]
    assert finding.reason == "self_contradiction"
    assert finding.kind == "metadata"
    assert "C_DeriveKey" in finding.label
    assert finding.detail is not None
    assert "C_DeriveKey" in finding.detail["child_detail"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_terminal_finding_preserves_following_signal_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        handle_child_provider_finding(
            -11,
            _marker(),
            "segmentation fault after provider observation",
            context="CKM_AES_KEY_WRAP_KWP decrypt",
            expected_reason="self_contradiction",
            expected_kind="policy",
            operation="C_Decrypt",
            mechanism="CKM_AES_KEY_WRAP_KWP",
        )

    assert [item.reason for item in classification.get_records()] == [
        "self_contradiction",
        "crash",
    ]


def test_unwrap_path_cannot_accept_a_c_decrypt_terminal_marker() -> None:
    context = "CKM_AES_KEY_WRAP_KWP unwrap: corruption=padding"
    assert (
        _handle_corrupted_provider_finding(
            1,
            _marker(),
            "spoofed decrypt marker on unwrap path",
            api="unwrap",
            context=context,
            mechanism="CKM_AES_KEY_WRAP_KWP",
        )
        is False
    )
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        assert_subprocess_no_crash(
            1,
            _marker(),
            "spoofed decrypt marker on unwrap path",
            context=context,
        )

    assert [item.reason for item in classification.get_records()] == ["probe_incomplete"]


@pytest.mark.parametrize(
    ("overrides", "expected_reason", "expected_kind", "expected_operation", "mechanism"),
    [
        (
            {"reason": "sanctioned_refusal"},
            "self_contradiction",
            "policy",
            "C_Decrypt",
            "CKM_AES_KEY_WRAP_KWP",
        ),
        ({"kind": "crypto"}, "self_contradiction", "policy", "C_Decrypt", "CKM_AES_KEY_WRAP_KWP"),
        (
            {"operation": "C_Encrypt"},
            "self_contradiction",
            "policy",
            "C_Decrypt",
            "CKM_AES_KEY_WRAP_KWP",
        ),
        (
            {"mechanism": "CKM_AES_KEY_WRAP"},
            "self_contradiction",
            "policy",
            "C_Decrypt",
            "CKM_AES_KEY_WRAP_KWP",
        ),
    ],
)
def test_provider_finding_identity_or_downgrade_is_probe_incomplete(
    overrides: dict[str, object],
    expected_reason: str,
    expected_kind: str,
    expected_operation: str,
    mechanism: str,
) -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        handle_child_provider_finding(
            1,
            _marker(**overrides),
            "provider marker mismatch",
            context="CKM_AES_KEY_WRAP_KWP decrypt",
            expected_reason=expected_reason,
            expected_kind=expected_kind,
            operation=expected_operation,
            mechanism=mechanism,
        )

    assert [item.reason for item in classification.get_records()] == ["probe_incomplete"]


class _ToxicLengthRaw:
    """Minimal raw facade that makes the actual value-length oracle emit its marker."""

    def __init__(self, *, control_first: bool = False) -> None:
        self._next_handle = 1
        self._control_handle: int | None = None
        self._generate_count = 0
        self._control_first = control_first

    def available_function_names(self) -> set[str]:
        return {"C_DigestKey"}

    def __getattr__(self, name: str) -> Any:
        if name in {
            "C_CreateObject",
            "C_CopyObject",
            "C_GenerateKey",
            "C_UnwrapKey",
            "C_DeriveKey",
        }:
            return self._successful_handle_call(name)
        if name in {"C_DestroyObject", "C_SetAttributeValue", "C_DigestInit"}:
            return lambda *_args: 0
        raise AttributeError(name)

    def _successful_handle_call(self, name: str) -> Any:
        def call(*args: Any) -> int:
            handle = self._next_handle
            self._next_handle += 1
            args[-1]._obj.value = handle
            if name == "C_GenerateKey":
                self._generate_count += 1
                if self._control_first and self._generate_count == 1:
                    self._control_handle = handle
            return 0

        return call

    def C_GetAttributeValue(  # noqa: N802 - mirrors the PKCS#11 entry point
        self,
        _sh: int,
        _obj: int,
        attributes: Any,
        _count: int,
    ) -> int:
        attribute = attributes._obj
        value = ctypes.cast(attribute.pValue, ctypes.POINTER(CK_ULONG))
        value.contents.value = (
            32
            if self._control_handle is not None and _obj == self._control_handle
            else _CK_ULONG_MAX
        )
        return 0


@pytest.mark.parametrize(
    ("context", "producer_operation", "mechanism"),
    [
        ("C_CreateObject", "C_CreateObject", None),
        ("C_CopyObject", "C_CopyObject", None),
        ("C_SetAttributeValue", "C_SetAttributeValue", None),
        ("C_CreateObject for C_DigestKey", "C_CreateObject", "CKM_SHA256"),
        ("C_UnwrapKey", "C_UnwrapKey", "CKM_AES_ECB"),
        ("C_GenerateKey(GENERIC_SECRET)", "C_GenerateKey", "CKM_GENERIC_SECRET_KEY_GEN"),
        ("C_GenerateKey(PBKDF2)", "C_GenerateKey", "CKM_PKCS5_PBKD2"),
        ("C_DeriveKey", "C_DeriveKey", "CKM_HKDF_DERIVE"),
    ],
)
def test_actual_toxic_length_oracle_emits_producer_wiring(
    context: str,
    producer_operation: str,
    mechanism: str | None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pkcs11_check.testcases._probes import secret_key_value_len

    with pytest.raises(AssertionError, match="stored oversized CKA_VALUE_LEN"):
        secret_key_value_len._assert_value_len_not_toxic(
            _ToxicLengthRaw(),
            1,
            2,
            context,
            producer_operation=producer_operation,
            mechanism=mechanism,
        )

    payload, error = parse_provider_finding(capsys.readouterr().out)
    assert error is None
    assert payload is not None
    assert payload["reason"] == "self_contradiction"
    assert payload["kind"] == "metadata"
    assert payload["operation"] == "C_GetAttributeValue"
    assert payload["mechanism"] == mechanism
    assert producer_operation in payload["detail"]


@pytest.mark.parametrize(
    ("which", "extra", "context", "producer_operation", "mechanism"),
    [
        (
            "create_object",
            {"key_type_name": "CKK_GENERIC_SECRET", "include_value": True},
            "C_CreateObject",
            "C_CreateObject",
            None,
        ),
        ("copy_secret_key", {}, "C_CopyObject", "C_CopyObject", None),
        ("set_secret_key_attr", {}, "C_SetAttributeValue", "C_SetAttributeValue", None),
        ("digest_key", {}, "C_CreateObject for C_DigestKey", "C_CreateObject", "CKM_SHA256"),
        ("aes_ecb_unwrap", {}, "C_UnwrapKey", "C_UnwrapKey", "CKM_AES_ECB"),
        (
            "generate_generic_secret",
            {},
            "C_GenerateKey(GENERIC_SECRET)",
            "C_GenerateKey",
            "CKM_GENERIC_SECRET_KEY_GEN",
        ),
        ("generate_pbkdf2", {}, "C_GenerateKey(PBKDF2)", "C_GenerateKey", "CKM_PKCS5_PBKD2"),
        (
            "hkdf_derive",
            {"output_value_len": 255 * 32},
            "C_DeriveKey",
            "C_DeriveKey",
            "CKM_HKDF_DERIVE",
        ),
    ],
)
def test_dispatch_paths_emit_their_actual_producer_wiring(
    which: str,
    extra: dict[str, object],
    context: str,
    producer_operation: str,
    mechanism: str | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pkcs11_check.testcases._probes import secret_key_value_len
    from pkcs11_check.testcases._probes.session import ProbeContext

    raw = _ToxicLengthRaw(control_first=which == "generate_generic_secret")
    if which == "aes_ecb_unwrap":
        handles = iter((10, 11))
        monkeypatch.setattr(
            secret_key_value_len,
            "gen_aes_key",
            lambda *_args, **_kwargs: next(handles),
        )
        monkeypatch.setattr(
            secret_key_value_len,
            "wrap_key_recipe",
            lambda *_args, **_kwargs: b"wrapped",
        )
    probe_context = ProbeContext(
        raw=cast(Any, raw),
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    with pytest.raises(AssertionError, match="stored oversized CKA_VALUE_LEN"):
        secret_key_value_len._DISPATCH[which](probe_context, extra)

    payload, error = parse_provider_finding(capsys.readouterr().out)
    assert error is None
    assert payload is not None
    assert payload["operation"] == "C_GetAttributeValue"
    assert payload["mechanism"] == mechanism
    assert producer_operation in payload["detail"]
