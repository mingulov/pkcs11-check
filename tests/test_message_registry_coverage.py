"""Guardrails for registry-driven message-API coverage."""

from __future__ import annotations

from pathlib import Path

from pkcs11_check import plugin
from pkcs11_check.raw.types_std import (
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
)

REPO = Path(__file__).resolve().parents[1]
MECH_MESSAGE = REPO / "src" / "pkcs11_check" / "testcases" / "test_mech_message.py"


def test_plugin_exposes_message_flag_fixtures() -> None:
    assert plugin._LEGACY_FLAG_BY_FIXTURE["mech_message_encrypt_entry"] == int(
        CKF_MESSAGE_ENCRYPT
    )
    assert plugin._LEGACY_FLAG_BY_FIXTURE["mech_message_decrypt_entry"] == int(
        CKF_MESSAGE_DECRYPT
    )
    assert plugin._LEGACY_FLAG_BY_FIXTURE["mech_message_sign_entry"] == int(CKF_MESSAGE_SIGN)
    assert plugin._LEGACY_FLAG_BY_FIXTURE["mech_message_verify_entry"] == int(CKF_MESSAGE_VERIFY)


def test_mech_message_consumes_registry_message_fixtures() -> None:
    source = MECH_MESSAGE.read_text()

    for fixture in (
        "mech_message_encrypt_entry",
        "mech_message_decrypt_entry",
        "mech_message_sign_entry",
        "mech_message_verify_entry",
    ):
        assert fixture in source


def test_mech_message_has_registry_permission_negatives() -> None:
    source = MECH_MESSAGE.read_text()

    for test_name in (
        "test_registry_message_encrypt_without_flag",
        "test_registry_message_decrypt_without_flag",
        "test_registry_message_sign_without_flag",
        "test_registry_message_verify_without_flag",
    ):
        assert test_name in source

    assert "classify_policy_enforcement(" in source
    assert "classify_negative_rv(" in source
