"""Order-2 secret-handling goldens (validation F-001/F-002 + config sink).

Central policy: secret-valued argv flags are named once in
``SECRET_ARGV_FLAGS`` (``core._secrets``); every renderer of pytest args must
pass through ``redact_secret_args``. KEK transport is env-only:
``P11TEST_WRAP_KEY_VALUE`` picked up by ``P11TestConfig`` (BaseSettings);
never on a command line.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.core._secrets import SECRET_ARGV_FLAGS, redact_secret_args
from pkcs11_check.core.collection_errors import collection_failure_message


def test_secret_flags_cover_all_secret_valued_options() -> None:
    """The central policy must name every secret-valued pytest flag."""
    assert SECRET_ARGV_FLAGS == frozenset({"--p11-pin", "--p11-so-pin", "--p11-wrap-key-value"})


def test_redact_separate_token_form() -> None:
    """F-001: `--flag value` values are redacted, flags and rest intact."""
    args = [
        "--p11-module",
        "/tmp/m.so",
        "--p11-pin",
        "s3cret",
        "--p11-so-pin",
        "s0s3cret",
        "--p11-wrap-key-value",
        "deadbeef" * 8,
        "test_a.py",
    ]
    assert redact_secret_args(args) == [
        "--p11-module",
        "/tmp/m.so",
        "--p11-pin",
        "<redacted>",
        "--p11-so-pin",
        "<redacted>",
        "--p11-wrap-key-value",
        "<redacted>",
        "test_a.py",
    ]


def test_redact_equals_form_preserves_shape() -> None:
    """F-001: `--flag=value` keeps one token so messages stay reproducible."""
    assert redact_secret_args(["--p11-pin=s3cret", "test_a.py"]) == [
        "--p11-pin=<redacted>",
        "test_a.py",
    ]


def test_redact_leaves_unknown_flags_and_positionals() -> None:
    """Redaction only touches policy-listed flags."""
    args = ["--p11-slot", "0", "--timeout", "60", "test_a.py", "--p11-pin"]
    assert redact_secret_args(args) == args


def test_redact_empty() -> None:
    assert redact_secret_args([]) == []


def test_collection_failure_message_redacts_secrets() -> None:
    """F-001 end to end: the persisted diagnostic carries flags, never values."""
    message = collection_failure_message(
        returncode=2,
        stdout="",
        stderr="boom",
        targets=[],
        pytest_args=[
            "--p11-module",
            "/tmp/m.so",
            "--p11-pin",
            "s3cret",
            "--p11-wrap-key-value=deadbeef",
        ],
    )
    assert "--p11-pin" in message
    assert "--p11-wrap-key-value" in message
    assert "s3cret" not in message
    assert "deadbeef" not in message
    assert "/tmp/m.so" in message


# ---------------------------------------------------------------------------
# F-002: KEK transport is env-only
# ---------------------------------------------------------------------------


def test_wrap_key_value_flows_via_env_to_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-002: children pick the KEK up from P11TEST_WRAP_KEY_VALUE as SecretStr."""
    from pkcs11_check.config import P11TestConfig

    module = tmp_path / "module.so"
    module.write_text("", encoding="utf-8")
    monkeypatch.setenv("P11TEST_WRAP_KEY_VALUE", "ab" * 16)

    config = P11TestConfig(module=module)

    assert config.wrap_key_value is not None
    assert config.wrap_key_value.get_secret_value() == "ab" * 16


def test_config_error_masks_wrap_key_value(tmp_path: Path) -> None:
    """Config sink: malformed KEK must not echo in validation errors."""
    from pydantic import ValidationError

    from pkcs11_check.config import P11TestConfig

    module = tmp_path / "module.so"
    module.write_text("", encoding="utf-8")
    with pytest.raises(ValidationError) as exc_info:
        P11TestConfig(module=module, wrap_key_value="zzzz-not-hex")
    rendered = str(exc_info.value)
    assert "zzzz-not-hex" not in rendered
    assert "input_value" not in rendered
    assert "wrap_key_value" in rendered  # field + reason still debuggable


def test_redacted_env_keys_include_wrap_key() -> None:
    """F-002: the KEK env var joins the fingerprint-snapshot redaction set."""
    from pkcs11_check.core._run_state import _REDACTED_ENV_KEYS

    assert "P11TEST_WRAP_KEY_VALUE" in _REDACTED_ENV_KEYS


def test_fingerprint_env_redacts_wrap_key_value() -> None:
    """F-002 end to end: snapshots record presence, never the KEK."""
    from pkcs11_check.core._run_state import _fingerprint_env

    snapshot = _fingerprint_env({"P11TEST_WRAP_KEY_VALUE": "ab" * 16})
    assert snapshot == {"P11TEST_WRAP_KEY_VALUE": "<set>"}


def test_kek_bytes_unwraps_secret_and_plain() -> None:
    """Provisioning accepts SecretStr or plain hex (doubles use plain str)."""
    from pydantic import SecretStr

    from pkcs11_check.testcases._provisioning import _kek_bytes_or_none

    assert _kek_bytes_or_none(SecretStr("ab" * 16)) == bytes.fromhex("ab" * 16)
    assert _kek_bytes_or_none("ab" * 16) == bytes.fromhex("ab" * 16)
    assert _kek_bytes_or_none(None) is None


def test_state_fingerprint_stable_across_secret_rotation() -> None:
    """Secret values must not invalidate resume fingerprints."""
    from pkcs11_check.core._run_state import build_state_fingerprint

    base = ["--p11-module", "/tmp/m.so", "--p11-pin"]
    first = build_state_fingerprint(["a.py"], [*base, "one"], env=None)
    second = build_state_fingerprint(["a.py"], [*base, "two"], env=None)
    assert first == second
    third = build_state_fingerprint(
        ["a.py"],
        ["--p11-module", "/tmp/m.so", "--p11-so-pin", "x", "--p11-wrap-key-value", "y"],
        env=None,
    )
    fourth = build_state_fingerprint(
        ["a.py"],
        ["--p11-module", "/tmp/m.so", "--p11-so-pin", "z", "--p11-wrap-key-value", "w"],
        env=None,
    )
    assert third == fourth


# ---------------------------------------------------------------------------
# M-12: the policy snapshot allowlist derives from the central secret policy
# ---------------------------------------------------------------------------


def test_snapshot_value_flags_cover_every_secret_flag() -> None:
    """Consistency pin: no secret flag can drift outside snapshot redaction."""
    from pkcs11_check.core._run_state import _SNAPSHOT_VALUE_FLAGS

    assert SECRET_ARGV_FLAGS <= _SNAPSHOT_VALUE_FLAGS


def test_backend_args_snapshot_redacts_every_secret_flag() -> None:
    """Every policy-listed secret flag snapshots redacted, in both arg forms."""
    from pkcs11_check.core._run_state import _backend_args_snapshot

    for flag in sorted(SECRET_ARGV_FLAGS):
        assert _backend_args_snapshot([flag, "s3cret"]) == [flag, "<redacted>"]
        assert _backend_args_snapshot([f"{flag}=s3cret"]) == [f"{flag}=<redacted>"]


def test_backend_args_snapshot_keeps_plaintext_flags() -> None:
    """Non-secret snapshot behavior is unchanged (module/slot/manifest/destructive)."""
    from pkcs11_check.core._run_state import _backend_args_snapshot

    assert _backend_args_snapshot(
        [
            "--p11-module",
            "/tmp/m.so",
            "--p11-slot",
            "3",
            "--p11-manifest",
            "/tmp/m.json",
            "--p11-destructive",
            "--timeout",
            "60",
        ]
    ) == [
        "--p11-module",
        "/tmp/m.so",
        "--p11-slot",
        "3",
        "--p11-manifest",
        "<manifest>",
        "--p11-destructive",
    ]


def test_policy_fingerprint_stable_across_secret_rotation() -> None:
    """Secret values must not invalidate policy fingerprints either."""
    from pkcs11_check.core._run_state import build_policy_fingerprint

    base = ["--p11-module", "/tmp/does-not-exist.so"]
    first = build_policy_fingerprint([*base, "--p11-pin", "one"], env={})
    second = build_policy_fingerprint([*base, "--p11-pin", "two"], env={})
    assert first == second
    third = build_policy_fingerprint(
        [*base, "--p11-so-pin", "x", "--p11-wrap-key-value", "y"], env={}
    )
    fourth = build_policy_fingerprint(
        [*base, "--p11-so-pin", "z", "--p11-wrap-key-value", "w"], env={}
    )
    assert third == fourth
