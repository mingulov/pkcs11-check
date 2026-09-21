"""H-10 (docs-true): per-key config layer truth for the `test` command.

docs/configuration.md promised CLI > env > TOML > defaults for every key, but
for most keys the lower layers can never take effect (SE-01). The v0.2.1 fix
is docs-true, not code-true: a single layer-truth table drives "setting
ignored" warnings plus `test --show-config` (effective value + source per key).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.config_layers import (
    TEST_LAYER_TRUTH,
    find_ignored_settings,
    resolve_config_rows,
)


def _cli_defaults() -> dict[str, object]:
    """CLI values exactly as `test` parses them when no flag is passed."""
    return {
        "module": "/x.so",
        "slot": 0,
        "interface": "auto",
        "pin": None,
        "so_pin": None,
        "destructive": False,
        "log_level": "INFO",
        "output": "rich",
        "rv_trace": False,
        "rv_trace_compact": None,
        "key_inject": "off",
        "wrap_key_source": "bootstrap",
        "wrap_key_label": None,
        "wrap_key_handle": None,
        "wrap_key_value": None,
        "wrap_mech": None,
        "wrap_rsa_bits": 2048,
        "wrap_oaep_hash": "auto",
        "allow_external_provision": False,
        "external_provision_cmd": None,
    }


def _row(rows: list, key: str) -> tuple[str, str]:
    for row in rows:
        if row.key == key:
            return row.effective, row.source
    raise AssertionError(f"no show-config row for {key!r}")


class TestLayerTruthTable:
    def test_covers_every_config_field(self) -> None:
        """The truth table must track P11TestConfig: a new field without a row fails."""
        from pkcs11_check.config import P11TestConfig

        assert {t.key for t in TEST_LAYER_TRUTH} == set(P11TestConfig.model_fields)

    def test_cli_only_keys(self) -> None:
        """slot/interface/module/output/log_level: CLI always wins, env/TOML dead."""
        by_key = {t.key: t for t in TEST_LAYER_TRUTH}
        for key in ("module", "slot", "interface", "log_level", "output"):
            assert by_key[key].live == ("cli",), key

    def test_dead_keys(self) -> None:
        """Keys with no reader (or locked on) have no live layer."""
        by_key = {t.key: t for t in TEST_LAYER_TRUTH}
        for key in ("timeout_operation", "timeout_test", "max_sessions", "skip_unsupported"):
            assert by_key[key].live == (), key

    def test_fall_through_keys(self) -> None:
        """Omission-shaped flags fall through to env/TOML in children."""
        by_key = {t.key: t for t in TEST_LAYER_TRUTH}
        for key in ("destructive", "key_inject", "wrap_mech", "pin", "rv_trace"):
            assert by_key[key].live == ("cli", "env", "toml"), key
        assert by_key["disabled_tests_file"].live == ("env", "toml")


class TestFindIgnoredSettings:
    def test_empty_world_is_quiet(self) -> None:
        assert find_ignored_settings(env={}, toml={}) == []

    def test_dead_env_slot_warns(self) -> None:
        warnings = find_ignored_settings(env={"P11TEST_SLOT": "9"}, toml={})
        assert len(warnings) == 1
        assert "P11TEST_SLOT" in warnings[0]
        assert "--slot" in warnings[0]

    def test_dead_toml_interface_warns(self) -> None:
        warnings = find_ignored_settings(env={}, toml={"interface": "3.2"})
        assert len(warnings) == 1
        assert "interface" in warnings[0]
        assert "--interface" in warnings[0]

    def test_dead_timeout_points_at_live_knob(self) -> None:
        warnings = find_ignored_settings(env={"P11TEST_TIMEOUT_TEST": "5"}, toml={})
        assert len(warnings) == 1
        assert "--timeout" in warnings[0]

    def test_live_layers_never_warn(self) -> None:
        warnings = find_ignored_settings(
            env={"P11TEST_KEY_INJECT": "unwrap", "P11TEST_PIN": "x"},
            toml={"destructive": True, "disabled_tests_file": "d.txt"},
        )
        assert warnings == []

    def test_secrets_warn_without_values(self) -> None:
        """Warning text names the setting, never the secret value."""
        warnings = find_ignored_settings(env={"P11TEST_MODULE": "/x.so"}, toml={})
        assert len(warnings) == 1
        assert "/x.so" not in warnings[0]


class TestResolveConfigRows:
    def test_defaults(self) -> None:
        rows = resolve_config_rows(cli_values=_cli_defaults(), env={}, toml={})
        assert _row(rows, "slot") == ("0", "cli (default)")
        assert _row(rows, "key_inject") == ("off", "default")
        assert _row(rows, "pin") == ("unset", "default")
        effective, source = _row(rows, "timeout_test")
        assert effective == "(no effect)"
        assert "--timeout" in source

    def test_cli_beats_env_beats_toml(self) -> None:
        env = {"P11TEST_KEY_INJECT": "unwrap"}
        toml = {"key_inject": "force-unwrap"}
        rows = resolve_config_rows(cli_values=_cli_defaults(), env=env, toml=toml)
        assert _row(rows, "key_inject") == ("unwrap", "env")

        rows = resolve_config_rows(cli_values=_cli_defaults(), env={}, toml=toml)
        assert _row(rows, "key_inject") == ("force-unwrap", "toml")

        cli = {**_cli_defaults(), "key_inject": "unwrap"}
        rows = resolve_config_rows(cli_values=cli, env=env, toml=toml)
        assert _row(rows, "key_inject") == ("unwrap", "cli")

    def test_cli_only_key_ignores_env_and_toml(self) -> None:
        rows = resolve_config_rows(
            cli_values=_cli_defaults(),
            env={"P11TEST_SLOT": "9"},
            toml={"slot": 7},
        )
        assert _row(rows, "slot") == ("0", "cli (default)")

        cli = {**_cli_defaults(), "slot": 2}
        rows = resolve_config_rows(cli_values=cli, env={}, toml={})
        assert _row(rows, "slot") == ("2", "cli")

    def test_secrets_never_render_values(self) -> None:
        cli = {**_cli_defaults(), "pin": "1234"}
        rows = resolve_config_rows(
            cli_values=cli, env={"P11TEST_SO_PIN": "so-1"}, toml={"wrap_key_value": "ab" * 16}
        )
        assert _row(rows, "pin") == ("set", "cli")
        assert _row(rows, "so_pin") == ("set", "env")
        assert _row(rows, "wrap_key_value") == ("set", "toml")
        blob = "\n".join(f"{r.key} {r.effective} {r.source}" for r in rows)
        assert "1234" not in blob and "so-1" not in blob

    def test_dead_key_shows_provider_layer(self) -> None:
        rows = resolve_config_rows(
            cli_values=_cli_defaults(), env={"P11TEST_TIMEOUT_TEST": "5"}, toml={}
        )
        effective, source = _row(rows, "timeout_test")
        assert effective == "(no effect)"
        assert source.startswith("env")


class TestShowConfigCommand:
    def test_show_config_exits_before_everything(self) -> None:
        """--show-config needs no module, no preflight, no validation."""
        from pkcs11_check.cli.app import app
        from tests._plain_cli_runner import PlainCliRunner

        result = PlainCliRunner().invoke(
            app, ["test", "--module", "/nonexistent.so", "--show-config"]
        )
        assert result.exit_code == 0, result.output
        assert "slot" in result.output
        assert "key_inject" in result.output
        assert "timeout_test" in result.output

    def test_show_config_reflects_cli_env_toml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.cli.app import app
        from tests._plain_cli_runner import PlainCliRunner

        monkeypatch.chdir(tmp_path)
        (tmp_path / "pkcs11_check.toml").write_text(
            'key_inject = "force-unwrap"\n', encoding="utf-8"
        )
        monkeypatch.setenv("P11TEST_WRAP_MECH", "CKM_RSA_AES_KEY_WRAP")
        for var in ("P11TEST_SLOT", "P11TEST_KEY_INJECT"):
            monkeypatch.delenv(var, raising=False)

        result = PlainCliRunner().invoke(
            app, ["test", "--module", str(tmp_path / "x.so"), "--show-config", "--slot", "2"]
        )
        assert result.exit_code == 0, result.output
        assert "force-unwrap" in result.output
        assert "CKM_RSA_AES_KEY_WRAP" in result.output

    def test_show_config_redacts_secrets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pkcs11_check.cli.app import app
        from tests._plain_cli_runner import PlainCliRunner

        monkeypatch.delenv("P11TEST_PIN", raising=False)
        result = PlainCliRunner().invoke(
            app,
            ["test", "--module", "/nonexistent.so", "--show-config", "--pin", "s3cr3t-pin"],
        )
        assert result.exit_code == 0, result.output
        assert "s3cr3t-pin" not in result.output


class TestIgnoredSettingWarnings:
    def test_dead_env_setting_warns_on_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A provided-but-dead setting warns instead of silently mis-scoping the run."""
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from pkcs11_check.core.preflight import CapabilityManifest
        from tests._plain_cli_runner import PlainCliRunner

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("P11TEST_SLOT", "9")
        module = tmp_path / "dummy.so"
        module.write_bytes(b"")

        def _dead_manifest(*args: object, **kwargs: object) -> CapabilityManifest:
            return CapabilityManifest(
                status="error",
                module_path=str(module),
                requested_interface="auto",
                interface_version=None,
                slot_index=0,
                slot_count=None,
                mechanisms=[],
                error="boom",
            )

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _dead_manifest)
        result = PlainCliRunner().invoke(app, ["test", "--module", str(module)])
        assert "P11TEST_SLOT" in result.output
        assert "--slot" in result.output

    def test_live_settings_stay_quiet(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.cli import test_cmd
        from pkcs11_check.cli.app import app
        from pkcs11_check.core.preflight import CapabilityManifest
        from tests._plain_cli_runner import PlainCliRunner

        monkeypatch.chdir(tmp_path)
        for var in (
            "P11TEST_MODULE",
            "P11TEST_SLOT",
            "P11TEST_INTERFACE",
            "P11TEST_TIMEOUT_OPERATION",
            "P11TEST_TIMEOUT_TEST",
            "P11TEST_MAX_SESSIONS",
            "P11TEST_SKIP_UNSUPPORTED",
            "P11TEST_LOG_LEVEL",
            "P11TEST_OUTPUT",
        ):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("P11TEST_KEY_INJECT", "unwrap")
        module = tmp_path / "dummy.so"
        module.write_bytes(b"")

        def _dead_manifest(*args: object, **kwargs: object) -> CapabilityManifest:
            return CapabilityManifest(
                status="error",
                module_path=str(module),
                requested_interface="auto",
                interface_version=None,
                slot_index=0,
                slot_count=None,
                mechanisms=[],
                error="boom",
            )

        monkeypatch.setattr(test_cmd, "run_preflight_subprocess", _dead_manifest)
        result = PlainCliRunner().invoke(app, ["test", "--module", str(module)])
        assert "P11TEST_KEY_INJECT" not in result.output
        assert "ignored" not in result.output.lower()
