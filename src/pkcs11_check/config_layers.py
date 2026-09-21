"""Per-key configuration layer truth for the ``test`` command (H-10).

``docs/configuration.md`` used to promise CLI > env > TOML > defaults for
every key, but for most keys the lower layers can never take effect: ``test``
always emits ``--slot``/``--interface`` (so env/TOML never apply), ``--module``
is required (so TOML ``module`` is dead), several keys have no readers at all.
The v0.2.1 fix is docs-true, not code-true: this table is the single source of
truth for which layers actually apply per key, and it drives both the
"setting ignored" warnings and ``test --show-config``. The docs table mirrors
it; full CLI-default-aware merging is deferred to v0.3+.

Scope note: this describes the ``test`` command. The direct-pytest path (no
``test`` wrapper) falls through to env/TOML for ``slot``/``interface`` when the
matching ``--p11-*`` options are omitted, because the fixtures only forward
explicit values.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TOML_FILENAME = "pkcs11_check.toml"


@dataclass(frozen=True)
class ConfigKeyTruth:
    """Which layers actually apply for one setting under ``test``."""

    key: str
    cli_flag: str | None
    live: tuple[str, ...] = ()
    cli_default: Any = None
    dead_note: str = ""
    default_display: str | None = None
    secret: bool = False

    @property
    def env_var(self) -> str:
        return "P11TEST_" + self.key.upper()


TEST_LAYER_TRUTH: tuple[ConfigKeyTruth, ...] = (
    ConfigKeyTruth("module", "--module", ("cli",), None, "only --module applies (required flag)"),
    ConfigKeyTruth("slot", "--slot", ("cli",), 0, "only --slot applies"),
    ConfigKeyTruth("pin", "--pin", ("cli", "env", "toml"), None, secret=True),
    ConfigKeyTruth("so_pin", "--so-pin", ("cli", "env", "toml"), None, secret=True),
    ConfigKeyTruth("interface", "--interface", ("cli",), "auto", "only --interface applies"),
    ConfigKeyTruth(
        "timeout_operation",
        None,
        (),
        None,
        "there is no reader (per-operation timeouts are unimplemented)",
    ),
    ConfigKeyTruth("timeout_test", None, (), None, "there is no reader (live knob: --timeout)"),
    ConfigKeyTruth("destructive", "--destructive", ("cli", "env", "toml"), False),
    ConfigKeyTruth("max_sessions", None, (), None, "there is no reader"),
    ConfigKeyTruth("skip_unsupported", None, (), None, "it is locked on and cannot be disabled"),
    ConfigKeyTruth(
        "log_level", "--log-level", ("cli",), "INFO", "only the global --log-level applies"
    ),
    ConfigKeyTruth("output", "--output", ("cli",), "rich", "only --output applies"),
    ConfigKeyTruth(
        "disabled_tests_file",
        None,
        ("env", "toml"),
        None,
        "",
        default_display="auto-discover",
    ),
    ConfigKeyTruth("rv_trace", "--rv-trace", ("cli", "env", "toml"), False),
    ConfigKeyTruth("rv_trace_compact", "--rv-trace-compact", ("cli", "env", "toml"), None),
    ConfigKeyTruth("key_inject", "--key-inject", ("cli", "env", "toml"), "off"),
    ConfigKeyTruth("wrap_key_source", "--wrap-key-source", ("cli", "env", "toml"), "bootstrap"),
    ConfigKeyTruth("wrap_key_label", "--wrap-key-label", ("cli", "env", "toml"), None),
    ConfigKeyTruth("wrap_key_handle", "--wrap-key-handle", ("cli", "env", "toml"), None),
    ConfigKeyTruth("wrap_key_value", "--wrap-key-value", ("cli", "env", "toml"), None, secret=True),
    ConfigKeyTruth("wrap_mech", "--wrap-mech", ("cli", "env", "toml"), None),
    ConfigKeyTruth("wrap_rsa_bits", "--wrap-rsa-bits", ("cli", "env", "toml"), 2048),
    ConfigKeyTruth("wrap_oaep_hash", "--wrap-oaep-hash", ("cli", "env", "toml"), "auto"),
    ConfigKeyTruth(
        "allow_external_provision", "--allow-external-provision", ("cli", "env", "toml"), False
    ),
    ConfigKeyTruth(
        "external_provision_cmd", "--external-provision-cmd", ("cli", "env", "toml"), None
    ),
)


@dataclass(frozen=True)
class ConfigRow:
    """One ``--show-config`` row: effective value + winning source."""

    key: str
    effective: str
    source: str


def read_toml_settings(path: Path | None = None) -> dict[str, Any]:
    """Best-effort read of top-level TOML settings (``{}`` when absent/broken).

    A broken file is not reported here: ``P11TestConfig`` construction surfaces
    the real error on the run path; warnings/show-config just skip TOML input.
    """
    target = path if path is not None else Path(TOML_FILENAME)
    try:
        with open(target, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return dict(data) if isinstance(data, dict) else {}


def find_ignored_settings(
    *,
    env: Mapping[str, str],
    toml: Mapping[str, Any],
    toml_name: str = TOML_FILENAME,
) -> list[str]:
    """Warning bodies for provided-but-dead settings, in table order.

    Only env/TOML layers can be "provided but dead": the CLI layer always wins
    where it is live, and dead keys have no live layer at all.
    """
    warnings: list[str] = []
    for truth in TEST_LAYER_TRUTH:
        if "env" not in truth.live and truth.env_var in env:
            warnings.append(
                f"{truth.env_var} is set, but {truth.dead_note}; the env value is ignored."
            )
        if "toml" not in truth.live and truth.key in toml:
            warnings.append(
                f"`{toml_name}` sets `{truth.key}`, but {truth.dead_note}; "
                "the TOML value is ignored."
            )
    return warnings


def _display(value: Any) -> str:
    if value is None:
        return "(unset)"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _resolve_row(
    truth: ConfigKeyTruth,
    cli_values: Mapping[str, Any],
    env: Mapping[str, str],
    toml: Mapping[str, Any],
) -> ConfigRow:
    if not truth.live:
        if truth.env_var in env:
            return ConfigRow(truth.key, "(no effect)", f"env (ignored: {truth.dead_note})")
        if truth.key in toml:
            return ConfigRow(truth.key, "(no effect)", f"toml (ignored: {truth.dead_note})")
        return ConfigRow(truth.key, "(no effect)", f"default (ignored: {truth.dead_note})")
    cli_value = cli_values.get(truth.key, truth.cli_default)
    if (
        "cli" in truth.live
        and truth.cli_flag is not None
        and truth.key in cli_values
        and cli_value != truth.cli_default
    ):
        effective = "set" if truth.secret else _display(cli_value)
        return ConfigRow(truth.key, effective, "cli")
    if "env" in truth.live and truth.env_var in env:
        effective = "set" if truth.secret else env[truth.env_var]
        return ConfigRow(truth.key, effective, "env")
    if "toml" in truth.live and truth.key in toml:
        effective = "set" if truth.secret else _display(toml[truth.key])
        return ConfigRow(truth.key, effective, "toml")
    if truth.secret:
        return ConfigRow(truth.key, "unset", "default")
    if truth.live == ("cli",):
        return ConfigRow(truth.key, _display(cli_value), "cli (default)")
    if truth.default_display is not None:
        return ConfigRow(truth.key, truth.default_display, "default")
    return ConfigRow(truth.key, _display(truth.cli_default), "default")


def resolve_config_rows(
    *,
    cli_values: Mapping[str, Any],
    env: Mapping[str, str],
    toml: Mapping[str, Any],
) -> list[ConfigRow]:
    """Resolve effective value + source per key, in table order.

    ``cli_values`` maps setting names to the ``test`` command's parsed values
    (only keys with a CLI flag; ``log_level`` is the global flag's effective
    value, read back from the root logger by the caller).
    """
    return [_resolve_row(truth, cli_values, env, toml) for truth in TEST_LAYER_TRUTH]
