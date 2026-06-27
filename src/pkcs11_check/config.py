"""pkcs11-check configuration - four-layer merge: CLI > env > TOML > defaults."""

from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)


class P11TestConfig(BaseSettings):
    """Configuration for pkcs11-check.

    Precedence: CLI flags > environment variables > TOML file > defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="P11TEST_",
        toml_file="pkcs11_check.toml",
    )

    module: Path
    slot: int = 0
    pin: SecretStr | None = None
    interface: str = "auto"
    timeout_operation: int = 30
    # Per-test timeout (pytest-timeout, signal method). Sized as a freeze/runaway
    # safety net, not a cap on legitimately-slow work: the slowest real tests are
    # the ACVP AES MCT cases (~100k chained ops, ~110s on transport-bound modules),
    # so 180s lets them always complete with margin while still
    # catching genuine hangs.
    timeout_test: int = 180
    destructive: bool = False
    max_sessions: int = 1
    skip_unsupported: bool = True
    log_level: str = "INFO"
    output: str = "rich"
    disabled_tests_file: Path | None = None
    # Per-test CK_RV trace (off by default). rv_trace_compact = ring-buffer
    # window size N (last-N entries); None = full capture. See docs/rv-trace-design.md.
    rv_trace: bool = False
    rv_trace_compact: int | None = None

    # Key-provisioning injection (see docs/.../key-provisioning-injection-design.md).
    # off: create->skip. unwrap: create->unwrap->skip. force-unwrap: unwrap->skip (no create).
    key_inject: str = "off"
    wrap_key_source: str = "bootstrap"  # bootstrap | configured
    wrap_key_label: str | None = None
    wrap_key_handle: int | None = None
    wrap_key_value: str | None = None  # hex; only for a symmetric configured KEK
    # override auto-selected unwrap mechanism (e.g. "CKM_RSA_AES_KEY_WRAP")
    wrap_mech: str | None = None
    wrap_rsa_bits: int = 2048
    wrap_oaep_hash: str = "auto"  # OAEP hash for wrapping: "auto" (probe), "sha1", or "sha256"

    # External-tool provisioning tier (Phase 6).
    # allow_external_provision: strict opt-in acknowledgement flag.
    # external_provision_cmd: operator command template; placeholders: {keyfile} {label}
    #   {key_type} {key_class}.
    allow_external_provision: bool = False
    external_provision_cmd: str | None = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(settings_cls),
        )
