"""pkcs11-check configuration -- four-layer merge: CLI > env > TOML > defaults."""

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
    timeout_test: int = 120
    destructive: bool = False
    max_sessions: int = 1
    skip_unsupported: bool = True
    log_level: str = "INFO"
    output: str = "rich"

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
