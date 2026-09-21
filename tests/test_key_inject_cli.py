"""H-12: `test --key-inject` typo must fail fast with a clean CLI error.

A bare str flowed from the CLI into provisioning, where any value that is
neither "off" nor "force-unwrap" silently enables injection -- so `--key-inject
of` (or `unwarp`) injected keys instead of erroring. The CLI validates before
anything else runs (ahead of even the module-exists check).
"""

from __future__ import annotations

from pkcs11_check.cli.app import app
from tests._plain_cli_runner import PlainCliRunner

runner = PlainCliRunner()


def test_key_inject_typo_is_usage_error() -> None:
    result = runner.invoke(app, ["test", "--module", "/nonexistent.so", "--key-inject", "of"])
    assert result.exit_code == 2, result.output
    assert "--key-inject" in result.output
    assert "of" in result.output


def test_key_inject_validation_runs_before_module_check() -> None:
    """Early validation: a bad flag beats a missing module (exit 2, not 3)."""
    result = runner.invoke(app, ["test", "--module", "/nonexistent.so", "--key-inject", "unwarp"])
    assert result.exit_code == 2, result.output
    assert "Module not found" not in result.output


def test_key_inject_valid_modes_pass_validation(tmp_path=None) -> None:
    """Valid modes sail past validation to the module check (exit 3 here)."""
    for mode in ("off", "unwrap", "force-unwrap"):
        result = runner.invoke(app, ["test", "--module", "/nonexistent.so", "--key-inject", mode])
        assert result.exit_code == 3, (mode, result.output)
        assert "Module not found" in result.output
