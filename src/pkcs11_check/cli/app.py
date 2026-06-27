"""pkcs11-check CLI application."""

from __future__ import annotations

import typer

from pkcs11_check.cli.compare_cmd import compare_coverage_command, compare_results_command
from pkcs11_check.cli.compliance_cmd import compliance_report_command
from pkcs11_check.cli.crash_calls_cmd import crash_calls_command
from pkcs11_check.cli.doctor_cmd import doctor_command
from pkcs11_check.cli.fetch_cmd import fetch_data_command, fetch_disabled_command
from pkcs11_check.cli.info_cmd import info_command
from pkcs11_check.cli.list_cmd import list_command
from pkcs11_check.cli.shard_cmd import merge_shards_command, shard_units_command
from pkcs11_check.cli.state_cmd import state_command
from pkcs11_check.cli.test_cmd import test_command

app = typer.Typer(
    name="pkcs11-check",
    help="CLI-first PKCS#11 test suite with segfault survival and interface forcing.",
    no_args_is_help=True,
    invoke_without_command=True,
)


@app.callback()
def callback(
    log_level: str = typer.Option("INFO", "--log-level", help="Log level"),
    trace: bool = typer.Option(False, "--trace", help="Trace PKCS#11 calls"),
) -> None:
    """CLI-first PKCS#11 test suite."""
    from pkcs11_check.core.logging import setup_logging

    setup_logging(level=log_level, trace=trace)


app.command("test")(test_command)
app.command("doctor")(doctor_command)
app.command("info")(info_command)
app.command("list")(list_command)
app.command("state")(state_command)
app.command("compliance-report")(compliance_report_command)
app.command("compare-coverage")(compare_coverage_command)
app.command("compare-results")(compare_results_command)
app.command("fetch-data")(fetch_data_command)
app.command("fetch-disabled")(fetch_disabled_command)
app.command("shard-units")(shard_units_command)
app.command("merge-shards")(merge_shards_command)
app.command("crash-calls")(crash_calls_command)


@app.command()
def version() -> None:
    """Show pkcs11-check version."""
    from pkcs11_check import __version__

    typer.echo(f"pkcs11-check {__version__}")


def main() -> None:
    app()
