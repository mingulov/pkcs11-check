"""The CLI test runner must neutralise ANSI, or CLI assertions become environment-dependent.

Without this, ten CLI tests passed or failed according to whether the developer's terminal
exported FORCE_COLOR, because Rich styles digit runs inside otherwise-plain messages
("PKCS#11" renders as "PKCS#\x1b[1;36m11\x1b[0m").
"""

from __future__ import annotations

import typer
from typer.testing import CliRunner

from tests._plain_cli_runner import PlainCliRunner, strip_ansi

# A styled line standing in for Rich's output. Driving a controlled app rather than the real
# CLI keeps this test deterministic: the real consoles are module-level, so whether they emit
# escapes depends on the environment at import time -- the very coupling under test here.
STYLED = "PKCS#\x1b[1;36m11\x1b[0m preflight error"
PLAIN = "PKCS#11 preflight error"


def _styled_app() -> typer.Typer:
    app = typer.Typer()

    @app.command()
    def main() -> None:
        typer.echo(STYLED)

    return app


def test_strip_ansi_removes_csi_sequences() -> None:
    assert strip_ansi(STYLED) == PLAIN


def test_strip_ansi_leaves_unstyled_text_untouched() -> None:
    assert strip_ansi(PLAIN) == PLAIN


def test_stock_runner_leaks_escapes_into_output() -> None:
    """Pins the behaviour PlainCliRunner exists to correct.

    If this ever stops holding, the stripping below would be vacuous and the guard on the
    real CLI tests would be silently gone.
    """
    result = CliRunner().invoke(_styled_app(), [], color=True)

    assert "\x1b[" in result.output
    assert PLAIN not in result.output


def test_plain_runner_strips_escapes_from_output() -> None:
    result = PlainCliRunner().invoke(_styled_app(), [], color=True)

    assert "\x1b[" not in result.output
    assert PLAIN in result.output
