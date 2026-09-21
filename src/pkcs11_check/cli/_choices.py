"""Shared constrained CLI option types.

Annotating a ``typer.Option`` with one of these aliases makes typer validate
the value as a Choice at parse time: a typo is a usage error (exit 2 with
"Invalid value") instead of a downstream failure. ``Literal`` (rather than
``Enum``) keeps the received value a plain ``str``, so no call site changes.
"""

from __future__ import annotations

from typing import Literal

# Must stay in sync with SUPPORTED_INTERFACES in core/loader.py; guarded by
# tests/test_cli_choices.py::TestInterfaceChoiceDrift.
InterfaceChoice = Literal["auto", "2.40", "3.0", "3.1", "3.2"]

LogLevelChoice = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
