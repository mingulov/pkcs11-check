"""Logging setup for pkcs11-check."""

from __future__ import annotations

import logging

from rich.logging import RichHandler


def setup_logging(level: str = "INFO", trace: bool = False) -> None:
    """Configure logging with rich handler.

    If trace=True, sets level to DEBUG and enables PKCS#11 call tracing.
    """
    effective_level = "DEBUG" if trace else level.upper()
    logging.basicConfig(
        level=effective_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
        force=True,
    )
    logging.getLogger("asyncio").setLevel(logging.WARNING)
