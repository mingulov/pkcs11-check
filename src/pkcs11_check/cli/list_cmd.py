"""pkcs11-check list command — list available tests."""

from __future__ import annotations

import typer
from rich.console import Console

console = Console()

TEST_CATEGORIES = {
    "interface": "Library & Interface Management",
    "slot": "Slot / Token / Session",
    "object": "Object / Key / Attribute",
    "mechanism": "Mechanism Discovery",
    "encrypt": "Encrypt / Decrypt",
    "sign": "Sign / Verify",
    "digest": "Digest / MAC / Wrap / Unwrap",
    "pqc": "PQC (ML-KEM, ML-DSA, SLH-DSA)",
    "profiles": "Profiles & Validation",
    "async": "Async Operations",
    "concurrency": "Concurrency Stress",
    "errors": "Error Handling & Edge Cases",
}


def list_command(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
) -> None:
    """List available PKCS#11 test categories."""
    for key, desc in TEST_CATEGORIES.items():
        if category and key != category:
            continue
        console.print(f"  [bold]{key}[/bold] -- {desc}")
