"""Test-only probe for verifying unbuffered launcher output durability."""

from __future__ import annotations

import os
import sys

from pkcs11_check.testcases._probes.params import ProbeParams


def main() -> None:
    """Load dispatch parameters, print a marker, and exit without flushing."""
    ProbeParams.load(sys.argv[1])
    print("ABRUPT_MARKER")
    os._exit(17)


if __name__ == "__main__":
    main()
