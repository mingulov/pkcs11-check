#!/usr/bin/env python3
"""Check for missing exports in pkcs11_check.raw __init__.py

Scans all Python files in the codebase for imports from pkcs11_check.raw
and verifies they are present in __all__. Reports any missing exports.

Usage:
    python scripts/check_raw_exports.py
    exit code 1 if missing exports found
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def extract_imports_from_file(file_path: Path) -> set[str]:
    """Extract all symbols imported from pkcs11_check.raw in a file."""
    imports = set()
    try:
        content = file_path.read_text()
    except Exception:
        return imports

    # Match both single-line and multi-line imports
    patterns = [
        r"^from pkcs11_check\.raw import \((.*?)\)",  # Multi-line
        r"^from pkcs11_check\.raw import ([^\n]+)",  # Single line
    ]

    for pattern in patterns:
        matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
        for match in matches:
            # Extract identifiers (ALL_CAPS names and CamelCase)
            names = re.findall(r"\b([A-Z][A-Z0-9_]+)\b", match)
            imports.update(names)

    return imports


def get_all_imports(source_dir: Path) -> set[str]:
    """Get all imports from pkcs11_check.raw across the codebase."""
    all_imports = set()

    for py_file in source_dir.rglob("*.py"):
        imports = extract_imports_from_file(py_file)
        all_imports.update(imports)

    return all_imports


def get_exported_symbols(init_file: Path) -> set[str]:
    """Get all symbols exported in __all__ from __init__.py."""
    try:
        content = init_file.read_text()
    except Exception as e:
        print(f"Error reading {init_file}: {e}", file=sys.stderr)
        return set()

    match = re.search(r"__all__ = \[(.*?)\]", content, re.DOTALL)
    if not match:
        return set()

    # Extract both single and double quoted strings
    exported = set()
    for quote in ['"', "'"]:
        exported.update(re.findall(rf"{quote}([A-Z_][A-Z0-9_]*){quote}", match.group(1)))

    return exported


def main() -> int:
    """Check for missing exports."""
    script_dir = Path(__file__).parent.parent
    source_dir = script_dir / "src"
    init_file = script_dir / "src" / "pkcs11_check" / "raw" / "__init__.py"

    if not init_file.exists():
        print(f"Error: {init_file} not found", file=sys.stderr)
        return 1

    imports = get_all_imports(source_dir)
    exported = get_exported_symbols(init_file)

    # Filter out known non-pkcs11_check.raw imports
    known_non_raw = {
        "PKCS11",  # From PKCS11 constant definitions
        "R",  # Type annotation
        "TYPE_CHECKING",  # Type checking
    }
    imports = {name for name in imports if name not in known_non_raw}

    missing = sorted(imports - exported)

    if missing:
        print("Missing exports in pkcs11_check.raw/__init__.py:", file=sys.stderr)
        for name in missing:
            print(f"  {name}")
        print(file=sys.stderr)
        print("Add these to both the import statement and __all__ list", file=sys.stderr)
        return 1

    print("✓ All pkcs11_check.raw imports are properly exported")
    return 0


if __name__ == "__main__":
    sys.exit(main())
