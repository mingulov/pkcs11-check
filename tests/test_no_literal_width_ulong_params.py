"""Guard: no CK_ULONG mechanism parameter may be hand-serialized at a literal width.

``value.to_bytes(8, "little")`` is 8 bytes on LP64 but must be 4 on Win64 LLP64, where
``CK_ULONG`` is 32-bit; a literal width silently sends a malformed parameter on the packed
Windows/Wine ABI (and would false-accuse a compliant provider). Scalar CK_ULONG parameters
must be built with ``raw.pack.mech_ulong`` / ``ck_ulong_bytes``, which take the width and byte
order from the ctypes type. This guard flags any ``*.to_bytes(..., "little")`` passed directly
into a ``mech_bytes(...)`` call (the crypto ``to_bytes(..., "big")`` integer encodings are a
different concern and are untouched). Annotate a genuine exception with ``# audit-ok:``.
"""

from __future__ import annotations

import ast
from pathlib import Path

_TESTCASES = Path(__file__).resolve().parent.parent / "src" / "pkcs11_check" / "testcases"


def _is_named_call(func: ast.expr, name: str) -> bool:
    return (isinstance(func, ast.Name) and func.id == name) or (
        isinstance(func, ast.Attribute) and func.attr == name
    )


def _is_to_bytes_little(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "to_bytes"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "little"
    )


def _violations(path: Path) -> list[str]:
    source_lines = path.read_text().splitlines()
    tree = ast.parse("\n".join(source_lines), filename=str(path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_named_call(node.func, "mech_bytes")):
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in args:
            if not _is_to_bytes_little(arg):
                continue
            line_idx = arg.lineno - 1
            if 0 <= line_idx < len(source_lines) and "# audit-ok:" in source_lines[line_idx]:
                continue
            hits.append(f"{path.relative_to(_TESTCASES.parent.parent.parent)}:{arg.lineno}")
    return hits


def test_no_literal_width_ulong_mech_params() -> None:
    offenders: list[str] = []
    for path in _TESTCASES.rglob("*.py"):
        offenders.extend(_violations(path))
    assert not offenders, (
        "CK_ULONG mechanism params serialized at a literal width; use raw.pack.mech_ulong / "
        "ck_ulong_bytes instead:\n  " + "\n  ".join(sorted(offenders))
    )
