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
    # Only a LITERAL integer width is a violation: to_bytes(8, "little") is wrong on Win64, but
    # to_bytes(ctypes.sizeof(ctypes.c_ulong), "little") derives width from the ABI and is fine.
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "to_bytes"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, int)
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "little"
    )


_SCOPE_BOUNDARY = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _local_nodes(scope: ast.AST) -> list[ast.AST]:
    """Nodes in ``scope``'s body, NOT descending into nested function/class/lambda scopes."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        out.append(node)
        if isinstance(node, _SCOPE_BOUNDARY):
            continue  # visible as a node, but its body is a separate scope
        stack.extend(ast.iter_child_nodes(node))
    return out


def _scopes(tree: ast.Module) -> list[ast.AST]:
    return [
        tree,
        *(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
    ]


def _violations_in_source(source: str, label: str) -> list[str]:
    source_lines = source.splitlines()
    tree = ast.parse("\n".join(source_lines), filename=label)

    def audited(lineno: int) -> bool:
        idx = lineno - 1
        return 0 <= idx < len(source_lines) and "# audit-ok:" in source_lines[idx]

    hits: set[tuple[str, int]] = set()
    for scope in _scopes(tree):
        nodes = _local_nodes(scope)
        # Names bound to a literal-width little-endian to_bytes() in this scope (the two-step
        # `x = v.to_bytes(8, "little"); mech_bytes(m, x)` that escapes a direct-arg-only check).
        little_vars: dict[str, int] = {}
        for node in nodes:
            if isinstance(node, ast.Assign) and _is_to_bytes_little(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        little_vars[target.id] = node.value.lineno
        for node in nodes:
            if not (isinstance(node, ast.Call) and _is_named_call(node.func, "mech_bytes")):
                continue
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                if _is_to_bytes_little(arg) and not audited(arg.lineno):
                    hits.add((label, arg.lineno))  # inline
                elif isinstance(arg, ast.Name) and arg.id in little_vars:
                    line = little_vars[arg.id]
                    if not audited(line):
                        hits.add((label, line))  # two-step via a local variable
    return [f"{label}:{lineno}" for label, lineno in sorted(hits)]


def _violations(path: Path) -> list[str]:
    label = str(path.relative_to(_TESTCASES.parent.parent.parent))
    return _violations_in_source(path.read_text(encoding="utf-8"), label)


def test_inline_and_two_step_literal_widths_flagged_abi_general_and_cross_scope_not() -> None:
    inline = 'mech_bytes(m, v.to_bytes(8, "little"))'
    two_step = 'p = v.to_bytes(8, "little")\nmech_bytes(m, p)'
    audit = 'mech_bytes(m, v.to_bytes(8, "little"))  # audit-ok: fixed-width block counter'
    clean = "mech_bytes(m, mech_ulong(v))"
    abi_general = 'n = v.to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")\nmech_bytes(m, n)'
    cross = 'def a():\n    p = v.to_bytes(8, "little")\ndef b():\n    mech_bytes(m, p)'
    assert _violations_in_source(inline, "x") == ["x:1"]
    assert _violations_in_source(two_step, "x") == ["x:1"]
    assert _violations_in_source(audit, "x") == []
    assert _violations_in_source(clean, "x") == []
    # width from sizeof(c_ulong) is ABI-general, not a literal width -> not flagged.
    assert _violations_in_source(abi_general, "x") == []
    # `p` in b() is a different scope's name, not the little-width one from a() -> not flagged.
    assert _violations_in_source(cross, "x") == []


def test_no_literal_width_ulong_mech_params() -> None:
    offenders: list[str] = []
    for path in _TESTCASES.rglob("*.py"):
        offenders.extend(_violations(path))
    assert not offenders, (
        "CK_ULONG mechanism params serialized at a literal width; use raw.pack.mech_ulong / "
        "ck_ulong_bytes instead:\n  " + "\n  ".join(sorted(offenders))
    )
