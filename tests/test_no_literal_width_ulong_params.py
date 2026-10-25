"""Guard: no CK_ULONG mechanism parameter may be hand-serialized at a literal width.

``value.to_bytes(8, "little")`` is 8 bytes on LP64 but must be 4 on Win64 LLP64, where
``CK_ULONG`` is 32-bit; a literal width silently sends a malformed parameter on the packed
Windows/Wine ABI (and would false-accuse a compliant provider). Scalar CK_ULONG parameters
must be built with ``raw.pack.mech_ulong`` / ``ck_ulong_bytes``, which take the width and byte
order from the ctypes type. This guard flags any ``*.to_bytes(..., "little")`` passed directly
into a ``mech_bytes(...)`` call (the crypto ``to_bytes(..., "big")`` integer encodings are a
different concern and are untouched). Annotate a genuine exception with ``# audit-ok:``.

S3 widening (platform-assumption design 2026-10-25, section 5.1): the scan
covers all of ``src/pkcs11_check/`` + ``tests/`` (not just ``testcases/``),
and three sinks join ``mech_bytes(...)`` for a literal width of exactly 4 or
8 in either byte order: assignment to a struct-field-shaped attribute,
construction of a ctypes array type ``(T * n)(...)`` from the bytes, and
storage into a name matching ``*(ulong|length|len|size)*``. The name
heuristic is deliberately narrow; wire-format counters (RFC 8439 and
friends) carry different names and stay untouched. Widths derived from
``sizeof(c_ulong)`` are ABI-general and never flagged.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_TREES = (_ROOT / "src" / "pkcs11_check", _ROOT / "tests")
_NAME_HINTS = ("ulong", "length", "len", "size")


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


def _is_to_bytes_width48(node: ast.expr) -> bool:
    """``to_bytes(4|8, "little"|"big")`` -- the two CK_ULONG width literals."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "to_bytes"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value in (4, 8)
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value in ("little", "big")
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
        # Same, for the S3 widths (4|8, either order) feeding the widened sinks.
        width_vars: dict[str, int] = {}
        for node in nodes:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if _is_to_bytes_little(node.value):
                    little_vars[target.id] = node.value.lineno
                if _is_to_bytes_width48(node.value):
                    width_vars[target.id] = node.value.lineno

        def tb_lineno(
            node: ast.expr, vars_: dict[str, int], pred: Callable[[ast.expr], bool]
        ) -> int | None:
            if pred(node):
                return node.lineno
            if isinstance(node, ast.Name):
                return vars_.get(node.id)
            return None

        for node in nodes:
            # Original sink: into mech_bytes(...), little-endian, any literal width.
            if isinstance(node, ast.Call) and _is_named_call(node.func, "mech_bytes"):
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    line = tb_lineno(arg, little_vars, _is_to_bytes_little)
                    if line is not None and not audited(line):
                        hits.add((label, line))
            # S3 sink: ctypes array construction (T * n)(...) from literal-width bytes.
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.BinOp)
                and isinstance(node.func.op, ast.Mult)
            ):
                for arg in node.args:
                    inner = arg.value if isinstance(arg, ast.Starred) else arg
                    line = tb_lineno(inner, width_vars, _is_to_bytes_width48)
                    if line is not None and not audited(line):
                        hits.add((label, line))
            # S3 sinks: struct-field (attribute) and width-hinting name targets.
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                targets, value = list(node.targets), node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            elif isinstance(node, ast.AugAssign):
                targets, value = [node.target], node.value
            if value is None:
                continue
            line = tb_lineno(value, width_vars, _is_to_bytes_width48)
            if line is None or audited(line):
                continue
            for target in targets:
                if isinstance(target, ast.Attribute):
                    hits.add((label, line))  # struct field
                elif isinstance(target, ast.Name) and any(
                    hint in target.id.lower() for hint in _NAME_HINTS
                ):
                    hits.add((label, line))  # ulong/length/len/size name
    return [f"{label}:{lineno}" for label, lineno in sorted(hits)]


def _violations(path: Path) -> list[str]:
    label = path.relative_to(_ROOT).as_posix()
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


def test_widened_sinks_flagged_wire_format_and_abi_general_not() -> None:
    # S3 name sink: width-hinting target names, either byte order, width 4|8.
    assert _violations_in_source('value_len = v.to_bytes(8, "little")', "x") == ["x:1"]
    assert _violations_in_source('ULONG_SIZE = v.to_bytes(4, "big")', "x") == ["x:1"]
    two = 'p = v.to_bytes(8, "little")\nout_length = p'
    assert _violations_in_source(two, "x") == ["x:1"]
    # S3 struct-field sink, direct and two-step.
    assert _violations_in_source('params.data = v.to_bytes(8, "little")', "x") == ["x:1"]
    field_two = 'p = v.to_bytes(4, "big")\nparams.data = p'
    assert _violations_in_source(field_two, "x") == ["x:1"]
    field_audit = 'params.data = v.to_bytes(8, "little")  # audit-ok: wire field, fixed 8B'
    assert _violations_in_source(field_audit, "x") == []
    # S3 ctypes-array sink.
    array = 'buf = (ctypes.c_ubyte * 8)(*v.to_bytes(8, "little"))'
    assert _violations_in_source(array, "x") == ["x:1"]
    assert _violations_in_source("buf = (ctypes.c_ubyte * 8)(*payload)", "x") == []
    # Spared: wire-format names, non-4/8 widths, ABI-general width, big-endian
    # crypto encodings outside the new sinks.
    assert _violations_in_source('counter_bytes = v.to_bytes(4, "little")', "x") == []
    assert _violations_in_source('params.data = v.to_bytes(2, "little")', "x") == []
    abi = 'value_len = v.to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")'
    assert _violations_in_source(abi, "x") == []
    assert _violations_in_source('send(v.to_bytes(8, "big"))', "x") == []


def test_no_literal_width_ulong_mech_params() -> None:
    offenders: list[str] = []
    for tree in _TREES:
        for path in sorted(tree.rglob("*.py")):
            offenders.extend(_violations(path))
    assert not offenders, (
        "CK_ULONG values serialized at a literal width (mech_bytes, struct field, "
        "ctypes array, or width-named target); use raw.pack.mech_ulong / "
        "ck_ulong_bytes instead:\n  " + "\n  ".join(sorted(offenders))
    )
