"""PIN-leak guard: a PIN value must never be interpolated into a string.

Invariant I3 of the probe model: the user PIN travels ONLY via
``run_probe(pin=...)`` -> the ``_P11CHECK_PIN`` child environment variable.  It is
never embedded in a ``python -c`` script, an argv element, a log line, or any
generated source.  Interpolating a plaintext PIN into a string (f-string,
``str.format``, or ``%``) is exactly how the historical leak happened
(``f"login_user(..., {pin.get_secret_value()})"`` exposed the PIN in the child
argv via ``ps``/``/proc`` and in tracebacks).

This static AST gate walks every ``testcases/**`` file (including ``_probes/``)
and fails if a PIN-bearing expression is used as a string-interpolation argument:

- a ``.get_secret_value()`` call inside an f-string field, a ``.format()`` arg,
  or a ``%`` operand (the plaintext unwrap must never reach a string template), or
- a bare PIN variable (``pin`` / ``pin_bytes`` / ``pin_repr`` / ...) used the
  same way.

Reading the PIN from ``os.environ.get("_P11CHECK_PIN")`` and unwrapping it for an
in-process API call (``login_user(raw, sh, CKU_USER, pin)``) or forwarding it to
an env dict is fine -- those are not string interpolation and are not flagged.
"""

from __future__ import annotations

import ast
import pathlib

_TESTCASES = pathlib.Path(__file__).resolve().parent.parent / "src/pkcs11_check/testcases"

# Variable names that hold a plaintext (already-unwrapped) PIN.
_PIN_NAMES = {"pin", "pin_bytes", "pin_repr", "pin_str", "_pin", "user_pin", "so_pin"}


def _is_secret_unwrap(node: ast.AST) -> bool:
    """True for a ``<something>.get_secret_value(...)`` call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_secret_value"
    )


def _subtree_unwraps_secret(node: ast.AST) -> bool:
    """True if any node in ``node``'s subtree unwraps a SecretStr PIN."""
    return any(_is_secret_unwrap(n) for n in ast.walk(node))


def _is_pin_name(node: ast.AST) -> bool:
    """True for a bare plaintext-PIN variable reference."""
    return isinstance(node, ast.Name) and node.id in _PIN_NAMES


def _classify(expr: ast.expr) -> str | None:
    """Return a leak-kind label if ``expr`` carries a plaintext PIN, else None.

    ``get_secret_value()`` anywhere in the subtree is an unconditional leak; a
    bare PIN variable is flagged only when it is the *direct* interpolated value
    (so ``f"{pin is not None}"`` -- a Compare, not a Name -- is not flagged).
    """
    if _subtree_unwraps_secret(expr):
        return "get_secret_value() unwrap"
    if _is_pin_name(expr):
        return "PIN variable"
    return None


def _scan_file(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders: list[str] = []
    rel = path.relative_to(_TESTCASES)

    def flag(lineno: int, ctx: str, kind: str) -> None:
        offenders.append(f"{rel}:{lineno}: {kind} interpolated via {ctx}")

    for node in ast.walk(tree):
        # f-strings: f"...{ <pin> }..."
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    kind = _classify(value.value)
                    if kind:
                        flag(node.lineno, "f-string", kind)
        # "...".format(<pin>) / .format(k=<pin>)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                kind = _classify(arg)
                if kind:
                    flag(node.lineno, ".format()", kind)
        # "..." % <pin>  /  "..." % (<pin>, ...)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left_is_str = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
            if left_is_str or isinstance(node.left, ast.JoinedStr):
                right = node.right
                operands = right.elts if isinstance(right, (ast.Tuple, ast.List)) else [right]
                for operand in operands:
                    kind = _classify(operand)
                    if kind:
                        flag(node.lineno, "%-format", kind)
    return offenders


def _all_testcases_files() -> list[pathlib.Path]:
    return sorted(_TESTCASES.rglob("*.py"))


def test_no_pin_interpolated_into_source() -> None:
    """No testcases file (including _probes/) may interpolate a plaintext PIN into
    a string; the PIN must travel only via run_probe(pin=...) -> _P11CHECK_PIN (I3)."""
    offenders: list[str] = []
    for path in _all_testcases_files():
        offenders.extend(_scan_file(path))
    assert not offenders, (
        "plaintext PIN interpolated into a string under testcases/ -- the PIN must "
        "travel only via run_probe(pin=...) -> _P11CHECK_PIN env (Invariant I3):\n"
        + "\n".join(offenders)
    )
