"""Text I/O must name its encoding, or it silently means "whatever the locale says".

Python's text mode defaults to the locale encoding. On Linux that is UTF-8, so an omitted
`encoding=` is invisible; on a stock Windows it is cp1252, where byte 0x81 is *undefined* and
decoding raises. That asymmetry is why this class of bug reaches Windows users and CI while
every local Linux run is green.

It really happened: the smoke-windows job failed 39 meta-tests, 17 of them with the identical
`UnicodeDecodeError: 'charmap' codec can't decode byte 0x81 in position 39420`, because guard
tests read project sources with a bare `read_text()` and one source file contains `10⁶`
(U+2076, whose UTF-8 continuation byte is 0x81). Four *product* sites had the same defect in
`subprocess.run(..., text=True)`, which decodes a child's output with the locale codec -- so a
provider or child emitting any non-ASCII byte would crash the harness on Windows.

The fix is to say `encoding="utf-8"` and mean it. UTF-8 mode (PYTHONUTF8=1) would also make
the symptom disappear, but it was deliberately NOT used: a real Windows user does not have it
set, so relying on it would hide exactly the class of defect this project exists to surface.

Binary mode is exempt -- it has no encoding. Everything else must be explicit.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_TREES = (_ROOT / "src", _ROOT / "tests")

#: Calls that open a text stream and therefore need an encoding.
_PATH_TEXT_METHODS = frozenset({"read_text", "write_text"})
#: Calls that decode a child process's output when asked for text.
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "check_output", "call", "check_call"})
_TEXT_FLAGS = frozenset({"text", "universal_newlines"})


def _kwarg(call: ast.Call, name: str) -> ast.keyword | None:
    return next((k for k in call.keywords if k.arg == name), None)


def _mode_strings(call: ast.Call) -> list[str]:
    """Every string that could be a mode: the kwarg, or any positional.

    Both positions matter and they differ by callee: builtin ``open(file, mode)`` puts mode
    second, while ``Path.open(mode)`` and ``tarfile.open(name, mode=...)`` put it first or
    name it. Checking only one position is what made this detector's first version report
    ``path.open("wb")`` as text.
    """
    out = []
    mode = _kwarg(call, "mode")
    if mode is not None and isinstance(mode.value, ast.Constant):
        out.append(str(mode.value.value))
    out.extend(
        a.value for a in call.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
    )
    return out


def _is_binary_mode(call: ast.Call) -> bool:
    # ":" catches tarfile's "r:gz"/"w:bz2", which are binary despite carrying no "b".
    return any("b" in m or ":" in m for m in _mode_strings(call))


def _attr_name(func: ast.expr) -> str | None:
    return func.attr if isinstance(func, ast.Attribute) else None


def offenders_in(source: str, label: str) -> list[str]:
    """Return `label:line  reason` for every implicit-encoding text call."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        if _kwarg(node, "encoding") is not None:
            continue
        attr = _attr_name(node.func)
        name = node.func.id if isinstance(node.func, ast.Name) else attr

        if attr in _PATH_TEXT_METHODS:
            found.append(f"{label}:{node.lineno}  .{attr}() without encoding=")
        elif isinstance(node.func, ast.Name) and name == "open" and not _is_binary_mode(node):
            # Builtin open(): a missing mode means text mode, so it needs an encoding.
            found.append(f"{label}:{node.lineno}  open() in text mode without encoding=")
        elif attr == "open" and _mode_strings(node) and not _is_binary_mode(node):
            # Method .open(): only judged when a mode is actually visible. A bare
            # receiver.open() is left alone because the receiver may be a ZipFile or
            # tarfile member, which yields a binary stream and takes no encoding.
            found.append(f"{label}:{node.lineno}  .open() in text mode without encoding=")
        elif attr in _SUBPROCESS_FUNCS or name in _SUBPROCESS_FUNCS:
            asks_text = any(
                k.arg in _TEXT_FLAGS and isinstance(k.value, ast.Constant) and k.value.value
                for k in node.keywords
            )
            if asks_text:
                found.append(f"{label}:{node.lineno}  subprocess text=True without encoding=")
    return found


def test_no_implicit_text_encoding() -> None:
    bad: list[str] = []
    for tree in _TREES:
        for path in sorted(tree.rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            bad.extend(offenders_in(path.read_text(encoding="utf-8"), rel))
    assert not bad, (
        "text I/O without an explicit encoding (locale-dependent; breaks on cp1252 Windows):\n"
        + "\n".join("  " + b for b in bad)
    )


def test_detector_actually_fires() -> None:
    """A guard that cannot fail is not a guard.

    Without this, a bug in the AST walk above would make the suite silently green on a
    codebase full of offenders -- which is exactly the failure mode this file exists to stop.
    """
    sample = (
        "import subprocess\n"
        "from pathlib import Path\n"
        "Path('a').read_text()\n"
        "Path('b').write_text('x')\n"
        "open('c').read()\n"
        "Path('d').open('w').write('x')\n"
        "subprocess.run(['x'], text=True)\n"
    )
    assert len(offenders_in(sample, "sample.py")) == 5

    clean = (
        "import subprocess\n"
        "from pathlib import Path\n"
        "Path('a').read_text(encoding='utf-8')\n"
        "Path('b').write_text('x', encoding='utf-8')\n"
        "open('c', encoding='utf-8').read()\n"
        "open('d', 'rb').read()\n"
        "Path('e').open('wb').write(b'x')\n"
        "tarfile.open('f', mode='r:gz')\n"
        "subprocess.run(['x'], text=True, encoding='utf-8')\n"
        "subprocess.run(['x'], capture_output=True)\n"
    )
    assert offenders_in(clean, "clean.py") == []
