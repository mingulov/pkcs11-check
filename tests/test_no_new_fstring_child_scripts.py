"""Anti-regression guard: no test may reintroduce an inline ``python -c`` child.

The probe-script extraction migration replaced ~133 f-string ``python -c``
subprocess children under ``testcases/`` with real ``_probes/`` modules launched
through ``python -m ... <probe>`` by ``run_probe`` (Invariant I11, no shell, no
source interpolation).  This static AST gate keeps the migration from regressing:
a new subprocess child that runs an *inline* script (``[sys.executable, "-c",
<script>]``) -- or that calls one of the removed launchers -- fails here.

What is allowed (and why the gate still passes on the clean tree):

- ``python -m pkcs11_check.testcases._probes.<probe>`` launches (runner.py,
  test_interop_openssl.py) -- these use ``"-m"``, not ``"-c"``, so they carry no
  inline script and are not flagged.
- external-tool CLIs (openssl / p11-kit / ``/bin/sh -c <mint-cmd>``) -- these do
  not invoke ``sys.executable``, so they are not flagged.
- ``test_threading.py`` -- the one legitimate remaining ``sys.executable -c``
  child.  It runs a **static module-level constant** workload (not an f-string:
  every parameter, including the PIN, travels via the child *environment*) in a
  dedicated process that does its own ``C_Initialize(CKF_OS_LOCKING_OK)`` and
  real OS threads -- something ``run_probe``'s single-shot probe model cannot
  express.  It is sanctioned explicitly below.
"""

from __future__ import annotations

import ast
import pathlib

# testcases root, resolved from this file so the gate is cwd-independent.
_TESTCASES = pathlib.Path(__file__).resolve().parent.parent / "src/pkcs11_check/testcases"

# The framework subprocess-launcher / result helper modules are the sanctioned
# home for subprocess plumbing; the gate governs the *test* files, not these.
_HELPER_MODULES = {
    "_subprocess_preamble.py",
    "_raw_subprocess.py",
    "_subprocess_result.py",
    "_subprocess_trace.py",
    "_subprocess.py",  # ckr/_subprocess.py
}

# Files with a sanctioned, reviewed inline ``sys.executable -c`` child.  See the
# module docstring for why test_threading.py cannot use run_probe.
_SANCTIONED = {"test_threading.py"}

# Launchers removed by the migration -- a call to any of these is a regression.
_REMOVED_LAUNCHERS = {
    "run_with_coverage",
    "subprocess_session_preamble",
    "run_raw_script",
    "run_raw_subprocess",
}


def _is_sys_executable(node: ast.expr) -> bool:
    """True for ``sys.executable`` (or a bare ``executable`` name)."""
    if isinstance(node, ast.Attribute) and node.attr == "executable":
        return True
    return isinstance(node, ast.Name) and node.id == "executable"


def _is_dash_c(node: ast.expr) -> bool:
    """True for the ``"-c"`` string constant."""
    return isinstance(node, ast.Constant) and node.value == "-c"


def _list_is_inline_python_c(node: ast.AST) -> bool:
    """True for a list/tuple that names ``sys.executable`` together with ``"-c"``.

    That shape is unambiguously an inline ``python -c <script>`` child argv,
    regardless of whether the script element is a literal, an f-string, or a
    name bound to one.
    """
    if not isinstance(node, (ast.List, ast.Tuple)):
        return False
    elts = node.elts
    return any(_is_sys_executable(e) for e in elts) and any(_is_dash_c(e) for e in elts)


def _call_target_name(node: ast.Call) -> str | None:
    """Return the simple/attribute name being called (e.g. ``run_raw_script``)."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _scan_file(path: pathlib.Path) -> list[str]:
    """Return human-readable offender descriptions for one file."""
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders: list[str] = []
    rel = path.relative_to(_TESTCASES)
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)
        if _list_is_inline_python_c(node):
            offenders.append(f"{rel}:{lineno}: inline `[sys.executable, '-c', ...]` child")
        elif isinstance(node, ast.Call):
            name = _call_target_name(node)
            if name in _REMOVED_LAUNCHERS:
                offenders.append(f"{rel}:{lineno}: call to removed launcher `{name}()`")
    return offenders


def _governed_files() -> list[pathlib.Path]:
    """testcases/*.py excluding the _probes/ package and the helper modules."""
    files: list[pathlib.Path] = []
    for path in sorted(_TESTCASES.rglob("*.py")):
        if "_probes" in path.relative_to(_TESTCASES).parts:
            continue
        if path.name in _HELPER_MODULES:
            continue
        files.append(path)
    return files


def test_no_inline_python_c_child_scripts() -> None:
    """No governed testcases file may launch an inline ``python -c`` child or call
    a removed launcher; new subprocess probes must go through ``_probes`` +
    ``run_probe``."""
    offenders: list[str] = []
    for path in _governed_files():
        if path.name in _SANCTIONED:
            continue
        offenders.extend(_scan_file(path))
    assert not offenders, (
        "inline `python -c` child scripts / removed-launcher calls reintroduced "
        "under testcases/ -- route new subprocess probes through _probes + run_probe:\n"
        + "\n".join(offenders)
    )


def test_sanctioned_files_still_contain_an_inline_child() -> None:
    """Each sanctioned file must still contain the inline child it is exempted for.

    Prevents a stale exemption: if test_threading.py is ever migrated to
    ``run_probe`` (or deleted), the sanction must be removed so the gate stays
    tight for that filename.
    """
    stale = []
    for name in _SANCTIONED:
        path = _TESTCASES / name
        if not path.exists():
            stale.append(f"{name}: sanctioned file no longer exists")
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        if not any(_list_is_inline_python_c(n) for n in ast.walk(tree)):
            stale.append(f"{name}: no inline `sys.executable -c` child -- remove from _SANCTIONED")
    assert not stale, "stale entries in _SANCTIONED:\n" + "\n".join(stale)
