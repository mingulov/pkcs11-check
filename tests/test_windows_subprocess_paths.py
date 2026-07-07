"""Generated subprocess scripts must repr-quote interpolated module paths.

A Windows path (``D:\\a\\pkcs11-check\\...``) interpolated into a bare ``"..."``
string literal in a generated child script turns ``\\p`` / ``\\a`` into invalid
escape sequences, mangling the path so ctypes.CDLL fails and the child exits 1
(this passes on Linux, whose paths have no backslashes). Use ``{x!r}`` or
``json.dumps(x)`` instead. See the Windows ABI work / GitHub issue #3.
"""

from __future__ import annotations

import re
from pathlib import Path

_TESTCASES = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"

# A module path dropped into a bare double-quoted literal inside a generated script,
# in any form -- CDLL("{module_path}"), RawPKCS11.from_lib("{module}"),
# os.environ["..."] = "{module}". The path field is always named module/module_path,
# so a double-quote immediately followed by "{module" is the unsafe signature.
_UNSAFE = re.compile(r'"\{module')


def test_no_unsafe_module_path_interpolation_in_generated_scripts() -> None:
    offenders: list[str] = []
    for path in _TESTCASES.rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _UNSAFE.search(line):
                offenders.append(f"{path.relative_to(_TESTCASES)}:{lineno}: {line.strip()}")
    assert offenders == [], (
        "module path interpolated into a bare string literal (mangles on Windows); "
        "use {x!r} or json.dumps(x):\n" + "\n".join(offenders)
    )
