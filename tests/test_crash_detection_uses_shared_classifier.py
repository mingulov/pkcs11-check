"""Anti-regression: secondary crash detectors must route through crash_codes, not a
bare ``rc < 0``, so a Windows NTSTATUS crash is never misclassified. Guards the sites
fixed in the 2026-07-16 cross-platform branch."""

from __future__ import annotations

import re
from pathlib import Path

# Files that classify a subprocess crash and the shared router each must use.
_GUARDED = {
    "src/pkcs11_check/core/preflight.py": "is_crash_returncode",
    "src/pkcs11_check/core/doctor_probe.py": "is_crash_returncode",
    "src/pkcs11_check/testcases/test_dual_function.py": "is_crash_returncode",
    "src/pkcs11_check/testcases/test_initialize_args.py": "is_crash_returncode",
    "src/pkcs11_check/testcases/test_threading.py": "is_crash_returncode",
    "src/pkcs11_check/testcases/test_subprocess_safety.py": "is_crash_returncode",
    "src/pkcs11_check/testcases/security/test_ffi_length_boundary.py": (
        "assert_subprocess_completed"
    ),
}

# A ``< 0`` comparison against a returncode/rc variable used as a crash gate.
_BARE = re.compile(r"\b(rc|returncode|completed\.returncode)\s*<\s*0\b")
_REPO = Path(__file__).resolve().parents[1]


def test_no_bare_returncode_lt_zero_crash_gate() -> None:
    offenders: list[str] = []
    for rel, router in _GUARDED.items():
        text = (_REPO / rel).read_text(encoding="utf-8")
        assert router in text, f"{rel} no longer uses the shared crash router {router}"
        for i, line in enumerate(text.splitlines(), 1):
            if _BARE.search(line) and not line.lstrip().startswith("#"):
                offenders.append(f"{rel}:{i}: {line.strip()}")
    assert not offenders, "bare `< 0` crash gate(s) reintroduced:\n" + "\n".join(offenders)
