from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    ROOT / "src/pkcs11_check/testcases/test_sign_recover.py",
    ROOT / "src/pkcs11_check/testcases/test_dual_function.py",
    ROOT / "src/pkcs11_check/testcases/test_operation_state.py",
    ROOT / "src/pkcs11_check/testcases/test_remaining_gaps.py",
)
FORBIDDEN_PATTERNS = (
    "C_GetFunctionList = lib.C_GetFunctionList",
    "class CK_MECHANISM(ctypes.Structure):",
    "class CK_ATTRIBUTE(ctypes.Structure):",
)


def test_task8_target_files_use_shared_raw_helpers() -> None:
    for path in TARGETS:
        source = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            assert pattern not in source, f"{path.relative_to(ROOT)} still contains {pattern!r}"
