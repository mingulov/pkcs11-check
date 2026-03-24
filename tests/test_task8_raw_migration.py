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
TASK8_SPEC_FIX_PATTERNS = {
    ROOT / "src/pkcs11_check/testcases/test_remaining_gaps.py": (
        "raw._funcs",
    ),
    ROOT / "src/pkcs11_check/testcases/test_operation_state.py": (
        "C_OpenSession(slot_id, flags2, c_void_p(None), c_void_p(None), byref(hSession2))",
        "C_CloseSession(hSession2)",
    ),
}


def test_task8_target_files_use_shared_raw_helpers() -> None:
    for path in TARGETS:
        source = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            assert pattern not in source, f"{path.relative_to(ROOT)} still contains {pattern!r}"


def test_task8_spec_fix_followups_use_public_helpers_only() -> None:
    for path, patterns in TASK8_SPEC_FIX_PATTERNS.items():
        source = path.read_text(encoding="utf-8")
        for pattern in patterns:
            assert pattern not in source, f"{path.relative_to(ROOT)} still contains {pattern!r}"
