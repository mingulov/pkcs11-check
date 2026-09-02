"""PC-5 regression: a KWP/KW wrap-setup rejection inside the crash-isolated child
must be classified (emit a SETUP_XFAIL marker the parent turns into pytest.xfail),
not propagate as an unhandled Python error the parent reports as a generic
"subprocess failed with exit code 1". An UNKNOWN reject must NOT be swallowed --
it re-raises so a real provider bug/crash still surfaces.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_KEY_FUNCTION_NOT_PERMITTED
from pkcs11_check.testcases.security.conftest import child_setup_reject_known


def test_known_wrap_reject_emits_setup_xfail_marker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_KEY_FUNCTION_NOT_PERMITTED",
        int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    )
    handled = child_setup_reject_known(
        exc, (int(CKR_KEY_FUNCTION_NOT_PERMITTED),), "AES key wrap setup rejected"
    )
    assert handled is True
    out = capsys.readouterr().out
    assert out.startswith("SETUP_XFAIL:AES key wrap setup rejected: CKR_KEY_FUNCTION_NOT_PERMITTED")


def test_unknown_reject_returns_false_and_stays_silent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
    handled = child_setup_reject_known(
        exc, (int(CKR_KEY_FUNCTION_NOT_PERMITTED),), "AES key wrap setup rejected"
    )
    assert handled is False
    assert capsys.readouterr().out == ""


def test_kwp_wrap_setup_passes_output_size_hint() -> None:
    """Regression: the KWP wrap setup must pass output_size_hint so NSS softoken
    (which does not report the wrapped-key length on the NULL-buffer size-query
    pass for AES-KEY-WRAP-KWP) does not fail the setup with CKR_BUFFER_TOO_SMALL.
    Without it, NSS hard-failed all 21 corrupted/bit-flip KWP unwrap probes at
    setup (2026-06-09).

    The wrap setup now lives in the ``_probes/error_path_kwp.py`` probe child
    (a real ``wrap_key_recipe(..., output_size_hint=64)`` call), so the guard
    reads the probe module source and walks its AST for the hinted call.
    """
    import ast
    from pathlib import Path

    src = Path("src/pkcs11_check/testcases/_probes/error_path_kwp.py").read_text(encoding="utf-8")
    # The probe child must call wrap_key_recipe with the hint.
    assert "output_size_hint=64" in src
    tree = ast.parse(src)
    hinted = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "wrap_key_recipe"
        and any(kw.arg == "output_size_hint" for kw in node.keywords)
        for node in ast.walk(tree)
    )
    assert hinted, "probe must call wrap_key_recipe(..., output_size_hint=...)"
