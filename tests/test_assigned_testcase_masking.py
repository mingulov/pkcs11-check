"""Guard the remaining testcases against broad provider-error masking."""

from __future__ import annotations

import ast
from pathlib import Path

_TESTCASE_FILES = (
    Path("src/pkcs11_check/testcases/test_sensitivity.py"),
    Path("src/pkcs11_check/testcases/test_ecdh_extended.py"),
    Path("src/pkcs11_check/testcases/test_always_authenticate.py"),
    Path("src/pkcs11_check/testcases/test_attribute_enforcement.py"),
    Path("src/pkcs11_check/testcases/test_attribute_defaults.py"),
    Path("src/pkcs11_check/testcases/security/test_cve_regression.py"),
    Path("src/pkcs11_check/testcases/test_domain_params.py"),
    Path("src/pkcs11_check/testcases/test_gcm_parameter_fidelity.py"),
    Path("src/pkcs11_check/testcases/test_oaep_parameter_fidelity.py"),
    Path("src/pkcs11_check/testcases/test_remaining_gaps.py"),
    Path("src/pkcs11_check/testcases/test_v30_session.py"),
    Path("src/pkcs11_check/testcases/ckr/test_ckr_wrap.py"),
)


def test_provider_routing_does_not_catch_plain_assertion_errors() -> None:
    """Only CkrAssertionError may be routed as a provider return value."""
    offenders: list[str] = []
    for path in _TESTCASE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or node.type is None:
                continue
            if any(
                isinstance(child, ast.Name) and child.id == "AssertionError"
                for child in ast.walk(node.type)
            ):
                offenders.append(f"{path}:{node.lineno}")
    assert offenders == []
