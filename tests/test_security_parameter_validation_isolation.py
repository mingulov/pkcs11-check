from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_parameter_validation_security_probes_run_per_test_in_isolated_runner() -> None:
    source = (ROOT / "src/pkcs11_check/testcases/security/test_parameter_validation.py").read_text()

    assert "pytest.mark.subprocess_per_test" in source


def test_rsa_weak_public_exponent_probe_covers_zero_and_low_odd_exponent() -> None:
    from pkcs11_check.testcases.security.test_parameter_validation import _WEAK_RSA_EXPONENTS

    exponents = {param.values[0] for param in _WEAK_RSA_EXPONENTS}

    assert {0, 3}.issubset(exponents)
