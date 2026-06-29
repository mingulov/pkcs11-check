"""Real, importable child-probe modules (extracted from f-string subprocess scripts).

Intentionally side-effect-free at import: importing this package, or any module in
it, must never skip, raise on missing capability, or touch a PKCS#11 module. (Cf. the
acvp/aes eager-import collection crash.)
"""
