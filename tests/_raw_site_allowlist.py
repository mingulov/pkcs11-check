"""Files still containing raw pytest.xfail/fail under testcases/. SHRINKS to empty
as Phase 7 migrates each file to classify(). When empty, the static gate is fully hard."""

ALLOWLIST = {
    "src/pkcs11_check/testcases/test_cctv_rfc6979.py",
    "src/pkcs11_check/testcases/test_double_ratchet.py",
    "src/pkcs11_check/testcases/test_kem.py",
}
