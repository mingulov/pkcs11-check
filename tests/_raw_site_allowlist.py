"""Files still containing raw pytest.xfail/fail under testcases/. SHRINKS to empty
as Phase 7 migrates each file to classify(). When empty, the static gate is fully hard."""

ALLOWLIST = {
    "src/pkcs11_check/testcases/test_access_control.py",
    "src/pkcs11_check/testcases/test_blake2.py",
    "src/pkcs11_check/testcases/test_cctv_rfc6979.py",
    "src/pkcs11_check/testcases/test_cms.py",
    "src/pkcs11_check/testcases/test_double_ratchet.py",
    "src/pkcs11_check/testcases/test_dual_function.py",
    "src/pkcs11_check/testcases/test_hw_features.py",
    "src/pkcs11_check/testcases/test_kem.py",
    "src/pkcs11_check/testcases/test_mech_attribute.py",
    "src/pkcs11_check/testcases/test_mech_negative.py",
    "src/pkcs11_check/testcases/test_mechanism_objects.py",
    "src/pkcs11_check/testcases/test_object_visibility.py",
}
