from pkcs11_check.spec_refs import lookup


def test_lookup_by_function_is_v32_and_stable():
    ref = lookup("C_Decrypt", "CKM_RSA_PKCS", None)
    assert ref.startswith("PKCS#11 v3.2")
    assert "C_Decrypt" in ref or "RSA" in ref


def test_lookup_unknown_returns_stable_coarse_ref_never_empty_when_op_known():
    ref = lookup("C_Sign", None, None)
    assert ref.startswith("PKCS#11 v3.2")


def test_lookup_nothing_known_returns_empty():
    assert lookup(None, None, None) == ""
