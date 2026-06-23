from pkcs11_check.testcases.security.test_kdf_output_cap import hkdf_max_output


def test_hkdf_cap_sha256() -> None:
    assert hkdf_max_output(32) == 8160


def test_hkdf_cap_sha1() -> None:
    assert hkdf_max_output(20) == 5100
