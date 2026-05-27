"""Hygiene checks for advertised mechanism runtime classification."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKP_ML_KEM_512,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_kdf, test_pbe, test_trust_objects
from pkcs11_check.testcases._signature_policy import (
    NON_CLEAN_SIGNATURE_REJECT_RVS,
    SIGNATURE_REJECT_RVS,
)
from pkcs11_check.testcases.acvp import (
    test_acvp_ecdh,
    test_acvp_ecdsa,
    test_acvp_mldsa,
    test_acvp_mlkem,
)
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_aes,
    test_wycheproof_dsa,
    test_wycheproof_ecdh,
    test_wycheproof_ecdsa,
    test_wycheproof_hmac,
    test_wycheproof_rsa_decrypt,
    test_wycheproof_rsa_oaep,
    test_wycheproof_rsa_pss,
)

_LEGACY_CIPHER_FILES = (
    Path("src/pkcs11_check/testcases/test_aria.py"),
    Path("src/pkcs11_check/testcases/test_blowfish.py"),
    Path("src/pkcs11_check/testcases/test_camellia.py"),
    Path("src/pkcs11_check/testcases/test_twofish.py"),
)

_RUNTIME_SKIP_PATTERNS = {
    Path("src/pkcs11_check/testcases/test_ecdh_extended.py"): (
        "Cofactor ECDH cannot derive AES key",
        "EC_MONTGOMERY_KEY_PAIR_GEN not operational",
    ),
    Path("src/pkcs11_check/testcases/test_extended_mechanisms.py"): (
        "mechanism rejected by module",
    ),
    Path("src/pkcs11_check/testcases/test_mech_message.py"): ("CKR_MECHANISM_INVALID for CKM_",),
    Path("src/pkcs11_check/testcases/test_kdf.py"): ("HKDF derivation not operational",),
    Path("src/pkcs11_check/testcases/test_otp.py"): (
        "keygen rejected",
        "not operational",
        "CKM_KIP_DERIVE rejected",
    ),
    Path("src/pkcs11_check/testcases/test_pbe.py"): ("not operational",),
    Path("src/pkcs11_check/testcases/test_hkdf_extended.py"): (
        "CKM_HKDF_KEY_GEN with key_type=",
        "CKM_HKDF_KEY_GEN not operational with any key type",
    ),
    Path("src/pkcs11_check/testcases/test_benchmark.py"): (
        "Cannot generate AES-256 key",
        "AES key generation not operational",
    ),
    Path("src/pkcs11_check/testcases/test_cctv_mldsa.py"): ("key generation failed -",),
    Path("src/pkcs11_check/testcases/test_remaining_gaps.py"): ("HOTP key generation failed",),
    Path("src/pkcs11_check/testcases/acvp/test_acvp_hmac.py"): (
        "Cannot import",
        "Key not valid for HMAC mechanism",
    ),
    Path("src/pkcs11_check/testcases/acvp/test_acvp_rsa.py"): ("PSS params not supported",),
}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return ""


def _literal_strings(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


def test_advertised_legacy_cipher_runtime_rejections_are_not_skips() -> None:
    """Advertised-but-rejected mechanisms should remain visible as xfails."""
    offenders: list[str] = []
    for path in _LEGACY_CIPHER_FILES:
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            if any("Mechanism advertised but rejected at use" in s for s in _literal_strings(node)):
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []


def test_advertised_runtime_rejections_are_not_skipped() -> None:
    """Runtime rejection after capability checks should be xfail/fail evidence."""
    offenders: list[str] = []
    for path, skip_patterns in _RUNTIME_SKIP_PATTERNS.items():
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            strings = _literal_strings(node)
            if any(pattern in value for pattern in skip_patterns for value in strings):
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []


def test_acvp_rsa_keygen_uses_structured_ckr_checks() -> None:
    """ACVP RSA keygen should match CKR constants, not exception text."""
    path = Path("src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py")
    tree = ast.parse(path.read_text())

    offenders = [
        f"{path}:{node.lineno}: {node.value}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("CKR_")
    ]

    assert offenders == []


def test_acvp_asymmetric_vectors_use_structured_ckr_checks() -> None:
    """ACVP asymmetric vector tests should match CKR constants, not text."""
    paths = (
        Path("src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py"),
        Path("src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py"),
        Path("src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py"),
        Path("src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        offenders.extend(
            f"{path}:{node.lineno}: {node.value}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("CKR_")
        )

    assert offenders == []


def test_acvp_signature_rejects_stay_spec_specific() -> None:
    """Invalid-signature ACVP paths should not pass on generic runtime errors."""
    non_clean_rejects = (
        CKR_DATA_INVALID,
        CKR_DEVICE_ERROR,
        CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR,
    )

    assert not set(non_clean_rejects).intersection(SIGNATURE_REJECT_RVS)
    assert set(non_clean_rejects).issubset(NON_CLEAN_SIGNATURE_REJECT_RVS)


def test_acvp_capability_skips_do_not_accept_runtime_failure_ckrs() -> None:
    """Capability skips should not swallow provider runtime failures."""
    paths = (
        Path("src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py"),
        Path("src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py"),
        Path("src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py"),
        Path("src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py"),
    )
    capability_tuple_names = {
        "_CURVE_UNSUPPORTED_RVS",
        "_EC_CAPABILITY_REJECT_RVS",
        "_PQC_IMPORT_UNSUPPORTED_RVS",
        "_UNSUPPORTED_RVS",
    }
    disallowed = {"CKR_DEVICE_ERROR", "CKR_FUNCTION_FAILED", "CKR_GENERAL_ERROR"}
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            tuple_name = next(
                (
                    target.id
                    for target in node.targets
                    if isinstance(target, ast.Name) and target.id in capability_tuple_names
                ),
                None,
            )
            if tuple_name is None:
                continue
            offenders.extend(
                f"{path}:{name.lineno}: {tuple_name} contains {name.id}"
                for name in ast.walk(node.value)
                if isinstance(name, ast.Name) and name.id in disallowed
            )

    assert offenders == []


def test_acvp_ecdh_uses_structured_ckr_checks() -> None:
    """ACVP ECDH capability and runtime guards should match CKR constants."""
    path = Path("src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py")
    tree = ast.parse(path.read_text())

    offenders = [
        f"{path}:{node.lineno}: {node.value}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("CKR_")
    ]

    assert offenders == []


def test_acvp_ecdh_mechanism_param_reject_is_xfail() -> None:
    """Advertised ECDH derive returning CKR_MECHANISM_PARAM_INVALID is a finding."""
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
        int(CKR_MECHANISM_PARAM_INVALID),
    )

    with pytest.raises(pytest.xfail.Exception, match="advertised but ECDH derive"):
        test_acvp_ecdh._xfail_if_ecdh_runtime_reject(exc, "Curve P-256")


@pytest.mark.parametrize("rv", [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR])
def test_acvp_ecdh_generic_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised ECDH derive returning generic runtime errors is a finding."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised but ECDH derive"):
        test_acvp_ecdh._xfail_if_ecdh_runtime_reject(exc, "Curve P-384")


def test_acvp_ecdsa_host_memory_runtime_reject_is_xfail() -> None:
    """Advertised EC keygen/use returning CKR_HOST_MEMORY is a visible finding."""
    exc = CkrAssertionError("Unexpected CK_RV", int(CKR_HOST_MEMORY))

    with pytest.raises(pytest.xfail.Exception, match="Curve P-521 rejected"):
        test_acvp_ecdsa._handle_unsupported_curve(exc, "P-521")


def test_acvp_mlkem_uses_structured_ckr_checks() -> None:
    """ACVP ML-KEM capability/runtime guards should match CKR constants."""
    path = Path("src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py")
    tree = ast.parse(path.read_text())

    offenders = [
        f"{path}:{node.lineno}: {node.value}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("CKR_")
    ]

    assert offenders == []


def test_acvp_mlkem_capability_skips_stay_narrow() -> None:
    """ML-KEM unsupported-parameter skips should not hide runtime failures."""
    path = Path("src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py")
    tree = ast.parse(path.read_text())
    disallowed = {
        "CKR_DEVICE_ERROR",
        "CKR_FUNCTION_FAILED",
        "CKR_FUNCTION_NOT_SUPPORTED",
        "CKR_HOST_MEMORY",
        "CKR_MECHANISM_INVALID",
    }
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "_MLKEM_CAPABILITY_REJECT_RVS"
            for target in node.targets
        ):
            continue
        offenders.extend(
            f"{path}:{name.lineno}: {name.id}"
            for name in ast.walk(node.value)
            if isinstance(name, ast.Name) and name.id in disallowed
        )

    assert offenders == []


def test_acvp_mlkem_keygen_host_memory_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advertised ML-KEM keygen returning CKR_HOST_MEMORY is visible xfail evidence."""

    def _host_memory(*_args: object, **_kwargs: object) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV", int(CKR_HOST_MEMORY))

    session = type(
        "Session",
        (),
        {
            "raw": object(),
            "sh": 1,
            "has_mechanism": lambda self, name: name == "ML_KEM_KEY_PAIR_GEN",
        },
    )()
    vec = {
        "param_set": "ML-KEM-512",
        "parameter_set": CKP_ML_KEM_512,
    }
    monkeypatch.setattr(test_acvp_mlkem, "gen_keypair", _host_memory)

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM.*not cleanly operational"):
        test_acvp_mlkem.TestMlKemKeyGen().test_mlkem_keygen(
            session,
            "ML-KEM-keyGen-ML-KEM-512-tc1",
            vec,
        )


def test_pbe_pbkdf2_device_error_is_xfail() -> None:
    """Advertised PBKDF2 returning CKR_DEVICE_ERROR is a visible runtime finding."""
    with pytest.raises(pytest.xfail.Exception, match="CKM_PKCS5_PBKD2 advertised"):
        test_pbe._expect_pbe_gen_key_rv(CKR_DEVICE_ERROR, test_pbe.CKM_PKCS5_PBKD2)


def test_hkdf_python_bug_with_ckr_text_stays_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only PKCS#11 AssertionError paths should become HKDF provider xfails."""

    session = type(
        "Session",
        (),
        {
            "raw": object(),
            "sh": 1,
            "has_mechanism": lambda self, name: name == "HKDF_DERIVE",
        },
    )()

    def _broken_derive(*_args: object, **_kwargs: object) -> int:
        raise ValueError("decoder bug while handling CKR_FUNCTION_FAILED text")

    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_args: 1)
    monkeypatch.setattr(test_kdf, "derive_key", _broken_derive)
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_args: None)

    try:
        test_kdf.TestHKDF().test_hkdf_derive_basic(session)
    except BaseException as exc:
        assert isinstance(exc, ValueError)
        assert "decoder bug" in str(exc)
    else:
        pytest.fail("Expected HKDF Python bug to propagate")


def test_kdf_runtime_classifiers_do_not_catch_generic_exception() -> None:
    """KDF CKR classifiers should not turn arbitrary Python exceptions into xfails."""
    paths = (
        Path("src/pkcs11_check/testcases/test_kdf.py"),
        Path("src/pkcs11_check/testcases/test_hkdf_extended.py"),
        Path("src/pkcs11_check/testcases/test_misc_kdf.py"),
        Path("src/pkcs11_check/testcases/test_sp800_108_kdf.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                continue
            catches_exception = any(
                isinstance(child, ast.Name) and child.id == "Exception"
                for child in ast.walk(node.type)
            )
            if not catches_exception:
                continue
            if any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "xfail_if_known_ckr"
                for child in ast.walk(node)
            ):
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []


def test_object_metadata_classifiers_do_not_hide_python_bugs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Object metadata CKR classifiers should only handle PKCS#11 assertion paths."""

    class Session:
        raw = object()
        sh = 1

    def _broken_read_attributes(*_args: object, **_kwargs: object) -> dict[object, object]:
        raise ValueError("decoder bug while handling CKR_FUNCTION_FAILED text")

    monkeypatch.setattr(test_trust_objects, "_find_trust_objects", lambda *_args: [7])
    monkeypatch.setattr(test_trust_objects, "read_attributes", _broken_read_attributes)

    try:
        test_trust_objects.TestTrustObjects().test_trust_objects_have_issuer(Session())
    except BaseException as exc:
        assert isinstance(exc, ValueError)
        assert "decoder bug" in str(exc)
    else:
        pytest.fail("Expected trust-object Python bug to propagate")


def test_object_metadata_classifiers_do_not_catch_generic_exception() -> None:
    """Object metadata compatibility paths should not catch arbitrary Python exceptions."""
    paths = (
        Path("src/pkcs11_check/testcases/test_trust_objects.py"),
        Path("src/pkcs11_check/testcases/test_validation_objects.py"),
        Path("src/pkcs11_check/testcases/test_domain_params.py"),
        Path("src/pkcs11_check/testcases/test_profiles.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                continue
            catches_exception = any(
                isinstance(child, ast.Name) and child.id == "Exception"
                for child in ast.walk(node.type)
            )
            if catches_exception:
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []


@pytest.mark.parametrize("rv", [CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR])
def test_acvp_mldsa_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised ML-DSA sign/verify runtime rejects are findings, not skips."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised ML-DSA operation"):
        test_acvp_mldsa._xfail_if_mldsa_runtime_reject(exc, "ML-DSA-sigGen")


def test_wycheproof_ec_import_guards_use_structured_ckr_checks() -> None:
    """Large EC Wycheproof import probes should not parse CKR names from text."""
    paths = (
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_ed25519.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        offenders.extend(
            f"{path}:{node.lineno}: {node.value}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("CKR_")
        )

    assert offenders == []


def test_wycheproof_signature_vectors_use_verify_result() -> None:
    """Signature-vector tests must distinguish rejected from accepted signatures."""
    paths = (
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_dsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_ed25519.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        offenders.extend(
            f"{path}:{node.lineno}: verify_single() result ignored"
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "verify_single"
        )

    assert offenders == []


def test_wycheproof_invalid_signature_acceptance_is_reported() -> None:
    """Accepted invalid Wycheproof signatures are findings, not pass-like flow."""
    paths = (
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_dsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_ed25519.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            strings = _literal_strings(node.test)
            if "invalid" not in strings:
                continue
            for body_node in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(body_node, ast.Pass):
                    offenders.append(f"{path}:{body_node.lineno}: pass under invalid vector")

    assert offenders == []


def test_wycheproof_rsa_hmac_pqc_guards_use_structured_ckr_checks() -> None:
    """Wycheproof import guards should match CKR constants, not text."""
    paths = (
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_hmac.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        offenders.extend(
            f"{path}:{node.lineno}: {node.value}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("CKR_")
        )

    assert offenders == []


@pytest.mark.parametrize(
    "rv",
    [
        CKR_ARGUMENTS_BAD,
        CKR_DEVICE_ERROR,
        CKR_MECHANISM_PARAM_INVALID,
    ],
)
def test_wycheproof_rsa_pss_valid_parameter_rejects_are_xfail(rv: int) -> None:
    """Advertised RSA-PSS valid-vector parameter rejects are findings, not failures."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised RSA-PSS parameters"):
        test_wycheproof_rsa_pss._xfail_if_rsa_pss_runtime_reject(
            exc,
            "rsa_pss_2048_sha256_mgf1sha1_20_test.json:tc1-valid",
        )


@pytest.mark.parametrize(
    "rv",
    [
        CKR_DATA_LEN_RANGE,
        CKR_GENERAL_ERROR,
        CKR_MECHANISM_PARAM_INVALID,
    ],
)
def test_wycheproof_aes_valid_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised Wycheproof AES operation rejects are findings, not failures."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised AES operation"):
        test_wycheproof_aes._xfail_if_aes_runtime_reject(exc, "AES-KWP tc11-valid")


@pytest.mark.parametrize(
    "rv",
    [
        CKR_ARGUMENTS_BAD,
        CKR_GENERAL_ERROR,
        CKR_KEY_TYPE_INCONSISTENT,
        CKR_MECHANISM_PARAM_INVALID,
    ],
)
def test_wycheproof_rsa_oaep_valid_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised RSA-OAEP valid-vector runtime rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised RSA-OAEP parameters"):
        test_wycheproof_rsa_oaep._xfail_if_rsa_oaep_runtime_reject(
            exc,
            "rsa_oaep_2048_sha1_mgf1sha1_test.json:tc1-valid",
        )


def test_wycheproof_rsa_pkcs1_decrypt_valid_runtime_rejects_are_xfail() -> None:
    """Advertised RSA-PKCS decrypt valid-vector runtime rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(CKR_DEVICE_ERROR))

    with pytest.raises(pytest.xfail.Exception, match="advertised RSA PKCS#1 decrypt"):
        test_wycheproof_rsa_decrypt._xfail_if_rsa_pkcs1_decrypt_runtime_reject(
            exc,
            "rsa_pkcs1_2048_test.json:tc1-valid",
        )


@pytest.mark.parametrize(
    "rv",
    [
        CKR_GENERAL_ERROR,
        CKR_KEY_HANDLE_INVALID,
        CKR_KEY_SIZE_RANGE,
    ],
)
def test_wycheproof_hmac_valid_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised Wycheproof HMAC operation rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised HMAC operation"):
        test_wycheproof_hmac._xfail_if_hmac_runtime_reject(
            exc,
            "hmac_sha512_test.json:tc1-valid",
        )


@pytest.mark.parametrize(
    "rv",
    [
        CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR,
        CKR_MECHANISM_PARAM_INVALID,
    ],
)
def test_wycheproof_ecdh_valid_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised Wycheproof ECDH derive rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised ECDH derive"):
        test_wycheproof_ecdh._xfail_if_ecdh_runtime_reject(
            exc,
            "ecdh_brainpoolP224r1_test.json:tc1-valid",
        )


@pytest.mark.parametrize("rv", [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR])
def test_wycheproof_ecdsa_valid_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised Wycheproof ECDSA verify runtime rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised ECDSA verify"):
        test_wycheproof_ecdsa._xfail_if_ecdsa_runtime_reject(
            exc,
            "ecdsa_secp521r1_shake256_test.json:tc1-valid",
        )


@pytest.mark.parametrize("rv", [CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR])
def test_wycheproof_dsa_valid_runtime_rejects_are_xfail(rv: int) -> None:
    """Advertised Wycheproof DSA verify runtime rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match="advertised DSA verify"):
        test_wycheproof_dsa._xfail_if_dsa_runtime_reject(
            exc,
            "dsa_2048_224_sha224_test.json:tc2-valid",
        )


def test_wycheproof_hmac_invalid_tags_are_reported() -> None:
    """Invalid HMAC vectors must fail if the module produces the supplied tag."""
    paths = (
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_hmac.py"),
    )

    for path in paths:
        source = path.read_text()
        assert "Invalid HMAC tag" in source
        assert "truncated == tag_expected" in source


def test_wycheproof_rsa_decrypt_invalid_ciphertexts_are_reported() -> None:
    """Invalid RSA decrypt vectors must fail if decrypt succeeds."""
    paths = (
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py"),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py"),
    )

    for path in paths:
        source = path.read_text()
        assert "accepted invalid ciphertext" in source
        assert 'result == "invalid"' in source


def test_wycheproof_symmetric_invalid_outputs_are_reported() -> None:
    """Invalid symmetric vectors must fail on accepted invalid outputs."""
    expected = {
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof.py"): (
            "Invalid AES-GCM vector",
            "Invalid AES-CBC vector",
        ),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py"): (
            "AES-CMAC",
            "AES-KW wrap",
            "AES-KWP wrap",
            "AES-CCM decrypt",
            "AES-GMAC",
            "accepted invalid",
        ),
        Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py"): (
            "ChaCha20-Poly1305",
            "produced invalid",
        ),
    }

    for path, snippets in expected.items():
        source = path.read_text()
        for snippet in snippets:
            assert snippet in source
        assert 'result == "invalid"' in source


def test_wycheproof_hkdf_invalid_size_success_is_reported() -> None:
    """HKDF SizeTooLarge vectors must fail if key derivation succeeds."""
    source = Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py").read_text()

    assert "Invalid HKDF vector" in source
    assert "derived successfully" in source
    assert 'result == "invalid"' in source


def test_wycheproof_mlkem_malformed_decaps_success_is_reported() -> None:
    """Malformed ML-KEM decapsulation vectors must fail if decapsulation succeeds."""
    source = Path("src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py").read_text()

    assert "Invalid ML-KEM decapsulation vector" in source
    assert "produced a shared key" in source
    assert 'result == "invalid"' in source


def test_stateful_signature_guards_use_structured_ckr_checks() -> None:
    """Stateful signature guards should not parse CKR names from text."""
    path = Path("src/pkcs11_check/testcases/test_stateful_sigs.py")
    tree = ast.parse(path.read_text())

    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.endswith("_CKR_NAMES"):
                    offenders.append(f"{path}:{node.lineno}: {target.id}")
        if (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
            and node.left.value.startswith("CKR_")
            and any(isinstance(op, ast.In) for op in node.ops)
            and any(
                isinstance(comparator, ast.Name) and comparator.id == "exc_msg"
                for comparator in node.comparators
            )
        ):
            offenders.append(f"{path}:{node.lineno}: {node.left.value}")

    assert offenders == []
