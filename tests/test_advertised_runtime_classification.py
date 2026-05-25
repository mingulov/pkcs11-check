"""Hygiene checks for advertised mechanism runtime classification."""

from __future__ import annotations

import ast
from pathlib import Path

from pkcs11_check.raw.types_std import (
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases._signature_policy import (
    NON_CLEAN_SIGNATURE_REJECT_RVS,
    SIGNATURE_REJECT_RVS,
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
        assert "result == \"invalid\"" in source


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
            "AES-CCM encrypt",
            "AES-GMAC",
            "produced invalid",
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
        assert "result == \"invalid\"" in source


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
