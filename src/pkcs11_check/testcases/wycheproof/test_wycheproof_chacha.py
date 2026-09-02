"""Wycheproof ChaCha20-Poly1305 AEAD vectors.

Tests ChaCha20-Poly1305 (RFC 8439) encryption/decryption.
Skips on modules that don't support CKM_CHACHA20_POLY1305.

Uses raw ctypes mechanism params via mech_chacha20_poly1305.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, set_mechanism, set_params
from pkcs11_check.raw.pack import mech_chacha20_poly1305
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_CHACHA20,
    CKM_CHACHA20_POLY1305,
    CKR_ARGUMENTS_BAD,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    not_operational_reason,
    probe_operability,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    import_secret_key_negotiated,
    reject_or_classify,
)

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["CHACHA20_POLY1305"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402


def _load_chacha_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ChaCha20-Poly1305 vectors."""
    path = WYCHEPROOF_DIR / "chacha20_poly1305_test.json"
    if not path.exists():
        return []
    data = load_json_cached(path)
    vectors = []
    for group in data["testGroups"]:
        for test in group["tests"]:
            test["_group"] = {k: v for k, v in group.items() if k != "tests"}
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


_CHACHA_VECTORS = _load_chacha_vectors()
_CHACHA_CANONICAL_VECTOR = next(
    (vec for _vec_id, vec in _CHACHA_VECTORS if vec["result"] == "valid"), None
)

_CHACHA_TAG_REJECT_RVS = (CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE)
_CHACHA_NONCE_REJECT_RVS = (CKR_ARGUMENTS_BAD, CKR_MECHANISM_PARAM_INVALID)


def _chacha_decrypt_operability(rs: Any) -> OperabilityResult:
    """Probe one valid decrypt so ModifiedTag rejects are not vacuous."""

    def probe() -> OperabilityResult:
        vec = _CHACHA_CANONICAL_VECTOR
        if vec is None:
            return OperabilityResult(Operability.INCONCLUSIVE, "no canonical ChaCha vector")
        key = import_secret_key_negotiated(
            rs,
            int(CKK_CHACHA20),
            bytes.fromhex(vec["key"]),
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
        try:
            param = mech_chacha20_poly1305(
                CKM_CHACHA20_POLY1305,
                bytes.fromhex(vec["iv"]),
                aad=bytes.fromhex(vec["aad"]) or None,
            )
            try:
                plaintext = decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_CHACHA20_POLY1305,
                    bytes.fromhex(vec["ct"]) + bytes.fromhex(vec["tag"]),
                    mech_param=param,
                    output_size_hint=len(bytes.fromhex(vec["ct"])),
                )
            except CkrAssertionError as exc:
                return OperabilityResult(Operability.NOT_OPERATIONAL, ckr_name(exc.rv))
            expected = bytes.fromhex(vec["msg"])
            if plaintext == expected:
                return OperabilityResult(Operability.OPERATIONAL, "canonical valid decrypt worked")
            return OperabilityResult(Operability.WRONG_OUTPUT, "canonical plaintext mismatch")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    try:
        return probe_operability("CHACHA20_POLY1305:decrypt", probe)
    except CkrAssertionError:  # audit-ok: caller records this as not_operational
        # Key-import failure gives no mechanism evidence. The vector's own
        # import path still reports the advertised operation as non-operational.
        return OperabilityResult(Operability.INCONCLUSIVE, "canonical key import unavailable")


def _require_chacha_decrypt_operational(rs: Any, vec_id: str) -> None:
    result = _chacha_decrypt_operability(rs)
    if result.status is Operability.WRONG_OUTPUT:
        classify(
            "wrong_result",
            kind="crypto",
            label="CHACHA20_POLY1305:canonical-decrypt",
            summary=f"Canonical ChaCha20-Poly1305 decrypt returned wrong plaintext: {vec_id}",
        )
    if result.status is not Operability.OPERATIONAL:
        classify(
            "not_operational",
            label="CHACHA20_POLY1305:canonical-decrypt",
            summary=not_operational_reason(
                "CHACHA20_POLY1305:decrypt",
                f"invalid vector was not evaluated ({result.detail})",
            ),
        )


@pytest.mark.parametrize("vec_id,vec", _CHACHA_VECTORS, ids=[v[0] for v in _CHACHA_VECTORS])
def test_chacha20_poly1305(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ChaCha20-Poly1305 AEAD decryption from Wycheproof vectors.

    Decrypts the supplied ct||tag so invalid vectors actually exercise tag
    rejection. A module that decrypts a forged/modified ciphertext or tag is a
    crypto-correctness break (-> fail). The previous produce-direction
    (encrypt + compare) could never reject an invalid vector because a fresh
    correct ciphertext never matched the modified expected output.
    """
    rs = p11_module_session
    if not rs.has_mechanism("CHACHA20_POLY1305"):
        pytest.skip("CHACHA20_POLY1305 not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    aad = bytes.fromhex(vec["aad"])
    msg_expected = bytes.fromhex(vec["msg"])
    ct = bytes.fromhex(vec["ct"])
    tag = bytes.fromhex(vec["tag"])
    result = vec["result"]
    set_params({"cipher": "chacha20-poly1305"})
    set_mechanism("CHACHA20_POLY1305", operation="C_Decrypt", expect_success=(result == "valid"))

    # The ChaCha20 key is the subject key of the advertised AEAD op (it decrypts
    # the supplied ct||tag), so its negotiated import is the canonical capability
    # path for CHACHA20_POLY1305.
    try:
        key = import_secret_key_negotiated(
            rs,
            int(CKK_CHACHA20),
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except CkrAssertionError as exc:
        # CHACHA20_POLY1305 was advertised (has_mechanism gate passed above); a
        # negotiation-exhausted key import refusal is "advertised but not
        # operational" -> xfail per the classification model, never skip.
        reject_or_classify(
            exc,
            (),
            label="CHACHA20_POLY1305:key-import",
            kind="lifecycle",
        )

    # CK_SALSA20_CHACHA20_POLY1305_PARAMS: (nonce, aad)
    chacha_param = mech_chacha20_poly1305(CKM_CHACHA20_POLY1305, iv, aad=aad if aad else None)
    plaintext = None
    try:
        plaintext = decrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_CHACHA20_POLY1305,
            ct + tag,
            mech_param=chacha_param,
            output_size_hint=len(ct),
        )
    except CkrAssertionError as exc:
        if result == "valid":
            reject_or_classify(
                exc,
                (),
                label=f"CHACHA20_POLY1305:C_Decrypt {vec_id}",
                kind="lifecycle",
            )
        _require_chacha_decrypt_operational(rs, vec_id)
        expected_rvs = (
            _CHACHA_NONCE_REJECT_RVS
            if "InvalidNonceSize" in vec.get("flags", [])
            else _CHACHA_TAG_REJECT_RVS
        )
        reject_or_classify(
            exc,
            expected_rvs,
            label=f"CHACHA20_POLY1305:C_Decrypt reject {vec_id}",
            kind="crypto",
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and plaintext is not None:
        assert_correct(
            actual=plaintext,
            expected=msg_expected,
            label=f"CHACHA20_POLY1305:C_Decrypt KAT {vec_id}",
            operation="C_Decrypt",
            mechanism="CKM_CHACHA20_POLY1305",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and plaintext is not None:
        classify(
            "accepted_invalid",
            kind="crypto",
            label="CHACHA20_POLY1305",
            summary=f"ChaCha20-Poly1305 decrypt {vec_id}: accepted invalid ciphertext/tag",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
