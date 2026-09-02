"""Wycheproof HKDF vectors.

Tests HKDF (RFC 5869) with SHA-1/SHA-256/SHA-384/SHA-512.
Requires CKM_HKDF_DERIVE mechanism with CK_HKDF_PARAMS.
Skips on modules without HKDF support.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, set_params
from pkcs11_check.raw.pack import mech_hkdf
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_HKDF_DERIVE,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKR_KEY_SIZE_RANGE,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases.conftest import (
    assert_correct,
    import_secret_key_negotiated,
    reject_or_classify,
)

pytestmark = [pytest.mark.wycheproof, pytest.mark.subprocess_per_test]
REQUIRED_MECHANISMS = ["HKDF_DERIVE"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

_HKDF_FILES = [
    ("hkdf_sha1_test.json", "SHA-1"),
    ("hkdf_sha256_test.json", "SHA-256"),
    ("hkdf_sha384_test.json", "SHA-384"),
    ("hkdf_sha512_test.json", "SHA-512"),
]

_SHA_HASH_MECHS: dict[str, int] = {
    "SHA-1": CKM_SHA_1,
    "SHA-256": CKM_SHA256,
    "SHA-384": CKM_SHA384,
    "SHA-512": CKM_SHA512,
}

# Wycheproof's only HKDF invalid vectors request an output larger than the
# mechanism permits; C_DeriveKey specifies CKR_KEY_SIZE_RANGE for that case.
_HKDF_NEGATIVE_REJECT_CKRS = (CKR_KEY_SIZE_RANGE,)


def _load_hkdf_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load HKDF vectors."""
    vectors = []
    for filename, sha in _HKDF_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        data = load_json_cached(path)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_sha"] = sha
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_HKDF_VECTORS = _load_hkdf_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_HKDF_VECTORS, ids=[v[0] for v in _ALL_HKDF_VECTORS])
def test_hkdf(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """HKDF key derivation from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("HKDF_DERIVE"):
        pytest.skip("HKDF_DERIVE not supported")

    ikm = bytes.fromhex(vec["ikm"])
    salt = bytes.fromhex(vec["salt"])
    info = bytes.fromhex(vec["info"])
    okm_expected = bytes.fromhex(vec["okm"])
    okm_size = vec["size"]
    result = vec["result"]
    sha = vec["_sha"]

    hash_mech = _SHA_HASH_MECHS.get(sha)
    if hash_mech is None:
        pytest.skip(f"No hash mechanism mapping for {sha}")
    set_params({"hash": sha})

    # Import IKM as a generic secret key. The IKM is the subject key of the
    # advertised HKDF op (it is what the derive runs FROM), so its negotiated
    # import is the canonical capability path for HKDF_DERIVE.
    try:
        ikm_key = import_secret_key_negotiated(
            rs,
            int(CKK_GENERIC_SECRET),
            ikm,
            attrs={
                CKA_VALUE_LEN: len(ikm),
                CKA_DERIVE: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError as exc:
        if not isinstance(exc, CkrAssertionError):
            # Non-CKR AssertionError -- a harness/ctypes bug must never be
            # classified as "not operational".
            raise
        if not is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
            reject_or_classify(exc, (), label="HKDF_DERIVE:key-import")
        # HKDF_DERIVE was advertised (has_mechanism gate passed above); a
        # negotiation-exhausted IKM import refusal is "advertised but not
        # operational" -> xfail per the classification model, never skip.
        classify(
            "not_operational",
            summary=not_operational_reason("HKDF_DERIVE:key-import", ckr_name(exc.rv)),
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    # CK_HKDF_PARAMS: (hash_mechanism, salt, info)
    # Uses extract+expand mode (standard HKDF)
    hkdf_param = mech_hkdf(
        CKM_HKDF_DERIVE,
        hash_mech=hash_mech,
        extract=True,
        expand=True,
        salt=salt if salt else None,
        info=info if info else None,
    )
    okm = None
    derived = None
    try:
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                ikm_key,
                CKM_HKDF_DERIVE,
                attrs={
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: okm_size,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                mech_param=hkdf_param,
            )
        except CkrAssertionError as exc:
            if result == "valid":
                if not is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
                    reject_or_classify(exc, (), label=f"HKDF:{vec_id}")
                classify(
                    "not_operational",
                    label=f"HKDF:{vec_id}",
                    summary=f"HKDF derive failed for valid vector {vec_id}: {exc}",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            else:
                reject_or_classify(
                    exc,
                    _HKDF_NEGATIVE_REJECT_CKRS,
                    label=f"HKDF:{vec_id}",
                )
            return

        if result == "invalid":
            classify(
                "accepted_invalid",
                kind="crypto",
                summary=f"Invalid HKDF vector {vec_id} derived successfully",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
        if CKA_VALUE not in attrs:
            if result in ("valid", "acceptable"):
                classify(
                    "not_operational",
                    label=f"HKDF:{vec_id}",
                    summary=(
                        f"HKDF derived key value unavailable for {result} vector {vec_id}; "
                        "the result cannot be verified"
                    ),
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            return
        okm = attrs[CKA_VALUE]
        assert isinstance(okm, bytes)
    finally:
        if derived is not None:
            destroy_quietly(rs.raw, rs.sh, derived)
        destroy_quietly(rs.raw, rs.sh, ikm_key)

    if result in ("valid", "acceptable") and okm is not None:
        assert_correct(
            actual=okm,
            expected=okm_expected,
            label=f"HKDF:C_DeriveKey KAT {vec_id}",
            operation="C_DeriveKey",
            mechanism="CKM_HKDF_DERIVE",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
