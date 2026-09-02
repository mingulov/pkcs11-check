"""Wycheproof HMAC vectors - all SHA variants."""

from __future__ import annotations

from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify, set_mechanism, set_params, xfail_as
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_secret_key,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_GENERIC_SECRET,
    CKK_SHA3_224_HMAC,
    CKK_SHA3_256_HMAC,
    CKK_SHA3_384_HMAC,
    CKK_SHA3_512_HMAC,
    CKK_SHA224_HMAC,
    CKK_SHA384_HMAC,
    CKK_SHA512_224_HMAC,
    CKK_SHA512_256_HMAC,
    CKK_SHA512_HMAC,
    CKK_SHA_1_HMAC,
    CKM_SHA3_224_HMAC,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_384_HMAC,
    CKM_SHA3_512_HMAC,
    CKM_SHA224_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_224_HMAC,
    CKM_SHA512_256_HMAC,
    CKM_SHA512_HMAC,
    CKM_SHA_1_HMAC,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    is_known_error,
    reject_or_classify,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.wycheproof

# Cache of (mechanism, key_size_bytes) pairs for which the module rejected all
# key import attempts (both typed and GENERIC_SECRET fallback). Populated on
# first total failure; subsequent tests with the same pair skip immediately
# without attempting C_CreateObject probes.
_UNSUPPORTED_HMAC_KEYS: set[tuple[int, int]] = set()

_HMAC_KEY_IMPORT_UNSUPPORTED_CKRS = (
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
)

_HMAC_RUNTIME_REJECT_CKRS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
)

# Map mechanisms to their name for availability checking
_MECH_NAMES: dict[int, str] = {
    CKM_SHA_1_HMAC: "SHA_1_HMAC",
    CKM_SHA224_HMAC: "SHA224_HMAC",
    CKM_SHA384_HMAC: "SHA384_HMAC",
    CKM_SHA512_HMAC: "SHA512_HMAC",
    CKM_SHA512_224_HMAC: "SHA512_224_HMAC",
    CKM_SHA512_256_HMAC: "SHA512_256_HMAC",
    CKM_SHA3_224_HMAC: "SHA3_224_HMAC",
    CKM_SHA3_256_HMAC: "SHA3_256_HMAC",
    CKM_SHA3_384_HMAC: "SHA3_384_HMAC",
    CKM_SHA3_512_HMAC: "SHA3_512_HMAC",
}

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

_HMAC_FILES: dict[str, tuple[int | None, int | None, int | None]] = {
    "hmac_sha1_test.json": (CKK_SHA_1_HMAC, CKM_SHA_1_HMAC, CKK_GENERIC_SECRET),
    "hmac_sha224_test.json": (
        CKK_SHA224_HMAC,
        CKM_SHA224_HMAC,
        CKK_GENERIC_SECRET,
    ),
    "hmac_sha256_test.json": (None, None, None),  # already in test_wycheproof.py
    "hmac_sha384_test.json": (
        CKK_SHA384_HMAC,
        CKM_SHA384_HMAC,
        CKK_GENERIC_SECRET,
    ),
    "hmac_sha512_test.json": (
        CKK_SHA512_HMAC,
        CKM_SHA512_HMAC,
        CKK_GENERIC_SECRET,
    ),
    # SHA-512 truncated variants (PKCS#11 v3.0)
    "hmac_sha512_224_test.json": (
        CKK_SHA512_224_HMAC,
        CKM_SHA512_224_HMAC,
        CKK_GENERIC_SECRET,
    ),
    "hmac_sha512_256_test.json": (
        CKK_SHA512_256_HMAC,
        CKM_SHA512_256_HMAC,
        CKK_GENERIC_SECRET,
    ),
    # SHA-3 HMAC (PKCS#11 v3.0)
    "hmac_sha3_224_test.json": (
        CKK_SHA3_224_HMAC,
        CKM_SHA3_224_HMAC,
        CKK_GENERIC_SECRET,
    ),
    "hmac_sha3_256_test.json": (
        CKK_SHA3_256_HMAC,
        CKM_SHA3_256_HMAC,
        CKK_GENERIC_SECRET,
    ),
    "hmac_sha3_384_test.json": (
        CKK_SHA3_384_HMAC,
        CKM_SHA3_384_HMAC,
        CKK_GENERIC_SECRET,
    ),
    "hmac_sha3_512_test.json": (
        CKK_SHA3_512_HMAC,
        CKM_SHA3_512_HMAC,
        CKK_GENERIC_SECRET,
    ),
}


def _load_hmac_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, (key_type, mechanism, fallback_type) in _HMAC_FILES.items():
        if key_type is None:
            continue  # skip sha256 - already covered
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        data = load_json_cached(path)
        for group in data["testGroups"]:
            tag_size = group.get("tagSize", 256) // 8
            for test in group["tests"]:
                test["_key_type"] = key_type
                test["_mechanism"] = mechanism
                test["_fallback_type"] = fallback_type
                test["_tag_size"] = tag_size
                test["_file"] = filename
                vectors.append((f"{filename}:tc{test['tcId']}-{test['result']}", test))
    return vectors


_ALL_HMAC_VECTORS = _load_hmac_vectors()


def _xfail_if_hmac_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised HMAC operation rejects as non-clean findings."""
    xfail_if_known_ckr(
        exc,
        _HMAC_RUNTIME_REJECT_CKRS,
        f"{label}: advertised HMAC operation is not operational",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_HMAC_VECTORS, ids=[v[0] for v in _ALL_HMAC_VECTORS])
def test_hmac_wycheproof(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """HMAC tag verification from Wycheproof vectors.

    Verifies the *supplied* tag with C_Verify so invalid vectors actually
    exercise rejection. A module that verifies an invalid (forged) tag as valid
    is a crypto-correctness break (-> fail). The previous
    produce-direction (C_Sign + compare) could never reject an invalid vector
    because a fresh correct tag never matched the modified expected tag. A
    valid MAC the module declines to verify (e.g. an unsupported truncated tag
    length) is an honest, provider-dependent deviation -> xfail.
    """
    rs = p11_module_session
    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]
    mechanism = vec["_mechanism"]

    # Check mechanism availability from the module's mechanism list
    mech_display = _MECH_NAMES.get(mechanism, f"0x{mechanism:08x}")
    if not rs.has_mechanism(mech_display):
        pytest.skip(f"{mech_display} not supported by module")
    set_params({"hash": mech_display})
    set_mechanism(mech_display, operation="C_Verify", expect_success=(result == "valid"))

    cache_key = (mechanism, len(key_bytes))
    if cache_key in _UNSUPPORTED_HMAC_KEYS:
        pytest.skip(f"{mech_display} {len(key_bytes)}-byte key not supported (cached)")

    # Try typed key, fall back to GENERIC_SECRET
    key = None
    saw_permanent_rejection = False
    last_exc_msg = ""
    last_exc: CkrAssertionError | None = None
    for kt in (vec["_key_type"], vec["_fallback_type"]):
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                kt,
                key_bytes,
                attrs={
                    CKA_SIGN: True,
                    CKA_VERIFY: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                },
            )
            break
        except AssertionError as exc:
            if not isinstance(exc, CkrAssertionError):
                raise
            if not (is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)):
                raise
            last_exc = exc
            last_exc_msg = str(exc)
            if is_known_error(exc, _HMAC_KEY_IMPORT_UNSUPPORTED_CKRS):
                saw_permanent_rejection = True
            continue

    if key is None:
        # Only cache permanent key rejections, not transient errors.
        if saw_permanent_rejection:
            _UNSUPPORTED_HMAC_KEYS.add(cache_key)
        xfail_as(
            "not_operational",
            label="HMAC:key-import",
            summary=f"Cannot import {len(key_bytes)}-byte HMAC key: {last_exc_msg}",
            actual=last_exc.rv if last_exc is not None else None,
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    try:
        verified = verify_single(rs.raw, rs.sh, key, mechanism, msg, tag_expected)
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_hmac_runtime_reject(exc, vec_id)
        if not isinstance(exc, CkrAssertionError):
            raise
        reject_or_classify(
            exc,
            (CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE),
            label=f"HMAC:{vec_id}",
            kind="crypto",
        )
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and not verified:
        # The module declined to verify a valid MAC -- e.g. an unsupported
        # truncated tag length. Honest, provider-dependent deviation -> xfail.
        classify(
            "honest_deviation",
            summary=f"{vec_id}: module did not verify a valid HMAC tag",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and verified:
        classify(
            "accepted_invalid",
            kind="crypto",
            summary=f"HMAC {vec_id}: accepted invalid tag (forged tag verified)",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
