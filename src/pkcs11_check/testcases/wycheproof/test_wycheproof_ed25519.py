"""Wycheproof Ed25519 and Ed448 signature verification vectors."""

from __future__ import annotations

from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify, set_params
from pkcs11_check.raw.recipes import (
    destroy_quietly,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._eddsa_public_key import (
    import_eddsa_public_key_with_supported_encoding,
    select_eddsa_public_key_encoding,
    verify_eddsa_signature_with_supported_params,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["EDDSA"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

# Module-level cache of Edwards curve OIDs that failed C_CreateObject with a domain/curve error.
# Keyed by OID bytes; avoids redundant probe calls for unsupported Edwards curves.
_UNSUPPORTED_CURVE_OIDS: set[bytes] = set()

_CURVE_UNSUPPORTED_CKRS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_EDWARDS_PUBLIC_IMPORT_UNSUPPORTED_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_KEY_SIZE_RANGE,
)

# Map Edwards curve OID bytes -> human label for the advertised-but-not-operational
# xfail detail (so the shared encoding probe can name the curve it failed on).
_OID_LABELS = {
    bytes([0x06, 0x03, 0x2B, 0x65, 0x70]): "Ed25519",
    bytes([0x06, 0x03, 0x2B, 0x65, 0x71]): "Ed448",
}


def _classify_valid_verify_reject(
    exc: AssertionError,
    *,
    label: str,
    summary: str,
    source: str | None = None,
    vector_id: str | None = None,
) -> NoReturn:
    """Route a valid-vector verify reject without catching harness failures."""
    if not isinstance(exc, CkrAssertionError):
        raise exc
    if not signature_rejected_or_xfail(exc, label):
        classify(
            "not_operational",
            label=label,
            summary=summary,
            source=source,
            vector_id=vector_id,
        )
    raise exc


def _load_ed25519_vectors() -> list[tuple[str, dict[str, Any]]]:
    path = WYCHEPROOF_DIR / "ed25519_test.json"
    if not path.exists():
        return []
    data = load_json_cached(path)
    vectors = []
    for group in data["testGroups"]:
        pk_info = group.get("publicKey", group.get("key", {}))
        for test in group["tests"]:
            test["_pk"] = pk_info
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


_ED25519_VECTORS = _load_ed25519_vectors()
_ED25519_PROBE = next((vec for _vec_id, vec in _ED25519_VECTORS if vec["result"] == "valid"), None)


def _select_eddsa_public_key_encoding_for_wycheproof(
    rs: Any,
    *,
    oid: bytes,
    public_key: bytes,
    message: bytes,
    signature: bytes,
    result: str,
    probe: dict[str, Any] | None,
) -> None:
    """Probe raw vs DER-wrapped EdDSA public-key import for this module/curve."""
    if result != "valid":
        if probe is None:
            return
        public_key = bytes.fromhex(probe["_pk"]["pk"])
        message = bytes.fromhex(probe["msg"])
        signature = bytes.fromhex(probe["sig"])
    try:
        select_eddsa_public_key_encoding(
            rs.raw,
            rs.sh,
            ec_params=oid,
            public_key=public_key,
            message=message,
            signature=signature,
        )
    except CkrAssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            # Genuine capability absence: this Edwards curve is not supported. Skip stays.
            _UNSUPPORTED_CURVE_OIDS.add(oid)
            pytest.skip(f"Cannot import EdDSA public key: {exc}")
        if is_known_error(exc, _EDWARDS_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            # EDDSA is advertised (has_mechanism gate passed in the caller) and the
            # multi-encoding negotiated import is exhausted -> "advertised but not
            # operational" -> xfail per the classification model (not skip).
            # May include curve-capability rejects expressed as generic CKRs --
            # recorded as xfail, not hidden.
            classify(
                "not_operational",
                label="EDDSA:key-import",
                summary=not_operational_reason(
                    "EDDSA:key-import",
                    f"{_OID_LABELS.get(oid, oid.hex())}: {ckr_name(exc.rv)}",
                ),
            )
        signature_rejected_or_xfail(exc, "EdDSA public-key encoding probe")


@pytest.mark.parametrize("vec_id,vec", _ED25519_VECTORS, ids=[v[0] for v in _ED25519_VECTORS])
def test_ed25519_wycheproof(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Ed25519 signature verification from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA not supported")

    set_params({"curve": "ed25519"})

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    pk_info = vec["_pk"]

    # Ed25519 public key: 32 bytes raw
    pk_hex = pk_info.get("pk", "")
    if not pk_hex:
        pytest.skip("No public key in vector")
    pk_bytes = bytes.fromhex(pk_hex)

    # Ed25519 OID: 1.3.101.112
    ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])

    if ed25519_oid in _UNSUPPORTED_CURVE_OIDS:
        pytest.skip("Ed25519 not supported (cached)")

    try:
        _select_eddsa_public_key_encoding_for_wycheproof(
            rs,
            oid=ed25519_oid,
            public_key=pk_bytes,
            message=msg,
            signature=sig,
            result=result,
            probe=_ED25519_PROBE,
        )
        pub_key = import_eddsa_public_key_with_supported_encoding(
            rs.raw,
            rs.sh,
            ec_params=ed25519_oid,
            public_key=pk_bytes,
            attrs={CKA_VERIFY: True},
        )
    except CkrAssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            # Genuine capability absence: Ed25519 not supported. Skip stays.
            _UNSUPPORTED_CURVE_OIDS.add(ed25519_oid)
            pytest.skip(f"Cannot import Ed25519 public key: {exc}")
        if is_known_error(exc, _EDWARDS_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            # EDDSA is advertised (has_mechanism gate passed above) and the
            # negotiated import is exhausted -> "advertised but not operational"
            # -> xfail per the classification model (not skip).
            # May include curve-capability rejects expressed as generic CKRs --
            # recorded as xfail, not hidden.
            classify(
                "not_operational",
                label="EDDSA:key-import",
                summary=not_operational_reason("EDDSA:key-import", f"Ed25519: {ckr_name(exc.rv)}"),
            )
        raise

    try:
        verified = verify_eddsa_signature_with_supported_params(
            rs.raw,
            rs.sh,
            public_key_handle=pub_key,
            ec_params=ed25519_oid,
            message=msg,
            signature=sig,
        )
        if result == "invalid":
            if verified:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="EDDSA-Ed25519",
                    summary=f"Invalid Ed25519 sig {vec_id} accepted by module",
                )
            return
        if result == "valid" and not verified:
            classify(
                "wrong_result",
                kind="crypto",
                label="EDDSA-Ed25519",
                summary=f"Valid Ed25519 sig {vec_id} rejected by module",
            )
    except CkrAssertionError as exc:
        if result == "valid":
            _classify_valid_verify_reject(
                exc,
                label="EDDSA-Ed25519",
                summary=f"Valid Ed25519 sig {vec_id} rejected: {exc}",
            )
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)


# --- Ed448 ---


def _load_ed448_vectors() -> list[tuple[str, dict[str, Any]]]:
    path = WYCHEPROOF_DIR / "ed448_test.json"
    if not path.exists():
        return []
    data = load_json_cached(path)
    vectors = []
    for group in data["testGroups"]:
        pk_info = group.get("publicKey", group.get("key", {}))
        for test in group["tests"]:
            test["_pk"] = pk_info
            vec_id = f"ed448:tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


_ED448_VECTORS = _load_ed448_vectors()
_ED448_PROBE = next((vec for _vec_id, vec in _ED448_VECTORS if vec["result"] == "valid"), None)


@pytest.mark.parametrize("vec_id,vec", _ED448_VECTORS, ids=[v[0] for v in _ED448_VECTORS])
def test_ed448_wycheproof(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Ed448 signature verification from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA not supported")

    set_params({"curve": "ed448"})

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    pk_info = vec["_pk"]

    pk_hex = pk_info.get("pk", "")
    if not pk_hex:
        pytest.skip("No public key in vector")
    pk_bytes = bytes.fromhex(pk_hex)

    # Ed448 OID: 1.3.101.113
    ed448_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x71])

    if ed448_oid in _UNSUPPORTED_CURVE_OIDS:
        pytest.skip("Ed448 not supported (cached)")

    try:
        _select_eddsa_public_key_encoding_for_wycheproof(
            rs,
            oid=ed448_oid,
            public_key=pk_bytes,
            message=msg,
            signature=sig,
            result=result,
            probe=_ED448_PROBE,
        )
        pub_key = import_eddsa_public_key_with_supported_encoding(
            rs.raw,
            rs.sh,
            ec_params=ed448_oid,
            public_key=pk_bytes,
            attrs={CKA_VERIFY: True},
        )
    except CkrAssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            # Genuine capability absence: Ed448 not supported. Skip stays.
            _UNSUPPORTED_CURVE_OIDS.add(ed448_oid)
            pytest.skip(f"Cannot import Ed448 public key: {exc}")
        if is_known_error(exc, _EDWARDS_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            # EDDSA is advertised (has_mechanism gate passed above) and the
            # negotiated import is exhausted -> "advertised but not operational"
            # -> xfail per the classification model (not skip).
            # May include curve-capability rejects expressed as generic CKRs --
            # recorded as xfail, not hidden.
            classify(
                "not_operational",
                label="EDDSA:key-import",
                summary=not_operational_reason("EDDSA:key-import", f"Ed448: {ckr_name(exc.rv)}"),
            )
        raise

    try:
        verified = verify_eddsa_signature_with_supported_params(
            rs.raw,
            rs.sh,
            public_key_handle=pub_key,
            ec_params=ed448_oid,
            message=msg,
            signature=sig,
        )
        if result == "invalid":
            if verified:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="EDDSA-Ed448",
                    summary=f"Invalid Ed448 sig {vec_id} accepted by module",
                )
            return
        if result == "valid" and not verified:
            classify(
                "wrong_result",
                kind="crypto",
                label="EDDSA-Ed448",
                summary=f"Valid Ed448 sig {vec_id} rejected by module",
            )
    except CkrAssertionError as exc:
        if result == "valid":
            _classify_valid_verify_reject(
                exc,
                label="EDDSA-Ed448",
                summary=f"Valid Ed448 sig {vec_id} rejected: {exc}",
            )
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)
