"""Provider-general classification regressions surfaced by the kryoptic triage.

Two over-strictness gaps were found in the 2026-06-11 kryoptic long-tail triage
and are fixed here (effect-gated, provider-general -- no provider identity):

1. ``test_wycheproof_x25519.test_xdh`` hard-failed 12 Wycheproof ``InvalidPublic``
   JWK vectors (x25519 7, x448 5) whose invalidity lives entirely in the JWK
   wrapper (wrong ``crv``/``kty``).  The harness decoder extracts only the raw
   ``x`` coordinate, so the module sees a canonical-length raw point, which per
   RFC 7748 sec 5 is always a valid X25519/X448 public key -- deriving a secret is
   correct module behaviour, not an accepted invalid point.  These vectors are
   the direct analog of the ECDH ``InvalidAsn``/``InvalidPem`` untestable-flag
   class and must be dropped at load (not testable through the raw-point path).

2. ``test_wycheproof_mldsa_sign.test_mldsa_sign`` hard-failed 6 ``InvalidPrivateKey``
   vectors (out-of-range s1/s2) because the module *correctly rejected* the
   malformed private key at ``C_CreateObject`` -- but with ``CKR_DEVICE_ERROR``,
   a clean non-spec reject code outside the narrow 3-code import-reject set.
   Per the classification model, a negative vector rejected with some other
   *clean* code is a pass/xfail, never a fail.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKP_ML_DSA_44,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_mldsa_sign as msign,
)
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_x25519 as xdh,
)

# --------------------------------------------------------------------------
# 1. X25519/X448 JWK InvalidPublic vectors are not testable via the raw point
# --------------------------------------------------------------------------


def test_x25519_invalidpublic_jwk_vectors_dropped_at_load() -> None:
    """The JWK ``InvalidPublic`` canonical-length vectors are excluded at load.

    The 12 kryoptic failures (and the identical opencryptoki/bouncyhsm/nss
    failures) are all JWK vectors whose ``x`` decodes to the canonical length.
    After the fix they must not be parametrized at all -- their invalidity is
    not representable once the JWK wrapper is stripped.
    """
    loaded_ids = {vid for vid, _vec in xdh._ALL_XDH_VECTORS}
    must_be_absent = [
        "x25519_jwk_test.json:tc519-invalid",
        "x25519_jwk_test.json:tc522-invalid",
        "x25519_jwk_test.json:tc524-invalid",
        "x25519_jwk_test.json:tc525-invalid",
        "x25519_jwk_test.json:tc526-invalid",
        "x25519_jwk_test.json:tc527-invalid",
        "x25519_jwk_test.json:tc529-invalid",
        "x448_jwk_test.json:tc516-invalid",
        "x448_jwk_test.json:tc517-invalid",
        "x448_jwk_test.json:tc518-invalid",
        "x448_jwk_test.json:tc519-invalid",
        "x448_jwk_test.json:tc521-invalid",
    ]
    still_present = [vid for vid in must_be_absent if vid in loaded_ids]
    assert not still_present, (
        f"JWK InvalidPublic canonical-length vectors must be dropped at load "
        f"(invalidity is not representable through the raw-point path); still "
        f"present: {still_present}"
    )


def test_x25519_wrong_length_jwk_invalid_still_loaded() -> None:
    """Wrong-length / missing-field JWK invalid vectors stay testable.

    These remain a genuine signal: a wrong-length ``x`` is rejected by a careful
    module's import, so they must NOT be swept by the InvalidPublic drop.  Only
    the canonical-length container-mismatch class is untestable.
    """
    loaded_ids = {vid for vid, _vec in xdh._ALL_XDH_VECTORS}
    # tc520 uses a P-384 x (48 bytes) -> wrong length for X25519; tc528 has no x.
    assert "x25519_jwk_test.json:tc520-invalid" in loaded_ids
    assert "x25519_jwk_test.json:tc528-invalid" in loaded_ids


def test_x25519_valid_jwk_vectors_unaffected() -> None:
    """Valid JWK vectors are never dropped by the InvalidPublic filter."""
    loaded_ids = {vid for vid, _vec in xdh._ALL_XDH_VECTORS}
    assert any(
        vid.startswith("x25519_jwk_test.json:") and vid.endswith("-valid") for vid in loaded_ids
    )


# --------------------------------------------------------------------------
# 2. ML-DSA sign: clean reject of an InvalidPrivateKey vector at import
# --------------------------------------------------------------------------


def _msign_vec(*, result: str, flags: list[str]) -> dict[str, Any]:
    return {
        "_group": {"privateKey": "ab" * 2560},
        "_parameter_set": CKP_ML_DSA_44,
        "_filename": "mldsa_44_sign_noseed_test.json",
        "msg": "6d7367",
        "result": result,
        "flags": flags,
    }


@pytest.mark.parametrize(
    "rv",
    [CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR],
)
def test_mldsa_sign_invalid_privatekey_clean_import_reject_is_not_fail(
    monkeypatch: Any, rv: int
) -> None:
    """Rejecting an out-of-range private key at import with a clean code is OK.

    kryoptic rejects ``InvalidPrivateKey`` vectors at ``C_CreateObject`` with
    ``CKR_DEVICE_ERROR``; that is the right direction (a malformed key is
    rejected) with a non-spec but clean code, so it must classify as pass/xfail,
    never as a hard fail.  Reproduced provider-generally for the generic clean
    error codes.
    """
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _n: True)

    def _import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError(f"Unexpected CK_RV; rv={rv}", rv)

    monkeypatch.setattr(msign, "import_pqc_private_key", _import)
    monkeypatch.setattr(msign, "destroy_quietly", lambda *_a, **_k: None)

    vec = _msign_vec(result="invalid", flags=["InvalidPrivateKey"])
    # Must NOT raise Failed; an xfail (Skipped/XFailed) or clean return is fine.
    try:
        msign.test_mldsa_sign("mldsa_44_sign_noseed_test.json:tc52-invalid", vec, rs)
    except pytest.fail.Exception as exc:  # pragma: no cover - failure path
        pytest.fail(f"clean import reject of invalid-key vector wrongly failed: {exc}")
    except (pytest.xfail.Exception,):
        pass  # xfail is an acceptable classification


def test_mldsa_sign_valid_vector_import_crash_codes_still_propagate(
    monkeypatch: Any,
) -> None:
    """A clean import reject on a VALID vector is still a real signal (not pass).

    The InvalidPrivateKey leniency must not bleed into valid vectors: a valid
    vector whose import fails is an operability deviation (xfail at worst), and
    must never be silently swallowed as a pass.
    """
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _n: True)

    def _import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV", CKR_DEVICE_ERROR)

    monkeypatch.setattr(msign, "import_pqc_private_key", _import)
    monkeypatch.setattr(msign, "destroy_quietly", lambda *_a, **_k: None)

    vec = _msign_vec(result="valid", flags=["ValidSignature"])
    with pytest.raises((pytest.xfail.Exception, pytest.fail.Exception, CkrAssertionError)):
        msign.test_mldsa_sign("mldsa_44_sign_noseed_test.json:tc1-valid", vec, rs)
