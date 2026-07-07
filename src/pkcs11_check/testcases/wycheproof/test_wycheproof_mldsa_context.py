"""Wycheproof ML-DSA context-string sign/verify coverage.

FIPS 204 signs ML-DSA over a *context string* (0..255 bytes) that is
domain-separated from the message: a signature produced under context C must
verify under C and must NOT verify under a different context. PKCS#11 carries
the context in ``CK_SIGN_ADDITIONAL_CONTEXT.pContext`` (here via
``mech_sign_context(CKM_ML_DSA, context=...)``).

The Wycheproof ML-DSA *sign* files carry ``ctx`` vectors that the existing
sign/verify tests ignore (``test_wycheproof_mldsa_sign.py`` signs only ``msg``;
the verify files have no ``ctx``). This module wires those vectors in to cover
three otherwise-untested provider branches:

* **KAT verify-with-context** -- the vector's reference signature must verify
  under its non-empty context (incl. the 255-byte boundary, tc4).
* **context binding** -- that same signature must be REJECTED when verified
  under the empty/default context (a non-binding provider would wrongly accept).
* **over-long context reject** -- signing with a 256-byte context (tc5,
  ``InvalidContext``) must be rejected (the 255-byte FIPS 204 bound).

Each vector is gated by a sign+verify round-trip with its own key: if the
module cannot do context signing at all, the checks ``xfail`` (advertised but
not operational) rather than masquerade as a pass.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, set_params
from pkcs11_check.raw.pack_mechanisms import mech_sign_context
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_pqc_private_key,
    import_pqc_public_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKK_ML_DSA,
    CKM_ML_DSA,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import reject_or_classify
from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached

pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc]

_SIGN_FILES = [
    ("mldsa_44_sign_noseed_test.json", CKP_ML_DSA_44),
    ("mldsa_65_sign_noseed_test.json", CKP_ML_DSA_65),
    ("mldsa_87_sign_noseed_test.json", CKP_ML_DSA_87),
    ("mldsa_44_sign_seed_test.json", CKP_ML_DSA_44),
    ("mldsa_65_sign_seed_test.json", CKP_ML_DSA_65),
    ("mldsa_87_sign_seed_test.json", CKP_ML_DSA_87),
]

# Bare ML-DSA parameter-set labels for per-parameter-set report breakdown.
_PARAM_LABELS: dict[int, str] = {
    CKP_ML_DSA_44: "44",
    CKP_ML_DSA_65: "65",
    CKP_ML_DSA_87: "87",
}

# An over-long context (256 > 255) must be rejected; the spec does not pin a
# single CKR, so all three are accepted as spec-correct (others -> xfail).
_OVERLONG_CTX_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
)


def _load_context_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Collect ML-DSA sign vectors that carry a context (ctx) field."""
    vectors: list[tuple[str, dict[str, Any]]] = []
    for filename, param_set in _SIGN_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        data = load_json_cached(path)
        for group in data.get("testGroups", []):
            priv = group.get("privateKey", "")
            pub = group.get("publicKey", "")
            for test in group.get("tests", []):
                ctx = test.get("ctx", "")
                is_overlong = "InvalidContext" in test.get("flags", [])
                if not ctx and not is_overlong:
                    continue
                test["_param_set"] = param_set
                test["_private_key"] = priv
                test["_public_key"] = pub
                vectors.append((f"{filename}:tc{test['tcId']}", test))
    return vectors


_CONTEXT_VECTORS = _load_context_vectors()


def _import_keys(rs: Any, vec: dict[str, Any]) -> tuple[int | None, int | None]:
    """Import (private, public) ML-DSA keys for a vector; None on missing."""
    priv_hex = vec["_private_key"]
    pub_hex = vec["_public_key"]
    param_set = vec["_param_set"]
    priv = pub = None
    if priv_hex:
        priv = import_pqc_private_key(
            rs.raw,
            rs.sh,
            key_type=int(CKK_ML_DSA),
            value=bytes.fromhex(priv_hex),
            parameter_set=param_set,
            attrs={CKA_SIGN: True},
        )
    if pub_hex:
        pub = import_pqc_public_key(
            rs.raw,
            rs.sh,
            key_type=int(CKK_ML_DSA),
            value=bytes.fromhex(pub_hex),
            parameter_set=param_set,
            attrs={CKA_VERIFY: True},
        )
    return priv, pub


def _context_signing_operational(rs: Any, priv: int, pub: int, msg: bytes) -> bool:
    """Round-trip probe: does the module actually sign+verify with a context?"""
    probe_ctx = b"pkcs11-check-ctx-probe"
    param = mech_sign_context(CKM_ML_DSA, context=probe_ctx)
    try:
        sig = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, msg, mech_param=param)
        return bool(sig) and verify_single(
            rs.raw, rs.sh, pub, CKM_ML_DSA, msg, sig, mech_param=param
        )
    except CkrAssertionError:
        return False  # audit-ok: operability probe; CkrAssertionError means not operational


@pytest.mark.parametrize(
    "vec_id,vec",
    _CONTEXT_VECTORS,
    ids=[v[0] for v in _CONTEXT_VECTORS],
)
def test_mldsa_context(vec_id: str, vec: dict[str, Any], p11_module_session: Any) -> None:
    """ML-DSA context-string verify/sign per Wycheproof ctx vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("ML_DSA"):
        pytest.skip("ML_DSA not supported")

    msg = bytes.fromhex(vec.get("msg", ""))
    ctx = bytes.fromhex(vec.get("ctx", ""))
    is_overlong = "InvalidContext" in vec.get("flags", [])
    set_params({"mldsa": _PARAM_LABELS.get(vec.get("_param_set", -1), "")})

    try:
        priv, pub = _import_keys(rs, vec)
    except CkrAssertionError as import_exc:
        classify(
            "not_operational",
            label="ML_DSA:key-import",
            summary=f"ML-DSA private/public key import not operational: {import_exc}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if priv is None or pub is None:
        pytest.skip("vector lacks an importable private+public key")

    try:
        if is_overlong:
            # Negative: signing with a 256-byte context must be rejected.
            param = mech_sign_context(CKM_ML_DSA, context=ctx)
            sign_exc: CkrAssertionError | None = None
            try:
                sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, msg, mech_param=param)
            except CkrAssertionError as e:
                sign_exc = e
            reject_or_classify(
                sign_exc,
                _OVERLONG_CTX_REJECT_RVS,
                label=f"ML-DSA 256-byte context [{vec_id}]",
            )
            return

        # Positive vectors: only meaningful if the module can do context signing.
        if not _context_signing_operational(rs, priv, pub, msg):
            classify(
                "not_operational",
                label=f"ML_DSA:context-sign:{vec_id}",
                summary=f"ML-DSA context signing advertised but not operational [{vec_id}]",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        sig = bytes.fromhex(vec.get("sig", ""))
        if not sig:
            pytest.skip("no reference signature in vector")

        ctx_param = mech_sign_context(CKM_ML_DSA, context=ctx)

        # KAT: the reference signature must verify under its own context.
        verified = verify_single(rs.raw, rs.sh, pub, CKM_ML_DSA, msg, sig, mech_param=ctx_param)
        assert verified, (
            f"valid ML-DSA signature failed to verify under its context (len={len(ctx)}) [{vec_id}]"
        )

        # Context binding: that signature must NOT verify under the empty/default
        # context. A module that accepts it is not binding the context (cross-
        # context forgery). A clean error here means the module requires a context
        # parameter -- noted, not a finding.
        try:
            mismatched = verify_single(rs.raw, rs.sh, pub, CKM_ML_DSA, msg, sig)
        except CkrAssertionError:
            mismatched = False
        assert not mismatched, (
            f"ML-DSA signature over a non-empty context verified under the empty "
            f"context -- context not bound [{vec_id}]"
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, priv)
        destroy_quietly(rs.raw, rs.sh, pub)
