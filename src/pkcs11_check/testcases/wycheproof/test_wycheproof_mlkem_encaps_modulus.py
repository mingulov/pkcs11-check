"""Wycheproof ML-KEM ModulusOverflow encapsulation-key rejection.

FIPS 203 requires the encapsulation-key *modulus check*: every 12-bit-packed
coefficient of an ML-KEM encapsulation key (``ek``) must be reduced modulo the
field prime ``q = 3329`` (FIPS 203 Section 7.2, and the input-validation note in
Section 6.2). A *non-canonical* key -- one with at least one coefficient in the
range ``[q, 2**12 - 1]`` -- is malformed and MUST be rejected: a compliant
module either refuses to import it or refuses to encapsulate with it.

Wycheproof flags these malformed encapsulation keys as ``ModulusOverflow``
(``result == "invalid"``) inside the ML-KEM *encaps* test files. Those files
cannot drive a normal ``C_Encapsulate`` known-answer test -- PKCS#11 generates
the encapsulation message ``m`` internally, so the fixed ``m`` in the vector is
unusable -- but the malformed ``ek`` values are exactly the negative inputs we
want for public-key-import / encapsulate validation.

Classification (negative op, per docs/classification-model-design.md):

* rejected with ``CKR_ATTRIBUTE_VALUE_INVALID`` (the spec-correct code for a bad
  ``CKA_VALUE``)            -> ``pass``
* rejected with some other clean ``CKR``                          -> ``xfail``
* accepted (encapsulation succeeds with a non-canonical ``ek``)   -> ``fail``
  (Type A: the module performed a cryptographic operation with a malformed key,
  a FIPS 203 modulus-check violation)

The test only runs where the module can import a *valid* raw ``ek`` and
encapsulate with it; modules that only accept generated key pairs (no raw
public-key import) legitimately ``skip`` -- that is a missing capability, not a
hidden failure.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encapsulate_key,
    import_pqc_public_key,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ENCAPSULATE,
    CKA_KEY_TYPE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_ML_KEM,
    CKM_ML_KEM,
    CKO_SECRET_KEY,
    CKP_ML_KEM_512,
    CKP_ML_KEM_768,
    CKP_ML_KEM_1024,
    CKR_ATTRIBUTE_VALUE_INVALID,
)
from pkcs11_check.testcases.conftest import reject_or_classify
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = [
    pytest.mark.wycheproof,
    pytest.mark.pqc,
    pytest.mark.needs_function("C_EncapsulateKey"),
]

_PARAM_SETS: dict[int, int] = {
    512: CKP_ML_KEM_512,
    768: CKP_ML_KEM_768,
    1024: CKP_ML_KEM_1024,
}

_ENCAPS_FILES = [
    ("mlkem_512_encaps_test.json", 512),
    ("mlkem_768_encaps_test.json", 768),
    ("mlkem_1024_encaps_test.json", 1024),
]

# The spec-correct rejection code for a malformed CKA_VALUE; any other clean
# reject code is classified as xfail (honest deviation), acceptance as fail.
_MODULUS_REJECT_RVS = (CKR_ATTRIBUTE_VALUE_INVALID,)


def _load_modulus_overflow_vectors() -> tuple[list[tuple[str, dict[str, Any]]], dict[int, str]]:
    """Return (ModulusOverflow vectors, one sample valid ek hex per param set)."""
    vectors: list[tuple[str, dict[str, Any]]] = []
    sample_valid_ek: dict[int, str] = {}
    for filename, ps_bits in _ENCAPS_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data.get("testGroups", []):
            for test in group.get("tests", []):
                ek = test.get("ek")
                if not ek:
                    continue
                if test.get("result") == "valid" and ps_bits not in sample_valid_ek:
                    sample_valid_ek[ps_bits] = ek
                if "ModulusOverflow" in test.get("flags", []):
                    test["_parameter_set"] = ps_bits
                    vectors.append((f"{filename}:tc{test['tcId']}", test))
    return vectors, sample_valid_ek


_MODULUS_OVERFLOW_VECTORS, _SAMPLE_VALID_EK = _load_modulus_overflow_vectors()

# Cache the raw-ek-import capability probe per parameter set (per test process;
# isolation runs each file in its own subprocess, so a module global is fine).
_RAW_EK_IMPORT_OK: dict[int, bool] = {}


def _raw_ek_import_supported(rs: Any, ps_bits: int) -> bool:
    """Probe whether the module can import a *valid* raw ek and encapsulate.

    Cached per parameter set. Returns False when raw public-key import or
    encapsulation is unavailable, so the negative tests can skip rather than
    pass vacuously.
    """
    if ps_bits in _RAW_EK_IMPORT_OK:
        return _RAW_EK_IMPORT_OK[ps_bits]
    valid_ek = _SAMPLE_VALID_EK.get(ps_bits)
    ok = False
    if valid_ek:
        pub = None
        secret = None
        try:
            pub = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_KEM),
                value=bytes.fromhex(valid_ek),
                parameter_set=_PARAM_SETS[ps_bits],
                attrs={CKA_ENCAPSULATE: True},
            )
            secret = encapsulate_key(
                rs.raw,
                rs.sh,
                pub,
                CKM_ML_KEM,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    # Required by strict-but-conformant modules (opencryptoki) per PKCS#11
                    # v3.2; the ML-KEM shared secret is 32 bytes (FIPS 203).
                    CKA_VALUE_LEN: 32,
                },
            )[0]
            ok = True
        except CkrAssertionError:
            ok = False
        finally:
            if secret is not None:
                destroy_quietly(rs.raw, rs.sh, secret)
            if pub is not None:
                destroy_quietly(rs.raw, rs.sh, pub)
    _RAW_EK_IMPORT_OK[ps_bits] = ok
    return ok


@pytest.mark.parametrize(
    "vec_id,vec",
    _MODULUS_OVERFLOW_VECTORS,
    ids=[v[0] for v in _MODULUS_OVERFLOW_VECTORS],
)
def test_mlkem_encaps_modulus_overflow(
    vec_id: str, vec: dict[str, Any], p11_module_session: Any
) -> None:
    """A non-canonical (ModulusOverflow) ML-KEM ek must be rejected."""
    rs = p11_module_session
    if not rs.has_mechanism("ML_KEM"):
        pytest.skip("ML_KEM not supported")

    ps_bits = vec["_parameter_set"]
    if not _raw_ek_import_supported(rs, ps_bits):
        pytest.skip("module does not support raw ML-KEM encapsulation-key import + encapsulate")

    ek = bytes.fromhex(vec["ek"])
    label = f"ML-KEM-{ps_bits} ModulusOverflow ek [{vec_id}]"

    exc: CkrAssertionError | None = None
    pub: int | None = None
    secret: int | None = None
    try:
        pub = import_pqc_public_key(
            rs.raw,
            rs.sh,
            key_type=int(CKK_ML_KEM),
            value=ek,
            parameter_set=_PARAM_SETS[ps_bits],
            attrs={CKA_ENCAPSULATE: True},
        )
    except CkrAssertionError as e:
        # Rejected at public-key import -- the canonical place for the check.
        exc = e

    if pub is not None:
        # Import accepted the malformed key; the module must still refuse to
        # encapsulate with it. Success here is the crypto-correctness break.
        try:
            secret = encapsulate_key(
                rs.raw,
                rs.sh,
                pub,
                CKM_ML_KEM,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    # Required by strict-but-conformant modules (opencryptoki) per PKCS#11
                    # v3.2; the ML-KEM shared secret is 32 bytes (FIPS 203).
                    CKA_VALUE_LEN: 32,
                },
            )[0]
        except CkrAssertionError as e:
            exc = e
        finally:
            if secret is not None:
                destroy_quietly(rs.raw, rs.sh, secret)
            destroy_quietly(rs.raw, rs.sh, pub)

    reject_or_classify(exc, _MODULUS_REJECT_RVS, label=label)
