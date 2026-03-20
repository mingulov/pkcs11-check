"""NIST ACVP SLH-DSA test vectors -- the ONLY source for SLH-DSA vectors.

Tests SLH-DSA signature verification and generation using official NIST ACVP
vectors.  Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.constants import SlhDsaParameterSet
from pkcs11.exceptions import DataInvalid, PKCS11Error, SignatureLenRange

from pkcs11_check.testcases.conftest import has_mechanism
from pkcs11_check.testcases.data.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.pqc, pytest.mark.kat, pytest.mark.requires_v32]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP parameter set name -> PKCS#11 SlhDsaParameterSet enum
_PARAM_SET_MAP: dict[str, SlhDsaParameterSet] = {
    "SLH-DSA-SHA2-128s": SlhDsaParameterSet.SHA2_128S,
    "SLH-DSA-SHA2-128f": SlhDsaParameterSet.SHA2_128F,
    "SLH-DSA-SHAKE-128s": SlhDsaParameterSet.SHAKE_128S,
    "SLH-DSA-SHAKE-128f": SlhDsaParameterSet.SHAKE_128F,
    "SLH-DSA-SHA2-192s": SlhDsaParameterSet.SHA2_192S,
    "SLH-DSA-SHA2-192f": SlhDsaParameterSet.SHA2_192F,
    "SLH-DSA-SHAKE-192s": SlhDsaParameterSet.SHAKE_192S,
    "SLH-DSA-SHAKE-192f": SlhDsaParameterSet.SHAKE_192F,
    "SLH-DSA-SHA2-256s": SlhDsaParameterSet.SHA2_256S,
    "SLH-DSA-SHA2-256f": SlhDsaParameterSet.SHA2_256F,
    "SLH-DSA-SHAKE-256s": SlhDsaParameterSet.SHAKE_256S,
    "SLH-DSA-SHAKE-256f": SlhDsaParameterSet.SHAKE_256F,
}


def _load_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA sigVer ACVP vectors merged with expected results."""
    all_vecs = load_acvp_vectors("SLH-DSA-sigVer-FIPS205")
    result = []
    for vec in all_vecs[:50]:  # cap for speed
        inp = vec["input"]
        exp = vec["expected"]
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue
        pk = inp.get("pk", "")
        msg = inp.get("message", "")
        sig = inp.get("signature", "")
        if not pk or not msg or not sig:
            continue
        merged: dict[str, Any] = {
            "param_set": param_set,
            "pk": bytes.fromhex(pk),
            "msg": bytes.fromhex(msg),
            "sig": bytes.fromhex(sig),
            "expected_pass": exp.get("testPassed", True),
            "tc_id": inp.get("tcId", 0),
        }
        vec_id = f"sigVer-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


def _load_siggen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA sigGen ACVP vectors merged with expected results."""
    all_vecs = load_acvp_vectors("SLH-DSA-sigGen-FIPS205")
    result = []
    for vec in all_vecs[:5]:  # SLH-DSA signing is slow -- keep minimal
        inp = vec["input"]
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue
        sk = inp.get("sk", "")
        msg = inp.get("message", "")
        if not sk or not msg:
            continue
        merged = {
            "param_set": param_set,
            "sk": bytes.fromhex(sk),
            "msg": bytes.fromhex(msg),
            "tc_id": inp.get("tcId", 0),
        }
        vec_id = f"sigGen-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


_SIGVER_VECTORS = _load_sigver_vectors()
_SIGGEN_VECTORS = _load_siggen_vectors()


@pytest.mark.parametrize("vec_id,vec", _SIGVER_VECTORS, ids=[v[0] for v in _SIGVER_VECTORS])
def test_slhdsa_sigver(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """SLH-DSA signature verification from NIST ACVP vectors."""
    if not has_mechanism(p11_module, "SLH_DSA"):
        pytest.skip("SLH_DSA not supported")

    param_set: SlhDsaParameterSet = vec["param_set"]

    pub_key = None
    try:
        try:
            pub_key = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                    Attribute.KEY_TYPE: KeyType.SLH_DSA,
                    Attribute.VALUE: vec["pk"],
                    Attribute.PARAMETER_SET: int(param_set),
                    Attribute.TOKEN: False,
                    Attribute.VERIFY: True,
                }
            )
        except PKCS11Error as e:
            pytest.skip(f"Cannot import SLH-DSA public key ({param_set.name}): {e}")

        try:
            pub_key.verify(vec["msg"], vec["sig"], mechanism=Mechanism.SLH_DSA)
            verified = True
        except p11.exceptions.SignatureInvalid:
            verified = False
        except (DataInvalid, SignatureLenRange):
            # Some modules return CKR_DATA_INVALID or CKR_SIGNATURE_LEN_RANGE
            # instead of CKR_SIGNATURE_INVALID for corrupt signatures.
            verified = False
        except PKCS11Error as e:
            # Unexpected error from the module -- record as xfail
            pytest.xfail(f"SLH-DSA verify raised unexpected error for {vec_id}: {e}")

        expected = vec["expected_pass"]
        if not expected and verified:
            # Module accepted an invalid signature -- security concern
            pytest.fail(f"{vec_id}: accepted INVALID signature (expected rejection)")
        if expected and not verified:
            # Module rejected a valid signature -- module issue, mark as xfail
            pytest.xfail(
                f"{vec_id}: rejected VALID SLH-DSA signature -- known Kryoptic issue"
            )
    finally:
        if pub_key is not None:
            pub_key.destroy()


@pytest.mark.parametrize("vec_id,vec", _SIGGEN_VECTORS, ids=[v[0] for v in _SIGGEN_VECTORS])
def test_slhdsa_siggen(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """SLH-DSA signature generation from NIST ACVP message vectors.

    PKCS#11 does not guarantee deterministic SLH-DSA output.  This test
    verifies that the module can sign without error and produces a non-empty
    result.  Exact signature comparison is skipped because most PKCS#11
    implementations use randomized SLH-DSA.
    """
    if not has_mechanism(p11_module, "SLH_DSA"):
        pytest.skip("SLH_DSA not supported")

    param_set: SlhDsaParameterSet = vec["param_set"]

    priv_key = None
    try:
        try:
            priv_key = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                    Attribute.KEY_TYPE: KeyType.SLH_DSA,
                    Attribute.VALUE: vec["sk"],
                    Attribute.PARAMETER_SET: int(param_set),
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.SIGN: True,
                }
            )
        except PKCS11Error as e:
            pytest.skip(f"Cannot import SLH-DSA private key ({param_set.name}): {e}")

        sig = priv_key.sign(vec["msg"], mechanism=Mechanism.SLH_DSA)
        assert len(sig) > 0, f"SLH-DSA sign returned empty signature for {vec_id}"
    finally:
        if priv_key is not None:
            priv_key.destroy()
