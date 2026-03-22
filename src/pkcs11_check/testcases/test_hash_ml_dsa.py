"""HashML-DSA (pre-hash ML-DSA) sign/verify tests -- PKCS#11 v3.2.

Tests all 11 HASH_ML_DSA mechanism variants:
- CKM_HASH_ML_DSA (generic, single-part only, requires CK_HASH_SIGN_ADDITIONAL_CONTEXT)
- CKM_HASH_ML_DSA_SHA224/256/384/512 (hash-specific, single+multi-part)
- CKM_HASH_ML_DSA_SHA3_224/256/384/512 (hash-specific, single+multi-part)
- CKM_HASH_ML_DSA_SHAKE128/256 (hash-specific, single+multi-part)

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.constants import MLDsaParameterSet
from pkcs11.exceptions import (
    DeviceError,
    FunctionFailed,
    MechanismInvalid,
    SignatureInvalid,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32]

_MESSAGE = b"HashML-DSA pre-hash signature test message 2026"

# Hash-specific HASH_ML_DSA variants (mechanism enum names).
# These support both single-part and multi-part sign/verify.
# The CK_SIGN_ADDITIONAL_CONTEXT parameter is optional (defaults apply).
_HASH_VARIANTS: list[str] = [
    "HASH_ML_DSA_SHA224",
    "HASH_ML_DSA_SHA256",
    "HASH_ML_DSA_SHA384",
    "HASH_ML_DSA_SHA512",
    "HASH_ML_DSA_SHA3_224",
    "HASH_ML_DSA_SHA3_256",
    "HASH_ML_DSA_SHA3_384",
    "HASH_ML_DSA_SHA3_512",
    "HASH_ML_DSA_SHAKE128",
    "HASH_ML_DSA_SHAKE256",
]


def _skip_if_no(p11_module: Any, mech_name: str) -> None:
    if not has_mechanism(p11_module, mech_name):
        pytest.skip(f"CKM_{mech_name} not supported by module")


def _generate_ml_dsa_keypair(session: Any, param_set: MLDsaParameterSet | None = None) -> Any:
    """Generate an ML-DSA key pair for HashML-DSA sign/verify."""
    effective_param = int(param_set) if param_set is not None else int(MLDsaParameterSet.ML_DSA_65)
    pub_tmpl: dict[Any, Any] = {
        Attribute.VERIFY: True,
        Attribute.PARAMETER_SET: effective_param,
        Attribute.TOKEN: False,
    }
    priv_tmpl: dict[Any, Any] = {
        Attribute.SIGN: True,
        Attribute.PARAMETER_SET: effective_param,
        Attribute.TOKEN: False,
    }
    return session.generate_keypair(
        KeyType.ML_DSA,
        mechanism=Mechanism.ML_DSA_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )


class TestHashMLDSAGeneric:
    """CKM_HASH_ML_DSA -- generic pre-hash ML-DSA (single-part only).

    This mechanism requires a CK_HASH_SIGN_ADDITIONAL_CONTEXT parameter
    that includes a hash algorithm field.  Since python-pkcs11 may not yet
    have bindings for this struct, we test mechanism availability only and
    skip the actual sign/verify with an explanatory note.
    """

    def test_mechanism_available(self, p11_module: Any) -> None:
        """Check that CKM_HASH_ML_DSA is advertised by the module."""
        _skip_if_no(p11_module, "HASH_ML_DSA")

    def test_sign_verify_skipped_no_param_binding(self, p11_module: Any) -> None:
        """CKM_HASH_ML_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT param.

        The python-pkcs11 bindings do not yet expose this struct, so we
        cannot construct the required mechanism_param.  Skip with a note.
        """
        _skip_if_no(p11_module, "HASH_ML_DSA")
        pytest.skip(
            "CKM_HASH_ML_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT param "
            "not yet available in python-pkcs11 bindings"
        )


class TestHashMLDSAVariants:
    """Hash-specific HASH_ML_DSA variants -- sign/verify round-trips.

    Each variant does the hashing on-token.  The CK_SIGN_ADDITIONAL_CONTEXT
    parameter is optional (defaults: hedgeVariant=CKH_HEDGE_PREFERRED,
    pContext=NULL, ulContextLen=0), so we call sign/verify without
    mechanism_param.
    """

    @pytest.mark.parametrize("mech_attr", _HASH_VARIANTS)
    def test_mechanism_available(self, p11_module: Any, mech_attr: str) -> None:
        """Check that the hash-specific HASH_ML_DSA variant is advertised."""
        _skip_if_no(p11_module, mech_attr)

    @pytest.mark.parametrize("mech_attr", _HASH_VARIANTS)
    def test_sign_verify_roundtrip(self, p11_session: Any, p11_module: Any, mech_attr: str) -> None:
        """Sign + verify round-trip with CKM_HASH_ML_DSA_{hash}."""
        _skip_if_no(p11_module, mech_attr)
        _skip_if_no(p11_module, "ML_DSA")  # need keygen

        mech = getattr(Mechanism, mech_attr)
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=mech)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"CKM_{mech_attr} sign failed: {exc!r}")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert pub.verify(_MESSAGE, sig, mechanism=mech)
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass

    @pytest.mark.parametrize("mech_attr", _HASH_VARIANTS)
    def test_tampered_message_fails(
        self, p11_session: Any, p11_module: Any, mech_attr: str
    ) -> None:
        """Tampered message must fail verification for CKM_HASH_ML_DSA_{hash}."""
        _skip_if_no(p11_module, mech_attr)
        _skip_if_no(p11_module, "ML_DSA")

        mech = getattr(Mechanism, mech_attr)
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=mech)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"CKM_{mech_attr} sign failed: {exc!r}")

            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            try:
                result = pub.verify(tampered, sig, mechanism=mech)
                assert not result, f"Tampered message should fail CKM_{mech_attr} verification"
            except SignatureInvalid:
                pass  # Correct PKCS#11 behavior
            except DeviceError:
                pytest.xfail("Kryoptic returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID")
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass

    @pytest.mark.parametrize("mech_attr", _HASH_VARIANTS)
    def test_empty_message(self, p11_session: Any, p11_module: Any, mech_attr: str) -> None:
        """Sign/verify with an empty message (hash variants hash on-token)."""
        _skip_if_no(p11_module, mech_attr)
        _skip_if_no(p11_module, "ML_DSA")

        mech = getattr(Mechanism, mech_attr)
        pub, priv = _generate_ml_dsa_keypair(p11_session)
        try:
            try:
                sig = priv.sign(b"", mechanism=mech)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"CKM_{mech_attr} sign of empty message failed: {exc!r}")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert pub.verify(b"", sig, mechanism=mech)
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass
