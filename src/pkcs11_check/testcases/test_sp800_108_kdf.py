"""Tests for NIST SP 800-108 Key Derivation Functions.

Covers CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF,
and CKM_SP800_108_DOUBLE_PIPELINE_KDF.

These mechanisms derive keys using a PRF (typically HMAC-SHA256) in
different iteration modes defined by NIST SP 800-108 Rev. 1.

OASIS spec: sp800-108_key_derivation.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    FunctionFailed,
    GeneralError,
    MechanismInvalid,
    MechanismParamInvalid,
)
from pkcs11.mechanisms import (
    SP800108CounterFormat,
    SP800108DataParam,
    SP800108DataType,
    SP800108DKMLengthFormat,
    SP800108DKMLengthMethod,
    SP800108FeedbackKDFParams,
    SP800108KDFParams,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# 32-byte base key material for HMAC-SHA256 PRF
_BASE_KEY_BYTES = bytes(range(32))

# Label and context for KDF data parameters
_LABEL = b"SP800-108 test label"
_CONTEXT = b"SP800-108 test context"

_DERIVE_TEMPLATE: dict[Attribute, Any] = {
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.TOKEN: False,
}

# Common derivation error tuple for SP800-108 operations
_DERIVE_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
)


def _create_base_key(session: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> Any:
    """Create a GENERIC_SECRET base key suitable for derivation."""
    return session.create_object(
        {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.VALUE: key_bytes,
            Attribute.DERIVE: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
        }
    )


def _counter_kdf_params() -> SP800108KDFParams:
    """Build standard counter-mode KDF parameters using HMAC-SHA256 PRF."""
    return SP800108KDFParams(
        prf_type=Mechanism.SHA256_HMAC,
        data_params=[
            SP800108DataParam(
                SP800108DataType.ITERATION_VARIABLE,
                SP800108CounterFormat(32),
            ),
            SP800108DataParam(SP800108DataType.BYTE_ARRAY, _LABEL),
            SP800108DataParam(SP800108DataType.BYTE_ARRAY, _CONTEXT),
            SP800108DataParam(
                SP800108DataType.DKM_LENGTH,
                SP800108DKMLengthFormat(SP800108DKMLengthMethod.SUM_OF_KEYS, 32),
            ),
        ],
    )


def _feedback_kdf_params(*, iv: bytes = b"") -> SP800108FeedbackKDFParams:
    """Build standard feedback-mode KDF parameters using HMAC-SHA256 PRF."""
    return SP800108FeedbackKDFParams(
        prf_type=Mechanism.SHA256_HMAC,
        data_params=[
            SP800108DataParam(
                SP800108DataType.ITERATION_VARIABLE,
                SP800108CounterFormat(32),
            ),
            SP800108DataParam(SP800108DataType.BYTE_ARRAY, _LABEL),
            SP800108DataParam(SP800108DataType.BYTE_ARRAY, _CONTEXT),
            SP800108DataParam(
                SP800108DataType.DKM_LENGTH,
                SP800108DKMLengthFormat(SP800108DKMLengthMethod.SUM_OF_KEYS, 32),
            ),
        ],
        iv=iv,
    )


def _double_pipeline_kdf_params() -> SP800108KDFParams:
    """Build standard double-pipeline KDF parameters using HMAC-SHA256 PRF."""
    return SP800108KDFParams(
        prf_type=Mechanism.SHA256_HMAC,
        data_params=[
            SP800108DataParam(
                SP800108DataType.ITERATION_VARIABLE,
                SP800108CounterFormat(32),
            ),
            SP800108DataParam(SP800108DataType.BYTE_ARRAY, _LABEL),
            SP800108DataParam(SP800108DataType.BYTE_ARRAY, _CONTEXT),
            SP800108DataParam(
                SP800108DataType.DKM_LENGTH,
                SP800108DKMLengthFormat(SP800108DKMLengthMethod.SUM_OF_KEYS, 32),
            ),
        ],
    )


class TestSP800108CounterKDF:
    """CKM_SP800_108_COUNTER_KDF — NIST SP 800-108 Counter mode KDF."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_SP800_108_COUNTER_KDF is advertised."""
        if not has_mechanism(p11_module, "SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

    def test_derive_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 128-bit AES key via counter-mode KDF."""
        if not has_mechanism(p11_module, "SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _counter_kdf_params()
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_COUNTER_KDF,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_aes256(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 256-bit AES key via counter-mode KDF."""
        if not has_mechanism(p11_module, "SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _counter_kdf_params()
            derived = base_key.derive_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.SP800_108_COUNTER_KDF,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 32, f"Expected 32 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF 256-bit derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same inputs must produce the same derived key material."""
        if not has_mechanism(p11_module, "SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params1 = _counter_kdf_params()
            params2 = _counter_kdf_params()
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_COUNTER_KDF,
                mechanism_param=params1,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_COUNTER_KDF,
                mechanism_param=params2,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "Deterministic KDF produced different outputs"
            finally:
                derived2.destroy()
                derived1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_different_label_produces_different_key(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different labels must produce different derived keys."""
        if not has_mechanism(p11_module, "SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params_a = SP800108KDFParams(
                prf_type=Mechanism.SHA256_HMAC,
                data_params=[
                    SP800108DataParam(
                        SP800108DataType.ITERATION_VARIABLE,
                        SP800108CounterFormat(32),
                    ),
                    SP800108DataParam(SP800108DataType.BYTE_ARRAY, b"label-A"),
                    SP800108DataParam(
                        SP800108DataType.DKM_LENGTH,
                        SP800108DKMLengthFormat(SP800108DKMLengthMethod.SUM_OF_KEYS, 32),
                    ),
                ],
            )
            params_b = SP800108KDFParams(
                prf_type=Mechanism.SHA256_HMAC,
                data_params=[
                    SP800108DataParam(
                        SP800108DataType.ITERATION_VARIABLE,
                        SP800108CounterFormat(32),
                    ),
                    SP800108DataParam(SP800108DataType.BYTE_ARRAY, b"label-B"),
                    SP800108DataParam(
                        SP800108DataType.DKM_LENGTH,
                        SP800108DKMLengthFormat(SP800108DKMLengthMethod.SUM_OF_KEYS, 32),
                    ),
                ],
            )
            derived_a = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_COUNTER_KDF,
                mechanism_param=params_a,
                template=_DERIVE_TEMPLATE,
            )
            derived_b = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_COUNTER_KDF,
                mechanism_param=params_b,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val_a = derived_a[Attribute.VALUE]
                val_b = derived_b[Attribute.VALUE]
                assert val_a != val_b, "Different labels produced same derived key"
            finally:
                derived_b.destroy()
                derived_a.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()


class TestSP800108FeedbackKDF:
    """CKM_SP800_108_FEEDBACK_KDF — NIST SP 800-108 Feedback mode KDF."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_SP800_108_FEEDBACK_KDF is advertised."""
        if not has_mechanism(p11_module, "SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")

    def test_derive_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 128-bit AES key via feedback-mode KDF."""
        if not has_mechanism(p11_module, "SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _feedback_kdf_params()
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_FEEDBACK_KDF,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_with_iv(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a key using feedback mode with a non-empty IV."""
        if not has_mechanism(p11_module, "SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            iv = bytes(range(32))  # 32-byte IV (HMAC-SHA256 output size)
            params = _feedback_kdf_params(iv=iv)
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_FEEDBACK_KDF,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF with IV not operational: {exc}")
        finally:
            base_key.destroy()

    def test_iv_affects_output(self, p11_session: Any, p11_module: Any) -> None:
        """Different IVs must produce different derived keys."""
        if not has_mechanism(p11_module, "SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params_no_iv = _feedback_kdf_params(iv=b"")
            params_with_iv = _feedback_kdf_params(iv=b"\xff" * 32)

            derived_no_iv = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_FEEDBACK_KDF,
                mechanism_param=params_no_iv,
                template=_DERIVE_TEMPLATE,
            )
            derived_with_iv = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_FEEDBACK_KDF,
                mechanism_param=params_with_iv,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived_no_iv[Attribute.VALUE]
                val2 = derived_with_iv[Attribute.VALUE]
                assert val1 != val2, "Different IVs produced same derived key"
            finally:
                derived_with_iv.destroy()
                derived_no_iv.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same inputs must produce the same derived key material."""
        if not has_mechanism(p11_module, "SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params1 = _feedback_kdf_params()
            params2 = _feedback_kdf_params()
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_FEEDBACK_KDF,
                mechanism_param=params1,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_FEEDBACK_KDF,
                mechanism_param=params2,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "Deterministic KDF produced different outputs"
            finally:
                derived2.destroy()
                derived1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()


class TestSP800108DoublePipelineKDF:
    """CKM_SP800_108_DOUBLE_PIPELINE_KDF — NIST SP 800-108 Double Pipeline KDF."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_SP800_108_DOUBLE_PIPELINE_KDF is advertised."""
        if not has_mechanism(p11_module, "SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")

    def test_derive_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 128-bit AES key via double-pipeline KDF."""
        if not has_mechanism(p11_module, "SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _double_pipeline_kdf_params()
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_DOUBLE_PIPELINE_KDF,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_DOUBLE_PIPELINE_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_aes256(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 256-bit AES key via double-pipeline KDF."""
        if not has_mechanism(p11_module, "SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _double_pipeline_kdf_params()
            derived = base_key.derive_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.SP800_108_DOUBLE_PIPELINE_KDF,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 32, f"Expected 32 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(
                f"CKM_SP800_108_DOUBLE_PIPELINE_KDF 256-bit derivation not operational: {exc}"
            )
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same inputs must produce the same derived key material."""
        if not has_mechanism(p11_module, "SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")

        base_key = _create_base_key(p11_session)
        try:
            params1 = _double_pipeline_kdf_params()
            params2 = _double_pipeline_kdf_params()
            derived1 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_DOUBLE_PIPELINE_KDF,
                mechanism_param=params1,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SP800_108_DOUBLE_PIPELINE_KDF,
                mechanism_param=params2,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "Deterministic KDF produced different outputs"
            finally:
                derived2.destroy()
                derived1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SP800_108_DOUBLE_PIPELINE_KDF derivation not operational: {exc}")
        finally:
            base_key.destroy()
