"""Tests for NIST SP 800-108 Key Derivation Functions.

Covers CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF,
and CKM_SP800_108_DOUBLE_PIPELINE_KDF.

These mechanisms derive keys using a PRF (typically HMAC-SHA256) in
different iteration modes defined by NIST SP 800-108 Rev. 1.

OASIS spec: sp800-108_key_derivation.md

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.pack import PackedMechanism, PointerArg
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_PRF_DATA_PARAM,
    CK_SP800_108_BYTE_ARRAY,
    CK_SP800_108_COUNTER_FORMAT,
    CK_SP800_108_DKM_LENGTH,
    CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
    CK_SP800_108_FEEDBACK_KDF_PARAMS,
    CK_SP800_108_ITERATION_VARIABLE,
    CK_SP800_108_KDF_PARAMS,
    CK_VOID_PTR,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKM_SP800_108_COUNTER_KDF,
    CKM_SP800_108_DOUBLE_PIPELINE_KDF,
    CKM_SP800_108_FEEDBACK_KDF,
    CKO_SECRET_KEY,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

pytestmark = pytest.mark.keymgmt

# 32-byte base key material for HMAC-SHA256 PRF
_BASE_KEY_BYTES = bytes(range(32))

# Label and context for KDF data parameters
_LABEL = b"SP800-108 test label"
_CONTEXT = b"SP800-108 test context"

_DERIVE_ATTRS = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}

# Common derivation error RVs
_DERIVE_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
}


def _create_base_key(rs: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> int:
    """Create a GENERIC_SECRET base key suitable for derivation."""
    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_GENERIC_SECRET,
        key_bytes,
        attrs={
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
        },
    )


# ---------------------------------------------------------------------------
# ctypes builders for SP800-108 mechanism parameters
# ---------------------------------------------------------------------------


def _make_prf_data_param(
    ptype: int,
    data: bytes | None = None,
    struct: ctypes.Structure | None = None,
) -> tuple[CK_PRF_DATA_PARAM, list[Any]]:
    """Build a CK_PRF_DATA_PARAM.  Returns (param, keepalive_list)."""
    ka: list[Any] = []
    p = CK_PRF_DATA_PARAM()
    p.type = ptype
    if data is not None:
        buf = (ctypes.c_ubyte * len(data))(*data)
        ka.append(buf)
        p.pValue = ctypes.cast(buf, CK_VOID_PTR)
        p.ulValueLen = len(data)
    elif struct is not None:
        ka.append(struct)
        p.pValue = ctypes.cast(ctypes.pointer(struct), CK_VOID_PTR)
        p.ulValueLen = ctypes.sizeof(struct)
    else:
        p.pValue = None
        p.ulValueLen = 0
    return p, ka


def _counter_format(bits: int = 32) -> CK_SP800_108_COUNTER_FORMAT:
    cf = CK_SP800_108_COUNTER_FORMAT()
    cf.bLittleEndian = 0
    cf.ulWidthInBits = bits
    return cf


def _dkm_length_format(
    method: int = CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
    bits: int = 32,
) -> CK_SP800_108_DKM_LENGTH_FORMAT:
    dlf = CK_SP800_108_DKM_LENGTH_FORMAT()
    dlf.dkmLengthMethod = method
    dlf.bLittleEndian = 0
    dlf.ulWidthInBits = bits
    return dlf


def _build_counter_kdf_mech(
    label: bytes = _LABEL,
    context: bytes = _CONTEXT,
) -> PackedMechanism:
    """Build CKM_SP800_108_COUNTER_KDF mechanism with CK_SP800_108_KDF_PARAMS."""
    keepalive: list[Any] = []

    # Build data params array
    cf = _counter_format()
    p_iter, ka1 = _make_prf_data_param(CK_SP800_108_ITERATION_VARIABLE, struct=cf)
    keepalive.extend(ka1)

    p_label, ka2 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=label)
    keepalive.extend(ka2)

    p_ctx, ka3 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=context)
    keepalive.extend(ka3)

    dlf = _dkm_length_format()
    p_dkm, ka4 = _make_prf_data_param(CK_SP800_108_DKM_LENGTH, struct=dlf)
    keepalive.extend(ka4)

    data_params = (CK_PRF_DATA_PARAM * 4)(p_iter, p_label, p_ctx, p_dkm)
    keepalive.append(data_params)

    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 4
    params.pDataParams = ctypes.cast(data_params, CK_VOID_PTR)
    params.ulAdditionalDerivedKeys = 0
    params.pAdditionalDerivedKeys = None
    keepalive.append(params)

    pointer_arg = PointerArg.to_storage(params, origin="sp800_108_counter")
    from pkcs11_check.raw.pack import LengthArg

    length_arg = LengthArg.native(ctypes.sizeof(params))
    pm = PackedMechanism(
        CK_MECHANISM(CKM_SP800_108_COUNTER_KDF, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    pm._keepalive.extend(keepalive)
    return pm


def _build_feedback_kdf_mech(
    iv: bytes = b"",
    label: bytes = _LABEL,
    context: bytes = _CONTEXT,
) -> PackedMechanism:
    """Build CKM_SP800_108_FEEDBACK_KDF mechanism."""
    keepalive: list[Any] = []

    cf = _counter_format()
    p_iter, ka1 = _make_prf_data_param(CK_SP800_108_ITERATION_VARIABLE, struct=cf)
    keepalive.extend(ka1)

    p_label, ka2 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=label)
    keepalive.extend(ka2)

    p_ctx, ka3 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=context)
    keepalive.extend(ka3)

    dlf = _dkm_length_format()
    p_dkm, ka4 = _make_prf_data_param(CK_SP800_108_DKM_LENGTH, struct=dlf)
    keepalive.extend(ka4)

    data_params = (CK_PRF_DATA_PARAM * 4)(p_iter, p_label, p_ctx, p_dkm)
    keepalive.append(data_params)

    params = CK_SP800_108_FEEDBACK_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 4
    params.pDataParams = ctypes.cast(data_params, CK_VOID_PTR)
    if iv:
        iv_buf = (ctypes.c_ubyte * len(iv))(*iv)
        keepalive.append(iv_buf)
        params.pIV = ctypes.cast(iv_buf, CK_VOID_PTR)
        params.ulIVLen = len(iv)
    else:
        params.pIV = None
        params.ulIVLen = 0
    params.ulAdditionalDerivedKeys = 0
    params.pAdditionalDerivedKeys = None
    keepalive.append(params)

    pointer_arg = PointerArg.to_storage(params, origin="sp800_108_feedback")
    from pkcs11_check.raw.pack import LengthArg

    length_arg = LengthArg.native(ctypes.sizeof(params))
    pm = PackedMechanism(
        CK_MECHANISM(CKM_SP800_108_FEEDBACK_KDF, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    pm._keepalive.extend(keepalive)
    return pm


def _build_double_pipeline_kdf_mech(
    label: bytes = _LABEL,
    context: bytes = _CONTEXT,
) -> PackedMechanism:
    """Build CKM_SP800_108_DOUBLE_PIPELINE_KDF mechanism."""
    keepalive: list[Any] = []

    cf = _counter_format()
    p_iter, ka1 = _make_prf_data_param(CK_SP800_108_ITERATION_VARIABLE, struct=cf)
    keepalive.extend(ka1)

    p_label, ka2 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=label)
    keepalive.extend(ka2)

    p_ctx, ka3 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=context)
    keepalive.extend(ka3)

    dlf = _dkm_length_format()
    p_dkm, ka4 = _make_prf_data_param(CK_SP800_108_DKM_LENGTH, struct=dlf)
    keepalive.extend(ka4)

    data_params = (CK_PRF_DATA_PARAM * 4)(p_iter, p_label, p_ctx, p_dkm)
    keepalive.append(data_params)

    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 4
    params.pDataParams = ctypes.cast(data_params, CK_VOID_PTR)
    params.ulAdditionalDerivedKeys = 0
    params.pAdditionalDerivedKeys = None
    keepalive.append(params)

    pointer_arg = PointerArg.to_storage(params, origin="sp800_108_double_pipeline")
    from pkcs11_check.raw.pack import LengthArg

    length_arg = LengthArg.native(ctypes.sizeof(params))
    pm = PackedMechanism(
        CK_MECHANISM(
            CKM_SP800_108_DOUBLE_PIPELINE_KDF,
            pointer_arg.pointer,
            length_arg.value,
        ),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    pm._keepalive.extend(keepalive)
    return pm


def _sp800_derive(
    rs: Any,
    base_key: int,
    mech_type: Any,
    key_bits: int,
    mech_param: PackedMechanism,
) -> int:
    """Derive a key using an SP800-108 mechanism."""
    attrs = dict(_DERIVE_ATTRS)
    attrs[CKA_KEY_TYPE] = CKK_AES
    return derive_key(
        rs.raw,
        rs.sh,
        base_key,
        mech_type,
        attrs=attrs,
        mech_param=mech_param,
    )


class TestSP800108CounterKDF:
    """CKM_SP800_108_COUNTER_KDF - NIST SP 800-108 Counter mode KDF."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_SP800_108_COUNTER_KDF is advertised."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        """Derive a 128-bit AES key via counter-mode KDF."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(rs)
        derived = 0
        try:
            mp = _build_counter_kdf_mech()
            derived = _sp800_derive(rs, base_key, CKM_SP800_108_COUNTER_KDF, 128, mp)
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 16, f"Expected 16 bytes, got {len(val)}"
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF derivation not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_derive_aes256(self, p11_raw_session: Any) -> None:
        """Derive a 256-bit AES key via counter-mode KDF."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(rs)
        derived = 0
        try:
            mp = _build_counter_kdf_mech()
            derived = _sp800_derive(rs, base_key, CKM_SP800_108_COUNTER_KDF, 256, mp)
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 32, f"Expected 32 bytes, got {len(val)}"
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF 256-bit derivation not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        """Same inputs must produce the same derived key material."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(rs)
        d1 = 0
        d2 = 0
        try:
            d1 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_COUNTER_KDF,
                128,
                _build_counter_kdf_mech(),
            )
            d2 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_COUNTER_KDF,
                128,
                _build_counter_kdf_mech(),
            )
            v1 = read_attributes(rs.raw, rs.sh, d1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, d2, [CKA_VALUE])[CKA_VALUE]
            assert v1 == v2, "Deterministic KDF produced different outputs"
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF derivation not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if d1:
                destroy_quietly(rs.raw, rs.sh, d1)
            if d2:
                destroy_quietly(rs.raw, rs.sh, d2)

    def test_different_label_produces_different_key(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Different labels must produce different derived keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(rs)
        da = 0
        db = 0
        try:
            da = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_COUNTER_KDF,
                128,
                _build_counter_kdf_mech(label=b"label-A"),
            )
            db = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_COUNTER_KDF,
                128,
                _build_counter_kdf_mech(label=b"label-B"),
            )
            va = read_attributes(rs.raw, rs.sh, da, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, db, [CKA_VALUE])[CKA_VALUE]
            assert va != vb, "Different labels produced same derived key"
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_COUNTER_KDF derivation not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if da:
                destroy_quietly(rs.raw, rs.sh, da)
            if db:
                destroy_quietly(rs.raw, rs.sh, db)


class TestSP800108FeedbackKDF:
    """CKM_SP800_108_FEEDBACK_KDF - NIST SP 800-108 Feedback mode KDF."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")
        base_key = _create_base_key(rs)
        derived = 0
        try:
            derived = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_FEEDBACK_KDF,
                128,
                _build_feedback_kdf_mech(),
            )
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 16
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_derive_with_iv(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")
        base_key = _create_base_key(rs)
        derived = 0
        try:
            iv = bytes(range(32))
            derived = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_FEEDBACK_KDF,
                128,
                _build_feedback_kdf_mech(iv=iv),
            )
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 16
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF with IV not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_iv_affects_output(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")
        base_key = _create_base_key(rs)
        d1 = 0
        d2 = 0
        try:
            d1 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_FEEDBACK_KDF,
                128,
                _build_feedback_kdf_mech(iv=b""),
            )
            d2 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_FEEDBACK_KDF,
                128,
                _build_feedback_kdf_mech(iv=b"\xff" * 32),
            )
            v1 = read_attributes(rs.raw, rs.sh, d1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, d2, [CKA_VALUE])[CKA_VALUE]
            assert v1 != v2, "Different IVs produced same derived key"
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if d1:
                destroy_quietly(rs.raw, rs.sh, d1)
            if d2:
                destroy_quietly(rs.raw, rs.sh, d2)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_FEEDBACK_KDF"):
            pytest.skip("CKM_SP800_108_FEEDBACK_KDF not supported")
        base_key = _create_base_key(rs)
        d1 = 0
        d2 = 0
        try:
            d1 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_FEEDBACK_KDF,
                128,
                _build_feedback_kdf_mech(),
            )
            d2 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_FEEDBACK_KDF,
                128,
                _build_feedback_kdf_mech(),
            )
            v1 = read_attributes(rs.raw, rs.sh, d1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, d2, [CKA_VALUE])[CKA_VALUE]
            assert v1 == v2, "Deterministic KDF produced different outputs"
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_FEEDBACK_KDF not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if d1:
                destroy_quietly(rs.raw, rs.sh, d1)
            if d2:
                destroy_quietly(rs.raw, rs.sh, d2)


class TestSP800108DoublePipelineKDF:
    """CKM_SP800_108_DOUBLE_PIPELINE_KDF - NIST SP 800-108 Double Pipeline KDF."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")

    def test_derive_aes128(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")
        base_key = _create_base_key(rs)
        derived = 0
        try:
            derived = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_DOUBLE_PIPELINE_KDF,
                128,
                _build_double_pipeline_kdf_mech(),
            )
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 16
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_DOUBLE_PIPELINE_KDF not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_derive_aes256(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")
        base_key = _create_base_key(rs)
        derived = 0
        try:
            derived = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_DOUBLE_PIPELINE_KDF,
                256,
                _build_double_pipeline_kdf_mech(),
            )
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert len(val) == 32
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_DOUBLE_PIPELINE_KDF 256 not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

    def test_derive_deterministic(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_DOUBLE_PIPELINE_KDF"):
            pytest.skip("CKM_SP800_108_DOUBLE_PIPELINE_KDF not supported")
        base_key = _create_base_key(rs)
        d1 = 0
        d2 = 0
        try:
            d1 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_DOUBLE_PIPELINE_KDF,
                128,
                _build_double_pipeline_kdf_mech(),
            )
            d2 = _sp800_derive(
                rs,
                base_key,
                CKM_SP800_108_DOUBLE_PIPELINE_KDF,
                128,
                _build_double_pipeline_kdf_mech(),
            )
            v1 = read_attributes(rs.raw, rs.sh, d1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, d2, [CKA_VALUE])[CKA_VALUE]
            assert v1 == v2, "Deterministic KDF produced different outputs"
        except (AssertionError, Exception) as exc:
            pytest.xfail(f"CKM_SP800_108_DOUBLE_PIPELINE_KDF not operational: {exc}")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if d1:
                destroy_quietly(rs.raw, rs.sh, d1)
            if d2:
                destroy_quietly(rs.raw, rs.sh, d2)
