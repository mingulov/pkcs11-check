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
import hashlib
import hmac
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import PackedMechanism, PointerArg
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CK_DERIVED_KEY,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
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
    CKA_VALUE_LEN,
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
from pkcs11_check.testcases.conftest import assert_correct, xfail_if_known_ckr

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


def _sp800_108_counter_hmac_sha256_reference(
    base_key: bytes,
    label: bytes,
    context: bytes,
    key_bits: int,
) -> bytes:
    """Compute SP800-108 counter-mode HMAC-SHA256 output for the test parameter order."""
    if key_bits <= 0 or key_bits % 8 != 0:
        raise ValueError("key_bits must be a positive multiple of 8")
    wanted = key_bits // 8
    fixed_input_suffix = label + b"\x00" + context + key_bits.to_bytes(4, "big")
    output = b""
    counter = 1
    while len(output) < wanted:
        data = counter.to_bytes(4, "big") + fixed_input_suffix
        output += hmac.new(base_key, data, hashlib.sha256).digest()
        counter += 1
    return output[:wanted]


def _sp800_108_feedback_hmac_sha256_reference(
    base_key: bytes,
    label: bytes,
    context: bytes,
    key_bits: int,
    *,
    iv: bytes = b"",
) -> bytes:
    """Compute SP800-108 feedback-mode HMAC-SHA256 for the test parameter order."""
    if key_bits <= 0 or key_bits % 8 != 0:
        raise ValueError("key_bits must be a positive multiple of 8")
    wanted = key_bits // 8
    fixed_input_suffix = label + b"\x00" + context + key_bits.to_bytes(4, "big")
    output = b""
    previous = iv
    while len(output) < wanted:
        previous = hmac.new(base_key, previous + fixed_input_suffix, hashlib.sha256).digest()
        output += previous
    return output[:wanted]


def _sp800_108_double_pipeline_hmac_sha256_reference(
    base_key: bytes,
    label: bytes,
    context: bytes,
    key_bits: int,
) -> bytes:
    """Compute SP800-108 double-pipeline HMAC-SHA256 for the test parameter order."""
    if key_bits <= 0 or key_bits % 8 != 0:
        raise ValueError("key_bits must be a positive multiple of 8")
    wanted = key_bits // 8
    fixed_input = label + b"\x00" + context + key_bits.to_bytes(4, "big")
    output = b""
    previous_a = fixed_input
    while len(output) < wanted:
        previous_a = hmac.new(base_key, previous_a, hashlib.sha256).digest()
        output += hmac.new(base_key, previous_a + fixed_input, hashlib.sha256).digest()
    return output[:wanted]


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


def _additional_derived_keys(count: int, key_bits: int = 128) -> tuple[Any, list[Any], list[Any]]:
    """Build writable CK_DERIVED_KEY entries for SP800-108 additional outputs."""
    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    keepalive: list[Any] = []
    handles: list[Any] = []
    derived = (CK_DERIVED_KEY * count)()
    for index in range(count):
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_ulong(CKA_VALUE_LEN, key_bits // 8),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        handle = CK_OBJECT_HANDLE(0)
        handles.append(handle)
        keepalive.extend([tmpl, handle])
        derived[index].pTemplate = ctypes.cast(tmpl.ptr, CK_VOID_PTR)
        derived[index].ulAttributeCount = tmpl.count
        derived[index].phKey = ctypes.cast(ctypes.pointer(handle), CK_VOID_PTR)
    keepalive.append(derived)
    return derived, handles, keepalive


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

    p_sep, ka3 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=b"\x00")
    keepalive.extend(ka3)

    p_ctx, ka4 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=context)
    keepalive.extend(ka4)

    dlf = _dkm_length_format()
    p_dkm, ka5 = _make_prf_data_param(CK_SP800_108_DKM_LENGTH, struct=dlf)
    keepalive.extend(ka5)

    data_params = (CK_PRF_DATA_PARAM * 5)(p_iter, p_label, p_sep, p_ctx, p_dkm)
    keepalive.append(data_params)

    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 5
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

    p_iter, ka1 = _make_prf_data_param(CK_SP800_108_ITERATION_VARIABLE)
    keepalive.extend(ka1)

    p_label, ka2 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=label)
    keepalive.extend(ka2)

    p_sep, ka3 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=b"\x00")
    keepalive.extend(ka3)

    p_ctx, ka4 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=context)
    keepalive.extend(ka4)

    dlf = _dkm_length_format()
    p_dkm, ka5 = _make_prf_data_param(CK_SP800_108_DKM_LENGTH, struct=dlf)
    keepalive.extend(ka5)

    data_params = (CK_PRF_DATA_PARAM * 5)(p_iter, p_label, p_sep, p_ctx, p_dkm)
    keepalive.append(data_params)

    params = CK_SP800_108_FEEDBACK_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 5
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

    p_iter, ka1 = _make_prf_data_param(CK_SP800_108_ITERATION_VARIABLE)
    keepalive.extend(ka1)

    p_label, ka2 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=label)
    keepalive.extend(ka2)

    p_sep, ka3 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=b"\x00")
    keepalive.extend(ka3)

    p_ctx, ka4 = _make_prf_data_param(CK_SP800_108_BYTE_ARRAY, data=context)
    keepalive.extend(ka4)

    dlf = _dkm_length_format()
    p_dkm, ka5 = _make_prf_data_param(CK_SP800_108_DKM_LENGTH, struct=dlf)
    keepalive.extend(ka5)

    data_params = (CK_PRF_DATA_PARAM * 5)(p_iter, p_label, p_sep, p_ctx, p_dkm)
    keepalive.append(data_params)

    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 5
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
    attrs[CKA_VALUE_LEN] = key_bits // 8
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
            expected = _sp800_108_counter_hmac_sha256_reference(
                _BASE_KEY_BYTES, _LABEL, _CONTEXT, 128
            )
            assert_correct(
                actual=val,
                expected=expected,
                label="CKM_SP800_108_COUNTER_KDF:C_DeriveKey KAT (AES-128)",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_COUNTER_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_COUNTER_KDF derivation not operational"
            )
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
            expected = _sp800_108_counter_hmac_sha256_reference(
                _BASE_KEY_BYTES, _LABEL, _CONTEXT, 256
            )
            assert_correct(
                actual=val,
                expected=expected,
                label="CKM_SP800_108_COUNTER_KDF:C_DeriveKey KAT (AES-256)",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_COUNTER_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DERIVE_ERROR_RVS,
                "CKM_SP800_108_COUNTER_KDF 256-bit derivation not operational",
            )
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
            assert_correct(
                actual=v1,
                expected=v2,
                label="CKM_SP800_108_COUNTER_KDF:C_DeriveKey determinism",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_COUNTER_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_COUNTER_KDF derivation not operational"
            )
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
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_COUNTER_KDF derivation not operational"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if da:
                destroy_quietly(rs.raw, rs.sh, da)
            if db:
                destroy_quietly(rs.raw, rs.sh, db)

    def test_additional_derived_key_handles(self, p11_raw_session: Any) -> None:
        """CKM_SP800_108_COUNTER_KDF can return additional derived key handles."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")

        base_key = _create_base_key(rs)
        primary = 0
        handle_refs: list[Any] = []
        try:
            mp = _build_counter_kdf_mech()
            derived_array, handle_refs, keepalive = _additional_derived_keys(1, 128)
            mp._keepalive.extend(keepalive)
            mp.params.ulAdditionalDerivedKeys = 1
            mp.params.pAdditionalDerivedKeys = ctypes.cast(derived_array, CK_VOID_PTR)
            try:
                primary = _sp800_derive(rs, base_key, CKM_SP800_108_COUNTER_KDF, 128, mp)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _DERIVE_ERROR_RVS,
                    "CKM_SP800_108_COUNTER_KDF additional derived keys not operational",
                )
                raise

            additional_handles = [int(handle.value) for handle in handle_refs if handle.value]
            assert primary != 0
            assert additional_handles, "C_DeriveKey did not return additional derived key handle"
            for handle in additional_handles:
                attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
                assert isinstance(attrs[CKA_VALUE], bytes)
                assert len(attrs[CKA_VALUE]) == 16
        finally:
            destroy_quietly(rs.raw, rs.sh, primary)
            for handle in (int(handle.value) for handle in handle_refs if handle.value):
                destroy_quietly(rs.raw, rs.sh, handle)
            destroy_quietly(rs.raw, rs.sh, base_key)


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
            expected = _sp800_108_feedback_hmac_sha256_reference(
                _BASE_KEY_BYTES, _LABEL, _CONTEXT, 128
            )
            assert_correct(
                actual=val,
                expected=expected,
                label="CKM_SP800_108_FEEDBACK_KDF:C_DeriveKey KAT (AES-128)",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_FEEDBACK_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_FEEDBACK_KDF not operational")
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
            expected = _sp800_108_feedback_hmac_sha256_reference(
                _BASE_KEY_BYTES, _LABEL, _CONTEXT, 128, iv=iv
            )
            assert_correct(
                actual=val,
                expected=expected,
                label="CKM_SP800_108_FEEDBACK_KDF:C_DeriveKey KAT (AES-128 with IV)",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_FEEDBACK_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_FEEDBACK_KDF with IV not operational"
            )
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
            if v1 == v2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_SP800_108_FEEDBACK_KDF:IV must affect output",
                    operation="C_DeriveKey",
                    mechanism="CKM_SP800_108_FEEDBACK_KDF",
                    summary=(
                        "CKM_SP800_108_FEEDBACK_KDF: two different IVs produced the same "
                        "derived key -- the IV was ignored"
                    ),
                )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_FEEDBACK_KDF not operational")
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
            assert_correct(
                actual=v1,
                expected=v2,
                label="CKM_SP800_108_FEEDBACK_KDF:C_DeriveKey determinism",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_FEEDBACK_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_FEEDBACK_KDF not operational")
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
            expected = _sp800_108_double_pipeline_hmac_sha256_reference(
                _BASE_KEY_BYTES, _LABEL, _CONTEXT, 128
            )
            assert_correct(
                actual=val,
                expected=expected,
                label="CKM_SP800_108_DOUBLE_PIPELINE_KDF:C_DeriveKey KAT (AES-128)",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_DOUBLE_PIPELINE_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_DOUBLE_PIPELINE_KDF not operational"
            )
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
            expected = _sp800_108_double_pipeline_hmac_sha256_reference(
                _BASE_KEY_BYTES, _LABEL, _CONTEXT, 256
            )
            assert_correct(
                actual=val,
                expected=expected,
                label="CKM_SP800_108_DOUBLE_PIPELINE_KDF:C_DeriveKey KAT (AES-256)",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_DOUBLE_PIPELINE_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_DOUBLE_PIPELINE_KDF 256 not operational"
            )
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
            assert_correct(
                actual=v1,
                expected=v2,
                label="CKM_SP800_108_DOUBLE_PIPELINE_KDF:C_DeriveKey determinism",
                operation="C_DeriveKey",
                mechanism="CKM_SP800_108_DOUBLE_PIPELINE_KDF",
            )
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, _DERIVE_ERROR_RVS, "CKM_SP800_108_DOUBLE_PIPELINE_KDF not operational"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if d1:
                destroy_quietly(rs.raw, rs.sh, d1)
            if d2:
                destroy_quietly(rs.raw, rs.sh, d2)
