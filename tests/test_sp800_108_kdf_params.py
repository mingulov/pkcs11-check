"""Parameter-shape tests for SP800-108 KDF mechanism builders."""

from __future__ import annotations

import ctypes
from typing import Any, cast

from pkcs11_check.raw.types_std import (
    CK_PRF_DATA_PARAM,
    CK_SP800_108_COUNTER_FORMAT,
    CK_SP800_108_ITERATION_VARIABLE,
)
from pkcs11_check.testcases import test_sp800_108_kdf


def _first_data_param(mech: Any) -> CK_PRF_DATA_PARAM:
    data_params = ctypes.cast(mech.params.pDataParams, ctypes.POINTER(CK_PRF_DATA_PARAM))
    return cast(CK_PRF_DATA_PARAM, data_params[0])


def test_counter_iteration_variable_uses_counter_format_pointer() -> None:
    param = _first_data_param(test_sp800_108_kdf._build_counter_kdf_mech())

    assert param.type == CK_SP800_108_ITERATION_VARIABLE
    assert param.pValue is not None
    assert param.ulValueLen == ctypes.sizeof(CK_SP800_108_COUNTER_FORMAT)


def test_feedback_iteration_variable_uses_null_value() -> None:
    param = _first_data_param(test_sp800_108_kdf._build_feedback_kdf_mech())

    assert param.type == CK_SP800_108_ITERATION_VARIABLE
    assert param.pValue is None
    assert param.ulValueLen == 0


def test_double_pipeline_iteration_variable_uses_null_value() -> None:
    param = _first_data_param(test_sp800_108_kdf._build_double_pipeline_kdf_mech())

    assert param.type == CK_SP800_108_ITERATION_VARIABLE
    assert param.pValue is None
    assert param.ulValueLen == 0
