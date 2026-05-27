"""Regression for PC-1: the GCM NULL-AAD probe must build its CK_AES_GCM_PARAMS
without raising in the subprocess script.

The probe assigned a raw ctypes array to the ``pIv`` pointer field, which raised
inside the generated subprocess script on *every* provider, so the probe died in
setup and never reached ``C_EncryptInit`` (and the real NULL-pAAD-with-nonzero-len
behaviour was never exercised). This meta-test execs the param-building snippet
offline (no provider) and pins that it constructs cleanly with the intended
NULL-pointer + non-zero-length mismatch.
"""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.types_std import CK_AES_GCM_PARAMS
from pkcs11_check.testcases.security.test_parameter_validation import (
    _GCM_NULL_AAD_PARAMS_SNIPPET,
)


def test_gcm_null_aad_params_snippet_builds_without_error() -> None:
    namespace: dict[str, object] = {
        "ctypes": ctypes,
        "CK_AES_GCM_PARAMS": CK_AES_GCM_PARAMS,
    }
    # Must not raise (the original bug raised here on the pIv assignment).
    exec(_GCM_NULL_AAD_PARAMS_SNIPPET, namespace)  # noqa: S102

    params = namespace["params"]
    assert isinstance(params, CK_AES_GCM_PARAMS)
    # The deliberate probe condition: NULL AAD pointer, non-zero AAD length.
    assert params.pAAD is None
    assert params.ulAADLen == 16
    # IV wired through the pointer field (the part that used to fail).
    assert params.pIv is not None
    assert params.ulIvLen == 12
