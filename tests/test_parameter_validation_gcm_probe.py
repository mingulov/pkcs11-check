"""Regression for PC-1: the GCM NULL-AAD probe must build its CK_AES_GCM_PARAMS
without raising.

The probe assigned a raw ctypes array to the ``pIv`` pointer field, which raised
on *every* provider, so the probe died in setup and never reached
``C_EncryptInit`` (and the real NULL-pAAD-with-nonzero-len behaviour was never
exercised). This meta-test builds the params offline (no provider) and pins that
they construct cleanly with the intended NULL-pointer + non-zero-length mismatch.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import CK_AES_GCM_PARAMS
from pkcs11_check.testcases._probes.parameter_validation import build_gcm_null_aad_params


def test_gcm_null_aad_params_builds_without_error() -> None:
    # Must not raise (the original bug raised on the pIv assignment).
    params, _iv_keepalive = build_gcm_null_aad_params()

    assert isinstance(params, CK_AES_GCM_PARAMS)
    # The deliberate probe condition: NULL AAD pointer, non-zero AAD length.
    assert params.pAAD is None
    assert params.ulAADLen == 16
    # IV wired through the pointer field (the part that used to fail).
    assert params.pIv is not None
    assert params.ulIvLen == 12
