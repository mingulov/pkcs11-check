"""Regression tests for version-aware Wycheproof AES-GMAC parameters.

P11C-010: CKM_AES_GMAC takes a raw IV on the 2.40 interface but a
CK_GCM_PARAMS struct on 3.x (mirroring the ACVP GMAC branch in
``testcases/acvp/aes/test_gcm.py``). The Wycheproof GMAC test previously
passed the raw IV unconditionally.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CK_GCM_PARAMS, CKM_AES_GMAC
from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as aes

_NO_VECTORS = "Wycheproof vectors not available (run `pkcs11-check fetch-data wycheproof`)"


class _GmacSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "AES_GMAC"


@pytest.mark.parametrize("interface_version", ["2.40", "3.0", "3.1", "3.2"])
def test_wycheproof_gmac_param_encoding_follows_interface_version(
    monkeypatch: pytest.MonkeyPatch, interface_version: str
) -> None:
    """GMAC params are raw IV on 2.40 and a CK_GCM_PARAMS struct on 3.x."""
    if not aes._AES_GMAC_VECTORS:
        pytest.skip(_NO_VECTORS)
    vec_id, vec = next((cid, v) for cid, v in aes._AES_GMAC_VECTORS if v["result"] == "valid")
    seen: dict[str, Any] = {}

    def _verify(
        _raw: Any,
        _sh: int,
        _key: int,
        mechanism: Any,
        data: bytes,
        signature: bytes,
        **kwargs: Any,
    ) -> bool:
        seen["mechanism"] = mechanism
        seen["data"] = data
        seen["signature"] = signature
        seen["mech_param"] = kwargs["mech_param"]
        return True

    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_k: 1)
    monkeypatch.setattr(aes, "verify_single", _verify)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_gmac(_GmacSession(), interface_version, vec_id, vec)

    iv = bytes.fromhex(vec["iv"])
    tag = bytes.fromhex(vec["tag"])
    assert seen["mechanism"] == CKM_AES_GMAC
    assert seen["data"] == bytes.fromhex(vec["msg"])
    assert seen["signature"] == tag
    packed = seen["mech_param"]
    if interface_version == "2.40":
        assert int(packed.ck.ulParameterLen) == len(iv)
        assert ctypes.string_at(packed.ck.pParameter, packed.ck.ulParameterLen) == iv
    else:
        assert int(packed.ck.ulParameterLen) == ctypes.sizeof(CK_GCM_PARAMS)
        params = ctypes.cast(packed.ck.pParameter, ctypes.POINTER(CK_GCM_PARAMS)).contents
        assert ctypes.string_at(params.pIv, params.ulIvLen) == iv
        assert int(params.ulIvBits) == len(iv) * 8
        assert not params.pAAD
        assert int(params.ulAADLen) == 0
        assert int(params.ulTagBits) == len(tag) * 8
