"""Meta-test: provision_ec_private_key resolution branches (no real module needed).

Uses monkeypatch to stub recipes and a synthetic RS.  Covers:
  (a) create_available + mode "unwrap"  -> calls import_ec_private_key_negotiated, no ctx built
  (b) force-unwrap + fake context       -> unwrap_key called with payload == ec_pkcs8_from_private
                                           output; template has CKA_CLASS=CKO_PRIVATE_KEY +
                                           CKA_KEY_TYPE=CKK_EC and NO CKA_EC_PARAMS (even when
                                           passed in attrs)
  (c) mode "off" + create-absent        -> pytest.skip("...C_CreateObject...")
  (d) build_wrap_context returns None   -> pytest.skip("no wrapping path")
  (e) create_available + negotiated-import raises -> exception propagates, no unwrap path entered
  (f) ValueError from ec_pkcs8_from_private on unwrap path -> pytest.skip

Follows the pattern of tests/test_provision_rsa_private_key.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as _crypto_ec

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.key_encoding import ec_pkcs8_from_private
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_EC,
    CKO_PRIVATE_KEY,
)

# ---------------------------------------------------------------------------
# P-256 test key (generated once; used across all tests for payload checks)
# ---------------------------------------------------------------------------

# P-256 named-curve OID DER: 1.2.840.10045.3.1.7
EC_P256_PARAMS = bytes.fromhex("06082a8648ce3d030107")

_EC_KEY = _crypto_ec.generate_private_key(_crypto_ec.SECP256R1())
EC_SCALAR = _EC_KEY.private_numbers().private_value.to_bytes(32, "big")
EC_KEY_TYPE = CKK_EC

# Expected PKCS#8 payload for our test key
_EXPECTED_PKCS8 = ec_pkcs8_from_private(
    scalar=EC_SCALAR,
    ec_params=EC_P256_PARAMS,
    key_type=EC_KEY_TYPE,
)

# Usage-flag attrs (no EC-specific attrs)
_EC_ATTRS: dict[Any, Any] = {
    CKA_SIGN: True,
    CKA_TOKEN: False,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rs(sh: int, *, has_mech: bool = True) -> Any:
    """Synthetic RS; has_mechanism always returns has_mech."""
    return type(
        "RS",
        (),
        {
            "raw": object(),
            "sh": sh,
            "slot_id": 0,
            "has_mechanism": lambda self, n: has_mech,
        },
    )()


def _reset_cache() -> None:
    _prov._PROFILE_CACHE.clear()


def _make_cfg(key_inject: str, wrap_rsa_bits: int = 2048, wrap_oaep_hash: str = "sha1") -> Any:
    from pkcs11_check.config import P11TestConfig

    return P11TestConfig(
        module=Path("/stub.so"),
        key_inject=key_inject,
        wrap_rsa_bits=wrap_rsa_bits,
        wrap_oaep_hash=wrap_oaep_hash,
    )


# ---------------------------------------------------------------------------
# (a) create_available + mode "unwrap" -> calls import_ec_private_key_negotiated,
#     no wrap context built
# ---------------------------------------------------------------------------


def test_create_available_calls_negotiated_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_available + key_inject=unwrap must call import_ec_private_key_negotiated."""
    import_called: list[dict[str, Any]] = []
    build_ctx_called: list[Any] = []

    def fake_negotiated(
        rs: Any,
        *,
        ec_params: bytes,
        value: bytes,
        key_type: int = int(CKK_EC),
        attrs: Any = None,
        purpose: str = "",
    ) -> int:
        import_called.append({"ec_params": ec_params, "value": value, "attrs": attrs})
        return 101

    def fake_build_ctx(rs: Any, cfg: Any) -> None:
        build_ctx_called.append(True)
        return None

    def fake_ec_import(raw: Any, sh: int, attrs: Any = None, **kwargs: Any) -> int:
        # probe for create_verdict("private") -> "create_available"
        return 999

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr(
        "pkcs11_check.testcases.conftest.import_ec_private_key_negotiated",
        fake_negotiated,
    )
    monkeypatch.setattr(_prov, "build_wrap_context", fake_build_ctx)
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_ec_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_ec_private_key

    rs = _make_rs(sh=400)
    cfg = _make_cfg("unwrap")
    h = provision_ec_private_key(
        rs,
        cfg,
        ec_params=EC_P256_PARAMS,
        value=EC_SCALAR,
        key_type=EC_KEY_TYPE,
        attrs=_EC_ATTRS,
        label="t",
    )

    assert h == 101, "must return import_ec_private_key_negotiated's handle"
    assert len(import_called) == 1, "import_ec_private_key_negotiated must be called once"
    assert import_called[0]["ec_params"] == EC_P256_PARAMS, "correct ec_params forwarded"
    assert import_called[0]["value"] == EC_SCALAR, "correct scalar forwarded"
    assert not build_ctx_called, "build_wrap_context must NOT be called on create_available path"


# ---------------------------------------------------------------------------
# (b) force-unwrap + fake context/strategy -> unwrap_key called with correct payload
#     and template containing CKA_CLASS=CKO_PRIVATE_KEY + CKA_KEY_TYPE=CKK_EC,
#     crucially NO CKA_EC_PARAMS (even when passed in attrs)
# ---------------------------------------------------------------------------


def test_force_unwrap_uses_pkcs8_payload_and_strips_ec_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """force-unwrap must call unwrap_key with PKCS#8 DER payload and strip CKA_EC_PARAMS."""
    fake_ctx = _prov.WrapContext(
        rsa_pub_der=b"\x00" * 32,
        rsa_unwrap_handle=555,
        aes_kek_handle=None,
        sym_kek=None,
        aes_bits=256,
        oaep_hash="sha1",
        strategy_name="RSA_AES_KEY_WRAP",
    )

    class FakeStrategy:
        name = "RSA_AES_KEY_WRAP"
        unwrap_mech = 0x00000250  # CKM_RSA_AES_KEY_WRAP value

        def usable(self, profile: Any) -> bool:
            return True

        def max_target_size(self, ctx: _prov.WrapContext) -> int | None:
            return None  # unbounded

        def wrap(self, ctx: _prov.WrapContext, target: bytes) -> bytes:
            return b"FAKEBLOB:" + target

        def unwrap_mech_param(self, ctx: _prov.WrapContext) -> PackedMechanism | None:
            return None

        def unwrapping_key_handle(self, ctx: _prov.WrapContext) -> int | None:
            return 555

    fake_strategy = FakeStrategy()

    unwrap_calls: list[dict[str, Any]] = []

    def fake_unwrap(
        raw: Any,
        sh: int,
        unwrapping_key: int,
        wrapped_key: bytes,
        mechanism: Any,
        attrs: Any = None,
        *,
        mech_param: PackedMechanism | None = None,
    ) -> int:
        unwrap_calls.append(
            {
                "wrapped_key": wrapped_key,
                "mechanism": mechanism,
                "attrs": dict(attrs) if attrs else {},
                "mech_param": mech_param,
            }
        )
        return 200

    monkeypatch.setattr(_prov, "build_wrap_context", lambda rs, cfg: fake_ctx)
    monkeypatch.setattr(_prov, "DEFAULT_STRATEGIES", [fake_strategy])
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_ec_private_key

    rs = _make_rs(sh=401, has_mech=True)
    cfg = _make_cfg("force-unwrap")

    # Deliberately include CKA_EC_PARAMS and CKA_VALUE in attrs to verify they are stripped
    attrs_with_ec_params: dict[Any, Any] = {
        CKA_SIGN: True,
        CKA_TOKEN: False,
        CKA_EC_PARAMS: EC_P256_PARAMS,  # MUST be stripped
        CKA_VALUE: EC_SCALAR,  # MUST be stripped
    }

    h = provision_ec_private_key(
        rs,
        cfg,
        ec_params=EC_P256_PARAMS,
        value=EC_SCALAR,
        key_type=EC_KEY_TYPE,
        attrs=attrs_with_ec_params,
        label="t",
    )

    assert h == 200, "must return unwrap_key's handle"
    assert len(unwrap_calls) == 1, "unwrap_key must be called exactly once"

    call = unwrap_calls[0]

    # Payload must be the PKCS#8 DER encoding (embedded in FakeStrategy.wrap output)
    expected_blob = b"FAKEBLOB:" + _EXPECTED_PKCS8
    assert call["wrapped_key"] == expected_blob, (
        "wrapped_key blob must derive from ec_pkcs8_from_private output"
    )

    # Template must contain CKA_CLASS=CKO_PRIVATE_KEY and CKA_KEY_TYPE=CKK_EC
    template = call["attrs"]
    assert CKA_CLASS in template, "CKA_CLASS must be in unwrap template"
    assert template[CKA_CLASS] == CKO_PRIVATE_KEY, (
        f"CKA_CLASS must be CKO_PRIVATE_KEY, got {template[CKA_CLASS]!r}"
    )
    assert CKA_KEY_TYPE in template, "CKA_KEY_TYPE must be in unwrap template"
    assert template[CKA_KEY_TYPE] == CKK_EC, (
        f"CKA_KEY_TYPE must be CKK_EC, got {template[CKA_KEY_TYPE]!r}"
    )

    # CKA_EC_PARAMS MUST be absent — it is READ_ONLY on C_UnwrapKey
    assert CKA_EC_PARAMS not in template, (
        "CKA_EC_PARAMS must NOT be in unwrap template (READ_ONLY; softhsm2 returns "
        "CKR_ATTRIBUTE_READ_ONLY); it is derived from the PKCS#8 payload"
    )

    # CKA_VALUE MUST be absent — value comes from the encrypted blob
    assert CKA_VALUE not in template, "CKA_VALUE must NOT be in unwrap template"

    # Caller's usage flags must be forwarded
    assert template.get(CKA_SIGN) is True, "CKA_SIGN from attrs must be in template"


# ---------------------------------------------------------------------------
# (c) mode "off" + create-absent -> pytest.skip("...C_CreateObject...")
# ---------------------------------------------------------------------------


def test_off_create_absent_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """mode=off + create_absent must skip with C_CreateObject message."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_ec_import(raw: Any, sh: int, attrs: Any = None, **kwargs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_ec_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_ec_private_key

    rs = _make_rs(sh=402)
    cfg = _make_cfg("off")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_ec_private_key(
            rs,
            cfg,
            ec_params=EC_P256_PARAMS,
            value=EC_SCALAR,
            key_type=EC_KEY_TYPE,
            attrs=_EC_ATTRS,
            label="t",
        )

    assert "C_CreateObject" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (d) build_wrap_context returns None -> pytest.skip("no wrapping path")
# ---------------------------------------------------------------------------


def test_no_wrap_ctx_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_wrap_context returning None must skip with 'no wrapping path'."""
    monkeypatch.setattr(_prov, "build_wrap_context", lambda rs, cfg: None)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_ec_private_key

    rs = _make_rs(sh=403, has_mech=True)
    cfg = _make_cfg("force-unwrap")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_ec_private_key(
            rs,
            cfg,
            ec_params=EC_P256_PARAMS,
            value=EC_SCALAR,
            key_type=EC_KEY_TYPE,
            attrs=_EC_ATTRS,
            label="t",
        )

    assert "no wrapping path" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (e) create_available + negotiated-import raises -> exception propagates, no unwrap
# ---------------------------------------------------------------------------


def test_create_available_failure_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_available + import_ec_private_key_negotiated raises -> propagates, no unwrap."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED

    build_ctx_called: list[Any] = []

    def fake_negotiated_raises(
        rs: Any,
        *,
        ec_params: bytes,
        value: bytes,
        key_type: int = int(CKK_EC),
        attrs: Any = None,
        purpose: str = "",
    ) -> int:
        raise CkrAssertionError("function failed", CKR_FUNCTION_FAILED)

    def fake_build_ctx(rs: Any, cfg: Any) -> None:
        build_ctx_called.append(True)
        return None

    def fake_ec_import(raw: Any, sh: int, attrs: Any = None, **kwargs: Any) -> int:
        # probe for create_verdict("private") -> "create_available"
        return 999

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr(
        "pkcs11_check.testcases.conftest.import_ec_private_key_negotiated",
        fake_negotiated_raises,
    )
    monkeypatch.setattr(_prov, "build_wrap_context", fake_build_ctx)
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_ec_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_ec_private_key

    rs = _make_rs(sh=404)
    cfg = _make_cfg("unwrap")
    with pytest.raises(CkrAssertionError):
        provision_ec_private_key(
            rs,
            cfg,
            ec_params=EC_P256_PARAMS,
            value=EC_SCALAR,
            key_type=EC_KEY_TYPE,
            attrs=_EC_ATTRS,
            label="t",
        )

    assert not build_ctx_called, "build_wrap_context must NOT be called when create path raises"


# ---------------------------------------------------------------------------
# (f) ValueError from ec_pkcs8_from_private on unwrap path -> pytest.skip
# ---------------------------------------------------------------------------


def test_unsupported_key_type_on_unwrap_path_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """ec_pkcs8_from_private raising ValueError on unwrap path -> pytest.skip."""
    fake_ctx = _prov.WrapContext(
        rsa_pub_der=b"\x00" * 32,
        rsa_unwrap_handle=555,
        aes_kek_handle=None,
        sym_kek=None,
        aes_bits=256,
        oaep_hash="sha1",
        strategy_name="RSA_AES_KEY_WRAP",
    )

    class FakeStrategy:
        name = "RSA_AES_KEY_WRAP"
        unwrap_mech = 0x00000250

        def usable(self, profile: Any) -> bool:
            return True

        def max_target_size(self, ctx: _prov.WrapContext) -> int | None:
            return None

        def wrap(self, ctx: _prov.WrapContext, target: bytes) -> bytes:
            return b"FAKEBLOB:" + target

        def unwrap_mech_param(self, ctx: _prov.WrapContext) -> PackedMechanism | None:
            return None

        def unwrapping_key_handle(self, ctx: _prov.WrapContext) -> int | None:
            return 555

    monkeypatch.setattr(_prov, "build_wrap_context", lambda rs, cfg: fake_ctx)
    monkeypatch.setattr(_prov, "DEFAULT_STRATEGIES", [FakeStrategy()])
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_ec_private_key

    rs = _make_rs(sh=405, has_mech=True)
    cfg = _make_cfg("force-unwrap")

    # Use an unsupported key_type (not CKK_EC/CKK_EC_EDWARDS/CKK_EC_MONTGOMERY) —
    # ec_pkcs8_from_private will raise ValueError naturally, which must become a pytest.skip.
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_ec_private_key(
            rs,
            cfg,
            ec_params=EC_P256_PARAMS,
            value=EC_SCALAR,
            key_type=0xDEADBEEF,  # unsupported key type -> ValueError from ec_pkcs8_from_private
            attrs=_EC_ATTRS,
            label="mykey",
        )

    skip_msg = str(exc_info.value)
    assert "mykey" in skip_msg, "skip message must contain the label"
    assert "PKCS#8" in skip_msg or "encoding" in skip_msg, (
        "skip message must mention PKCS#8 encoding"
    )
