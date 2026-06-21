"""Meta-test: provision_rsa_private_key resolution branches (no real module needed).

Uses monkeypatch to stub recipes and a synthetic RS.  Covers:
  (a) create_available + mode "unwrap"  -> calls import_rsa_private_key_negotiated, no ctx built
  (b) force-unwrap + fake context       -> unwrap_key called, template=CKA_CLASS+CKA_KEY_TYPE+attrs,
                                           payload == rsa_pkcs8_from_crt(...)
  (c) mode "off" + create-absent        -> pytest.skip("...C_CreateObject...")
  (d) build_wrap_context returns None   -> pytest.skip("no wrapping path")

Follows the pattern of tests/test_provision_secret_key.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.key_encoding import rsa_pkcs8_from_crt
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_RSA,
    CKO_PRIVATE_KEY,
)

# ---------------------------------------------------------------------------
# RSA-2048 test key (generated once; used across all tests for payload checks)
# ---------------------------------------------------------------------------

_RSA_KEY = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PRIV_NUMS = _RSA_KEY.private_numbers()
_RSA_PUB_NUMS = _RSA_PRIV_NUMS.public_numbers

_N_INT = _RSA_PUB_NUMS.n
_E_INT = _RSA_PUB_NUMS.e
_D_INT = _RSA_PRIV_NUMS.d
_P_INT = _RSA_PRIV_NUMS.p
_Q_INT = _RSA_PRIV_NUMS.q
_DMP1_INT = _RSA_PRIV_NUMS.dmp1
_DMQ1_INT = _RSA_PRIV_NUMS.dmq1
_IQMP_INT = _RSA_PRIV_NUMS.iqmp


def _int_to_bytes(v: int) -> bytes:
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


RSA_N = _int_to_bytes(_N_INT)
RSA_E = _int_to_bytes(_E_INT)
RSA_D = _int_to_bytes(_D_INT)
RSA_P = _int_to_bytes(_P_INT)
RSA_Q = _int_to_bytes(_Q_INT)
RSA_DMP1 = _int_to_bytes(_DMP1_INT)
RSA_DMQ1 = _int_to_bytes(_DMQ1_INT)
RSA_IQMP = _int_to_bytes(_IQMP_INT)

# Expected PKCS#8 payload for our test key
_EXPECTED_PKCS8 = rsa_pkcs8_from_crt(
    n=RSA_N,
    e=RSA_E,
    d=RSA_D,
    p=RSA_P,
    q=RSA_Q,
    dmp1=RSA_DMP1,
    dmq1=RSA_DMQ1,
    iqmp=RSA_IQMP,
)

# Usage-flag attrs (no CRT components)
_RSA_ATTRS: dict[Any, Any] = {
    CKA_SIGN: True,
    CKA_DECRYPT: True,
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
# (a) create_available + mode "unwrap" -> calls import_rsa_private_key_negotiated,
#     no wrap context built
# ---------------------------------------------------------------------------


def test_create_available_calls_negotiated_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_available + key_inject=unwrap must call import_rsa_private_key_negotiated."""
    import_called: list[dict[str, Any]] = []
    build_ctx_called: list[Any] = []

    def fake_negotiated(
        rs: Any,
        *,
        n: bytes,
        e: bytes,
        d: bytes,
        p: bytes,
        q: bytes,
        dmp1: bytes,
        dmq1: bytes,
        iqmp: bytes,
        attrs: Any = None,
        purpose: str = "",
    ) -> int:
        import_called.append({"n": n, "attrs": attrs})
        return 101

    def fake_build_ctx(rs: Any, cfg: Any) -> None:
        build_ctx_called.append(True)
        return None

    def fake_ec_import(raw: Any, sh: int, **kwargs: Any) -> int:
        # probe for create_verdict("private") → "create_available"
        return 999

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr(
        "pkcs11_check.testcases.conftest.import_rsa_private_key_negotiated",
        fake_negotiated,
    )
    monkeypatch.setattr(_prov, "build_wrap_context", fake_build_ctx)
    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_private_key", fake_ec_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_rsa_private_key

    rs = _make_rs(sh=300)
    cfg = _make_cfg("unwrap")
    h = provision_rsa_private_key(
        rs,
        cfg,
        n=RSA_N,
        e=RSA_E,
        d=RSA_D,
        p=RSA_P,
        q=RSA_Q,
        dmp1=RSA_DMP1,
        dmq1=RSA_DMQ1,
        iqmp=RSA_IQMP,
        attrs=_RSA_ATTRS,
        label="t",
    )

    assert h == 101, "must return import_rsa_private_key_negotiated's handle"
    assert len(import_called) == 1, "import_rsa_private_key_negotiated must be called once"
    assert import_called[0]["n"] == RSA_N, "correct modulus forwarded"
    assert not build_ctx_called, "build_wrap_context must NOT be called on create_available path"


# ---------------------------------------------------------------------------
# (b) force-unwrap + fake context/strategy -> unwrap_key called with correct payload
#     and template containing CKA_CLASS=CKO_PRIVATE_KEY + CKA_KEY_TYPE=CKK_RSA,
#     NO CRT component attrs; payload == rsa_pkcs8_from_crt(...)
# ---------------------------------------------------------------------------


def test_force_unwrap_uses_pkcs8_payload_and_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """force-unwrap must call unwrap_key with PKCS#8 DER payload and correct template."""
    # Build a fake WrapContext and strategy that always succeed
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
            # Return a fake "encrypted" blob
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

    from pkcs11_check.testcases._provisioning import provision_rsa_private_key

    rs = _make_rs(sh=301, has_mech=True)
    cfg = _make_cfg("force-unwrap")
    h = provision_rsa_private_key(
        rs,
        cfg,
        n=RSA_N,
        e=RSA_E,
        d=RSA_D,
        p=RSA_P,
        q=RSA_Q,
        dmp1=RSA_DMP1,
        dmq1=RSA_DMQ1,
        iqmp=RSA_IQMP,
        attrs=_RSA_ATTRS,
        label="t",
    )

    assert h == 200, "must return unwrap_key's handle"
    assert len(unwrap_calls) == 1, "unwrap_key must be called exactly once"

    call = unwrap_calls[0]

    # Payload must be the PKCS#8 DER encoding (embedded in FakeStrategy.wrap output)
    expected_blob = b"FAKEBLOB:" + _EXPECTED_PKCS8
    assert call["wrapped_key"] == expected_blob, (
        "wrapped_key blob must derive from rsa_pkcs8_from_crt output"
    )

    # Template must contain CKA_CLASS=CKO_PRIVATE_KEY and CKA_KEY_TYPE=CKK_RSA
    template = call["attrs"]
    assert CKA_CLASS in template, "CKA_CLASS must be in unwrap template"
    assert template[CKA_CLASS] == CKO_PRIVATE_KEY, (
        f"CKA_CLASS must be CKO_PRIVATE_KEY, got {template[CKA_CLASS]!r}"
    )
    assert CKA_KEY_TYPE in template, "CKA_KEY_TYPE must be in unwrap template"
    assert template[CKA_KEY_TYPE] == CKK_RSA, (
        f"CKA_KEY_TYPE must be CKK_RSA, got {template[CKA_KEY_TYPE]!r}"
    )

    # Template must NOT contain CRT component attrs — only usage flags from attrs
    from pkcs11_check.raw.types_std import (
        CKA_COEFFICIENT,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_PRIVATE_EXPONENT,
    )

    crt_attrs = {
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
        CKA_PRIVATE_EXPONENT,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_COEFFICIENT,
    }
    for attr in crt_attrs:
        assert attr not in template, f"CRT attr {attr!r} must NOT be in unwrap template"

    # Caller's usage flags must be forwarded
    assert template.get(CKA_SIGN) is True, "CKA_SIGN from attrs must be in template"
    assert template.get(CKA_DECRYPT) is True, "CKA_DECRYPT from attrs must be in template"


# ---------------------------------------------------------------------------
# (e) create_available + negotiated-import RAISES -> exception propagates, no unwrap
# ---------------------------------------------------------------------------


def test_create_available_failure_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_available + import_rsa_private_key_negotiated raises -> propagates, no unwrap."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED

    build_ctx_called: list[Any] = []

    def fake_negotiated_raises(
        rs: Any,
        *,
        n: bytes,
        e: bytes,
        d: bytes,
        p: bytes,
        q: bytes,
        dmp1: bytes,
        dmq1: bytes,
        iqmp: bytes,
        attrs: Any = None,
        purpose: str = "",
    ) -> int:
        raise CkrAssertionError("function failed", CKR_FUNCTION_FAILED)

    def fake_build_ctx(rs: Any, cfg: Any) -> None:
        build_ctx_called.append(True)
        return None

    def fake_ec_import(raw: Any, sh: int, **kwargs: Any) -> int:
        # probe for create_verdict("private") → "create_available"
        return 999

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr(
        "pkcs11_check.testcases.conftest.import_rsa_private_key_negotiated",
        fake_negotiated_raises,
    )
    monkeypatch.setattr(_prov, "build_wrap_context", fake_build_ctx)
    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_private_key", fake_ec_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_rsa_private_key

    rs = _make_rs(sh=304)
    cfg = _make_cfg("unwrap")
    with pytest.raises(CkrAssertionError):
        provision_rsa_private_key(
            rs,
            cfg,
            n=RSA_N,
            e=RSA_E,
            d=RSA_D,
            p=RSA_P,
            q=RSA_Q,
            dmp1=RSA_DMP1,
            dmq1=RSA_DMQ1,
            iqmp=RSA_IQMP,
            attrs=_RSA_ATTRS,
            label="t",
        )

    assert not build_ctx_called, "build_wrap_context must NOT be called when create path raises"


# ---------------------------------------------------------------------------
# (f) force-unwrap -> import_rsa_private_key_negotiated is NEVER called
# ---------------------------------------------------------------------------


def test_force_unwrap_does_not_call_create(monkeypatch: pytest.MonkeyPatch) -> None:
    """force-unwrap must NOT call import_rsa_private_key_negotiated."""
    negotiated_called: list[Any] = []

    def fake_negotiated_not_called(rs: Any, **kwargs: Any) -> int:
        negotiated_called.append(True)
        return 0

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
        return 201

    monkeypatch.setattr(
        "pkcs11_check.testcases.conftest.import_rsa_private_key_negotiated",
        fake_negotiated_not_called,
    )
    monkeypatch.setattr(_prov, "build_wrap_context", lambda rs, cfg: fake_ctx)
    monkeypatch.setattr(_prov, "DEFAULT_STRATEGIES", [FakeStrategy()])
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_rsa_private_key

    rs = _make_rs(sh=305, has_mech=True)
    cfg = _make_cfg("force-unwrap")
    h = provision_rsa_private_key(
        rs,
        cfg,
        n=RSA_N,
        e=RSA_E,
        d=RSA_D,
        p=RSA_P,
        q=RSA_Q,
        dmp1=RSA_DMP1,
        dmq1=RSA_DMQ1,
        iqmp=RSA_IQMP,
        attrs=_RSA_ATTRS,
        label="t",
    )

    assert h == 201, "must return unwrap_key's handle"
    assert not negotiated_called, (
        "import_rsa_private_key_negotiated must NOT be called in force-unwrap mode"
    )


# ---------------------------------------------------------------------------
# (c) mode "off" + create-absent -> pytest.skip("...C_CreateObject...")
# ---------------------------------------------------------------------------


def test_off_create_absent_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """mode=off + create_absent must skip with C_CreateObject message."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_ec_import(raw: Any, sh: int, **kwargs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_private_key", fake_ec_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_rsa_private_key

    rs = _make_rs(sh=302)
    cfg = _make_cfg("off")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_rsa_private_key(
            rs,
            cfg,
            n=RSA_N,
            e=RSA_E,
            d=RSA_D,
            p=RSA_P,
            q=RSA_Q,
            dmp1=RSA_DMP1,
            dmq1=RSA_DMQ1,
            iqmp=RSA_IQMP,
            attrs=_RSA_ATTRS,
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

    from pkcs11_check.testcases._provisioning import provision_rsa_private_key

    rs = _make_rs(sh=303, has_mech=True)
    cfg = _make_cfg("force-unwrap")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_rsa_private_key(
            rs,
            cfg,
            n=RSA_N,
            e=RSA_E,
            d=RSA_D,
            p=RSA_P,
            q=RSA_Q,
            dmp1=RSA_DMP1,
            dmq1=RSA_DMQ1,
            iqmp=RSA_IQMP,
            attrs=_RSA_ATTRS,
            label="t",
        )

    assert "no wrapping path" in str(exc_info.value)
