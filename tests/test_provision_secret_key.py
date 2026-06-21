"""Meta-test: provision_secret_key resolution branches (no real module needed).

Uses monkeypatch to stub recipes and a synthetic RS whose has_mechanism advertises
wrap mechs.  Covers:
  (a) create_available + key_inject=off  -> calls import_secret_key, returns handle
  (b) create_available + key_inject=unwrap -> same (create path wins over unwrap)
  (c) create_absent   + key_inject=off   -> pytest.skip("...C_CreateObject...")
  (d) create_absent   + key_inject=unwrap -> unwrap path, integrity readback runs
  (e) force-unwrap                        -> never calls import_secret_key
  (f) force-unwrap + wrap_ctx=None        -> pytest.skip("no wrapping path")
  (g) unwrap path + value mismatch        -> pytest.skip("...mismatch...")
  (h) no usable strategy                  -> pytest.skip("no wrapping path: no usable...")

Follows the pattern of tests/test_import_ec_private_key_negotiated.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKO_SECRET_KEY,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rs(sh: int, *, has_mech: bool = True) -> Any:
    """Synthetic RS object; has_mechanism always returns has_mech."""
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


def _make_cfg(key_inject: str, wrap_rsa_bits: int = 2048) -> Any:
    from pkcs11_check.config import P11TestConfig

    return P11TestConfig(
        module=Path("/stub.so"),
        key_inject=key_inject,
        wrap_rsa_bits=wrap_rsa_bits,
    )


_AES_VALUE = bytes(range(32))
_AES_ATTRS: dict[Any, Any] = {
    CKA_ENCRYPT: True,
    CKA_DECRYPT: True,
    CKA_TOKEN: False,
    CKA_SENSITIVE: False,
}
_AES_ATTRS_WITH_VALUE: dict[Any, Any] = {
    **_AES_ATTRS,
    CKA_VALUE: _AES_VALUE,
    CKA_VALUE_LEN: len(_AES_VALUE),
}


# ---------------------------------------------------------------------------
# (a) create_available + key_inject=off -> create path, returns import handle
# ---------------------------------------------------------------------------


def test_create_available_off_calls_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_available + key_inject=off must call import_secret_key and return its handle."""
    import_called: list[tuple[Any, ...]] = []
    unwrap_called: list[Any] = []

    def fake_import(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        import_called.append((raw, sh, key_type, value, attrs))
        return 55

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass  # probe probe cleanup

    def fake_unwrap(*args: Any, **kwargs: Any) -> int:
        unwrap_called.append(True)
        return 0

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=200)
    cfg = _make_cfg("off")
    h = provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert h == 55, "must return import_secret_key's handle"
    assert len(import_called) >= 1, "import_secret_key must be called"
    # The last call must be the actual import (not a probe destroyed afterward).
    # Probe calls go through destroy_quietly; the real import handle is returned.
    assert import_called[-1][3] == _AES_VALUE, "correct value forwarded"
    assert not unwrap_called, "unwrap_key must NOT be called on create_available path"


# ---------------------------------------------------------------------------
# (b) create_available + key_inject=unwrap -> create path (not unwrap)
# ---------------------------------------------------------------------------


def test_create_available_unwrap_still_uses_create(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_available + key_inject=unwrap must still use create (not unwrap)."""
    unwrap_called: list[Any] = []

    def fake_import(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        return 66

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    def fake_unwrap(*args: Any, **kwargs: Any) -> int:
        unwrap_called.append(True)
        return 0

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=201)
    cfg = _make_cfg("unwrap")
    h = provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert h == 66
    assert not unwrap_called, "unwrap_key must NOT be called when create is available"


# ---------------------------------------------------------------------------
# (c) create_absent + key_inject=off -> pytest.skip("...C_CreateObject...")
# ---------------------------------------------------------------------------


def test_create_absent_off_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_absent + key_inject=off must skip with a C_CreateObject message."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_import_absent(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import_absent)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=202)
    cfg = _make_cfg("off")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert "C_CreateObject" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (d) create_absent + key_inject=unwrap -> unwrap path, integrity readback runs
# ---------------------------------------------------------------------------


def test_create_absent_unwrap_path_returns_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_absent + key_inject=unwrap -> unwrap path used, returns unwrapped handle."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_import_absent(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    # unwrap_key records call details and returns a known handle
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
            {"mechanism": mechanism, "mech_param": mech_param, "wrapped_key": wrapped_key}
        )
        return 77

    # read_attributes returns the injected value for integrity check
    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        return {CKA_VALUE: _AES_VALUE}

    # gen_rsa_keypair for build_wrap_context bootstrap
    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    _priv = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub_der = _priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    _pub_nums = _priv.public_key().public_numbers()
    _n_bytes = _pub_nums.n.to_bytes((_pub_nums.n.bit_length() + 7) // 8, "big")
    _e_bytes = _pub_nums.e.to_bytes((_pub_nums.e.bit_length() + 7) // 8, "big")

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return 10, 11

    read_calls: list[Any] = []

    def fake_read_attributes_multi(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        read_calls.append(handle)
        if handle == 10:  # RSA pub key for build_wrap_context
            from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

            return {CKA_MODULUS: _n_bytes, CKA_PUBLIC_EXPONENT: _e_bytes}
        # handle == 77: the unwrapped key, integrity check
        return {CKA_VALUE: _AES_VALUE}

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import_absent)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes_multi)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=203, has_mech=True)
    cfg = _make_cfg("unwrap")
    h = provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert h == 77, "must return unwrap_key's handle"
    assert len(unwrap_calls) == 1, "unwrap_key must be called exactly once"
    call = unwrap_calls[0]
    from pkcs11_check.raw.types_std import CKM_RSA_AES_KEY_WRAP

    assert call["mechanism"] == CKM_RSA_AES_KEY_WRAP, "RSA-AES-KeyWrap envelope expected"
    assert len(call["wrapped_key"]) > 0, "blob must be non-empty"


# ---------------------------------------------------------------------------
# (e) force-unwrap -> never calls import_secret_key, uses unwrap path
# ---------------------------------------------------------------------------


def test_force_unwrap_skips_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """force-unwrap must NEVER call import_secret_key, always go to unwrap path."""
    import_called: list[Any] = []

    def fake_import(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        import_called.append(True)
        return 0

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

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
        unwrap_calls.append({"mechanism": mechanism, "wrapped_key": wrapped_key})
        return 88

    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa

    _priv = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub_nums = _priv.public_key().public_numbers()
    _n_bytes = _pub_nums.n.to_bytes((_pub_nums.n.bit_length() + 7) // 8, "big")
    _e_bytes = _pub_nums.e.to_bytes((_pub_nums.e.bit_length() + 7) // 8, "big")

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return 20, 21

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if handle == 20:
            from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

            return {CKA_MODULUS: _n_bytes, CKA_PUBLIC_EXPONENT: _e_bytes}
        return {CKA_VALUE: _AES_VALUE}

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=204, has_mech=True)
    cfg = _make_cfg("force-unwrap")
    h = provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert h == 88
    # import_secret_key may be called for the probe ONLY (via _probe_secret during
    # profile_for). On force-unwrap path, profile creation is NOT probed at all —
    # we go straight to wrap context. So import_called must be empty.
    assert not import_called, "import_secret_key must never be called on force-unwrap"
    assert len(unwrap_calls) == 1
    from pkcs11_check.raw.types_std import CKM_RSA_AES_KEY_WRAP

    assert unwrap_calls[0]["mechanism"] == CKM_RSA_AES_KEY_WRAP


# ---------------------------------------------------------------------------
# (f) force-unwrap + build_wrap_context returns None -> skip("no wrapping path")
# ---------------------------------------------------------------------------


def test_force_unwrap_no_ctx_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """force-unwrap when build_wrap_context returns None must skip."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_KEY_SIZE_RANGE

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        raise CkrAssertionError("size range", CKR_KEY_SIZE_RANGE)

    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=205, has_mech=True)
    cfg = _make_cfg("force-unwrap")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert "no wrapping path" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (g) unwrap path + value mismatch -> skip("...mismatch...")
# ---------------------------------------------------------------------------


def test_value_mismatch_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-sensitive key value mismatch on readback must skip (corrupted setup)."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_import_absent(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

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
        return 90

    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa

    _priv = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub_nums = _priv.public_key().public_numbers()
    _n_bytes = _pub_nums.n.to_bytes((_pub_nums.n.bit_length() + 7) // 8, "big")
    _e_bytes = _pub_nums.e.to_bytes((_pub_nums.e.bit_length() + 7) // 8, "big")

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return 30, 31

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if handle == 30:
            from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

            return {CKA_MODULUS: _n_bytes, CKA_PUBLIC_EXPONENT: _e_bytes}
        # Return WRONG value to trigger mismatch
        return {CKA_VALUE: b"\xff" * 32}

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import_absent)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=206, has_mech=True)
    cfg = _make_cfg("unwrap")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert "mismatch" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (h) no usable strategy -> skip("no wrapping path: no usable wrap mechanism...")
# ---------------------------------------------------------------------------


def test_no_strategy_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """No usable wrap mechanism for the module -> skip with 'no usable wrap mechanism'."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_import_absent(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa

    _priv = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub_nums = _priv.public_key().public_numbers()
    _n_bytes = _pub_nums.n.to_bytes((_pub_nums.n.bit_length() + 7) // 8, "big")
    _e_bytes = _pub_nums.e.to_bytes((_pub_nums.e.bit_length() + 7) // 8, "big")

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return 40, 41

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

        return {CKA_MODULUS: _n_bytes, CKA_PUBLIC_EXPONENT: _e_bytes}

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import_absent)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    # has_mech=False so supports_unwrap_mech returns False for all strategies
    rs = _make_rs(sh=207, has_mech=False)
    cfg = _make_cfg("unwrap")
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert "no usable wrap mechanism" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (i) unwrap path: attrs template strips CKA_VALUE and CKA_VALUE_LEN
# ---------------------------------------------------------------------------


def test_unwrap_template_strips_value_attrs(monkeypatch: pytest.MonkeyPatch) -> None:
    """unwrap call must not include CKA_VALUE or CKA_VALUE_LEN in the template."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_import_absent(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

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
        unwrap_calls.append({"attrs": dict(attrs) if attrs else {}})
        return 91

    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa

    _priv = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub_nums = _priv.public_key().public_numbers()
    _n_bytes = _pub_nums.n.to_bytes((_pub_nums.n.bit_length() + 7) // 8, "big")
    _e_bytes = _pub_nums.e.to_bytes((_pub_nums.e.bit_length() + 7) // 8, "big")

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return 50, 51

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if handle == 50:
            from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

            return {CKA_MODULUS: _n_bytes, CKA_PUBLIC_EXPONENT: _e_bytes}
        return {CKA_VALUE: _AES_VALUE}

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import_absent)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=208, has_mech=True)
    cfg = _make_cfg("unwrap")
    provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS_WITH_VALUE, label="t")

    assert len(unwrap_calls) == 1
    template_attrs = unwrap_calls[0]["attrs"]
    assert CKA_VALUE not in template_attrs, "CKA_VALUE must be stripped from unwrap template"
    assert CKA_VALUE_LEN not in template_attrs, (
        "CKA_VALUE_LEN must be stripped from unwrap template"
    )


# ---------------------------------------------------------------------------
# (j) sensitive key: no readback (read_attributes not called for integrity)
# ---------------------------------------------------------------------------


def test_sensitive_key_skips_integrity_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sensitive key: value-integrity readback must NOT be attempted."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_import_absent(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

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
        return 92

    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa

    _priv = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub_nums = _priv.public_key().public_numbers()
    _n_bytes = _pub_nums.n.to_bytes((_pub_nums.n.bit_length() + 7) // 8, "big")
    _e_bytes = _pub_nums.e.to_bytes((_pub_nums.e.bit_length() + 7) // 8, "big")

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return 60, 61

    read_calls: list[int] = []

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        read_calls.append(handle)
        from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

        return {CKA_MODULUS: _n_bytes, CKA_PUBLIC_EXPONENT: _e_bytes}

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import_absent)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=209, has_mech=True)
    cfg = _make_cfg("unwrap")
    sensitive_attrs = {**_AES_ATTRS, CKA_SENSITIVE: True}
    h = provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, sensitive_attrs, label="t")

    assert h == 92
    # read_attributes called for RSA pub key (handle=60) but NOT for the unwrapped key (92)
    assert 92 not in read_calls, "read_attributes must NOT be called for sensitive key integrity"


# ---------------------------------------------------------------------------
# (k) unwrap template includes CKA_CLASS and CKA_KEY_TYPE (regression: real
#     modules return CKR_ARGUMENTS_BAD when these are absent)
# ---------------------------------------------------------------------------


def test_unwrap_template_includes_class_and_key_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_UnwrapKey template must contain CKA_CLASS==CKO_SECRET_KEY and CKA_KEY_TYPE==key_type.

    Without these a real module (softhsm2, etc.) returns CKR_ARGUMENTS_BAD or
    CKR_TEMPLATE_INCOMPLETE.  The fake unwrap captures attrs and asserts both are present.
    """
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    def fake_import_absent(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

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
        unwrap_calls.append({"attrs": dict(attrs) if attrs else {}})
        return 93

    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa

    _priv = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub_nums = _priv.public_key().public_numbers()
    _n_bytes = _pub_nums.n.to_bytes((_pub_nums.n.bit_length() + 7) // 8, "big")
    _e_bytes = _pub_nums.e.to_bytes((_pub_nums.e.bit_length() + 7) // 8, "big")

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return 70, 71

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        if handle == 70:
            from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

            return {CKA_MODULUS: _n_bytes, CKA_PUBLIC_EXPONENT: _e_bytes}
        return {CKA_VALUE: _AES_VALUE}

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import_absent)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=210, has_mech=True)
    cfg = _make_cfg("unwrap")
    provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    assert len(unwrap_calls) == 1, "unwrap_key must be called exactly once"
    template_attrs = unwrap_calls[0]["attrs"]
    assert CKA_CLASS in template_attrs, "CKA_CLASS must be present in unwrap template"
    assert template_attrs[CKA_CLASS] == CKO_SECRET_KEY, (
        f"CKA_CLASS must be CKO_SECRET_KEY, got {template_attrs[CKA_CLASS]!r}"
    )
    assert CKA_KEY_TYPE in template_attrs, "CKA_KEY_TYPE must be present in unwrap template"
    assert template_attrs[CKA_KEY_TYPE] == CKK_AES, (
        f"CKA_KEY_TYPE must equal the passed key_type (CKK_AES), "
        f"got {template_attrs[CKA_KEY_TYPE]!r}"
    )
