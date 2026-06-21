"""Meta-test: build_wrap_context bootstrap path (no real module needed).

Uses monkeypatch to stub gen_rsa_keypair, read_attributes, and unwrap_key so all
bootstrap scenarios can be exercised without a real PKCS#11 module.
Follows the pattern of tests/test_import_ec_private_key_negotiated.py.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rs(sh: int) -> Any:
    """Synthetic RS object with no real module."""
    return type(
        "RS",
        (),
        {
            "raw": object(),
            "sh": sh,
            "slot_id": 0,
            "has_mechanism": lambda self, n: True,
        },
    )()


def _reset_cache() -> None:
    _prov._PROFILE_CACHE.clear()


def _real_rsa_numbers(bits: int = 2048) -> tuple[bytes, bytes]:
    """Generate a real RSA key and return (n_be_bytes, e_be_bytes)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub_numbers = priv.public_key().public_numbers()
    n = pub_numbers.n
    e = pub_numbers.e
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return n_bytes, e_bytes


def _stub_keygen_and_attrs(
    monkeypatch: pytest.MonkeyPatch,
    pub_h: int,
    priv_h: int,
    n_bytes: bytes,
    e_bytes: bytes,
) -> None:
    """Monkeypatch gen_rsa_keypair and read_attributes to avoid a real module."""

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        return pub_h, priv_h

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        return {CKA_MODULUS: n_bytes, CKA_PUBLIC_EXPONENT: e_bytes}

    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)


# ---------------------------------------------------------------------------
# Success: bootstrap builds a usable WrapContext (explicit hash — no negotiation)
# ---------------------------------------------------------------------------


def test_bootstrap_builds_usable_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """bootstrap success -> WrapContext.rsa_pub_der round-trips to same modulus/exponent."""
    pub_h = 10
    priv_h = 11
    n_bytes, e_bytes = _real_rsa_numbers(2048)

    _stub_keygen_and_attrs(monkeypatch, pub_h, priv_h, n_bytes, e_bytes)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context, profile_for

    cfg = P11TestConfig(
        module=Path("/ignored.so"),
        key_inject="unwrap",
        wrap_rsa_bits=2048,
        wrap_oaep_hash="sha1",  # explicit: no auto-negotiation
    )
    rs = _make_rs(sh=100)
    ctx = build_wrap_context(rs, cfg)

    assert ctx is not None
    assert ctx.unwrapping_key_handle == priv_h

    # rsa_pub_der must be set and must round-trip back to the same n/e
    assert ctx.rsa_pub_der is not None
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    loaded_pub = load_der_public_key(ctx.rsa_pub_der)
    assert isinstance(loaded_pub, RSAPublicKey)
    loaded_nums = loaded_pub.public_numbers()
    expected_n = int.from_bytes(n_bytes, "big")
    expected_e = int.from_bytes(e_bytes, "big")
    assert loaded_nums.n == expected_n
    assert loaded_nums.e == expected_e

    # profile_for(rs).rsa_pub_der_probe must equal ctx.rsa_pub_der
    assert profile_for(rs).rsa_pub_der_probe == ctx.rsa_pub_der


# ---------------------------------------------------------------------------
# Size escalation: 2048 refused -> 3072 succeeds (explicit hash)
# ---------------------------------------------------------------------------


def test_size_escalation_2048_refused_3072_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """gen_rsa_keypair raises CKR_KEY_SIZE_RANGE for 2048 -> must retry at 3072."""
    pub_h = 20
    priv_h = 21
    n_bytes, e_bytes = _real_rsa_numbers(3072)
    calls: list[int] = []

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        calls.append(bits)
        if bits == 2048:
            raise CkrAssertionError("key size range", CKR_KEY_SIZE_RANGE)
        return pub_h, priv_h

    def fake_read_attributes(
        raw: Any, session: int, handle: int, attr_types: Any
    ) -> dict[int, Any]:
        return {CKA_MODULUS: n_bytes, CKA_PUBLIC_EXPONENT: e_bytes}

    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context

    cfg = P11TestConfig(
        module=Path("/ignored.so"),
        key_inject="unwrap",
        wrap_rsa_bits=2048,
        wrap_oaep_hash="sha1",  # explicit: no auto-negotiation
    )
    rs = _make_rs(sh=101)
    ctx = build_wrap_context(rs, cfg)

    assert ctx is not None
    assert ctx.unwrapping_key_handle == priv_h
    # gen_rsa_keypair must have been called with 2048 first, then 3072
    assert calls == [2048, 3072]


# ---------------------------------------------------------------------------
# All sizes refused -> returns None
# ---------------------------------------------------------------------------


def test_all_sizes_refused_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """gen_rsa_keypair refuses all sizes -> build_wrap_context returns None."""

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        raise CkrAssertionError("key size range", CKR_KEY_SIZE_RANGE)

    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context

    cfg = P11TestConfig(module=Path("/ignored.so"), key_inject="unwrap", wrap_rsa_bits=2048)
    rs = _make_rs(sh=102)
    ctx = build_wrap_context(rs, cfg)

    assert ctx is None


# ---------------------------------------------------------------------------
# Unexpected CKR propagates (must not be swallowed as None)
# ---------------------------------------------------------------------------


def test_unexpected_keygen_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unexpected keygen CKR (not a size-refusal) must re-raise, not become None."""
    from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR

    def fake_gen_rsa_keypair(
        raw: Any, session: int, bits: int = 2048, **kwargs: Any
    ) -> tuple[int, int]:
        raise CkrAssertionError("device error", CKR_DEVICE_ERROR)

    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context

    cfg = P11TestConfig(module=Path("/ignored.so"), key_inject="unwrap", wrap_rsa_bits=2048)
    rs = _make_rs(sh=103)

    with pytest.raises(CkrAssertionError):
        build_wrap_context(rs, cfg)


# ---------------------------------------------------------------------------
# OAEP hash auto-negotiation: sha256 works -> oaep_hash == "sha256"
# ---------------------------------------------------------------------------


def test_auto_negotiate_sha256_preferred(monkeypatch: pytest.MonkeyPatch) -> None:
    """auto mode: sha256 unwrap succeeds on first probe -> oaep_hash == 'sha256'."""
    pub_h = 30
    priv_h = 31
    sha256_handle = 40
    n_bytes, e_bytes = _real_rsa_numbers(2048)
    destroy_calls: list[int] = []

    _stub_keygen_and_attrs(monkeypatch, pub_h, priv_h, n_bytes, e_bytes)

    def fake_unwrap_key(
        raw: Any,
        session: int,
        unwrapping_key: int,
        wrapped_key: bytes,
        mechanism: Any,
        attrs: Any = None,
        *,
        mech_param: Any = None,
    ) -> int:
        # sha256 attempt succeeds unconditionally
        return sha256_handle

    def fake_destroy_quietly(raw: Any, session: int, handle: int) -> None:
        destroy_calls.append(handle)

    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy_quietly)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context

    cfg = P11TestConfig(module=Path("/ignored.so"), key_inject="unwrap", wrap_oaep_hash="auto")
    rs = _make_rs(sh=200)
    ctx = build_wrap_context(rs, cfg)

    assert ctx is not None
    assert ctx.oaep_hash == "sha256"
    # The throwaway probe key must have been destroyed
    assert sha256_handle in destroy_calls


# ---------------------------------------------------------------------------
# OAEP hash auto-negotiation: sha256 fails, sha1 succeeds -> oaep_hash == "sha1"
# ---------------------------------------------------------------------------


def test_auto_negotiate_sha1_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """auto mode: sha256 unwrap raises, sha1 succeeds -> oaep_hash == 'sha1'."""
    pub_h = 50
    priv_h = 51
    sha1_handle = 60
    n_bytes, e_bytes = _real_rsa_numbers(2048)
    destroy_calls: list[int] = []
    unwrap_attempts: list[str] = []

    _stub_keygen_and_attrs(monkeypatch, pub_h, priv_h, n_bytes, e_bytes)

    def fake_unwrap_key(
        raw: Any,
        session: int,
        unwrapping_key: int,
        wrapped_key: bytes,
        mechanism: Any,
        attrs: Any = None,
        *,
        mech_param: Any = None,
    ) -> int:
        # Discriminate by blob length: sha256-OAEP adds a larger overhead than sha1-OAEP
        # for the same 16-byte payload (256-byte key = 2048-bit RSA).
        # sha256 overhead: 2 + 2*32 + 1 = 67 → blob ≠ sha1 overhead: 2 + 2*20 + 1 = 43.
        # Simpler: just track call order.
        attempt = "sha256" if not unwrap_attempts else "sha1"
        unwrap_attempts.append(attempt)
        if attempt == "sha256":
            raise CkrAssertionError("mechanism invalid", CKR_MECHANISM_INVALID)
        return sha1_handle

    def fake_destroy_quietly(raw: Any, session: int, handle: int) -> None:
        destroy_calls.append(handle)

    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy_quietly)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context

    cfg = P11TestConfig(module=Path("/ignored.so"), key_inject="unwrap", wrap_oaep_hash="auto")
    rs = _make_rs(sh=201)
    ctx = build_wrap_context(rs, cfg)

    assert ctx is not None
    assert ctx.oaep_hash == "sha1"
    assert unwrap_attempts == ["sha256", "sha1"]
    assert sha1_handle in destroy_calls


# ---------------------------------------------------------------------------
# OAEP hash auto-negotiation: both candidates fail -> returns None
# ---------------------------------------------------------------------------


def test_auto_negotiate_both_fail_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """auto mode: both sha256 and sha1 fail -> build_wrap_context returns None."""
    pub_h = 70
    priv_h = 71
    n_bytes, e_bytes = _real_rsa_numbers(2048)

    _stub_keygen_and_attrs(monkeypatch, pub_h, priv_h, n_bytes, e_bytes)

    def fake_unwrap_key(
        raw: Any,
        session: int,
        unwrapping_key: int,
        wrapped_key: bytes,
        mechanism: Any,
        attrs: Any = None,
        *,
        mech_param: Any = None,
    ) -> int:
        raise CkrAssertionError("mechanism invalid", CKR_MECHANISM_INVALID)

    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context

    cfg = P11TestConfig(module=Path("/ignored.so"), key_inject="unwrap", wrap_oaep_hash="auto")
    rs = _make_rs(sh=202)
    ctx = build_wrap_context(rs, cfg)

    assert ctx is None


# ---------------------------------------------------------------------------
# Explicit sha256: skips negotiation, uses sha256 directly
# ---------------------------------------------------------------------------


def test_explicit_sha256_skips_negotiation(monkeypatch: pytest.MonkeyPatch) -> None:
    """wrap_oaep_hash='sha256' must use sha256 directly, no unwrap_key probe."""
    pub_h = 80
    priv_h = 81
    n_bytes, e_bytes = _real_rsa_numbers(2048)
    unwrap_called: list[bool] = []

    _stub_keygen_and_attrs(monkeypatch, pub_h, priv_h, n_bytes, e_bytes)

    def fake_unwrap_key(*args: Any, **kwargs: Any) -> int:
        unwrap_called.append(True)
        return 999

    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap_key)
    _reset_cache()

    from pathlib import Path

    from pkcs11_check.config import P11TestConfig
    from pkcs11_check.testcases._provisioning import build_wrap_context

    cfg = P11TestConfig(
        module=Path("/ignored.so"),
        key_inject="unwrap",
        wrap_oaep_hash="sha256",
    )
    rs = _make_rs(sh=300)
    ctx = build_wrap_context(rs, cfg)

    assert ctx is not None
    assert ctx.oaep_hash == "sha256"
    # No negotiation probe should have called unwrap_key
    assert not unwrap_called
