"""Meta-test: ProvisioningEvent accumulator — record/get/clear + wiring checks.

Uses monkeypatch stubs (same recipe as test_provision_secret_key.py /
test_provision_rsa_private_key.py) — no real module needed.

Covers:
  (a) record/get/clear round-trip (unit)
  (b) create-available secret provision records ("secret", "ran_via_create")
  (c) force-unwrap secret provision records ("secret", "ran_via_unwrap")
  (d) off + create-absent secret provision records ("secret", "skipped_no_path")
  (e) force-unwrap RSA private provision records ("private", "ran_via_unwrap")
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
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
)
from pkcs11_check.testcases._provisioning import (
    ProvisioningEvent,
    clear_provisioning_events,
    get_provisioning_events,
    record_provisioning_event,
)

# ---------------------------------------------------------------------------
# RSA-2048 test key (reused across RSA private-key tests)
# ---------------------------------------------------------------------------

_RSA_KEY = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PRIV_NUMS = _RSA_KEY.private_numbers()
_RSA_PUB_NUMS = _RSA_PRIV_NUMS.public_numbers


def _int_to_bytes(v: int) -> bytes:
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


RSA_N = _int_to_bytes(_RSA_PUB_NUMS.n)
RSA_E = _int_to_bytes(_RSA_PUB_NUMS.e)
RSA_D = _int_to_bytes(_RSA_PRIV_NUMS.d)
RSA_P = _int_to_bytes(_RSA_PRIV_NUMS.p)
RSA_Q = _int_to_bytes(_RSA_PRIV_NUMS.q)
RSA_DMP1 = _int_to_bytes(_RSA_PRIV_NUMS.dmp1)
RSA_DMQ1 = _int_to_bytes(_RSA_PRIV_NUMS.dmq1)
RSA_IQMP = _int_to_bytes(_RSA_PRIV_NUMS.iqmp)

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

# ---------------------------------------------------------------------------
# AES test constants
# ---------------------------------------------------------------------------

_AES_VALUE = bytes(range(32))
_AES_ATTRS: dict[Any, Any] = {
    CKA_ENCRYPT: True,
    CKA_DECRYPT: True,
    CKA_TOKEN: False,
    CKA_SENSITIVE: False,
}
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
# (a) record/get/clear round-trip (pure unit — no module needed)
# ---------------------------------------------------------------------------


def test_record_get_clear_round_trip() -> None:
    """record_provisioning_event appends; get returns copy; clear empties."""
    clear_provisioning_events()
    assert get_provisioning_events() == []

    record_provisioning_event("secret", "ran_via_create")
    record_provisioning_event("private", "skipped_no_path")

    events = get_provisioning_events()
    assert events == [
        ProvisioningEvent("secret", "ran_via_create"),
        ProvisioningEvent("private", "skipped_no_path"),
    ]

    # get() must return a COPY — mutating it must not affect the accumulator
    events.append(ProvisioningEvent("public", "ran_via_external"))
    assert len(get_provisioning_events()) == 2, "get() must return a copy"

    clear_provisioning_events()
    assert get_provisioning_events() == [], "clear() must empty the list"


def test_record_never_raises_on_bad_input() -> None:
    """record_provisioning_event must swallow any internal error (observability)."""
    clear_provisioning_events()
    # Passing None should not raise — best-effort guard
    try:
        record_provisioning_event(None, None)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"record_provisioning_event raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# (b) create-available secret -> ("secret", "ran_via_create")
# ---------------------------------------------------------------------------


def test_secret_create_available_records_ran_via_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """create_available path must record exactly one ('secret', 'ran_via_create') event."""
    clear_provisioning_events()

    def fake_import(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        return 55

    def fake_destroy(raw: Any, sh: int, handle: int) -> None:
        pass

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=400)
    cfg = _make_cfg("off")
    provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    events = get_provisioning_events()
    assert events == [ProvisioningEvent("secret", "ran_via_create")]


# ---------------------------------------------------------------------------
# (c) force-unwrap secret -> ("secret", "ran_via_unwrap")
# ---------------------------------------------------------------------------


def test_secret_force_unwrap_records_ran_via_unwrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """force-unwrap path must record exactly one ('secret', 'ran_via_unwrap') event."""
    clear_provisioning_events()

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
        return 88

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

    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", fake_destroy)
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_rsa_keypair", fake_gen_rsa_keypair)
    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", fake_read_attributes)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_secret_key

    rs = _make_rs(sh=401, has_mech=True)
    cfg = _make_cfg("force-unwrap")
    provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    events = get_provisioning_events()
    assert ProvisioningEvent("secret", "ran_via_unwrap") in events, (
        f"expected ran_via_unwrap in {events}"
    )
    # No skipped_no_path should appear — it succeeded
    assert not any(e.method == "skipped_no_path" for e in events), (
        f"unexpected skipped_no_path in {events}"
    )


# ---------------------------------------------------------------------------
# (d) off + create-absent secret -> ("secret", "skipped_no_path") before skip
# ---------------------------------------------------------------------------


def test_secret_off_create_absent_records_skipped_no_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """off + create_absent must record ('secret', 'skipped_no_path') before pytest.skip."""
    clear_provisioning_events()

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

    rs = _make_rs(sh=402)
    cfg = _make_cfg("off")

    with pytest.raises(pytest.skip.Exception):
        provision_secret_key(rs, cfg, CKK_AES, _AES_VALUE, _AES_ATTRS, label="t")

    events = get_provisioning_events()
    assert ProvisioningEvent("secret", "skipped_no_path") in events, (
        f"expected skipped_no_path in {events}"
    )


# ---------------------------------------------------------------------------
# (e) force-unwrap RSA private -> ("private", "ran_via_unwrap")
# ---------------------------------------------------------------------------


def test_rsa_private_force_unwrap_records_ran_via_unwrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """force-unwrap RSA private path must record exactly one ('private', 'ran_via_unwrap')."""
    clear_provisioning_events()

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
        return 200

    monkeypatch.setattr(_prov, "build_wrap_context", lambda rs, cfg: fake_ctx)
    monkeypatch.setattr(_prov, "DEFAULT_STRATEGIES", [FakeStrategy()])
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", fake_unwrap)
    _reset_cache()

    from pkcs11_check.testcases._provisioning import provision_rsa_private_key

    rs = _make_rs(sh=403, has_mech=True)
    cfg = _make_cfg("force-unwrap")
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

    events = get_provisioning_events()
    assert ProvisioningEvent("private", "ran_via_unwrap") in events, (
        f"expected ran_via_unwrap in {events}"
    )
    assert not any(e.method == "skipped_no_path" for e in events), (
        f"unexpected skipped_no_path in {events}"
    )
