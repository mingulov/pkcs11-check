"""Meta-tests: provision_public_key / provision_certificate / provision_data resolution branches.

No real PKCS#11 module needed.  Uses monkeypatch to stub the create-verdict probe
and the underlying recipe / external-provision tier.

For EACH of the three functions, covers:
  (a) create_available → calls the create recipe, records ran_via_create, returns handle,
      never calls external_provision.
  (b) create_absent + external_provision returns a handle → returns it; skipped_no_path
      is NOT recorded.
  (c) create_absent + external_provision returns None → pytest.skip + skipped_no_path
      recorded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec as _crypto_ec
from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pkcs11_check.testcases._provisioning as _prov
from pkcs11_check.raw.types_std import CKK_EC_EDWARDS, CKK_EC_MONTGOMERY

# ---------------------------------------------------------------------------
# Test fixtures: a real P-256 keypair and RSA-2048 keypair for material tests
# ---------------------------------------------------------------------------

# EC P-256 key material
_EC_KEY = _crypto_ec.generate_private_key(_crypto_ec.SECP256R1())
_EC_PUB = _EC_KEY.public_key()
_EC_RAW_POINT = _EC_PUB.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
# DER OCTET STRING wrapper
EC_POINT = bytes([0x04, len(_EC_RAW_POINT)]) + _EC_RAW_POINT
EC_PARAMS = bytes.fromhex("06082a8648ce3d030107")  # P-256 OID
EC_P384_PARAMS = bytes.fromhex("06052b81040022")
EC_P521_PARAMS = bytes.fromhex("06052b81040023")

# RSA-2048 key material
_RSA_KEY = _crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PUB = _RSA_KEY.public_key()
_RSA_PUB_NUMS = _RSA_PUB.public_numbers()
RSA_N = _RSA_PUB_NUMS.n.to_bytes((_RSA_PUB_NUMS.n.bit_length() + 7) // 8, "big")
RSA_E = _RSA_PUB_NUMS.e.to_bytes((_RSA_PUB_NUMS.e.bit_length() + 7) // 8, "big")

# Dummy cert DER (not a real certificate, just bytes for test purposes)
CERT_DER = b"\x30\x82\x01\x00" + b"\x00" * 256

# Dummy data value
DATA_VALUE = b"hello provisioning"

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


def _make_cfg(*, allow_external: bool = False, external_cmd: str | None = None) -> Any:
    from pkcs11_check.config import P11TestConfig

    return P11TestConfig(
        module=Path("/stub.so"),
        key_inject="off",
        allow_external_provision=allow_external,
        external_provision_cmd=external_cmd if allow_external else None,
    )


def _pin_verdict(monkeypatch: pytest.MonkeyPatch, rs: Any, verdict: str) -> None:
    """Force create_verdict to return *verdict* for all obj_class strings."""
    prof = _prov.profile_for(rs)
    # Override _verdicts directly to bypass any real probe
    for cls in ("public", "cert", "data"):
        prof._verdicts[cls] = verdict


def _der_octet_string(value: bytes) -> bytes:
    """Encode one value as a canonical DER OCTET STRING."""
    if len(value) < 0x80:
        return b"\x04" + bytes([len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return b"\x04" + bytes([0x80 | len(length)]) + length + value


def _capture_external_material(
    monkeypatch: pytest.MonkeyPatch, rs: Any, *, handle: int = 556
) -> list[bytes]:
    captured: list[bytes] = []

    def fake_external(
        _rs: Any,
        _cfg: Any,
        *,
        material: bytes,
        label: str,
        key_type: Any,
        obj_class: str,
    ) -> int:
        captured.append(material)
        return handle

    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()
    _pin_verdict(monkeypatch, rs, "create_absent")
    return captured


# ===========================================================================
# provision_public_key — EC variant (create_available / absent / skip)
# ===========================================================================


def test_public_ec_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """(a) create_available + EC params → import_ec_public_key_negotiated called, ran_via_create."""
    imported: list[dict[str, Any]] = []

    def fake_import_ec(
        rs: Any,
        *,
        ec_params: bytes,
        ec_point: bytes,
        key_type: int,
        attrs: Any = None,
        **kw: Any,
    ) -> int:
        imported.append({"ec_params": ec_params, "ec_point": ec_point})
        return 11

    external_called: list[Any] = []

    def fake_external(*a: Any, **kw: Any) -> int | None:
        external_called.append(True)
        return None

    monkeypatch.setattr(
        "pkcs11_check.testcases.conftest.import_ec_public_key_negotiated", fake_import_ec
    )
    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()

    rs = _make_rs(sh=500)
    _pin_verdict(monkeypatch, rs, "create_available")

    from pkcs11_check.raw.types_std import CKK_EC
    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_public_key,
    )

    clear_provisioning_events()
    h = provision_public_key(
        rs,
        _make_cfg(),
        key_type=int(CKK_EC),
        attrs={},
        label="test-ec-pub",
        ec_params=EC_PARAMS,
        ec_point=EC_POINT,
    )

    assert h == 11, "must return negotiated-import handle"
    assert len(imported) == 1, "import_ec_public_key_negotiated must be called once"
    assert imported[0]["ec_params"] == EC_PARAMS
    assert imported[0]["ec_point"] == EC_POINT
    assert not external_called, "external_provision must NOT be called on create path"
    events = get_provisioning_events()
    assert any(e.obj_class == "public" and e.method == "ran_via_create" for e in events), (
        "ran_via_create must be recorded"
    )


def test_public_ec_create_absent_external_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """(b) create_absent + external returns handle → returns external handle, no skip."""
    external_handle = 555

    def fake_external(
        rs: Any,
        cfg: Any,
        *,
        material: bytes,
        label: str,
        key_type: Any,
        obj_class: str,
    ) -> int:
        from pkcs11_check.testcases._provisioning import record_provisioning_event

        record_provisioning_event(obj_class, "ran_via_external")
        return external_handle

    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()

    rs = _make_rs(sh=501)
    _pin_verdict(monkeypatch, rs, "create_absent")

    from pkcs11_check.raw.types_std import CKK_EC
    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_public_key,
    )

    clear_provisioning_events()
    h = provision_public_key(
        rs,
        _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
        key_type=int(CKK_EC),
        attrs={},
        label="test-ec-pub-ext",
        ec_params=EC_PARAMS,
        ec_point=EC_POINT,
    )

    assert h == external_handle, "must return external handle"
    events = get_provisioning_events()
    assert not any(e.method == "skipped_no_path" for e in events), (
        "skipped_no_path must NOT be recorded when external succeeds"
    )


@pytest.mark.parametrize(
    ("curve", "ec_params"),
    [
        (_crypto_ec.SECP256R1(), EC_PARAMS),
        (_crypto_ec.SECP384R1(), EC_P384_PARAMS),
        (_crypto_ec.SECP521R1(), EC_P521_PARAMS),
    ],
    ids=["p256", "p384", "p521"],
)
def test_public_ec_external_der_is_loadable_equivalent(
    monkeypatch: pytest.MonkeyPatch,
    curve: _crypto_ec.EllipticCurve,
    ec_params: bytes,
) -> None:
    """External conventional EC material is a loadable equivalent SPKI."""
    from pkcs11_check.raw.types_std import CKK_EC
    from pkcs11_check.testcases._provisioning import provision_public_key

    key = _crypto_ec.generate_private_key(curve)
    point = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    rs = _make_rs(sh=503)
    captured = _capture_external_material(monkeypatch, rs)

    handle = provision_public_key(
        rs,
        _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
        key_type=int(CKK_EC),
        attrs={},
        label="external conventional EC",
        ec_params=ec_params,
        ec_point=_der_octet_string(point),
    )

    assert handle == 556
    assert len(captured) == 1
    loaded = serialization.load_der_public_key(captured[0])
    assert isinstance(loaded, _crypto_ec.EllipticCurvePublicKey)
    assert loaded.public_numbers() == key.public_key().public_numbers()


@pytest.mark.parametrize(
    ("curve", "ec_params"),
    [
        (_crypto_ec.SECP256R1(), EC_PARAMS),
        (_crypto_ec.SECP384R1(), EC_P384_PARAMS),
        (_crypto_ec.SECP521R1(), EC_P521_PARAMS),
    ],
    ids=["p256", "p384", "p521-long-form"],
)
def test_public_ec_external_wrapped_compressed_is_loadable_equivalent(
    monkeypatch: pytest.MonkeyPatch,
    curve: _crypto_ec.EllipticCurve,
    ec_params: bytes,
) -> None:
    """External wrapped compressed SEC1 points become equivalent SPKI material."""
    from pkcs11_check.raw.types_std import CKK_EC
    from pkcs11_check.testcases._provisioning import provision_public_key

    key = _crypto_ec.generate_private_key(curve)
    point = key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    rs = _make_rs(sh=504)
    captured = _capture_external_material(monkeypatch, rs)

    provision_public_key(
        rs,
        _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
        key_type=int(CKK_EC),
        attrs={},
        label="external compressed EC",
        ec_params=ec_params,
        ec_point=_der_octet_string(point),
    )

    assert len(captured) == 1
    loaded = serialization.load_der_public_key(captured[0])
    assert isinstance(loaded, _crypto_ec.EllipticCurvePublicKey)
    assert loaded.public_numbers() == key.public_key().public_numbers()


@pytest.mark.parametrize(
    ("ec_params", "ec_point"),
    [
        (EC_PARAMS, _EC_RAW_POINT),
        (EC_PARAMS, EC_POINT + b"\x00"),
        (EC_PARAMS, b"\x04\x81\x41" + _EC_RAW_POINT),
        (EC_PARAMS + b"\x00", EC_POINT),
        (b"\x06", EC_POINT),
        (EC_PARAMS, b"\x04\x81"),
        (bytes.fromhex("06092a808648ce3d030107"), EC_POINT),
        (bytes.fromhex("06032b6570"), EC_POINT),
    ],
    ids=[
        "raw-point",
        "trailing-wrapper",
        "noncanonical-wrapper",
        "trailing-oid",
        "malformed-oid",
        "malformed-wrapper",
        "noncanonical-oid",
        "unsupported-oid",
    ],
)
def test_public_ec_external_conversion_fallback_is_exact(
    monkeypatch: pytest.MonkeyPatch, ec_params: bytes, ec_point: bytes
) -> None:
    """Malformed, noncanonical, and unsupported EC material remains byte-exact."""
    from pkcs11_check.raw.types_std import CKK_EC
    from pkcs11_check.testcases._provisioning import provision_public_key

    rs = _make_rs(sh=505)
    captured = _capture_external_material(monkeypatch, rs)

    provision_public_key(
        rs,
        _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
        key_type=int(CKK_EC),
        attrs={},
        label="external fallback EC",
        ec_params=ec_params,
        ec_point=ec_point,
    )

    assert captured == [ec_point]


@pytest.mark.parametrize(
    "key_type",
    [
        pytest.param(CKK_EC_EDWARDS, id="edwards"),
        pytest.param(CKK_EC_MONTGOMERY, id="montgomery"),
    ],
)
def test_public_ec_external_raw_nonconventional_key_types_are_exact(
    monkeypatch: pytest.MonkeyPatch, key_type: int
) -> None:
    """Raw Edwards/Montgomery public material never enters conventional EC conversion."""
    from pkcs11_check.testcases._provisioning import provision_public_key

    raw = bytes(range(32))
    rs = _make_rs(sh=506)
    captured = _capture_external_material(monkeypatch, rs)

    provision_public_key(
        rs,
        _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
        key_type=key_type,
        attrs={},
        label="external raw nonconventional key",
        ec_params=bytes.fromhex("06032b6570"),
        ec_point=raw,
    )

    assert captured == [raw]


def test_public_ec_external_unexpected_backend_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected backend/programming errors must not become a fallback provider result."""
    from pkcs11_check.raw.types_std import CKK_EC
    from pkcs11_check.testcases._provisioning import provision_public_key

    def fail_unexpectedly(_curve: Any, _data: bytes) -> Any:
        raise RuntimeError("backend invariant violated")

    monkeypatch.setattr(_crypto_ec.EllipticCurvePublicKey, "from_encoded_point", fail_unexpectedly)
    rs = _make_rs(sh=507)
    _capture_external_material(monkeypatch, rs)

    with pytest.raises(RuntimeError, match="backend invariant violated"):
        provision_public_key(
            rs,
            _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
            key_type=int(CKK_EC),
            attrs={},
            label="external unexpected EC",
            ec_params=EC_PARAMS,
            ec_point=EC_POINT,
        )


def test_public_ec_create_absent_no_external_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """(c) create_absent + external returns None → pytest.skip + skipped_no_path."""

    def fake_external(*a: Any, **kw: Any) -> None:
        return None

    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()

    rs = _make_rs(sh=502)
    _pin_verdict(monkeypatch, rs, "create_absent")

    from pkcs11_check.raw.types_std import CKK_EC
    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_public_key,
    )

    clear_provisioning_events()
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_public_key(
            rs,
            _make_cfg(),
            key_type=int(CKK_EC),
            attrs={},
            label="test-ec-pub-skip",
            ec_params=EC_PARAMS,
            ec_point=EC_POINT,
        )

    assert "no provisioning path" in str(exc_info.value), (
        "skip message must say no provisioning path"
    )
    events = get_provisioning_events()
    assert any(e.obj_class == "public" and e.method == "skipped_no_path" for e in events), (
        "skipped_no_path must be recorded"
    )


# ---------------------------------------------------------------------------
# provision_public_key — RSA variant (create_available path)
# ---------------------------------------------------------------------------


def test_public_rsa_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """(a) create_available + RSA n/e → import_rsa_public_key_negotiated called."""
    imported: list[dict[str, Any]] = []

    def fake_import_rsa(
        rs: Any,
        *,
        n: bytes,
        e: bytes,
        attrs: Any = None,
        **kw: Any,
    ) -> int:
        imported.append({"n": n, "e": e})
        return 22

    monkeypatch.setattr(
        "pkcs11_check.testcases.conftest.import_rsa_public_key_negotiated", fake_import_rsa
    )
    _reset_cache()

    rs = _make_rs(sh=510)
    _pin_verdict(monkeypatch, rs, "create_available")

    from pkcs11_check.raw.types_std import CKK_RSA
    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_public_key,
    )

    clear_provisioning_events()
    h = provision_public_key(
        rs,
        _make_cfg(),
        key_type=int(CKK_RSA),
        attrs={},
        label="test-rsa-pub",
        rsa_n=RSA_N,
        rsa_e=RSA_E,
    )

    assert h == 22, "must return negotiated-import handle"
    assert len(imported) == 1, "import_rsa_public_key_negotiated must be called once"
    assert imported[0]["n"] == RSA_N, "correct modulus forwarded"
    events = get_provisioning_events()
    assert any(e.obj_class == "public" and e.method == "ran_via_create" for e in events), (
        "ran_via_create must be recorded"
    )


# ===========================================================================
# provision_certificate
# ===========================================================================


def test_certificate_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """(a) create_available → create_object called with correct template, ran_via_create recorded."""  # noqa: E501
    created: list[dict[str, Any]] = []

    def fake_create_object(raw: Any, sh: int, template: dict[Any, Any]) -> int:
        created.append(dict(template))
        return 33

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_create_object)
    external_called: list[Any] = []
    monkeypatch.setattr(
        _prov, "external_provision", lambda *a, **kw: external_called.append(True) or None
    )
    _reset_cache()

    rs = _make_rs(sh=600)
    _pin_verdict(monkeypatch, rs, "create_available")

    from pkcs11_check.raw.types_std import (
        CKA_CERTIFICATE_TYPE,
        CKA_CLASS,
        CKA_LABEL,
        CKC_X_509,
        CKO_CERTIFICATE,
    )
    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_certificate,
    )

    clear_provisioning_events()
    h = provision_certificate(
        rs,
        _make_cfg(),
        value=CERT_DER,
        attrs={CKA_LABEL: b"my-cert"},
        label="test-cert",
    )

    assert h == 33, "must return create_object handle"
    assert len(created) == 1, "create_object must be called once"
    tmpl = created[0]
    assert tmpl[CKA_CLASS] == CKO_CERTIFICATE, "CKA_CLASS must be CKO_CERTIFICATE"
    assert tmpl[CKA_CERTIFICATE_TYPE] == CKC_X_509, "CKA_CERTIFICATE_TYPE must be CKC_X_509"
    assert tmpl.get(CKA_LABEL) == b"my-cert", "attrs must be merged"
    assert not external_called, "external_provision must NOT be called on create path"
    events = get_provisioning_events()
    assert any(e.obj_class == "cert" and e.method == "ran_via_create" for e in events), (
        "ran_via_create must be recorded for cert"
    )


def test_certificate_create_absent_external_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """(b) create_absent + external returns handle → returns it, skipped_no_path not recorded."""
    external_handle = 666

    def fake_external(
        rs: Any,
        cfg: Any,
        *,
        material: bytes,
        label: str,
        key_type: Any,
        obj_class: str,
    ) -> int:
        from pkcs11_check.testcases._provisioning import record_provisioning_event

        record_provisioning_event(obj_class, "ran_via_external")
        return external_handle

    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()

    rs = _make_rs(sh=601)
    _pin_verdict(monkeypatch, rs, "create_absent")

    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_certificate,
    )

    clear_provisioning_events()
    h = provision_certificate(
        rs,
        _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
        value=CERT_DER,
        attrs={},
        label="test-cert-ext",
    )

    assert h == external_handle, "must return external handle"
    events = get_provisioning_events()
    assert not any(e.method == "skipped_no_path" for e in events), (
        "skipped_no_path must NOT be recorded when external succeeds"
    )


def test_certificate_create_absent_no_external_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """(c) create_absent + external returns None → pytest.skip + skipped_no_path recorded."""

    def fake_external(*a: Any, **kw: Any) -> None:
        return None

    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()

    rs = _make_rs(sh=602)
    _pin_verdict(monkeypatch, rs, "create_absent")

    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_certificate,
    )

    clear_provisioning_events()
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_certificate(
            rs,
            _make_cfg(),
            value=CERT_DER,
            attrs={},
            label="test-cert-skip",
        )

    assert "no provisioning path" in str(exc_info.value)
    events = get_provisioning_events()
    assert any(e.obj_class == "cert" and e.method == "skipped_no_path" for e in events), (
        "skipped_no_path must be recorded"
    )


# ===========================================================================
# provision_data
# ===========================================================================


def test_data_create_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """(a) create_available → create_object called with correct template, ran_via_create recorded."""  # noqa: E501
    created: list[dict[str, Any]] = []

    def fake_create_object(raw: Any, sh: int, template: dict[Any, Any]) -> int:
        created.append(dict(template))
        return 44

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_create_object)
    external_called: list[Any] = []
    monkeypatch.setattr(
        _prov, "external_provision", lambda *a, **kw: external_called.append(True) or None
    )
    _reset_cache()

    rs = _make_rs(sh=700)
    _pin_verdict(monkeypatch, rs, "create_available")

    from pkcs11_check.raw.types_std import CKA_CLASS, CKA_LABEL, CKA_VALUE, CKO_DATA
    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_data,
    )

    clear_provisioning_events()
    h = provision_data(
        rs,
        _make_cfg(),
        value=DATA_VALUE,
        attrs={CKA_LABEL: b"my-data"},
        label="test-data",
    )

    assert h == 44, "must return create_object handle"
    assert len(created) == 1, "create_object must be called once"
    tmpl = created[0]
    assert tmpl[CKA_CLASS] == CKO_DATA, "CKA_CLASS must be CKO_DATA"
    assert tmpl[CKA_VALUE] == DATA_VALUE, "value must be in template"
    assert tmpl.get(CKA_LABEL) == b"my-data", "attrs must be merged"
    assert not external_called, "external_provision must NOT be called on create path"
    events = get_provisioning_events()
    assert any(e.obj_class == "data" and e.method == "ran_via_create" for e in events), (
        "ran_via_create must be recorded for data"
    )


def test_data_create_absent_external_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """(b) create_absent + external returns handle → returns it, skipped_no_path not recorded."""
    external_handle = 777

    def fake_external(
        rs: Any,
        cfg: Any,
        *,
        material: bytes,
        label: str,
        key_type: Any,
        obj_class: str,
    ) -> int:
        from pkcs11_check.testcases._provisioning import record_provisioning_event

        record_provisioning_event(obj_class, "ran_via_external")
        return external_handle

    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()

    rs = _make_rs(sh=701)
    _pin_verdict(monkeypatch, rs, "create_absent")

    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_data,
    )

    clear_provisioning_events()
    h = provision_data(
        rs,
        _make_cfg(allow_external=True, external_cmd="fake {keyfile} {label}"),
        value=DATA_VALUE,
        attrs={},
        label="test-data-ext",
    )

    assert h == external_handle, "must return external handle"
    events = get_provisioning_events()
    assert not any(e.method == "skipped_no_path" for e in events), (
        "skipped_no_path must NOT be recorded when external succeeds"
    )


def test_data_create_absent_no_external_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """(c) create_absent + external returns None → pytest.skip + skipped_no_path recorded."""

    def fake_external(*a: Any, **kw: Any) -> None:
        return None

    monkeypatch.setattr(_prov, "external_provision", fake_external)
    _reset_cache()

    rs = _make_rs(sh=702)
    _pin_verdict(monkeypatch, rs, "create_absent")

    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
        provision_data,
    )

    clear_provisioning_events()
    with pytest.raises(pytest.skip.Exception) as exc_info:
        provision_data(
            rs,
            _make_cfg(),
            value=DATA_VALUE,
            attrs={},
            label="test-data-skip",
        )

    assert "no provisioning path" in str(exc_info.value)
    events = get_provisioning_events()
    assert any(e.obj_class == "data" and e.method == "skipped_no_path" for e in events), (
        "skipped_no_path must be recorded"
    )
