"""Default attribute value tests.

Verifies that newly generated keys and objects have correct default
attribute values - especially security-critical defaults like
CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
and CKA_NEVER_EXTRACTABLE.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import classify, record_as
from pkcs11_check.raw.attr_metadata import ATTR_VALUE_TYPES
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.pack_mechanisms import mech_ecdh
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    gen_keypair,
    pack_attrs,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_OBJECT_HANDLE,
    CK_UNAVAILABLE_INFORMATION,
    CK_UNAVAILABLE_INFORMATION_32,
    CKA_ALWAYS_SENSITIVE,
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_DESTROYABLE,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LOCAL,
    CKA_MODIFIABLE,
    CKA_MODULUS_BITS,
    CKA_NEVER_EXTRACTABLE,
    CKA_PRIVATE,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_SIGN_RECOVER,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKA_VERIFY_RECOVER,
    CKD_NULL,
    CKK_GENERIC_SECRET,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDH1_DERIVE,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    require_bool_attr,
)
from pkcs11_check.testcases.conftest import (
    KEYPAIR_RUNTIME_REJECT_RVS,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    is_known_error,
    skip_if_data_objects_unsupported,
)

pytestmark = [pytest.mark.object]


def _read_attr(raw: Any, sh: int, handle: int, attr: int) -> Any:
    """Read one required attribute while preserving unavailable provider evidence."""
    try:
        attrs = read_attributes(raw, sh, handle, [attr])
        value = attr_or_record(
            attrs,
            attr,
            inherit_mechanism=False,
            label=f"attribute 0x{attr:08X}:default-readback",
            reason="honest_deviation",
            kind="metadata",
        )
        if value is MISSING_ATTRIBUTE:
            return MISSING_ATTRIBUTE
        if ATTR_VALUE_TYPES.get(attr) == "bool":
            return require_bool_attr(value, f"attribute 0x{attr:08X}")
        return value
    except CkrAssertionError as e:
        if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
            attr_name = ATTR_NAMES.get(int(attr), f"0x{attr:08X}")
            record_as(
                "honest_deviation",
                kind="metadata",
                label=f"attribute 0x{attr:08X}:default-readback",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=e.rv,
                summary=f"Module does not expose required attribute 0x{attr:08X}: {e}",
                detail={"attribute": {"name": attr_name, "id": int(attr)}},
            )
            return MISSING_ATTRIBUTE
        raise


class TestSecretKeyDefaults:
    """Verify default attribute values on a newly generated AES key.

    Only CKA_TOKEN=False is set explicitly; all other attributes
    should reflect the module's defaults.
    """

    @pytest.fixture()
    def aes_key(self, p11_raw_session: Any) -> Any:
        """Generate an AES setup key with minimal template."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_TOKEN: False},
            purpose="default attribute checks",
        )
        yield rs, key
        destroy_quietly(rs.raw, rs.sh, key)

    def test_token_is_false(self, aes_key: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        rs, key = aes_key
        attrs = read_attributes(rs.raw, rs.sh, key, [CKA_TOKEN])
        token = attr_or_record(
            attrs, CKA_TOKEN, inherit_mechanism=False, label="CKA_TOKEN:generated-AES"
        )
        if token is MISSING_ATTRIBUTE:
            return
        assert require_bool_attr(token, "CKA_TOKEN") is False

    def test_local_is_true(self, aes_key: Any) -> None:
        """CKA_LOCAL should be True for a generated key."""
        rs, key = aes_key
        attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LOCAL])
        local_raw = attr_or_record(
            attrs, CKA_LOCAL, inherit_mechanism=False, label="CKA_LOCAL:generated-AES"
        )
        if local_raw is MISSING_ATTRIBUTE:
            return
        local = require_bool_attr(local_raw, "CKA_LOCAL")
        if local is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returns CKA_LOCAL=False for generated secret key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: CKA_LOCAL True if key generated on token",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_LOCAL default (generated AES key)",
                spec_ref="PKCS#11 v3.2",
                summary="Module returns CKA_LOCAL=False for generated key (spec violation)",
            )

    def test_sensitive_is_bool(self, aes_key: Any) -> None:
        """CKA_SENSITIVE defaults to a boolean (True on most modules)."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_SENSITIVE)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)

    def test_extractable_is_bool(self, aes_key: Any) -> None:
        """CKA_EXTRACTABLE defaults to a boolean (False on most modules)."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_EXTRACTABLE)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)

    def test_modifiable_default(self, aes_key: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_MODIFIABLE)
        if val is MISSING_ATTRIBUTE:
            return
        assert val is True

    def test_copyable_default(self, aes_key: Any) -> None:
        """CKA_COPYABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_COPYABLE)
        if val is MISSING_ATTRIBUTE:
            return
        assert val is True

    def test_destroyable_default(self, aes_key: Any) -> None:
        """CKA_DESTROYABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_DESTROYABLE)
        if val is MISSING_ATTRIBUTE:
            return
        assert val is True

    def test_private_default(self, aes_key: Any) -> None:
        """CKA_PRIVATE defaults to True for secret keys."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_PRIVATE)
        if val is MISSING_ATTRIBUTE:
            return
        if val is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module defaults CKA_PRIVATE to False for secret keys (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: default CKA_PRIVATE is True for secret keys",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_PRIVATE default (secret key)",
                spec_ref="PKCS#11 v3.2",
                summary="Module defaults CKA_PRIVATE=False for secret keys (spec violation)",
            )

    def test_always_sensitive_consistent(self, aes_key: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is True when SENSITIVE defaults to True."""
        rs, key = aes_key
        sensitive = _read_attr(rs.raw, rs.sh, key, CKA_SENSITIVE)
        always_sensitive = _read_attr(rs.raw, rs.sh, key, CKA_ALWAYS_SENSITIVE)
        if sensitive is MISSING_ATTRIBUTE or always_sensitive is MISSING_ATTRIBUTE:
            return
        if sensitive:
            assert always_sensitive is True
        else:
            # If SENSITIVE defaults to False, ALWAYS_SENSITIVE must be False
            assert always_sensitive is False

    def test_never_extractable_consistent(self, aes_key: Any) -> None:
        """CKA_NEVER_EXTRACTABLE is True when EXTRACTABLE defaults to False."""
        rs, key = aes_key
        extractable = _read_attr(rs.raw, rs.sh, key, CKA_EXTRACTABLE)
        never_extractable = _read_attr(rs.raw, rs.sh, key, CKA_NEVER_EXTRACTABLE)
        if extractable is MISSING_ATTRIBUTE or never_extractable is MISSING_ATTRIBUTE:
            return
        if not extractable:
            assert never_extractable is True
        else:
            # If EXTRACTABLE defaults to True, NEVER_EXTRACTABLE must be False
            assert never_extractable is False


class TestKeyPairDefaults:
    """Verify default attribute values on a newly generated RSA-2048 keypair."""

    @pytest.fixture()
    def rsa_keypair(self, p11_raw_session: Any) -> Any:
        """Generate an RSA-2048 keypair with minimal template."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        yield rs, pub, priv
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)

    def test_public_key_local(self, rsa_keypair: Any) -> None:
        """Public key CKA_LOCAL should be True."""
        rs, pub, _priv = rsa_keypair
        attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_LOCAL])
        local_raw = attr_or_record(
            attrs, CKA_LOCAL, inherit_mechanism=False, label="CKA_LOCAL:RSA-public-key"
        )
        if local_raw is MISSING_ATTRIBUTE:
            return
        local = require_bool_attr(local_raw, "CKA_LOCAL")
        if local is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returns CKA_LOCAL=False for generated RSA public key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: CKA_LOCAL True if key generated on token",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_LOCAL default (RSA public key)",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "Module returns CKA_LOCAL=False for generated RSA public key (spec violation)"
                ),
            )

    def test_private_key_local(self, rsa_keypair: Any) -> None:
        """Private key CKA_LOCAL should be True."""
        rs, _pub, priv = rsa_keypair
        attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_LOCAL])
        local_raw = attr_or_record(
            attrs, CKA_LOCAL, inherit_mechanism=False, label="CKA_LOCAL:RSA-private-key"
        )
        if local_raw is MISSING_ATTRIBUTE:
            return
        local = require_bool_attr(local_raw, "CKA_LOCAL")
        if local is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returns CKA_LOCAL=False for generated RSA private key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: CKA_LOCAL True if key generated on token",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_LOCAL default (RSA private key)",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "Module returns CKA_LOCAL=False for generated RSA private key (spec violation)"
                ),
            )

    def test_private_key_sensitive(self, rsa_keypair: Any) -> None:
        """Private key CKA_SENSITIVE is a boolean.

        The PKCS#11 spec does not mandate a default for CKA_SENSITIVE --
        it is implementation-defined. The raw API does not force it, so
        the module may default to either True or False.
        """
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_SENSITIVE)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)

    def test_private_key_extractable(self, rsa_keypair: Any) -> None:
        """Private key CKA_EXTRACTABLE follows the token's default posture."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_EXTRACTABLE)
        if val is MISSING_ATTRIBUTE:
            return
        if val is not False:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module defaults CKA_EXTRACTABLE=True for RSA private key; recording the "
                "token-specific posture (not a PKCS#11 violation)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 CKA_EXTRACTABLE token-specific default posture",
            )

    def test_private_key_private(self, rsa_keypair: Any) -> None:
        """Private key CKA_PRIVATE defaults to True."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_PRIVATE)
        if val is MISSING_ATTRIBUTE:
            return
        if val is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module defaults CKA_PRIVATE=False for RSA private key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: default CKA_PRIVATE is True for private keys",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_PRIVATE default (RSA private key)",
                spec_ref="PKCS#11 v3.2",
                summary="Module defaults CKA_PRIVATE=False for RSA private key (spec violation)",
            )

    def test_public_key_encrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_ENCRYPT is a boolean."""
        rs, pub, _priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, pub, CKA_ENCRYPT)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)

    def test_public_key_verify_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_VERIFY is a boolean."""
        rs, pub, _priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, pub, CKA_VERIFY)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)

    def test_private_key_sign_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_SIGN is a boolean."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_SIGN)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)

    def test_private_key_decrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_DECRYPT is a boolean."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_DECRYPT)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)


class TestDataObjectDefaults:
    """Verify default attribute values on a CKO_DATA object."""

    @pytest.fixture()
    def data_obj(self, p11_raw_session: Any) -> Any:
        """Create a CKO_DATA object with minimal template."""
        rs = p11_raw_session
        skip_if_data_objects_unsupported(rs)
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_VALUE: b"test-defaults",
                CKA_TOKEN: False,
            },
        )
        yield rs, h
        destroy_quietly(rs.raw, rs.sh, h)

    def test_token_is_false(self, data_obj: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        rs, h = data_obj
        attrs = read_attributes(rs.raw, rs.sh, h, [CKA_TOKEN])
        token = attr_or_record(
            attrs, CKA_TOKEN, inherit_mechanism=False, label="CKA_TOKEN:data-object"
        )
        if token is MISSING_ATTRIBUTE:
            return
        assert require_bool_attr(token, "CKA_TOKEN") is False

    def test_modifiable_default(self, data_obj: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        rs, h = data_obj
        val = _read_attr(rs.raw, rs.sh, h, CKA_MODIFIABLE)
        if val is MISSING_ATTRIBUTE:
            return
        assert val is True

    def test_private_is_bool(self, data_obj: Any) -> None:
        """CKA_PRIVATE defaults to a boolean (module-dependent)."""
        rs, h = data_obj
        val = _read_attr(rs.raw, rs.sh, h, CKA_PRIVATE)
        if val is MISSING_ATTRIBUTE:
            return
        assert isinstance(val, bool)


# --- QC7d (#59.5): omitted derive/recover usage-flag defaults ----------------
#
# Minimal pairs are generated with only the mechanically required
# attributes (CKA_MODULUS_BITS / CKA_EC_PARAMS plus CKA_TOKEN=False), so
# no recipe injects usage flags. Table 26 defaults CKA_DERIVE to
# CK_FALSE on every key (both halves); Tables 27/29 give recover flags
# token-specific defaults, so either strict CK_BBOOL value passes.
# Strictness needs a raw read in this file: read_attributes decodes any
# nonzero byte as True, masking a malformed 0x02. Records carry lengths
# and the observed byte only.

_QC7D_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_QC7D_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_QC7D_HANDLE_SENTINEL = 0x51515151
_QC7D_UNAVAILABLE_LENS = {
    int(CK_UNAVAILABLE_INFORMATION),
    int(CK_UNAVAILABLE_INFORMATION_32),
}


def _qc7d_raise_strongest(records: list[C.Classification]) -> None:
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            1 if record.outcome == "fail" else 0,
            _QC7D_SEVERITY_PRIORITY.get(record.severity, 0),
            _QC7D_KIND_PRIORITY.get(record.kind or "", 0),
        ),
    )
    C.raise_for_record(strongest)


def _qc7d_detail(attr: int, **extra: Any) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "attribute": {"name": ATTR_NAMES.get(int(attr), f"0x{int(attr):08x}"), "id": int(attr)},
        "producer_operation": "C_GenerateKeyPair",
    }
    detail.update(extra)
    return detail


def _gen_minimal_pair(rs: Any, family: str) -> tuple[int, int]:
    """Generate a pair whose templates omit every usage flag."""
    if family == "rsa":
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported by module")
        mechanism = int(CKM_RSA_PKCS_KEY_PAIR_GEN)
        # CKA_PUBLIC_EXPONENT is a mechanically required generation input
        # (not a usage flag); every usage boolean stays omitted.
        pub_base = [
            attr_ulong(CKA_MODULUS_BITS, 2048),
            attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
        ]
        pub_skip = {CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT}
    else:
        if not (rs.has_mechanism("EC_KEY_PAIR_GEN") or rs.has_mechanism("ECDSA_KEY_PAIR_GEN")):
            pytest.skip("EC_KEY_PAIR_GEN not supported by module")
        mechanism = int(CKM_EC_KEY_PAIR_GEN)
        pub_base = [attr_bytes(CKA_EC_PARAMS, encode_named_curve_parameters("secp256r1"))]
        pub_skip = {CKA_EC_PARAMS}
    try:
        return gen_keypair(
            rs.raw,
            rs.sh,
            mechanism,
            pub_base=pub_base,
            priv_base=[],
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_TOKEN: False},
            pub_skip=pub_skip,
        )
    except CkrAssertionError as exc:
        if exc.rv in KEYPAIR_RUNTIME_REJECT_RVS:
            C.xfail_as(
                "not_operational",
                kind="metadata",
                label=f"QC7d minimal {family} pair setup",
                operation="C_GenerateKeyPair",
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=exc.rv,
                summary=f"minimal {family} pair generation refused: {ckr_name(exc.rv)}",
            )
        raise


def _read_bbool_raw(raw: Any, sh: int, handle: int, attr: int) -> tuple[int, int, int | None]:
    """One raw sentinel-buffer attribute read: (rv, returned length, first byte)."""
    cap = 8
    buf = (ctypes.c_ubyte * cap).from_buffer_copy(bytes([0xA5]) * cap)
    tmpl = (CK_ATTRIBUTE * 1)()
    tmpl[0].type = attr
    tmpl[0].pValue = ctypes.cast(buf, ctypes.c_void_p)
    tmpl[0].ulValueLen = cap
    rv = int(raw.C_GetAttributeValue(sh, handle, tmpl, 1))
    length = int(tmpl[0].ulValueLen)
    byte = int(buf[0]) if 1 <= length <= cap else None
    return rv, length, byte


def _check_bbool(
    rs: Any, handle: int, attr: int, *, label: str
) -> tuple[bool | None, list[C.Classification]]:
    """Strict CK_BBOOL read: present requires length 1 and byte in {0, 1}."""
    rv, length, byte = _read_bbool_raw(rs.raw, rs.sh, handle, attr)
    if rv == int(CKR_OK) and length not in _QC7D_UNAVAILABLE_LENS:
        if length == 1 and byte in (0, 1):
            return bool(byte), []
        return None, [
            C.record_as(
                "wrong_result",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                detail=_qc7d_detail(attr, length=length, byte=byte),
                summary=(f"{label}: malformed CK_BBOOL readback (length {length}, byte {byte})"),
            )
        ]
    if (
        rv == int(CKR_OK)
        or rv
        in (
            int(CKR_ATTRIBUTE_TYPE_INVALID),
            int(CKR_ATTRIBUTE_SENSITIVE),
        )
        or is_standard_ckr(rv)
        or is_vendor_defined_ckr(rv)
    ):
        return None, [
            C.record_as(
                "honest_deviation",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=rv if rv != int(CKR_OK) else None,
                detail=_qc7d_detail(attr, length=length),
                summary=f"{label}: required usage-flag attribute unavailable",
            )
        ]
    return None, [
        C.record_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=rv,
            detail=_qc7d_detail(attr, length=length),
            summary=f"{label}: attribute read returned undefined CK_RV {ckr_name(rv)}",
        )
    ]


def _check_derive_defaults(rs: Any, pub: int, priv: int, *, family: str) -> None:
    records: list[C.Classification] = []
    # Both halves are always read before any terminal verdict.
    pub_value, pub_records = _check_bbool(
        rs, pub, CKA_DERIVE, label=f"CKA_DERIVE default:{family}-public"
    )
    records.extend(pub_records)
    priv_value, priv_records = _check_bbool(
        rs, priv, CKA_DERIVE, label=f"CKA_DERIVE default:{family}-private"
    )
    records.extend(priv_records)
    for leg, value in (("public", pub_value), ("private", priv_value)):
        if value is True:
            # Present-byte 1 with no effect contradiction is an honest
            # deviation; only the live effect node can fail this claim.
            records.append(
                C.record_as(
                    "honest_deviation",
                    kind="metadata",
                    label=f"CKA_DERIVE default:{family}-{leg}",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    detail=_qc7d_detail(CKA_DERIVE, leg=leg),
                    summary=(
                        f"omitted CKA_DERIVE defaults to True on the {family} {leg} key; "
                        "Table 26 requires CK_FALSE"
                    ),
                )
            )
    _qc7d_raise_strongest(records)


def _check_recover_defaults(rs: Any, pub: int, priv: int, *, family: str) -> None:
    records: list[C.Classification] = []
    # Both halves are always read; either strict value passes (token-specific).
    _, pub_records = _check_bbool(
        rs, pub, CKA_VERIFY_RECOVER, label=f"CKA_VERIFY_RECOVER default:{family}-public"
    )
    records.extend(pub_records)
    _, priv_records = _check_bbool(
        rs, priv, CKA_SIGN_RECOVER, label=f"CKA_SIGN_RECOVER default:{family}-private"
    )
    records.extend(priv_records)
    _qc7d_raise_strongest(records)


class TestOmittedUsageFlagDefaults:
    """QC7d: defaults of omitted CKA_DERIVE / recover flags on minimal pairs."""

    def test_rsa_minimal_pair_derive_defaults_false(self, p11_raw_session: Any) -> None:
        """Omitted CKA_DERIVE is a strict CK_FALSE on both RSA halves."""
        rs = p11_raw_session
        pub, priv = _gen_minimal_pair(rs, "rsa")
        try:
            _check_derive_defaults(rs, pub, priv, family="rsa")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_minimal_pair_derive_defaults_false(self, p11_raw_session: Any) -> None:
        """Omitted CKA_DERIVE is a strict CK_FALSE on both EC halves."""
        rs = p11_raw_session
        pub, priv = _gen_minimal_pair(rs, "ec")
        try:
            _check_derive_defaults(rs, pub, priv, family="ec")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_minimal_pair_recover_defaults_are_booleans(self, p11_raw_session: Any) -> None:
        """Omitted recover flags read as strict CK_BBOOLs (either value, RSA)."""
        rs = p11_raw_session
        pub, priv = _gen_minimal_pair(rs, "rsa")
        try:
            _check_recover_defaults(rs, pub, priv, family="rsa")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_minimal_pair_recover_defaults_are_booleans(self, p11_raw_session: Any) -> None:
        """Omitted recover flags read as strict CK_BBOOLs (either value, EC)."""
        rs = p11_raw_session
        pub, priv = _gen_minimal_pair(rs, "ec")
        try:
            _check_recover_defaults(rs, pub, priv, family="ec")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_derive_false_claim_blocks_derive(self, p11_raw_session: Any) -> None:
        """Live effect: a DERIVE=False claim must actually refuse C_DeriveKey.

        Positive control first-class: an explicit CKA_DERIVE=True pair
        derives against the same peer point and its output is read back,
        proving the harness can derive before the negative leg is judged.
        A successful derive under a False claim fails wrong_result.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("ECDH1_DERIVE not supported by module")
        pub, priv = _gen_minimal_pair(rs, "ec")
        control_pub = control_priv = 0
        derived: list[int] = []
        records: list[C.Classification] = []
        try:
            claim, claim_records = _check_bbool(
                rs, priv, CKA_DERIVE, label="CKA_DERIVE claim:ec-private (effect leg)"
            )
            records.extend(claim_records)
            if claim is True:
                records.append(
                    C.record_as(
                        "honest_deviation",
                        kind="metadata",
                        label="CKA_DERIVE claim:ec-private (effect leg)",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        detail=_qc7d_detail(CKA_DERIVE, leg="private"),
                        summary=(
                            "omitted CKA_DERIVE defaults to True; the effect leg "
                            "requires a False claim and is not judged"
                        ),
                    )
                )
                _qc7d_raise_strongest(records)
                return
            if claim is not False:
                _qc7d_raise_strongest(records)
                return

            curve_oid = encode_named_curve_parameters("secp256r1")
            try:
                control_pub, control_priv = gen_keypair(
                    rs.raw,
                    rs.sh,
                    int(CKM_EC_KEY_PAIR_GEN),
                    pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
                    priv_base=[],
                    public_attrs={CKA_TOKEN: False, CKA_DERIVE: True},
                    private_attrs={CKA_TOKEN: False, CKA_DERIVE: True},
                    pub_skip={CKA_EC_PARAMS},
                )
            except CkrAssertionError as exc:
                if exc.rv in KEYPAIR_RUNTIME_REJECT_RVS:
                    records.append(
                        C.record_as(
                            "not_operational",
                            kind="metadata",
                            label="QC7d derive positive-control setup",
                            operation="C_GenerateKeyPair",
                            inherit_mechanism=False,
                            expected=CKR_OK,
                            actual=exc.rv,
                            summary=(
                                "explicit-derive control pair refused: "
                                f"{ckr_name(exc.rv)}; negative leg not judged"
                            ),
                        )
                    )
                    _qc7d_raise_strongest(records)
                    return
                raise

            peer_point = (
                ec.generate_private_key(ec.SECP256R1())
                .public_key()
                .public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
            )
            derived_attrs: dict[Any, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            }
            # Positive control: explicit True must derive and produce a usable key.
            try:
                control_key = derive_key(
                    rs.raw,
                    rs.sh,
                    control_priv,
                    CKM_ECDH1_DERIVE,
                    attrs=derived_attrs,
                    mech_param=mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=peer_point),
                )
            except CkrAssertionError as exc:
                if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
                    records.append(
                        C.record_as(
                            "not_operational",
                            kind="metadata",
                            label="QC7d derive positive control",
                            operation="C_DeriveKey",
                            inherit_mechanism=False,
                            expected=CKR_OK,
                            actual=exc.rv,
                            summary=(
                                "explicit CKA_DERIVE=True control refused derive: "
                                f"{ckr_name(exc.rv)}; negative leg not judged"
                            ),
                        )
                    )
                    _qc7d_raise_strongest(records)
                    return
                raise
            derived.append(control_key)
            control_attrs = read_attributes(rs.raw, rs.sh, control_key, [CKA_VALUE])
            control_value = attr_or_record(
                control_attrs,
                CKA_VALUE,
                label="CKA_VALUE:QC7d derive positive control output",
                inherit_mechanism=False,
            )
            if (
                control_value is MISSING_ATTRIBUTE
                or not isinstance(control_value, bytes)
                or len(control_value) != 32
            ):
                actual_len: int | None = None
                if control_value is not MISSING_ATTRIBUTE and isinstance(control_value, bytes):
                    actual_len = len(control_value)
                records.append(
                    C.record_as(
                        "wrong_result",
                        kind="crypto",
                        label="QC7d derive positive control output",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        detail=_qc7d_detail(CKA_VALUE, actual_len=actual_len),
                        summary="ECDH control output is not a readable 32-byte secret",
                    )
                )

            # Judged leg: raw derive under the proven False claim.
            mech = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=peer_point)
            tmpl = template(*pack_attrs(derived_attrs))
            out_handle = CK_OBJECT_HANDLE(_QC7D_HANDLE_SENTINEL)
            rv = int(
                rs.raw.C_DeriveKey(
                    rs.sh, mech.byref(), priv, tmpl.ptr, tmpl.count, byref(out_handle)
                )
            )
            if rv == int(CKR_OK):
                if int(out_handle.value) != _QC7D_HANDLE_SENTINEL:
                    derived.append(int(out_handle.value))
                records.append(
                    C.record_as(
                        "wrong_result",
                        kind="policy",
                        label="CKA_DERIVE=False claim vs derive effect",
                        operation="C_DeriveKey",
                        inherit_mechanism=False,
                        actual=rv,
                        detail=_qc7d_detail(CKA_DERIVE, leg="private"),
                        summary=(
                            "private key claims CKA_DERIVE=False yet C_DeriveKey "
                            "succeeded (claim/effect contradiction)"
                        ),
                    )
                )
            elif int(out_handle.value) != _QC7D_HANDLE_SENTINEL:
                derived.append(int(out_handle.value))
                records.append(
                    C.record_as(
                        "self_contradiction",
                        kind="metadata",
                        label="CKA_DERIVE=False derive refusal output",
                        operation="C_DeriveKey",
                        inherit_mechanism=False,
                        actual=rv,
                        detail=_qc7d_detail(CKA_DERIVE, leg="private"),
                        summary=(f"derive refusal {ckr_name(rv)} mutated the output handle"),
                    )
                )
            elif is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
                pass  # Clean refusal: the False claim is honored.
            else:
                records.append(
                    C.record_as(
                        "self_contradiction",
                        kind="metadata",
                        label="CKA_DERIVE=False derive refusal",
                        operation="C_DeriveKey",
                        inherit_mechanism=False,
                        actual=rv,
                        detail=_qc7d_detail(CKA_DERIVE, leg="private"),
                        summary=f"derive returned undefined CK_RV {ckr_name(rv)}",
                    )
                )
            _qc7d_raise_strongest(records)
        finally:
            for handle in derived:
                destroy_quietly(rs.raw, rs.sh, handle)
            if control_pub:
                destroy_quietly(rs.raw, rs.sh, control_pub)
            if control_priv:
                destroy_quietly(rs.raw, rs.sh, control_priv)
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
