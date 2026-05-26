"""EdDSA public-key import helpers.

PKCS#11 stores ``CKK_EC_EDWARDS`` public keys as raw RFC 8032 bytes in
``CKA_EC_POINT``. Some providers accept only a DER OCTET STRING wrapper in
practice, so vector tests probe with a known-good signature and then use the
working encoding for cryptographic coverage.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, import_ec_public_key, verify_single
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKK_EC_EDWARDS,
    CKM_EDDSA,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error

EdDsaPointEncoding = Literal["raw", "der"]
EdDsaMechanismParams = Literal["null", "explicit"]


@dataclass(frozen=True)
class EdDsaPublicKeyProfile:
    """Working provider profile for EdDSA vector verification."""

    point_encoding: EdDsaPointEncoding
    mechanism_params: EdDsaMechanismParams


_PROFILE_CACHE: dict[tuple[int, bytes], EdDsaPublicKeyProfile] = {}
_PREFERRED_PROFILES: tuple[EdDsaPublicKeyProfile, ...] = (
    EdDsaPublicKeyProfile("raw", "null"),
    EdDsaPublicKeyProfile("raw", "explicit"),
    EdDsaPublicKeyProfile("der", "null"),
    EdDsaPublicKeyProfile("der", "explicit"),
)
_PROFILE_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)


def clear_eddsa_public_key_encoding_cache() -> None:
    """Clear the process-local EdDSA public-key encoding cache."""
    _PROFILE_CACHE.clear()


def remember_eddsa_public_key_encoding(
    raw: object,
    ec_params: bytes,
    encoding: EdDsaPointEncoding,
) -> None:
    """Store a known working encoding for a module/curve pair."""
    remember_eddsa_public_key_profile(raw, ec_params, encoding, "explicit")


def remember_eddsa_public_key_profile(
    raw: object,
    ec_params: bytes,
    point_encoding: EdDsaPointEncoding,
    mechanism_params: EdDsaMechanismParams,
) -> None:
    """Store a known working EdDSA verification profile for a module/curve pair."""
    _PROFILE_CACHE[(id(raw), ec_params)] = EdDsaPublicKeyProfile(
        point_encoding,
        mechanism_params,
    )


def der_wrap_eddsa_public_key(public_key: bytes) -> bytes:
    """Return a DER OCTET STRING wrapper around raw Edwards public-key bytes."""
    length = len(public_key)
    if length < 0x80:
        return bytes([0x04, length]) + public_key
    return bytes([0x04, 0x81, length]) + public_key


def _point_for_encoding(public_key: bytes, encoding: EdDsaPointEncoding) -> bytes:
    if encoding == "raw":
        return public_key
    return der_wrap_eddsa_public_key(public_key)


def _mech_param_for_profile(profile: EdDsaPublicKeyProfile) -> Any:
    if profile.mechanism_params == "null":
        return mech_simple(CKM_EDDSA)
    return None


def _try_verify_with_profile(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    public_key: bytes,
    profile: EdDsaPublicKeyProfile,
    message: bytes,
    signature: bytes,
) -> bool:
    public_handle = 0
    try:
        public_handle = import_ec_public_key(
            raw,
            session,
            ec_params=ec_params,
            ec_point=_point_for_encoding(public_key, profile.point_encoding),
            key_type=int(CKK_EC_EDWARDS),
            attrs={CKA_VERIFY: True},
        )
        return verify_single(
            raw,
            session,
            public_handle,
            CKM_EDDSA,
            message,
            signature,
            mech_param=_mech_param_for_profile(profile),
        )
    finally:
        if public_handle:
            destroy_quietly(raw, session, public_handle)


def _is_profile_reject(exc: AssertionError) -> bool:
    """Return true when a provider rejects this encoding/parameter profile."""
    return is_known_error(exc, _PROFILE_REJECT_RVS)


def probe_eddsa_public_key_encodings(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> dict[EdDsaPointEncoding, bool]:
    """Return which Edwards public-key encodings verify a known-good signature."""
    result: dict[EdDsaPointEncoding, bool] = {"raw": False, "der": False}
    for profile in _PREFERRED_PROFILES:
        try:
            verified = _try_verify_with_profile(
                raw,
                session,
                ec_params=ec_params,
                public_key=public_key,
                profile=profile,
                message=message,
                signature=signature,
            )
        except AssertionError as exc:
            if not _is_profile_reject(exc):
                raise
            verified = False
        result[profile.point_encoding] = result[profile.point_encoding] or verified
    return result


def select_eddsa_public_key_profile(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> EdDsaPublicKeyProfile:
    """Probe and cache the working EdDSA verification profile for this module/curve."""
    cache_key = (id(raw), ec_params)
    cached = _PROFILE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    first_exc: AssertionError | None = None

    for profile in _PREFERRED_PROFILES:
        try:
            verified = _try_verify_with_profile(
                raw,
                session,
                ec_params=ec_params,
                public_key=public_key,
                profile=profile,
                message=message,
                signature=signature,
            )
        except AssertionError as exc:
            if not _is_profile_reject(exc):
                raise
            if first_exc is None:
                first_exc = exc
            continue
        if verified:
            _PROFILE_CACHE[cache_key] = profile
            return profile

    if first_exc is not None:
        raise first_exc

    profile = _PREFERRED_PROFILES[0]
    _PROFILE_CACHE[cache_key] = profile
    return profile


def select_eddsa_public_key_encoding(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> EdDsaPointEncoding:
    """Probe and cache the working EdDSA public-key encoding for this module/curve."""
    profile = select_eddsa_public_key_profile(
        raw,
        session,
        ec_params=ec_params,
        public_key=public_key,
        message=message,
        signature=signature,
    )
    return profile.point_encoding


def import_eddsa_public_key_with_supported_encoding(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    public_key: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import an EdDSA public key using the cached working encoding, raw by default."""
    profile = _PROFILE_CACHE.get((id(raw), ec_params), _PREFERRED_PROFILES[0])
    return import_ec_public_key(
        raw,
        session,
        ec_params=ec_params,
        ec_point=_point_for_encoding(public_key, profile.point_encoding),
        key_type=int(CKK_EC_EDWARDS),
        attrs=attrs,
    )


def verify_eddsa_signature_with_supported_params(
    raw: Any,
    session: int,
    *,
    public_key_handle: int,
    ec_params: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify EdDSA using the cached working mechanism-parameter mode."""
    profile = _PROFILE_CACHE.get((id(raw), ec_params), _PREFERRED_PROFILES[0])
    return verify_single(
        raw,
        session,
        public_key_handle,
        CKM_EDDSA,
        message,
        signature,
        mech_param=_mech_param_for_profile(profile),
    )
