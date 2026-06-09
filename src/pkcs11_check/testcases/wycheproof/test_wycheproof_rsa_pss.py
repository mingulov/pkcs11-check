"""Wycheproof RSA-PSS signature verification vectors.

Tests RSA-PSS (PKCS#1 v2.1) across key sizes 2048/3072/4096 with
SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 and varying salt lengths.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import mech_pss
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    generate_random,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA3_224,
    CKG_MGF1_SHA3_256,
    CKG_MGF1_SHA3_384,
    CKG_MGF1_SHA3_512,
    CKG_MGF1_SHA224,
    CKG_MGF1_SHA256,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA3_224,
    CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256,
    CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384,
    CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512,
    CKM_SHA3_512_RSA_PKCS_PSS,
    CKM_SHA224,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import (
    import_rsa_public_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Cache of RSA key sizes (in bits) that the module rejected on import.
# Populated on first failure; subsequent tests with the same key size skip
# immediately without attempting another C_CreateObject probe.
_UNSUPPORTED_RSA_KEY_SIZES: set[int] = set()

_RSA_PUBLIC_IMPORT_UNSUPPORTED_CKRS = (
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
)

_RSA_PSS_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

# Cache of (mech, hash_mech, mgf, salt_len) tuples we have already probed
# for "advertised but not operational". True = a fresh-key sign+verify
# roundtrip with these PSS params succeeded; False = the same provider
# could not produce a verifying signature for itself with this combo, so
# rejecting a known-valid Wycheproof sig with the same combo is the same
# class of deviation (classification model: xfail, not fail).
_PSS_COMBO_OPERATIONAL: dict[tuple[int, int, int, int], bool] = {}

# Canned message for the operational probe -- arbitrary content.
_PSS_PROBE_MESSAGE = b"pkcs11-check PSS combo operational probe"


def _pss_combo_operational(
    rs: Any, mechanism: int, hash_mech: int, mgf: int, salt_len: int
) -> bool:
    """Self-roundtrip probe: is this (mech, hash, mgf, salt_len) operational?

    On the first call for a given combo, generates a fresh RSA-2048 keypair
    and attempts a sign+verify roundtrip with the PSS params. Returns True
    if verification succeeds, False on any rejection / verify-False / setup
    failure. Result is cached per-combo for the rest of the run.

    The classification model uses this to distinguish:
    - real provider bug (combo operational, but rejects a known-valid sig
      from the test vector) -> hard ``fail``;
    - advertised-but-not-operational combo (provider's own sig also fails
      to verify with the same params) -> ``xfail``.
    """
    key = (mechanism, hash_mech, mgf, salt_len)
    cached = _PSS_COMBO_OPERATIONAL.get(key)
    if cached is not None:
        return cached
    operational = _probe_pss_combo(rs, mechanism, hash_mech, mgf, salt_len)
    _PSS_COMBO_OPERATIONAL[key] = operational
    return operational


def _probe_pss_combo(rs: Any, mechanism: int, hash_mech: int, mgf: int, salt_len: int) -> bool:
    pub = priv = 0
    try:
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
        except AssertionError:
            return False
        pss_param = mech_pss(mechanism, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
        try:
            sig = sign_single(
                rs.raw, rs.sh, priv, mechanism, _PSS_PROBE_MESSAGE, mech_param=pss_param
            )
        except AssertionError:
            return False
        try:
            return verify_single(
                rs.raw,
                rs.sh,
                pub,
                mechanism,
                _PSS_PROBE_MESSAGE,
                sig,
                mech_param=pss_param,
            )
        except AssertionError:
            return False
    finally:
        if priv:
            destroy_quietly(rs.raw, rs.sh, priv)
        if pub:
            destroy_quietly(rs.raw, rs.sh, pub)


_RsaPssFingerprint = tuple[int, int, int, int, bytes, bytes, bytes, bytes]


def _pkcs11_rsa_pss_fingerprint(test: dict[str, Any]) -> _RsaPssFingerprint | None:
    """Return PKCS#11-visible RSA-PSS verify inputs for duplicate detection."""
    try:
        public_key = test["_group"].get("publicKey", {})
        return (
            int(test["_mechanism"]),
            int(test["_hash_mech"]),
            int(test["_mgf"]),
            int(test["_sLen"]),
            pkcs11_bigint_from_hex(public_key.get("modulus", "")),
            pkcs11_bigint_from_hex(public_key.get("publicExponent", "")),
            bytes.fromhex(test["msg"]),
            bytes.fromhex(test["sig"]),
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _canonical_duplicate_id(entries: list[tuple[str, dict[str, Any]]]) -> str:
    """Choose the most PKCS#11-meaningful representative for duplicate vectors."""
    for preferred in ("valid", "acceptable"):
        for vec_id, test in entries:
            if test["result"] == preferred:
                return vec_id
    return entries[0][0]


def _mark_pkcs11_duplicate_vectors(vectors: list[tuple[str, dict[str, Any]]]) -> None:
    groups: dict[_RsaPssFingerprint, list[tuple[str, dict[str, Any]]]] = {}
    for vec_id, test in vectors:
        fingerprint = _pkcs11_rsa_pss_fingerprint(test)
        if fingerprint is not None:
            groups.setdefault(fingerprint, []).append((vec_id, test))
    for entries in groups.values():
        if len(entries) < 2:
            continue
        duplicate_of = _canonical_duplicate_id(entries)
        for vec_id, test in entries:
            if vec_id != duplicate_of:
                test["_pkcs11_duplicate_of"] = duplicate_of


# Map hash names to PKCS#11 mechanisms and hash mechanisms for PSS params
_SHA_MECHANISMS: dict[str, int] = {
    "SHA-1": CKM_SHA1_RSA_PKCS_PSS,
    "SHA-224": CKM_SHA224_RSA_PKCS_PSS,
    "SHA-256": CKM_SHA256_RSA_PKCS_PSS,
    "SHA-384": CKM_SHA384_RSA_PKCS_PSS,
    "SHA-512": CKM_SHA512_RSA_PKCS_PSS,
    "SHA3-224": CKM_SHA3_224_RSA_PKCS_PSS,
    "SHA3-256": CKM_SHA3_256_RSA_PKCS_PSS,
    "SHA3-384": CKM_SHA3_384_RSA_PKCS_PSS,
    "SHA3-512": CKM_SHA3_512_RSA_PKCS_PSS,
}

_SHA_HASH_MECHS: dict[str, int] = {
    "SHA-1": CKM_SHA_1,
    "SHA-224": CKM_SHA224,
    "SHA-256": CKM_SHA256,
    "SHA-384": CKM_SHA384,
    "SHA-512": CKM_SHA512,
    "SHA3-224": CKM_SHA3_224,
    "SHA3-256": CKM_SHA3_256,
    "SHA3-384": CKM_SHA3_384,
    "SHA3-512": CKM_SHA3_512,
}

_SHA_MGFS: dict[str, int] = {
    "SHA-1": CKG_MGF1_SHA1,
    "SHA-224": CKG_MGF1_SHA224,
    "SHA-256": CKG_MGF1_SHA256,
    "SHA-384": CKG_MGF1_SHA384,
    "SHA-512": CKG_MGF1_SHA512,
    "SHA3-224": CKG_MGF1_SHA3_224,
    "SHA3-256": CKG_MGF1_SHA3_256,
    "SHA3-384": CKG_MGF1_SHA3_384,
    "SHA3-512": CKG_MGF1_SHA3_512,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_SHA1_RSA_PKCS_PSS: "SHA1_RSA_PKCS_PSS",
    CKM_SHA224_RSA_PKCS_PSS: "SHA224_RSA_PKCS_PSS",
    CKM_SHA256_RSA_PKCS_PSS: "SHA256_RSA_PKCS_PSS",
    CKM_SHA384_RSA_PKCS_PSS: "SHA384_RSA_PKCS_PSS",
    CKM_SHA512_RSA_PKCS_PSS: "SHA512_RSA_PKCS_PSS",
    CKM_SHA3_224_RSA_PKCS_PSS: "SHA3_224_RSA_PKCS_PSS",
    CKM_SHA3_256_RSA_PKCS_PSS: "SHA3_256_RSA_PKCS_PSS",
    CKM_SHA3_384_RSA_PKCS_PSS: "SHA3_384_RSA_PKCS_PSS",
    CKM_SHA3_512_RSA_PKCS_PSS: "SHA3_512_RSA_PKCS_PSS",
}

# RSA-PSS vector files - standard and parameterized variants that map to
# the existing PKCS#11 PSS mechanism family.
_PSS_FILES = sorted(
    f.name
    for f in WYCHEPROOF_DIR.glob("rsa_pss_*_test.json")
    if f.exists() and "shake" not in f.name
)


def _load_pss_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all standard RSA-PSS vectors."""
    vectors = []
    for filename in _PSS_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mgf_sha = group.get("mgfSha", sha)
            mechanism = _SHA_MECHANISMS.get(sha)
            hash_mech = _SHA_HASH_MECHS.get(sha)
            mgf = _SHA_MGFS.get(mgf_sha)
            if mechanism is None or hash_mech is None or mgf is None:
                continue
            s_len = group.get("sLen", 0)
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_sLen"] = s_len
                test["_sha"] = sha
                test["_mgf_sha"] = mgf_sha
                test["_hash_mech"] = hash_mech
                test["_mgf"] = mgf
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    _mark_pkcs11_duplicate_vectors(vectors)
    return vectors


_ALL_PSS_VECTORS = _load_pss_vectors()


def _xfail_if_rsa_pss_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised RSA-PSS parameter/runtime rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _RSA_PSS_RUNTIME_REJECT_CKRS,
        f"{label}: advertised RSA-PSS parameters are not operational",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_PSS_VECTORS, ids=[v[0] for v in _ALL_PSS_VECTORS])
def test_rsa_pss(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA-PSS signature verification from Wycheproof vectors."""
    rs = p11_module_session
    mechanism = vec["_mechanism"]
    name = _MECH_DISPLAY.get(mechanism, "RSA_PKCS_PSS")
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 RSA-PSS operation input; covered by {duplicate_of}")

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]
    s_len = vec["_sLen"]
    hash_mech = vec["_hash_mech"]
    mgf = vec["_mgf"]

    pk = group.get("publicKey", {})
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    if not modulus_hex or not exp_hex:
        pytest.skip("No RSA public key in vector group")

    modulus = pkcs11_bigint_from_hex(modulus_hex)
    exponent = pkcs11_bigint_from_hex(exp_hex)
    key_bits = len(modulus) * 8

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        pytest.skip(f"RSA {key_bits}-bit keys not supported (cached)")

    try:
        pub_key = import_rsa_public_key_negotiated(
            rs,
            n=modulus,
            e=exponent,
            attrs={CKA_VERIFY: True},
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        # Only cache permanent key-size rejections, not transient errors.
        if is_known_error(exc, _RSA_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
        pytest.skip(f"Cannot import RSA {key_bits}-bit public key: {exc_msg}")

    # Build PSS params
    pss_param = mech_pss(mechanism, hash_mech=hash_mech, mgf=mgf, salt_len=s_len)

    try:
        verified = verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig, mech_param=pss_param)
        if result == "invalid":
            if verified:
                pytest.fail(f"Invalid RSA-PSS sig {vec_id} accepted by module")
            return
        if result == "valid" and not verified:
            if not _pss_combo_operational(rs, mechanism, hash_mech, mgf, s_len):
                pytest.xfail(
                    f"Valid {vec_id} rejected; sign+verify roundtrip with "
                    f"the same (mech, hash, mgf, sLen={s_len}) also fails "
                    "-- advertised but not operational"
                )
            pytest.fail(f"Valid RSA-PSS sig {vec_id} rejected by module")
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_rsa_pss_runtime_reject(exc, vec_id)
            sha = vec.get("_sha", "unknown")
            mgf_sha = vec.get("_mgf_sha", "unknown")
            flags = vec.get("flags", [])
            flags_str = ", ".join(flags) if flags else "none"
            pytest.fail(
                f"Valid RSA-PSS sig {vec_id} rejected (sLen={s_len}, "
                f"sha={sha}, mgf={mgf_sha}, flags=[{flags_str}]): {exc}"
            )
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
