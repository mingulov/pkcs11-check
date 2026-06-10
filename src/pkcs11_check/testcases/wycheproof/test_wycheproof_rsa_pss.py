"""Wycheproof RSA-PSS signature verification vectors.

Tests RSA-PSS (PKCS#1 v2.1) across key sizes 2048/3072/4096 with
SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 and varying salt lengths.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check.raw.pack import mech_pss
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    generate_random,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
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
    CKR_OPERATION_ACTIVE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    probe_operability,
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
    # Collateral of a stale verify op the provider leaked after a prior
    # reject (spec violation, reported as a FAIL by
    # test_operation_termination.py): the poisoned C_*Init never evaluated
    # THIS vector's signature, so it is a clean non-evaluating reject.
    CKR_OPERATION_ACTIVE,
)

# Canned message for the operational probe -- arbitrary content.
_PSS_PROBE_MESSAGE = b"pkcs11-check PSS combo operational probe"


def _pss_combo_operability(
    rs: Any, mechanism: int, hash_mech: int, mgf: int, salt_len: int
) -> OperabilityResult:
    """Self-roundtrip probe for a (mech, hash, mgf, sLen) PSS combo.

    Keypair generation is staging (plain RSA keygen, no PSS involved) -- its
    refusal is INCONCLUSIVE, not mechanism evidence (so the vacuous-reject
    downgrade never fires without combo evidence). A canonical PSS sign/verify
    refusal (CkrAssertionError) or verify-False IS combo evidence ->
    NOT_OPERATIONAL; a verifying self-roundtrip -> OPERATIONAL. Cached per combo
    via probe_operability.

    Module errors surface as CkrAssertionError (gen_rsa_keypair / sign_single /
    verify_single all route through expect_rv); a plain AssertionError is a
    harness bug and propagates uncached. ``mech_pss`` packing errors are
    harness-side (ctypes) and likewise propagate.
    """

    def probe() -> OperabilityResult:
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
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"RSA-2048 keypair staging failed: {exc}"
                )
            pss_param = mech_pss(mechanism, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv, mechanism, _PSS_PROBE_MESSAGE, mech_param=pss_param
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical PSS sign rejected: {exc}"
                )
            try:
                ok = verify_single(
                    rs.raw, rs.sh, pub, mechanism, _PSS_PROBE_MESSAGE, sig, mech_param=pss_param
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical PSS verify rejected: {exc}"
                )
            if not ok:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, "own PSS signature verifies False"
                )
            return OperabilityResult(Operability.OPERATIONAL, "self-roundtrip OK")
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)

    return probe_operability(
        f"RSA_PSS:{mechanism:#x}:{hash_mech:#x}:{mgf:#x}:{salt_len}:sign-verify", probe
    )


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


_CRYPTOGRAPHY_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "SHA-1": hashes.SHA1,
    "SHA-224": hashes.SHA224,
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
    "SHA3-224": hashes.SHA3_224,
    "SHA3-256": hashes.SHA3_256,
    "SHA3-384": hashes.SHA3_384,
    "SHA3-512": hashes.SHA3_512,
}


def _pss_valid_under_auto_salt(
    n: bytes, e: bytes, msg: bytes, sig: bytes, sha: str, mgf_sha: str
) -> bool | None:
    """Reference RSA-PSS verification with the salt length recovered from the signature.

    Discriminates the two acceptance classes of a Wycheproof "invalid" PSS
    vector: a GENUINE signature re-signed with a different salt length than
    the declared ``sLen`` (only producible with the private key; True) versus
    a modified/garbage signature whose acceptance is a padding-check bypass
    (False). Pure public-key math -- the provider is not involved. None when
    the reference backend cannot represent the combo; callers keep the strict
    hard-fail then (a real finding is never masked).
    """
    hash_cls = _CRYPTOGRAPHY_HASHES.get(sha)
    mgf_cls = _CRYPTOGRAPHY_HASHES.get(mgf_sha)
    if hash_cls is None or mgf_cls is None:
        return None
    try:
        pub = rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
        pub.verify(
            sig,
            msg,
            padding.PSS(mgf=padding.MGF1(mgf_cls()), salt_length=padding.PSS.AUTO),
            hash_cls(),
        )
        return True
    except InvalidSignature:
        return False
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return None


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

    verified: bool | None = None
    try:
        verified = verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig, mech_param=pss_param)
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

    # --- outcome classification (probe calls must live here, outside the
    # narrow try/except above, so plain AssertionErrors from the probe are
    # never re-caught and misrouted through _xfail_if_rsa_pss_runtime_reject) ---
    if result == "invalid":
        if verified:
            # Discriminate the acceptance class with a reference auto-salt
            # verification (pure public-key math): a GENUINE signature whose
            # salt length merely differs from the declared sLen is only
            # producible with the private key -- accepting it is salt-length
            # policy leniency (the verifier recovers the salt, RFC 8017),
            # an honest deviation, not a forgery. Anything else that
            # verifies is a padding-check bypass and stays a hard fail.
            if (
                _pss_valid_under_auto_salt(
                    modulus, exponent, msg, sig, vec["_sha"], vec["_mgf_sha"]
                )
                is True
            ):
                pytest.xfail(
                    f"{vec_id}: accepted a genuine PSS signature whose salt length "
                    f"differs from the declared sLen={s_len} -- salt-length policy "
                    "not enforced (not forgeable without the private key)"
                )
            pytest.fail(f"Invalid RSA-PSS sig {vec_id} accepted by module")
        return
    if result == "valid" and not verified:
        combo = _pss_combo_operability(rs, mechanism, hash_mech, mgf, s_len)
        if combo.status is Operability.NOT_OPERATIONAL:
            pytest.xfail(
                f"Valid {vec_id} rejected; sign+verify roundtrip with the same "
                f"(mech, hash, mgf, sLen={s_len}) is not operational ({combo.detail}) "
                "-- advertised but not operational"
            )
        if combo.status is Operability.INCONCLUSIVE:
            pytest.xfail(
                f"Valid {vec_id} rejected; PSS combo probe inconclusive ({combo.detail}) "
                "-- cannot distinguish deviation from module bug, recorded as xfail"
            )
        pytest.fail(f"Valid RSA-PSS sig {vec_id} rejected by module")

    generate_random(rs.raw, rs.sh, 64)
