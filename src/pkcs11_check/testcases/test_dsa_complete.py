"""Tests for the complete DSA mechanism family.

Covers raw CKM_DSA, prehash variants (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-*),
and CKM_DSA_PARAMETER_GEN.

Note: CKM_DSA_KEY_PAIR_GEN is already tested in test_sign.py.

OASIS PKCS#11 v3.2 spec: DSA.
"""

from __future__ import annotations

import ctypes
import hashlib
import uuid
from ctypes import byref
from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify, fail_as, record_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import (
    PackedMechanism,
    _mech_struct,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    copy_object,
    destroy_quietly,
    read_attributes,
    sign_multipart,
    sign_single,
    verify_multipart,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_BYTE,
    CK_DSA_PARAMETER_GEN_PARAM,
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_SUBPRIME_BITS,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_DSA,
    CKM_DSA,
    CKM_DSA_FIPS_G_GEN,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_DSA_PARAMETER_GEN,
    CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
    CKM_DSA_SHA1,
    CKM_DSA_SHA3_224,
    CKM_DSA_SHA3_256,
    CKM_DSA_SHA3_384,
    CKM_DSA_SHA3_512,
    CKM_DSA_SHA224,
    CKM_DSA_SHA256,
    CKM_DSA_SHA384,
    CKM_DSA_SHA512,
    CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
    CKM_SHA256,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._copy_mutability import (
    COPY_FORBIDDEN_REFUSE_RVS,
    classify_forbidden_change_refusal,
    classify_ignored_or_mutated,
    classify_rv_validity_or_none,
    read_qc3_attributes,
    validate_qc3_shape,
)
from pkcs11_check.testcases._ec_export import parse_raw_dss_or_classify
from pkcs11_check.testcases._exact_search import check_exact_and_changed_search, flip_last_byte
from pkcs11_check.testcases._signature_policy import (
    signature_rejected_or_xfail,
    xfail_if_op_not_operational,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    classify_negative_rv,
    create_object_negotiated,
    is_known_error,
    skip_unless_create_object_supported,
    xfail_if_known_ckr,
)

# Verification failure return values
_VERIFY_FAIL_RVS = {
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_FUNCTION_FAILED,
}

_DSA_PARAMETER_SIZE_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
)

_DSA_PARAMETER_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_BUFFER_TOO_SMALL,
)

# DSA parameter/key generation is heavy on several modules (10-32s per case
# on some modules); the keygen-bound classes below stay marked slow so a basic
# run can skip them with -m "not slow" (they still run in the full profile).
# The mark lives on the classes -- not the module -- so the bounded
# fixed-vector class (TestDSABoundedWidth, QC5b) runs in the ordinary
# selected profile without any generation on its hot path.
pytestmark = [pytest.mark.sign]

# Distinct-digest sample size for the repeated-r invariant below.
_DISTINCT_MESSAGE_SAMPLES = 20

_DSA_KEYPAIR_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_DSA_PARAMETER_TEMPLATE_REJECT_RVS = (CKR_TEMPLATE_INCOMPLETE,)

# Prehash DSA variants.
_DSA_HASH_MECHS = [
    pytest.param("DSA_SHA1", CKM_DSA_SHA1, id="SHA1"),
    pytest.param("DSA_SHA224", CKM_DSA_SHA224, id="SHA224"),
    pytest.param("DSA_SHA256", CKM_DSA_SHA256, id="SHA256"),
    pytest.param("DSA_SHA384", CKM_DSA_SHA384, id="SHA384"),
    pytest.param("DSA_SHA512", CKM_DSA_SHA512, id="SHA512"),
    pytest.param("DSA_SHA3_224", CKM_DSA_SHA3_224, id="SHA3-224"),
    pytest.param("DSA_SHA3_256", CKM_DSA_SHA3_256, id="SHA3-256"),
    pytest.param("DSA_SHA3_384", CKM_DSA_SHA3_384, id="SHA3-384"),
    pytest.param("DSA_SHA3_512", CKM_DSA_SHA3_512, id="SHA3-512"),
]

# Fixed DSA-2048/256 keypair (QC5b, issue #57.2): RFC 6979 (Pornin,
# "Deterministic Usage of DSA and ECDSA", August 2013), Appendix A.2.2.
# y == g**x mod p and the SHA-256("sample") signature below were verified
# with an independent DSA implementation at transcription time. Importing
# this vector bounds the ordinary-profile leg: no parameter or keypair
# generation runs on its hot path.
_FIXED_DSA_P = bytes.fromhex(
    "9db6fb5951b66bb6fe1e140f1d2ce5502374161fd6538df1648218642f0b5c48"
    "c8f7a41aadfa187324b87674fa1822b00f1ecf8136943d7c55757264e5a1a44f"
    "fe012e9936e00c1d3e9310b01c7d179805d3058b2a9f4bb6f9716bfe6117c6b5"
    "b3cc4d9be341104ad4a80ad6c94e005f4b993e14f091eb51743bf33050c38de2"
    "35567e1b34c3d6a5c0ceaa1a0f368213c3d19843d0b4b09dcb9fc72d39c8de41"
    "f1bf14d4bb4563ca28371621cad3324b6a2d392145bebfac748805236f5ca2fe"
    "92b871cd8f9c36d3292b5509ca8caa77a2adfc7bfd77dda6f71125a7456fea15"
    "3e433256a2261c6a06ed3693797e7995fad5aabbcfbe3eda2741e375404ae25b"
)
_FIXED_DSA_Q = bytes.fromhex("f2c3119374ce76c9356990b465374a17f23f9ed35089bd969f61c6dde9998c1f")
_FIXED_DSA_G = bytes.fromhex(
    "5c7ff6b06f8f143fe8288433493e4769c4d988ace5be25a0e24809670716c613"
    "d7b0cee6932f8faa7c44d2cb24523da53fbe4f6ec3595892d1aa58c4328a06c4"
    "6a15662e7eaa703a1decf8bbb2d05dbe2eb956c142a338661d10461c0d135472"
    "085057f3494309ffa73c611f78b32adbb5740c361c9f35be90997db2014e2ef5"
    "aa61782f52abeb8bd6432c4dd097bc5423b285dafb60dc364e8161f4a2a35aca"
    "3a10b1c4d203cc76a470a33afdcbdd92959859abd8b56e1725252d78eac66e71"
    "ba9ae3f1dd2487199874393cd4d832186800654760e1e34c09e4d155179f9ec0"
    "dc4473f996bdce6eed1cabed8b6f116f7ad9cf505df0f998e34ab27514b0ffe7"
)
_FIXED_DSA_X = bytes.fromhex("69c7548c21d0dfea6b9a51c9ead4e27c33d3b3f180316e5bcab92c933f0e4dbc")
_FIXED_DSA_Y = bytes.fromhex(
    "667098c654426c78d7f8201eac6c203ef030d43605032c2f1fa937e5237dbd94"
    "9f34a0a2564fe126dc8b715c5141802ce0979c8246463c40e6b6bdaa2513fa61"
    "1728716c2e4fd53bc95b89e69949d96512e873b9c8f8dfd499cc312882561ade"
    "cb31f658e934c0c197f2c4d96b05cbad67381e7b768891e4da3843d24d94cdfb"
    "5126e9b8bf21e8358ee0e0a30ef13fd6a664c0dce3731f7fb49a4845a4fd8254"
    "687972a2d382599c9bac4e0ed7998193078913032558134976410b89d2c171d1"
    "23ac35fd977219597aa7d15c1a9a428e59194f75c721ebcbcfae44696a499afa"
    "74e04299f132026601638cb87ab79190d4a0986315da8eec6561c938996beadf"
)
_FIXED_DSA_Q_INT = int.from_bytes(_FIXED_DSA_Q, "big")
_FIXED_DSA_HALF_LEN = 32
_FIXED_DSA_SAMPLE_DIGEST = hashlib.sha256(b"sample").digest()
_FIXED_DSA_SAMPLE_R = bytes.fromhex(
    "eace8bdbbe353c432a795d9ec556c6d021f7a03f42c36e9bc87e4ac7932cc809"
)
_FIXED_DSA_SAMPLE_S = bytes.fromhex(
    "7081e175455f9247b812b74583e9e94f9ea79bd640dc962533b0680793a38d53"
)

# Clean C_CreateObject refusals while staging the fixed DSA vector: the
# module advertises CKM_DSA but cannot stage the vector, so the padded-half
# oracle never ran -- xfail (recorded), never a crypto finding. Notably
# CKR_DOMAIN_PARAMS_INVALID is NOT here: the RFC 6979 parameters are valid,
# so rejecting them is a provider bug and must fail loudly.
_DSA_IMPORT_RUNTIME_REJECT_RVS = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
)


def _import_fixed_dsa_keypair(
    rs: Any, *, label: str | None = None, copyable: bool | None = None
) -> tuple[int, int]:
    """Import the fixed RFC 6979 DSA-2048 keypair (bounded, no generation).

    Returns (pub_handle, priv_handle). A clean refusal raises
    CkrAssertionError for the caller to route (xfail); the public half is
    destroyed if the private import fails.

    ``label`` and ``copyable`` are default-omitted and land on the public
    half only when requested (QC6a search scoping / QC6b copy premise), so
    the QC5b stimulus stays byte-identical.
    """
    public_attrs: dict[Any, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_DSA,
        CKA_TOKEN: False,
        CKA_PRIME: _FIXED_DSA_P,
        CKA_SUBPRIME: _FIXED_DSA_Q,
        CKA_BASE: _FIXED_DSA_G,
        CKA_VALUE: _FIXED_DSA_Y,
        CKA_VERIFY: True,
    }
    if label is not None:
        public_attrs[CKA_LABEL] = label
    if copyable is not None:
        public_attrs[CKA_COPYABLE] = copyable
    pub = create_object_negotiated(
        rs,
        public_attrs,
        purpose="QC5b fixed DSA-2048 public import",
    )
    try:
        priv = create_object_negotiated(
            rs,
            {
                CKA_CLASS: CKO_PRIVATE_KEY,
                CKA_KEY_TYPE: CKK_DSA,
                CKA_TOKEN: False,
                CKA_PRIME: _FIXED_DSA_P,
                CKA_SUBPRIME: _FIXED_DSA_Q,
                CKA_BASE: _FIXED_DSA_G,
                CKA_VALUE: _FIXED_DSA_X,
                CKA_SIGN: True,
            },
            purpose="QC5b fixed DSA-2048 private import",
        )
    except BaseException:
        destroy_quietly(rs.raw, rs.sh, pub)
        raise
    return pub, priv


def _dsa_parameter_gen_param_mech(
    mechanism: int,
    *,
    seed_len: int = 64,
    seed: bytes | None = None,
    index: int = 1,
    hash_mech: int = CKM_SHA256,
) -> PackedMechanism:
    """Pack CK_DSA_PARAMETER_GEN_PARAM with an owned mutable seed buffer."""
    if seed_len < 0:
        raise ValueError("seed_len must be non-negative")
    if seed is not None and len(seed) > seed_len:
        raise ValueError("seed does not fit in seed_len")

    seed_buf = (CK_BYTE * seed_len)()
    if seed:
        ctypes.memmove(seed_buf, seed, len(seed))

    params = CK_DSA_PARAMETER_GEN_PARAM()
    params.hash = hash_mech
    params.pSeed = ctypes.cast(seed_buf, ctypes.c_void_p)
    params.ulSeedLen = seed_len
    params.ulIndex = index

    packed = _mech_struct(mechanism, params, "dsa_parameter_gen_param")
    packed.add_buffer("seed", seed_buf, seed_len)
    return packed


def _generate_dsa_params(raw: Any, sh: int) -> int:
    """Generate DSA domain parameters using CKM_DSA_PARAMETER_GEN.

    Returns domain parameter object handle.
    """
    tmpl = template(
        attr_ulong(CKA_PRIME_BITS, 2048),
        attr_bool(CKA_TOKEN, False),
    )
    dp_handle = CK_OBJECT_HANDLE(0)
    mech = mech_simple(CKM_DSA_PARAMETER_GEN)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(dp_handle))
    expect_rv(rv, CKR_OK)
    return dp_handle.value


def _generate_dsa_pq_params(raw: Any, sh: int, mechanism: int) -> tuple[int, PackedMechanism]:
    """Generate DSA p/q domain parameters using a FIPS 186-4 variant mechanism."""
    tmpl = template(
        attr_ulong(CKA_PRIME_BITS, 2048),
        attr_ulong(CKA_SUBPRIME_BITS, 256),
        attr_bool(CKA_TOKEN, False),
    )
    dp_handle = CK_OBJECT_HANDLE(0)
    mech = _dsa_parameter_gen_param_mech(mechanism)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(dp_handle))
    expect_rv(rv, CKR_OK)
    return dp_handle.value, mech


def _assert_generated_dsa_pq_attrs(raw: Any, sh: int, dp_handle: int) -> tuple[bytes, bytes] | None:
    """Assert a FIPS 186-4 p/q-generation result contains the expected attributes.

    Returns (prime, subprime), or None if the provider omitted CKA_PRIME or
    CKA_SUBPRIME on readback (recorded via attr_or_record()) so the generated
    p/q cannot be used for dependent work.
    """
    attrs = read_attributes(
        raw,
        sh,
        dp_handle,
        [CKA_PRIME, CKA_SUBPRIME, CKA_PRIME_BITS, CKA_SUBPRIME_BITS],
    )
    prime = attr_or_record(
        attrs,
        CKA_PRIME,
        label="DSA parameter gen: CKA_PRIME readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    subprime = attr_or_record(
        attrs,
        CKA_SUBPRIME,
        label="DSA parameter gen: CKA_SUBPRIME readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    prime_bits = attr_or_record(
        attrs,
        CKA_PRIME_BITS,
        label="DSA parameter gen: CKA_PRIME_BITS readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    subprime_bits = attr_or_record(
        attrs,
        CKA_SUBPRIME_BITS,
        label="DSA parameter gen: CKA_SUBPRIME_BITS readback",
        reason="not_operational",
        inherit_mechanism=False,
    )

    if prime_bits is not MISSING_ATTRIBUTE:
        assert isinstance(prime_bits, int)
        assert_correct(
            actual=prime_bits,
            expected=2048,
            label="DSA parameter gen: CKA_PRIME_BITS readback",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            kind="metadata",
        )
    if subprime_bits is not MISSING_ATTRIBUTE:
        assert isinstance(subprime_bits, int)
        assert_correct(
            actual=subprime_bits,
            expected=256,
            label="DSA parameter gen: CKA_SUBPRIME_BITS readback",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            kind="metadata",
        )

    # Validate each present sibling before deciding whether dependent work can
    # continue.  A missing PRIME must not turn an empty or wrong-type SUBPRIME
    # into an unobserved setup omission (and vice versa).
    if prime is not MISSING_ATTRIBUTE:
        assert isinstance(prime, bytes)
        assert len(prime) > 0
    if subprime is not MISSING_ATTRIBUTE:
        assert isinstance(subprime, bytes)
        assert len(subprime) > 0

    if prime is MISSING_ATTRIBUTE or subprime is MISSING_ATTRIBUTE:
        return None

    assert isinstance(prime, bytes)
    assert isinstance(subprime, bytes)
    return prime, subprime


def _dsa_returned_seed(mech: PackedMechanism) -> bytes:
    """Return the provider-written seed from a DSA p/q-generation mechanism."""
    assert isinstance(mech.params, CK_DSA_PARAMETER_GEN_PARAM)
    storage, capacity = mech.buffer_storage("seed")
    seed_len = int(mech.params.ulSeedLen)
    assert 0 < seed_len <= capacity
    return bytes(storage[:seed_len])


def _generate_dsa_base_from_pq(
    raw: Any,
    sh: int,
    *,
    prime: bytes,
    subprime: bytes,
    seed: bytes,
    index: int,
) -> int:
    """Generate DSA base g from p/q plus the seed returned by a p/q variant."""
    tmpl = template(
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_SUBPRIME, subprime),
        attr_bool(CKA_TOKEN, False),
    )
    base_handle = CK_OBJECT_HANDLE(0)
    mech = _dsa_parameter_gen_param_mech(
        CKM_DSA_FIPS_G_GEN,
        seed_len=len(seed),
        seed=seed,
        index=index,
    )
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(base_handle))
    expect_rv(rv, CKR_OK)
    return base_handle.value


def _skip_or_xfail_dsa_param_gen_reject(exc: AssertionError) -> NoReturn:
    if is_known_error(exc, _DSA_PARAMETER_SIZE_REJECT_RVS):
        pytest.skip(f"DSA-2048 parameter generation not supported: {exc}")
    xfail_if_known_ckr(
        exc,
        _DSA_PARAMETER_RUNTIME_REJECT_RVS,
        "DSA_PARAMETER_GEN advertised but parameter generation is not operational",
    )
    raise


def _xfail_if_dsa_keypair_reject(exc: AssertionError) -> NoReturn:
    xfail_if_known_ckr(
        exc,
        _DSA_KEYPAIR_RUNTIME_REJECT_RVS,
        "DSA_KEY_PAIR_GEN advertised but keypair generation from generated params "
        "is not operational",
    )
    raise


def _gen_dsa_keypair_from_params(
    raw: Any,
    sh: int,
    dp_handle: int,
) -> tuple[int, int] | None:
    """Generate a DSA keypair from domain parameters object.

    Reads PRIME, SUBPRIME, BASE from dp_handle, then calls C_GenerateKeyPair.
    Returns (pub_handle, priv_handle), or None if the provider omitted a
    required domain-parameter attribute on readback (recorded via
    attr_or_record()) so keypair generation could not be attempted.
    """
    dp_attrs = read_attributes(
        raw,
        sh,
        dp_handle,
        [CKA_PRIME, CKA_SUBPRIME, CKA_BASE],
    )
    prime = attr_or_record(
        dp_attrs,
        CKA_PRIME,
        label="DSA keypair from domain params: CKA_PRIME readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    subprime = attr_or_record(
        dp_attrs,
        CKA_SUBPRIME,
        label="DSA keypair from domain params: CKA_SUBPRIME readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    base = attr_or_record(
        dp_attrs,
        CKA_BASE,
        label="DSA keypair from domain params: CKA_BASE readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    # Check every value that was actually returned before an omitted sibling
    # short-circuits dependent key-pair generation.  This keeps malformed
    # present parameters visible even when another required parameter is absent.
    for value in (prime, subprime, base):
        if value is not MISSING_ATTRIBUTE:
            assert isinstance(value, bytes)
            assert len(value) > 0

    if prime is MISSING_ATTRIBUTE or subprime is MISSING_ATTRIBUTE or base is MISSING_ATTRIBUTE:
        return None

    assert isinstance(prime, bytes)
    assert isinstance(subprime, bytes)
    assert isinstance(base, bytes)

    pub_tmpl = template(
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_SUBPRIME, subprime),
        attr_bytes(CKA_BASE, base),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_VERIFY, True),
    )
    priv_tmpl = template(
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SIGN, True),
    )
    mech = mech_simple(CKM_DSA_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    expect_rv(rv, CKR_OK)
    return pub_h.value, priv_h.value


def _generate_dsa_keypair(
    rs: Any,
) -> tuple[int, int, int] | None:
    """Generate DSA domain parameters and keypair.

    Returns (dp_handle, public_key_handle, private_key_handle), or None if
    keypair generation could not be attempted because the provider omitted a
    required domain-parameter attribute on readback.
    Skips the test if DSA param/key generation is not supported.
    """
    if not rs.has_mechanism("DSA_PARAMETER_GEN"):
        pytest.skip("CKM_DSA_PARAMETER_GEN not supported for DSA setup")
    try:
        dp_handle = _generate_dsa_params(rs.raw, rs.sh)
    except AssertionError as e:
        _skip_or_xfail_dsa_param_gen_reject(e)
    if not rs.has_mechanism("DSA_KEY_PAIR_GEN"):
        destroy_quietly(rs.raw, rs.sh, dp_handle)
        pytest.skip("CKM_DSA_KEY_PAIR_GEN not supported for DSA setup")
    try:
        result = _gen_dsa_keypair_from_params(rs.raw, rs.sh, dp_handle)
    except AssertionError as e:
        destroy_quietly(rs.raw, rs.sh, dp_handle)
        _xfail_if_dsa_keypair_reject(e)
    if result is None:
        destroy_quietly(rs.raw, rs.sh, dp_handle)
        return None
    pub, priv = result
    return dp_handle, pub, priv


def _read_dsa_subprime(rs: Any, dp_handle: int) -> bytes | None:
    """Read the DSA subprime q for signature-width derivation.

    Returns the raw subprime bytes, or None if the provider omitted
    CKA_SUBPRIME on readback (recorded via attr_or_record()) so
    width-dependent signature analysis cannot run.
    """
    attrs = read_attributes(rs.raw, rs.sh, dp_handle, [CKA_SUBPRIME])
    subprime = attr_or_record(
        attrs,
        CKA_SUBPRIME,
        label="DSA signature width: CKA_SUBPRIME readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    if subprime is MISSING_ATTRIBUTE:
        return None
    assert isinstance(subprime, bytes)
    assert len(subprime) > 0
    return subprime


def _dsa_sign_or_xfail(rs: Any, priv: int, mechanism: int, data: bytes, label: str) -> bytes:
    try:
        return sign_single(rs.raw, rs.sh, priv, mechanism, data)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_sign_multipart_or_xfail(
    rs: Any,
    priv: int,
    mechanism: int,
    chunks: tuple[bytes, ...],
    label: str,
) -> bytes:
    try:
        return sign_multipart(rs.raw, rs.sh, priv, mechanism, chunks)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_verify_or_xfail(
    rs: Any,
    pub: int,
    mechanism: int,
    data: bytes,
    signature: bytes,
    label: str,
) -> bool:
    try:
        return verify_single(rs.raw, rs.sh, pub, mechanism, data, signature)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_verify_multipart_or_xfail(
    rs: Any,
    pub: int,
    mechanism: int,
    chunks: tuple[bytes, ...],
    signature: bytes,
    label: str,
) -> bool:
    try:
        return verify_multipart(rs.raw, rs.sh, pub, mechanism, chunks, signature)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_invalid_verify_rejected_or_xfail(
    rs: Any,
    pub: int,
    mechanism: int,
    data: bytes,
    signature: bytes,
    label: str,
) -> bool:
    try:
        return verify_single(rs.raw, rs.sh, pub, mechanism, data, signature)
    except AssertionError as exc:
        return signature_rejected_or_xfail(exc, label)


@pytest.mark.slow
class TestDSARaw:
    """Tests for raw CKM_DSA with pre-hashed data."""

    def test_raw_dsa_sign_verify(self, p11_module_session: Any) -> None:
        """Raw DSA sign/verify with a SHA-1-sized digest (20 bytes)."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            digest = hashlib.sha1(b"raw DSA test data", usedforsecurity=False).digest()  # noqa: S324
            assert len(digest) == 20

            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            assert len(sig) > 0

            result = verify_single(rs.raw, rs.sh, pub, CKM_DSA, digest, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_digest_fails(self, p11_module_session: Any) -> None:
        """Raw DSA verification with wrong digest must fail."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            digest = hashlib.sha1(b"original data", usedforsecurity=False).digest()  # noqa: S324
            wrong_digest = hashlib.sha1(b"tampered data", usedforsecurity=False).digest()  # noqa: S324

            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            result = verify_single(rs.raw, rs.sh, pub, CKM_DSA, wrong_digest, sig)
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_signature_length_fails(self, p11_module_session: Any) -> None:
        """Raw DSA verification with a truncated signature must fail."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            digest = hashlib.sha1(b"wrong signature length", usedforsecurity=False).digest()  # noqa: S324
            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            assert len(sig) > 1

            truncated_sig = sig[:-1]
            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                CKM_DSA,
                digest,
                truncated_sig,
                "CKM_DSA wrong-length signature",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_overlong_signature_length_fails(self, p11_module_session: Any) -> None:
        """Raw DSA verification with an overlong signature must fail."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            digest = hashlib.sha1(b"overlong signature length", usedforsecurity=False).digest()  # noqa: S324
            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            assert len(sig) > 0

            overlong_sig = sig + b"\x00"
            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                CKM_DSA,
                digest,
                overlong_sig,
                "CKM_DSA overlong signature",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_deterministic_signing_distinct_r(self, p11_module_session: Any) -> None:
        """Same-digest resignature passes (deterministic signing is valid).

        Identical signatures for the same digest are valid deterministic DSS
        behavior (RFC 6979 / FIPS 186-5), not nonce reuse. The adverse
        invariant is a repeated valid ``r`` across distinct digests, which
        signals equivalent-nonce reuse. Scalar widths come from the read-back
        subprime, never from fixed slicing.
        """
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            subprime = _read_dsa_subprime(rs, dp)
            if subprime is None:
                return
            half_len = len(subprime)
            order = int.from_bytes(subprime, "big")

            digest = hashlib.sha1(b"nonce test", usedforsecurity=False).digest()  # noqa: S324

            sig1 = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            parse_raw_dss_or_classify(
                sig1,
                half_len=half_len,
                order=order,
                label="CKM_DSA:sign deterministic signing",
                operation="C_Sign",
                mechanism="CKM_DSA",
            )
            sig2 = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            parse_raw_dss_or_classify(
                sig2,
                half_len=half_len,
                order=order,
                label="CKM_DSA:sign deterministic signing",
                operation="C_Sign",
                mechanism="CKM_DSA",
            )
            if sig1 == sig2:
                note(
                    "CKM_DSA: identical signatures for the same digest "
                    "(deterministic signing; valid per RFC 6979 / FIPS 186-5)",
                    ComplianceLevel.STANDARD,
                    reference="RFC 6979; FIPS 186-5",
                )
            else:
                note(
                    "CKM_DSA: varying signatures for the same digest (randomized signing)",
                    ComplianceLevel.EXTENDED,
                    reference="RFC 6979; FIPS 186-5",
                )
            seen_r: dict[int, int] = {}
            for i in range(_DISTINCT_MESSAGE_SAMPLES):
                distinct = hashlib.sha1(  # noqa: S324
                    f"DSA raw distinct digest {i}".encode(), usedforsecurity=False
                ).digest()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, distinct)
                r, _ = parse_raw_dss_or_classify(
                    sig,
                    half_len=half_len,
                    order=order,
                    label="CKM_DSA:sign distinct-digest r",
                    operation="C_Sign",
                    mechanism="CKM_DSA",
                )
                if r in seen_r:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="CKM_DSA:sign distinct-digest r",
                        operation="C_Sign",
                        mechanism="CKM_DSA",
                        summary=(
                            "CKM_DSA: repeated valid r across distinct digests "
                            f"(samples {seen_r[r]} and {i}); dangerous "
                            "equivalent-nonce reuse signal"
                        ),
                        detail={
                            "first_index": seen_r[r],
                            "repeat_index": i,
                            "samples": _DISTINCT_MESSAGE_SAMPLES,
                            "r_bit_length": r.bit_length(),
                        },
                    )
                seen_r[r] = i
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_length_digest(self, p11_module_session: Any) -> None:
        """Raw DSA with wrong-length digest should fail per spec."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            # 7 bytes is too short for any valid subprime size
            bad_digest = b"\x00" * 7

            # Sign with wrong-length digest - must be rejected
            mech = mech_simple(CKM_DSA)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            if rv != CKR_OK:
                # SignInit itself rejected it -- acceptable
                return

            in_buf = (ctypes.c_ubyte * len(bad_digest))(*bad_digest)
            out_len = ctypes.c_ulong(0)
            rv = rs.raw.C_Sign(rs.sh, in_buf, len(bad_digest), None, byref(out_len))
            if rv == CKR_OK and out_len.value > 0:
                out_buf = (ctypes.c_ubyte * out_len.value)()
                rv = rs.raw.C_Sign(
                    rs.sh,
                    in_buf,
                    len(bad_digest),
                    out_buf,
                    byref(out_len),
                )

            classify_negative_rv(
                rv,
                (CKR_DATA_LEN_RANGE,),
                label="CKM_DSA wrong-length digest",
                kind="crypto",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_length_verify_digest(self, p11_module_session: Any) -> None:
        """Raw DSA verification with wrong-length digest should fail per spec."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            digest = hashlib.sha1(  # noqa: S324
                b"raw DSA verify length baseline",
                usedforsecurity=False,
            ).digest()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            bad_digest = b"\x00" * 7

            mech = mech_simple(CKM_DSA)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                return

            in_buf = (ctypes.c_ubyte * len(bad_digest))(*bad_digest)
            sig_buf = (ctypes.c_ubyte * len(sig))(*sig)
            rv = rs.raw.C_Verify(rs.sh, in_buf, len(bad_digest), sig_buf, len(sig))

            classify_negative_rv(
                rv,
                (CKR_DATA_LEN_RANGE,),
                label="CKM_DSA wrong-length verify digest",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)


@pytest.mark.slow
class TestDSAPrehash:
    """Tests for prehash DSA variants (SHA-1, SHA-224, SHA-384, SHA-512, SHA3-*)."""

    def _multipart_sign_verify_roundtrip(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            chunks = (
                b"DSA prehash multipart ",
                b"sign/verify ",
                b"test data",
            )
            sig = _dsa_sign_multipart_or_xfail(
                rs,
                priv,
                mechanism,
                chunks,
                f"CKM_{mech_name_str} multipart sign",
            )
            assert len(sig) > 0

            result = _dsa_verify_multipart_or_xfail(
                rs,
                pub,
                mechanism,
                chunks,
                sig,
                f"CKM_{mech_name_str} multipart verify",
            )
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def _wrong_signature_lengths_fail(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            data = b"DSA prehash wrong signature length"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 1

            for wrong_sig, label, case_name in (
                (
                    sig[:-1],
                    f"CKM_{mech_name_str} wrong-length signature",
                    "wrong-length",
                ),
                (
                    sig + b"\x00",
                    f"CKM_{mech_name_str} overlong signature",
                    "overlong",
                ),
            ):
                result = _dsa_invalid_verify_rejected_or_xfail(
                    rs,
                    pub,
                    mechanism,
                    data,
                    wrong_sig,
                    label,
                )
                if result is True:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label=f"CKM_{mech_name_str} {case_name} signature",
                        operation="C_Verify",
                        mechanism=f"CKM_{mech_name_str}",
                        summary=f"CKM_{mech_name_str} accepted {case_name} signature",
                    )
                assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_multipart_sign_verify_roundtrip(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA multipart sign and verify should roundtrip."""
        self._multipart_sign_verify_roundtrip(p11_module_session, mech_name_str, mechanism)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_sign_verify_roundtrip(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Sign and verify with a prehash DSA mechanism."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            data = b"DSA prehash sign/verify roundtrip test data"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 0

            result = _dsa_verify_or_xfail(rs, pub, mechanism, data, sig, f"CKM_{mech_name_str}")
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_tampered_data_fails(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA verification with tampered data must fail."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            data = b"original prehash data"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")

            tampered = b"tampered prehash data"
            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                mechanism,
                tampered,
                sig,
                f"CKM_{mech_name_str}",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_tampered_signature_fails(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA verification with tampered signature must fail."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            data = b"signature tamper test"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")

            # Flip a byte in the signature
            sig_arr = bytearray(sig)
            sig_arr[len(sig_arr) // 2] ^= 0xFF
            tampered_sig = bytes(sig_arr)

            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                mechanism,
                data,
                tampered_sig,
                f"CKM_{mech_name_str}",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_wrong_signature_lengths_fail(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA verification with wrong-length signatures must fail."""
        self._wrong_signature_lengths_fail(p11_module_session, mech_name_str, mechanism)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_empty_data(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA sign/verify with empty data should work (hash of empty)."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            data = b""
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 0

            result = _dsa_verify_or_xfail(rs, pub, mechanism, data, sig, f"CKM_{mech_name_str}")
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_large_data(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA sign/verify with large data (10 KiB)."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        keypair = _generate_dsa_keypair(rs)
        if keypair is None:
            return
        dp, pub, priv = keypair
        try:
            data = b"A" * 10240
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 0

            result = _dsa_verify_or_xfail(rs, pub, mechanism, data, sig, f"CKM_{mech_name_str}")
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)


@pytest.mark.slow
class TestDSAParameterGen:
    """Tests for DSA domain-parameter generation mechanisms."""

    def test_parameter_gen_rejects_missing_prime_bits(self, p11_module_session: Any) -> None:
        """CKM_DSA_PARAMETER_GEN requires CKA_PRIME_BITS in the template."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        tmpl = template(attr_bool(CKA_TOKEN, False))
        dp_handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_DSA_PARAMETER_GEN)
        try:
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(dp_handle),
            )
            classify_negative_rv(
                rv,
                _DSA_PARAMETER_TEMPLATE_REJECT_RVS,
                label="CKM_DSA_PARAMETER_GEN missing CKA_PRIME_BITS",
            )
        finally:
            if dp_handle.value:
                destroy_quietly(rs.raw, rs.sh, dp_handle.value)

    def test_parameter_gen(self, p11_module_session: Any) -> None:
        """Generate DSA domain parameters using CKM_DSA_PARAMETER_GEN."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        try:
            dp = _generate_dsa_params(rs.raw, rs.sh)
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            assert dp != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_probabilistic_parameter_gen_returns_pq(self, p11_module_session: Any) -> None:
        """CKM_DSA_PROBABILISTIC_PARAMETER_GEN generates p/q and returns a seed."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PROBABILISTIC_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PROBABILISTIC_PARAMETER_GEN not supported")

        try:
            dp, mech = _generate_dsa_pq_params(
                rs.raw,
                rs.sh,
                CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
            )
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            _assert_generated_dsa_pq_attrs(rs.raw, rs.sh, dp)
            assert len(_dsa_returned_seed(mech)) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_shawe_taylor_parameter_gen_returns_pq(self, p11_module_session: Any) -> None:
        """CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN generates p/q and returns a seed."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_SHAWE_TAYLOR_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN not supported")

        try:
            dp, mech = _generate_dsa_pq_params(
                rs.raw,
                rs.sh,
                CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
            )
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            _assert_generated_dsa_pq_attrs(rs.raw, rs.sh, dp)
            assert len(_dsa_returned_seed(mech)) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_fips_g_gen_uses_generated_seed_and_pq(self, p11_module_session: Any) -> None:
        """CKM_DSA_FIPS_G_GEN generates g from generated p/q plus returned seed."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_FIPS_G_GEN"):
            pytest.skip("CKM_DSA_FIPS_G_GEN not supported")
        if not rs.has_mechanism("DSA_PROBABILISTIC_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PROBABILISTIC_PARAMETER_GEN not supported for setup")

        try:
            dp, mech = _generate_dsa_pq_params(
                rs.raw,
                rs.sh,
                CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
            )
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            pq = _assert_generated_dsa_pq_attrs(rs.raw, rs.sh, dp)
            seed = _dsa_returned_seed(mech)
            if pq is None:
                return
            prime, subprime = pq
            try:
                base_dp = _generate_dsa_base_from_pq(
                    rs.raw,
                    rs.sh,
                    prime=prime,
                    subprime=subprime,
                    seed=seed,
                    index=1,
                )
            except AssertionError as e:
                _skip_or_xfail_dsa_param_gen_reject(e)

            try:
                attrs = read_attributes(rs.raw, rs.sh, base_dp, [CKA_BASE])
                base = attr_or_record(
                    attrs,
                    CKA_BASE,
                    label="DSA FIPS G gen: CKA_BASE readback",
                    reason="not_operational",
                    inherit_mechanism=False,
                )
                if base is not MISSING_ATTRIBUTE:
                    assert isinstance(base, bytes)
                    assert len(base) > 0
            finally:
                destroy_quietly(rs.raw, rs.sh, base_dp)
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_parameter_gen_and_keypair(self, p11_module_session: Any) -> None:
        """Generate DSA parameters, then use them for keypair generation."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        try:
            dp = _generate_dsa_params(rs.raw, rs.sh)
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            if not rs.has_mechanism("DSA_KEY_PAIR_GEN"):
                pytest.skip("CKM_DSA_KEY_PAIR_GEN not supported")
            try:
                keypair = _gen_dsa_keypair_from_params(rs.raw, rs.sh, dp)
            except AssertionError as e:
                _xfail_if_dsa_keypair_reject(e)
            if keypair is None:
                return
            pub, priv = keypair

            try:
                assert pub != 0
                assert priv != 0
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_parameter_gen_sign_verify(self, p11_module_session: Any) -> None:
        """Generate DSA params, keypair, then sign and verify."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        # Need a signing mechanism too
        has_raw = rs.has_mechanism("DSA")
        has_sha256 = rs.has_mechanism("DSA_SHA256")
        if not has_raw and not has_sha256:
            pytest.skip("No DSA signing mechanism available")

        try:
            dp = _generate_dsa_params(rs.raw, rs.sh)
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            if not rs.has_mechanism("DSA_KEY_PAIR_GEN"):
                pytest.skip("CKM_DSA_KEY_PAIR_GEN not supported")
            try:
                keypair = _gen_dsa_keypair_from_params(rs.raw, rs.sh, dp)
            except AssertionError as e:
                _xfail_if_dsa_keypair_reject(e)
            if keypair is None:
                return
            pub, priv = keypair

            try:
                if has_raw:
                    digest = hashlib.sha1(b"param gen sign test", usedforsecurity=False).digest()  # noqa: S324
                    sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
                    result = verify_single(rs.raw, rs.sh, pub, CKM_DSA, digest, sig)
                else:
                    data = b"param gen sign test"
                    sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA_SHA256, data)
                    result = verify_single(
                        rs.raw,
                        rs.sh,
                        pub,
                        CKM_DSA_SHA256,
                        data,
                        sig,
                    )
                assert result is True
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)


class TestDSABoundedWidth:
    """Even padded-half DSA rejection over a bounded fixed-vector fixture.

    QC5b (issue #57.2): NO slow mark -- this class runs in the ordinary
    selected profile (``-m "not slow"``) because it imports the fixed
    RFC 6979 DSA-2048 vector instead of generating parameters.

    SELECTION RECORD: overlong-DSA-signature coverage formerly existed ONLY
    as TestDSARaw::test_raw_dsa_overlong_signature_length_fails, which is
    slow-marked (DSA-2048 generation on its hot path) and therefore excluded
    from the ordinary profile. That node is RETAINED unchanged as the
    slow odd-length (``sig + b"\\x00"``) negative. The even padded-half case
    (zero bytes prepended to EACH half, equal halves, same scalars, even
    total length) is now selected as
    TestDSABoundedWidth::test_fixed_dsa_even_padded_halves_rejected[pad-1]
    and [pad-100]. Slow generation, truncation
    (test_raw_dsa_wrong_signature_length_fails) and the odd-length negative
    stay distinct nodes by design.
    """

    @pytest.mark.parametrize(
        "pad_len", [pytest.param(1, id="pad-1"), pytest.param(100, id="pad-100")]
    )
    def test_fixed_dsa_even_padded_halves_rejected(
        self, p11_module_session: Any, pad_len: int
    ) -> None:
        """Even zero-padded DSA halves must be rejected (issue #57.2).

        PKCS#11 v3.2 Table 59 (section 6.2.11) fixes the C_Verify signature
        length at 2x the subprime length (64 bytes here); the padded form is
        longer with unchanged scalars, so acceptance is an accepted_invalid
        crypto break -> fail, a clean signature reject -> pass, and a
        non-clean refusal -> xfail. The unpadded token signature is the
        control and must verify.
        """
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")
        skip_unless_create_object_supported(rs)

        try:
            pub, priv = _import_fixed_dsa_keypair(rs)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _DSA_IMPORT_RUNTIME_REJECT_RVS,
                "CKM_DSA advertised but fixed-vector DSA import is not operational",
            )
            raise
        try:
            self._assert_import_coherence(rs, pub)
            digest = hashlib.sha1(  # noqa: S324
                b"QC5b even padded-half stimulus", usedforsecurity=False
            ).digest()
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            except CkrAssertionError as exc:
                # A clean refusal produces no output -> not_operational xfail
                # (original RV preserved); it demonstrates no wrong signature.
                xfail_if_op_not_operational(exc, "CKM_DSA QC5b padded-half stimulus sign")
            # Premise: the stimulus must be a well-formed 64-byte raw
            # signature with scalars in range of the FIXED subprime; a
            # malformed token signature is itself a wrong_result finding.
            parse_raw_dss_or_classify(
                sig,
                half_len=_FIXED_DSA_HALF_LEN,
                order=_FIXED_DSA_Q_INT,
                label="CKM_DSA:sign QC5b padded-half stimulus",
                operation="C_Sign",
                mechanism="CKM_DSA",
            )
            try:
                control = verify_single(rs.raw, rs.sh, pub, CKM_DSA, digest, sig)
            except CkrAssertionError as exc:
                # A clean refusal of the control never evaluated it -> the
                # premise is unestablished, not_operational xfail (original RV
                # preserved). An evaluated rejection (False) below stays a
                # genuine verification contradiction -> fail.
                xfail_if_op_not_operational(exc, "CKM_DSA fixed-key fresh-signature control")
            assert_correct(
                actual=control,
                expected=True,
                label="CKM_DSA fixed-key fresh-signature control",
                operation="C_Verify",
                mechanism="CKM_DSA",
            )
            padded = (
                b"\x00" * pad_len
                + sig[:_FIXED_DSA_HALF_LEN]
                + b"\x00" * pad_len
                + sig[_FIXED_DSA_HALF_LEN:]
            )
            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                CKM_DSA,
                digest,
                padded,
                "CKM_DSA even padded-half signature",
            )
            if result is True:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="CKM_DSA even padded-half signature",
                    operation="C_Verify",
                    mechanism="CKM_DSA",
                    summary="CKM_DSA accepted an even zero-padded overlong signature",
                )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @staticmethod
    def _assert_import_coherence(rs: Any, pub: int) -> None:
        """Prove the imported public key carries exactly the fixed material."""
        try:
            attrs = read_attributes(
                rs.raw, rs.sh, pub, [CKA_PRIME, CKA_SUBPRIME, CKA_BASE, CKA_VALUE]
            )
        except CkrAssertionError as exc:
            if exc.rv in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
                xfail_as(
                    "not_operational",
                    kind="metadata",
                    label="CKM_DSA fixed-vector import coherence",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    actual=exc.rv,
                    summary=(
                        "Cannot read back the fixed DSA public key "
                        f"for the import-coherence check: {exc}"
                    ),
                )
            raise
        expected = (
            (CKA_PRIME, _FIXED_DSA_P),
            (CKA_SUBPRIME, _FIXED_DSA_Q),
            (CKA_BASE, _FIXED_DSA_G),
            (CKA_VALUE, _FIXED_DSA_Y),
        )
        # Validate EVERY present attribute BEFORE terminating for omissions: a
        # missing attribute must not hide a contradiction in a returned
        # sibling. Mismatch failures carry the missing-attribute evidence
        # alongside so the omission is not lost either.
        mismatched = [t for t, exp in expected if t in attrs and attrs[t] != exp]
        missing = [t for t, _exp in expected if t not in attrs]
        missing_evidence = [{"name": str(t), "id": int(t)} for t in missing]
        for attr_type in mismatched[:-1]:
            record_as(
                "wrong_result",
                kind="metadata",
                label="CKM_DSA fixed-vector import coherence",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                summary="Fixed DSA public-key attribute differs from the imported material",
                detail={
                    "attribute": {"name": str(attr_type), "id": int(attr_type)},
                    "missing_attributes": missing_evidence,
                },
            )
        if mismatched:
            attr_type = mismatched[-1]
            fail_as(
                "wrong_result",
                kind="metadata",
                label="CKM_DSA fixed-vector import coherence",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                summary="Fixed DSA public-key attribute differs from the imported material",
                detail={
                    "attribute": {"name": str(attr_type), "id": int(attr_type)},
                    "missing_attributes": missing_evidence,
                },
            )
        if missing:
            xfail_as(
                "not_operational",
                kind="metadata",
                label="CKM_DSA fixed-vector import coherence",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                summary=(
                    "Fixed DSA public-key attribute unavailable for the import-coherence check"
                ),
                detail={"missing_attributes": missing_evidence},
            )


def _stage_fixed_dsa_pair(
    rs: Any, *, label: str | None = None, copyable: bool | None = None
) -> tuple[int, int]:
    """Stage the fixed DSA pair for QC6a/QC6b and prove import coherence.

    Setup routing matches the QC5b bounded-width leg: a clean refusal of
    the (valid) fixed vector xfails with the original RV, and coherence
    of every present public attribute is established before any search
    or copy verdict consumes the staged handles. On any staging verdict
    both handles are destroyed before the outcome propagates.
    """
    if not rs.has_mechanism("DSA"):
        pytest.skip("CKM_DSA not supported")
    skip_unless_create_object_supported(rs)
    try:
        pub, priv = _import_fixed_dsa_keypair(rs, label=label, copyable=copyable)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _DSA_IMPORT_RUNTIME_REJECT_RVS,
            "CKM_DSA advertised but fixed-vector DSA import is not operational",
        )
        raise
    try:
        TestDSABoundedWidth._assert_import_coherence(rs, pub)
    except BaseException:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)
        raise
    return pub, priv


class TestDSAPublicValueSearch:
    """Exact public-value search over the fixed DSA vector (QC6a, #58.1).

    No slow mark: staging is the bounded fixed import, so the node runs
    in the ordinary selected profile like TestDSABoundedWidth.
    """

    def test_fixed_dsa_search_by_exact_public_value(self, p11_module_session: Any) -> None:
        """Search the fixed DSA public key by its independent known Y.

        Coherence proves the stored attributes equal the fixed material
        before searching, so the template value is the fixed Y itself --
        not a provider readback fed back to itself. The changed-Y control
        differs only in the last byte (stored bytes are searched
        verbatim; value encodings are QC7a's concern, not asserted here).
        """
        rs = p11_module_session
        search_label = f"pkcs11-check-qc6a-dsa-{uuid.uuid4().hex[:8]}"
        pub, priv = _stage_fixed_dsa_pair(rs, label=search_label)
        try:
            exact_template = {
                CKA_LABEL: search_label,
                CKA_CLASS: CKO_PUBLIC_KEY,
                CKA_KEY_TYPE: CKK_DSA,
                CKA_VALUE: _FIXED_DSA_Y,
            }
            changed_template = {
                **exact_template,
                CKA_VALUE: flip_last_byte(_FIXED_DSA_Y),
            }
            check_exact_and_changed_search(
                rs,
                exact_template=exact_template,
                changed_template=changed_template,
                expected_handle=pub,
                label="DSA exact public-value search",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# QC6b citation gate (pinned from the standard text, NOT copied from QC3's
# secret-material row): PKCS#11 v3.2 section 6.2.2, Table 56 (DSA Public
# Key Object Attributes) lists CKA_VALUE with footnotes 1,4 only -- no
# Table 13 footnote 8 ("May be modified after object is created with a
# C_SetAttributeValue call, or in the process of copying object with a
# C_CopyObject call"). Section 4.1.3 limits attributes modifiable during
# C_CopyObject to those described as modifiable (footnote 8) plus
# CKA_TOKEN / CKA_PRIVATE / CKA_MODIFIABLE / CKA_DESTROYABLE. A
# different-value CKA_VALUE copy of a DSA public key is therefore
# forbidden, so the different-value node below carries the normative
# two-tier oracle (refused -> pass; accepted+ignored -> xfail;
# accepted+mutated -> fail). Secret-material copy rows are settled by
# QC3a (TestCopyForbiddenMutation in test_keymgmt.py) and are not
# duplicated here; this is the DSA *public-value* slice of QC6b.
_DSA_PUBLIC_VALUE_COPY_CITATION = (
    "PKCS#11 v3.2 §6.2.2 Table 56: DSA public-key CKA_VALUE carries footnotes "
    "1,4 only (no Table 13 footnote 8 modifiable marker); §4.1.3 limits "
    "C_CopyObject template changes to modifiable attributes plus "
    "CKA_TOKEN/CKA_PRIVATE/CKA_MODIFIABLE/CKA_DESTROYABLE, so a "
    "different-value CKA_VALUE copy is forbidden"
)

_QC6B_DIGEST = hashlib.sha1(  # noqa: S324
    b"QC6b DSA public copy stimulus", usedforsecurity=False
).digest()


def _qc6b_baseline_signature(rs: Any, pub: int, priv: int, *, label: str) -> bytes:
    """Validated sign/verify baseline over the fixed pair (premise first)."""
    try:
        sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, _QC6B_DIGEST)
    except CkrAssertionError as exc:
        xfail_if_op_not_operational(exc, f"{label}: baseline sign")
    parse_raw_dss_or_classify(
        sig,
        half_len=_FIXED_DSA_HALF_LEN,
        order=_FIXED_DSA_Q_INT,
        label=f"{label}: baseline sign",
        operation="C_Sign",
        mechanism="CKM_DSA",
    )
    try:
        control = verify_single(rs.raw, rs.sh, pub, CKM_DSA, _QC6B_DIGEST, sig)
    except CkrAssertionError as exc:
        xfail_if_op_not_operational(exc, f"{label}: baseline verify")
    assert_correct(
        actual=control,
        expected=True,
        label=f"{label}: baseline verify under the original public key",
        operation="C_Verify",
        mechanism="CKM_DSA",
    )
    return sig


def _qc6b_unproved(label: str, detail: dict[str, Any], summary: str) -> NoReturn:
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation="C_CopyObject",
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=_DSA_PUBLIC_VALUE_COPY_CITATION,
        summary=summary,
        detail={"disposition": "unproved-effect", **detail},
    )


def _check_dsa_public_copy_different(
    rs: Any,
    copy: int,
    *,
    sig: bytes,
    changed: bytes,
    label: str,
) -> NoReturn:
    """Two-tier verdict for an accepted forbidden different-Y (QC6b).

    Both observations (material readback, verify-under-copy) complete
    before the verdict. Mutation FAILS only when proved independently:
    readback shows the changed value AND the copy no longer verifies a
    signature the original verifies. Readback-original plus
    verify-passes is ignored input (xfail); every mixed or missing
    observation is unproved-effect (xfail), never mutated or ignored.
    """
    attrs = read_qc3_attributes(
        rs,
        copy,
        [CKA_VALUE],
        label=label,
        premise=False,
        spec_ref=_DSA_PUBLIC_VALUE_COPY_CITATION,
    )
    readback = attr_or_record(
        attrs,
        CKA_VALUE,
        label=f"{label}: material readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    verifies: bool | None = None
    verify_rv: int | None = None
    try:
        verifies = verify_single(rs.raw, rs.sh, copy, CKM_DSA, _QC6B_DIGEST, sig)
    except CkrAssertionError as exc:
        verify_rv = exc.rv
    detail: dict[str, Any] = {
        "readback_present": readback is not MISSING_ATTRIBUTE,
        "verify_under_copy": verifies,
        "verify_under_original": True,
    }
    if verify_rv is not None:
        classify_rv_validity_or_none(
            verify_rv,
            label=f"{label}: verify under copy",
            operation="C_Verify",
            mechanism="CKM_DSA",
            kind="policy",
        )
        _qc6b_unproved(
            label,
            {**detail, "verify_rv": ckr_name(verify_rv)},
            f"{label}: accepted but verify under copy refused with "
            f"{ckr_name(verify_rv)}; effect unproved",
        )
    if readback is MISSING_ATTRIBUTE:
        _qc6b_unproved(
            label,
            detail,
            f"{label}: accepted but the copy's public value is unavailable; effect unproved",
        )
    value = validate_qc3_shape(
        readback,
        "value",
        attr_name="CKA_VALUE",
        label=label,
        premise=False,
        spec_ref=_DSA_PUBLIC_VALUE_COPY_CITATION,
        expected_len=len(_FIXED_DSA_Y),
    )
    detail["readback_matches_original"] = value == _FIXED_DSA_Y
    detail["readback_matches_changed"] = value == changed
    if detail["readback_matches_original"] and verifies:
        classify_ignored_or_mutated(
            mutated=False,
            label=label,
            operation="C_CopyObject",
            spec_ref=_DSA_PUBLIC_VALUE_COPY_CITATION,
            ignored_summary=(
                f"{label}: different-value copy accepted but the copy keeps "
                "the original public value and still verifies (input ignored)"
            ),
            mutated_summary=f"{label}: different-value copy changed the public value",
            detail={**detail, "disposition": "ignored-input"},
        )
    if detail["readback_matches_changed"] and not verifies:
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation="C_CopyObject",
            spec_ref=_DSA_PUBLIC_VALUE_COPY_CITATION,
            ignored_summary=f"{label}: different-value copy ignored",
            mutated_summary=(
                f"{label}: different-value copy applied the forbidden new "
                "public value (readback changed and verification flipped)"
            ),
            detail={**detail, "disposition": "mutated"},
        )
    _qc6b_unproved(
        label,
        detail,
        f"{label}: accepted with mixed readback/verify evidence; effect unproved",
    )


class TestDSAPublicCopyObservations:
    """DSA public-value copy rows (QC6b, #58.3): empty / unchanged / different.

    Empty-template and unchanged-value copies are separate compatibility
    observations (noted, never cross-compared by RV); only the
    different-value row carries the normative oracle pinned by
    _DSA_PUBLIC_VALUE_COPY_CITATION. The source requests CKA_COPYABLE
    explicitly, so a staging refusal is a setup outcome, never a copy
    verdict. Secret-material rows live in QC3a and are not duplicated.
    """

    def _observe_public_copy(
        self, rs: Any, pub: int, priv: int, template: dict[Any, Any], *, leg: str
    ) -> None:
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, _QC6B_DIGEST)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(
                exc.rv, label=f"{leg} copy", operation="C_Sign", mechanism="CKM_DSA"
            )
            note(
                f"{leg} DSA public copy: baseline sign refused with "
                f"{ckr_name(exc.rv)}; copy not attempted",
                ComplianceLevel.STANDARD,
                reference="QC6b #58.3 compatibility observation",
            )
            return
        try:
            copy = copy_object(rs.raw, rs.sh, pub, template)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(exc.rv, label=f"{leg} copy", operation="C_CopyObject")
            note(
                f"{leg} DSA public copy refused with {ckr_name(exc.rv)} (no material to compare)",
                ComplianceLevel.STANDARD,
                reference="QC6b #58.3 compatibility observation",
            )
            return
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, copy, [CKA_VALUE])
            except CkrAssertionError as exc:
                classify_rv_validity_or_none(
                    exc.rv,
                    label=f"{leg} copy readback",
                    operation="C_GetAttributeValue",
                )
                material = f"copy readback refused with {ckr_name(exc.rv)}"
            else:
                readback = attr_or_record(
                    attrs,
                    CKA_VALUE,
                    label=f"{leg} DSA public copy: material readback",
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                if readback is MISSING_ATTRIBUTE:
                    material = "copy material unavailable (CKA_VALUE missing)"
                else:
                    material = (
                        f"copy material matches the fixed public value: {readback == _FIXED_DSA_Y}"
                    )
            try:
                verified = verify_single(rs.raw, rs.sh, copy, CKM_DSA, _QC6B_DIGEST, sig)
            except CkrAssertionError as exc:
                classify_rv_validity_or_none(
                    exc.rv,
                    label=f"{leg} copy use observation",
                    operation="C_Verify",
                    mechanism="CKM_DSA",
                )
                behavior = f"verify under copy refused with {ckr_name(exc.rv)}"
            else:
                behavior = f"verify under copy: {verified}"
            note(
                f"{leg} DSA public copy accepted (CKR_OK); {material}; {behavior}",
                ComplianceLevel.STANDARD,
                reference="QC6b #58.3 compatibility observation",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, copy)

    def test_fixed_dsa_public_copy_empty_template_observation(
        self, p11_module_session: Any
    ) -> None:
        """Compatibility observation: DSA public copy with an empty template."""
        rs = p11_module_session
        pub, priv = _stage_fixed_dsa_pair(rs, copyable=True)
        try:
            self._observe_public_copy(rs, pub, priv, {}, leg="empty-template")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_fixed_dsa_public_copy_unchanged_value_observation(
        self, p11_module_session: Any
    ) -> None:
        """Compatibility observation: copy restating the same public value.

        Separate from the empty-template row; its RV is never compared
        with that node's (unchanged input need not behave like omission).
        """
        rs = p11_module_session
        pub, priv = _stage_fixed_dsa_pair(rs, copyable=True)
        try:
            self._observe_public_copy(
                rs, pub, priv, {CKA_VALUE: _FIXED_DSA_Y}, leg="unchanged-value"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_fixed_dsa_public_copy_different_value_ignored_or_refused(
        self, p11_module_session: Any
    ) -> None:
        """Copy with a different DSA public value must refuse or ignore it."""
        rs = p11_module_session
        label = "C_CopyObject DSA public CKA_VALUE different-value (QC6b)"
        pub, priv = _stage_fixed_dsa_pair(rs, copyable=True)
        try:
            sig = _qc6b_baseline_signature(rs, pub, priv, label=label)
            changed = flip_last_byte(_FIXED_DSA_Y)
            try:
                copy = copy_object(rs.raw, rs.sh, pub, {CKA_VALUE: changed})
            except CkrAssertionError as exc:
                classify_forbidden_change_refusal(
                    exc,
                    COPY_FORBIDDEN_REFUSE_RVS,
                    label=label,
                    operation="C_CopyObject",
                )
                return
            try:
                _check_dsa_public_copy_different(rs, copy, sig=sig, changed=changed, label=label)
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
