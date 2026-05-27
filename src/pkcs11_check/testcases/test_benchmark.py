"""PKCS#11 performance benchmarks.

Measures throughput of core cryptographic operations using pytest-benchmark.
Run with: pytest test_benchmark.py --benchmark-enable --benchmark-only
"""

from __future__ import annotations

import hashlib
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    generate_random,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_ECDSA,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.benchmark

_AES_KEYGEN_RUNTIME_ERROR_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_BENCHMARK_OPERATION_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)


def _xfail_aes_keygen_reject(exc: AssertionError, msg: str) -> NoReturn:
    xfail_if_known_ckr(exc, _AES_KEYGEN_RUNTIME_ERROR_CKRS, msg)
    raise exc


def _xfail_benchmark_operation_reject(exc: AssertionError, msg: str) -> NoReturn:
    xfail_if_known_ckr(exc, _BENCHMARK_OPERATION_REJECT_CKRS, msg)
    raise exc


@pytest.fixture()
def aes256_key(p11_raw_session: Any) -> Any:
    """Generate a reusable AES-256 key for benchmarks."""
    rs = p11_raw_session
    key = gen_aes_key(rs.raw, rs.sh, 256)
    yield key, rs
    destroy_quietly(rs.raw, rs.sh, key)


@pytest.fixture()
def rsa2048_keypair(p11_raw_session: Any) -> Any:
    """Generate a reusable RSA-2048 keypair for benchmarks."""
    rs = p11_raw_session
    if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
        pytest.skip("RSA key pair generation not supported")
    pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
    yield pub, priv, rs
    destroy_quietly(rs.raw, rs.sh, pub)
    destroy_quietly(rs.raw, rs.sh, priv)


@pytest.fixture()
def ec_p256_keypair(p11_raw_session: Any) -> Any:
    """Generate a reusable EC P-256 keypair for benchmarks."""
    rs = p11_raw_session
    if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
        pytest.skip("EC key pair generation not supported")
    pub, priv = gen_ec_keypair_or_xfail(rs, encode_named_curve_parameters("secp256r1"))
    yield pub, priv, rs
    destroy_quietly(rs.raw, rs.sh, pub)
    destroy_quietly(rs.raw, rs.sh, priv)


def test_bench_aes256_cbc_encrypt(benchmark: Any, p11_raw_session: Any) -> None:
    """Benchmark AES-256-CBC encryption (1 KiB, block-aligned)."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES key generation not supported")
    data = b"\x00" * 1024  # 1024 bytes = 64 AES blocks, no padding needed
    try:
        key = gen_aes_key(rs.raw, rs.sh, 256)
    except AssertionError as e:
        _xfail_aes_keygen_reject(e, "CKM_AES_KEY_GEN advertised but AES-256 keygen rejected")
    iv = generate_random(rs.raw, rs.sh, 16)

    # Verify mechanism works before benchmarking
    try:
        encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CBC,
            data,
            mech_param=mech_bytes(CKM_AES_CBC, iv),
        )
    except AssertionError as exc:
        destroy_quietly(rs.raw, rs.sh, key)
        _xfail_benchmark_operation_reject(exc, "AES_CBC benchmark probe rejected")

    def encrypt() -> bytes:
        return encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CBC,
            data,
            mech_param=mech_bytes(CKM_AES_CBC, iv),
        )

    benchmark(encrypt)
    destroy_quietly(rs.raw, rs.sh, key)


def test_bench_aes256_ecb_encrypt(benchmark: Any, p11_raw_session: Any) -> None:
    """Benchmark AES-256-ECB encryption (1 KiB block)."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES key generation not supported")
    data = b"\x00" * 1024
    try:
        key = gen_aes_key(rs.raw, rs.sh, 256)
    except AssertionError as e:
        _xfail_aes_keygen_reject(e, "CKM_AES_KEY_GEN advertised but AES-256 keygen rejected")

    def encrypt() -> bytes:
        return encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)

    benchmark(encrypt)
    destroy_quietly(rs.raw, rs.sh, key)


def test_bench_rsa2048_sign(benchmark: Any, rsa2048_keypair: Any) -> None:
    """Benchmark RSA-2048 SHA-256 signing."""
    pub, priv, rs = rsa2048_keypair
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("SHA256_RSA_PKCS not supported")
    data = b"benchmark test data for RSA signing"

    def sign() -> bytes:
        try:
            return sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
        except AssertionError as exc:
            _xfail_benchmark_operation_reject(exc, "RSA SHA256 benchmark sign rejected")

    benchmark(sign)


def test_bench_rsa2048_verify(benchmark: Any, rsa2048_keypair: Any) -> None:
    """Benchmark RSA-2048 SHA-256 verification."""
    pub, priv, rs = rsa2048_keypair
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("SHA256_RSA_PKCS not supported")
    data = b"benchmark test data for RSA signing"
    try:
        sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
    except AssertionError as exc:
        _xfail_benchmark_operation_reject(exc, "RSA SHA256 benchmark verify setup sign rejected")

    def verify() -> None:
        try:
            verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        except AssertionError as exc:
            _xfail_benchmark_operation_reject(exc, "RSA SHA256 benchmark verify rejected")

    benchmark(verify)


def test_bench_ecdsa_p256_sign(benchmark: Any, ec_p256_keypair: Any) -> None:
    """Benchmark ECDSA P-256 signing."""
    pub, priv, rs = ec_p256_keypair
    digest = hashlib.sha256(b"benchmark test data").digest()

    def sign() -> bytes:
        return sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)

    benchmark(sign)


def test_bench_sha256_digest(benchmark: Any, p11_raw_session: Any) -> None:
    """Benchmark SHA-256 digest (1 KiB)."""
    rs = p11_raw_session
    if not rs.has_mechanism("SHA256"):
        pytest.skip("SHA256 not supported")
    data = b"\x00" * 1024

    def digest() -> bytes:
        try:
            return digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        except AssertionError as exc:
            _xfail_benchmark_operation_reject(exc, "SHA256 benchmark digest rejected")

    benchmark(digest)


def test_bench_rng(benchmark: Any, p11_raw_session: Any) -> None:
    """Benchmark random number generation (256 bytes)."""
    rs = p11_raw_session

    def generate() -> bytes:
        return generate_random(rs.raw, rs.sh, 256)

    benchmark(generate)


def test_bench_aes_keygen(benchmark: Any, p11_raw_session: Any) -> None:
    """Benchmark AES-256 key generation."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES key generation not supported")

    # Probe: verify key generation works at all
    try:
        probe = gen_aes_key(rs.raw, rs.sh, 256)
        destroy_quietly(rs.raw, rs.sh, probe)
    except AssertionError as e:
        _xfail_aes_keygen_reject(e, "CKM_AES_KEY_GEN advertised but keygen is not operational")

    def keygen() -> None:
        key = gen_aes_key(rs.raw, rs.sh, 256)
        destroy_quietly(rs.raw, rs.sh, key)

    benchmark(keygen)
