"""PKCS#11 performance benchmarks.

Measures throughput of core cryptographic operations using pytest-benchmark.
Run with: pytest test_benchmark.py --benchmark-enable --benchmark-only
"""

from __future__ import annotations

import hashlib
from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.benchmark


@pytest.fixture()
def aes256_key(p11_session: Any) -> Any:
    """Generate a reusable AES-256 key for benchmarks."""
    return p11_session.generate_key(
        KeyType.AES,
        256,
        template={
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: False,
        },
    )


@pytest.fixture()
def rsa2048_keypair(p11_session: Any) -> tuple[Any, Any]:
    """Generate a reusable RSA-2048 keypair for benchmarks."""
    pub, priv = p11_session.generate_keypair(
        KeyType.RSA,
        2048,
        public_template={Attribute.VERIFY: True, Attribute.TOKEN: False},
        private_template={Attribute.SIGN: True, Attribute.TOKEN: False},
    )
    return pub, priv


@pytest.fixture()
def ec_p256_keypair(p11_session: Any) -> tuple[Any, Any]:
    """Generate a reusable EC P-256 keypair for benchmarks."""
    params = pkcs11.util.ec.encode_named_curve_parameters("secp256r1")
    pub, priv = p11_session.generate_keypair(
        KeyType.EC,
        key_length=None,
        public_template={
            Attribute.EC_PARAMS: params,
            Attribute.VERIFY: True,
            Attribute.TOKEN: False,
        },
        private_template={Attribute.SIGN: True, Attribute.TOKEN: False},
    )
    return pub, priv


def test_bench_aes256_cbc_encrypt(benchmark: Any, p11_session: Any) -> None:
    """Benchmark AES-256-CBC encryption (1 KiB, block-aligned)."""
    import pkcs11 as p11

    data = b"\x00" * 1024  # 1024 bytes = 64 AES blocks, no padding needed
    key = p11_session.generate_key(KeyType.AES, 256)
    iv = p11_session.generate_random(16)

    # Verify mechanism works before benchmarking
    try:
        key.encrypt(data, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
    except p11.exceptions.PKCS11Error:
        pytest.skip("AES_CBC not available for benchmarking")

    def encrypt() -> bytes:
        return key.encrypt(  # type: ignore[no-any-return]
            data, mechanism=Mechanism.AES_CBC, mechanism_param=iv
        )

    benchmark(encrypt)


def test_bench_aes256_ecb_encrypt(benchmark: Any, p11_session: Any) -> None:
    """Benchmark AES-256-ECB encryption (1 KiB block)."""
    data = b"\x00" * 1024
    key = p11_session.generate_key(KeyType.AES, 256)

    def encrypt() -> bytes:
        return key.encrypt(data, mechanism=Mechanism.AES_ECB)  # type: ignore[no-any-return]

    benchmark(encrypt)


def test_bench_rsa2048_sign(benchmark: Any, rsa2048_keypair: Any) -> None:
    """Benchmark RSA-2048 SHA-256 signing."""
    _, priv = rsa2048_keypair
    data = b"benchmark test data for RSA signing"

    def sign() -> bytes:
        return priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)  # type: ignore[no-any-return]

    benchmark(sign)


def test_bench_rsa2048_verify(benchmark: Any, rsa2048_keypair: Any) -> None:
    """Benchmark RSA-2048 SHA-256 verification."""
    pub, priv = rsa2048_keypair
    data = b"benchmark test data for RSA signing"
    sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

    def verify() -> None:
        pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)

    benchmark(verify)


def test_bench_ecdsa_p256_sign(benchmark: Any, ec_p256_keypair: Any) -> None:
    """Benchmark ECDSA P-256 signing."""
    _, priv = ec_p256_keypair
    digest = hashlib.sha256(b"benchmark test data").digest()

    def sign() -> bytes:
        return priv.sign(digest, mechanism=Mechanism.ECDSA)  # type: ignore[no-any-return]

    benchmark(sign)


def test_bench_sha256_digest(benchmark: Any, p11_session: Any) -> None:
    """Benchmark SHA-256 digest (1 KiB)."""
    data = b"\x00" * 1024

    def digest() -> bytes:
        return p11_session.digest(data, mechanism=Mechanism.SHA256)  # type: ignore[no-any-return]

    benchmark(digest)


def test_bench_rng(benchmark: Any, p11_session: Any) -> None:
    """Benchmark random number generation (256 bytes)."""

    def generate() -> bytes:
        return p11_session.generate_random(256)  # type: ignore[no-any-return]

    benchmark(generate)


def test_bench_aes_keygen(benchmark: Any, p11_session: Any) -> None:
    """Benchmark AES-256 key generation."""

    def keygen() -> Any:
        return p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: True,
                Attribute.TOKEN: False,
            },
        )

    benchmark(keygen)
