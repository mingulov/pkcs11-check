"""RNG quality tests for C_GenerateRandom.

Basic statistical checks on random output quality. These are sanity checks,
NOT certification-grade tests (see NIST SP 800-22 for proper RNG testing).
Includes Shannon entropy estimation and runs test.
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from pkcs11_check.testcases.conftest import skip_unless_generate_random_supported

pytestmark = pytest.mark.security


@pytest.fixture(autouse=True)
def _skip_if_rng_not_operational(p11_session: Any) -> None:
    """Skip every RNG test when C_GenerateRandom is advertised-but-not-operational.

    some modules return CKR_FUNCTION_FAILED; some proxies return
    CKR_FUNCTION_NOT_SUPPORTED. Probing once avoids cascading the rejection
    into every statistical check.
    """
    skip_unless_generate_random_supported(p11_session)


class TestRNGBasic:
    """Basic random number generation quality checks."""

    def test_nonzero_output(self, p11_session: Any) -> None:
        """1KB of random data should not be all zeros."""
        data = p11_session.generate_random(8192)  # 1024 bytes
        assert data != bytes(1024)

    def test_nonzero_small(self, p11_session: Any) -> None:
        """Even 8 bytes should not be all zeros."""
        data = p11_session.generate_random(64)  # 8 bytes
        assert data != bytes(8)

    def test_non_repeating(self, p11_session: Any) -> None:
        """1000 x 32-byte generations should all be unique."""
        samples = set()
        for _ in range(1000):
            data = p11_session.generate_random(256)  # 32 bytes
            samples.add(data)
        assert len(samples) == 1000, "RNG produced duplicate 32-byte values"

    def test_different_lengths(self, p11_session: Any) -> None:
        """Generate random at various sizes - all must succeed."""
        for bits in [8, 64, 128, 256, 512, 1024, 8192]:
            data = p11_session.generate_random(bits)
            assert len(data) == bits // 8


class TestRNGStatistical:
    """Simple statistical tests on random output."""

    def test_bit_frequency(self, p11_session: Any) -> None:
        """Monobit test: count of 0s vs 1s should be roughly equal.

        For 10KB of data, the count of set bits should be within
        [39000, 41000] out of 81920 (50% +/- ~1.2%).
        """
        data = p11_session.generate_random(81920)  # 10240 bytes
        bit_count = sum(bin(byte).count("1") for byte in data)
        total_bits = len(data) * 8

        ratio = bit_count / total_bits
        # Very generous range: 45%-55%
        assert 0.45 < ratio < 0.55, (
            f"Bit frequency bias: {ratio:.3%} ones ({bit_count}/{total_bits})"
        )

    def test_byte_distribution(self, p11_session: Any) -> None:
        """Chi-squared-like test: byte values should be roughly uniform.

        For 10KB of data, each byte value should appear ~40 times (10240/256).
        Flag if any value appears more than 3x expected.
        """
        data = p11_session.generate_random(81920)  # 10240 bytes
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1

        expected = len(data) / 256
        max_count = max(counts)
        min_count = min(counts)

        # No byte should appear >3x or <0.2x the expected frequency
        assert max_count < expected * 3, (
            f"Byte 0x{counts.index(max_count):02x} appears {max_count} times "
            f"(expected ~{expected:.0f})"
        )
        assert min_count > expected * 0.2, (
            f"Byte 0x{counts.index(min_count):02x} appears {min_count} times "
            f"(expected ~{expected:.0f})"
        )

    def test_shannon_entropy(self, p11_session: Any) -> None:
        """Shannon entropy of random bytes should be close to 8.0 bits/byte.

        For truly random data, Shannon entropy = log2(256) = 8.0.
        We allow down to 7.9 bits/byte (very conservative threshold).
        """
        data = p11_session.generate_random(81920)  # 10240 bytes
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1

        total = len(data)
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        assert entropy > 7.9, (
            f"Shannon entropy too low: {entropy:.4f} bits/byte (expected ~8.0 for random data)"
        )

    def test_runs_test(self, p11_session: Any) -> None:
        """Runs test: count transitions between 0 and 1 bits.

        For random data, the number of runs should be roughly half
        the total bits. A very low or high run count suggests patterns.
        """
        data = p11_session.generate_random(8192)  # 1024 bytes
        total_bits = len(data) * 8

        # Count runs (transitions between 0 and 1)
        runs = 1
        prev_bit = data[0] >> 7
        for byte in data:
            for bit_pos in range(7, -1, -1):
                current_bit = (byte >> bit_pos) & 1
                if current_bit != prev_bit:
                    runs += 1
                prev_bit = current_bit

        # For random data, expected runs ~ total_bits/2
        expected_runs = total_bits / 2
        ratio = runs / expected_runs
        assert 0.9 < ratio < 1.1, (
            f"Runs test: {runs} runs (expected ~{expected_runs:.0f}), ratio={ratio:.3f}"
        )

    def test_seed_random(self, p11_session: Any) -> None:
        """C_SeedRandom should accept seed data without error.

        Seeding doesn't guarantee changed output (implementation-defined),
        but it should not crash or error.
        """
        from pkcs11_check.raw.types_std import (
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_OK,
            CKR_RANDOM_SEED_NOT_SUPPORTED,
        )

        skip_rvs = (CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_FUNCTION_NOT_SUPPORTED)
        rv = p11_session.seed_random(b"entropy seed data for testing 12345", extra_ok=skip_rvs)
        if rv in skip_rvs:
            pytest.skip(f"C_SeedRandom not supported ({rv:#x})")
        assert rv == CKR_OK
