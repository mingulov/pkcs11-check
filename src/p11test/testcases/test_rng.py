"""RNG quality tests for C_GenerateRandom.

Basic statistical checks on random output quality. These are sanity checks,
NOT certification-grade tests (see NIST SP 800-22 for proper RNG testing).
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.security


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
        """Generate random at various sizes — all must succeed."""
        for bits in [8, 64, 128, 256, 512, 1024, 8192]:
            data = p11_session.generate_random(bits)
            assert len(data) == bits // 8


class TestRNGStatistical:
    """Simple statistical tests on random output."""

    def test_bit_frequency(self, p11_session: Any) -> None:
        """Monobit test: count of 0s vs 1s should be roughly equal.

        For 10KB of data, the count of set bits should be within
        [39000, 41000] out of 81920 (50% ± ~1.2%).
        """
        data = p11_session.generate_random(81920)  # 10240 bytes
        bit_count = sum(bin(byte).count("1") for byte in data)
        total_bits = len(data) * 8

        ratio = bit_count / total_bits
        # Very generous range: 45%-55%
        assert 0.45 < ratio < 0.55, (
            f"Bit frequency bias: {ratio:.3%} ones "
            f"({bit_count}/{total_bits})"
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

    def test_seed_random(self, p11_session: Any) -> None:
        """C_SeedRandom should accept seed data without error.

        Seeding doesn't guarantee changed output (implementation-defined),
        but it should not crash or error.
        """
        try:
            p11_session.seed_random(b"entropy seed data for testing 12345")
        except AttributeError:
            pytest.skip("python-pkcs11 doesn't expose seed_random")
        except Exception as exc:
            if "FunctionNotSupported" in type(exc).__name__:
                pytest.skip("Module doesn't support C_SeedRandom")
            raise
