"""Shared fixtures and helpers for pkcs11-check PKCS#11 test cases.

Note: Static skips such as missing-module and destructive gating are handled in
plugin.py collection hooks. Dynamic version/mechanism skips are handled from the
collection-safe capability manifest before test setup.
"""

from __future__ import annotations

from typing import Any


def get_pin_bytes(p11_config: Any) -> bytes | None:
    """Extract PIN as bytes from config, or None if no PIN configured."""
    if p11_config.pin is None:
        return None
    pin = p11_config.pin
    pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
    return pin_str.encode("utf-8")


def extract_ec_point(ec_point_der: Any) -> Any:
    """Extract raw uncompressed EC point from DER OCTET STRING wrapper.

    PKCS#11 EC_POINT attribute is DER-encoded: 0x04 <length> <point_bytes>.
    Returns the raw point bytes (starting with 0x04 uncompressed prefix).
    """
    from pkcs11_check.raw.der import decode_ec_point

    data = bytes(ec_point_der)
    if not data or data[0] != 0x04:
        return ec_point_der  # not DER-wrapped, return as-is
    return decode_ec_point(data)
