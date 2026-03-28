"""pytest marker definitions for pkcs11-check."""

from __future__ import annotations

from dataclasses import dataclass

_VERSION_ORDER = {"2.40": 0, "3.0": 1, "3.1": 2, "3.2": 3}

_MARKER_MIN_VERSION: dict[str, str] = {
    "requires_v30": "3.0",
    "requires_v32": "3.2",
}


@dataclass(frozen=True)
class MarkerDef:
    """A pytest marker registered by pkcs11-check."""

    name: str
    description: str


MARKER_DEFINITIONS: list[MarkerDef] = [
    MarkerDef("access", "Attribute enforcement, session type, and access-control tests"),
    MarkerDef("acvp", "NIST ACVP known-answer test vector"),
    MarkerDef("benchmark", "Performance benchmark test"),
    MarkerDef("boundary", "Boundary-condition test"),
    MarkerDef("cctv", "CCTV (C2SP) edge-case test vector"),
    MarkerDef("crossverify", "Cross-verification test against an independent implementation"),
    MarkerDef("requires_v30", "Test requires PKCS#11 v3.0 or later"),
    MarkerDef("requires_v32", "Test requires PKCS#11 v3.2 or later"),
    MarkerDef("destructive", "Test modifies token state (requires --p11-destructive)"),
    MarkerDef("differential", "Cross-backend differential test"),
    MarkerDef("encrypt", "Encryption and decryption mechanism test"),
    MarkerDef("fault", "Fault-injection or crash-survival test"),
    MarkerDef("fips", "FIPS-relevant test subset"),
    MarkerDef("fips186_4_legacy", "Legacy compatibility test using FIPS 186-4-era vectors"),
    MarkerDef("full", "Full correctness profile"),
    MarkerDef("fuzz", "Fuzz or property-based test"),
    MarkerDef("hardware", "Safe for real hardware HSMs"),
    MarkerDef("hardware_only", "Requires real hardware or a hardware-specific feature"),
    MarkerDef("interop", "Interoperability or malformed-input corpus test"),
    MarkerDef("kat", "Known-answer test vector"),
    MarkerDef("keymgmt", "Key management test"),
    MarkerDef("lab", "Lab profile including expensive or invasive tests"),
    MarkerDef("mechflags", "Mechanism flags validation test"),
    MarkerDef("metamorphic", "Metamorphic relation test"),
    MarkerDef("multipart", "Multi-part or dual-function operation test"),
    MarkerDef("operation_state", "C_GetOperationState / C_SetOperationState test"),
    MarkerDef("pqc", "Post-quantum cryptography test"),
    MarkerDef("nonce_quality", "ECDSA/DSA nonce quality or reuse analysis"),
    MarkerDef("padding_oracle", "Padding-oracle detection test"),
    MarkerDef("protocol", "Protocol integration test"),
    MarkerDef("regressions", "Regression test for a known issue or CVE"),
    MarkerDef("search", "Object search and enumeration test"),
    MarkerDef("security", "Security attack-vector test"),
    MarkerDef("sign", "Signing or signature-verification mechanism test"),
    MarkerDef("smoke", "Quick smoke profile"),
    MarkerDef("slow", "Long-running test"),
    MarkerDef("needs_mechanism", "Test needs a specific PKCS#11 mechanism"),
    MarkerDef("stateful", "State-machine or stateful property test"),
    MarkerDef("stress", "Concurrency, resource, or longevity stress test"),
    MarkerDef("subprocess", "Test always runs in isolated subprocess (crash-prone operations)"),
    MarkerDef("subprocess_per_test", "Each test in file runs in its own subprocess"),
    MarkerDef("surface_audit", "API surface audit or hidden-capability probe"),
    MarkerDef("thread_safe", "Test requires --p11-thread-safe (concurrent same-session ops)"),
    MarkerDef("timing", "Timing side-channel or timing-behavior test"),
    MarkerDef("v30", "PKCS#11 v3.0-specific test"),
    MarkerDef("v32", "PKCS#11 v3.2-specific test"),
    MarkerDef("vendor", "Vendor-specific extension or mechanism test"),
    MarkerDef("cert", "X.509 certificate operation test"),
    MarkerDef("object", "Generic PKCS#11 object operation test"),
    MarkerDef("compliance", "PKCS#11 standard or profile compliance verification"),
    MarkerDef("wycheproof", "Wycheproof edge-case vector test"),
    MarkerDef("mechanism_coverage", "Mechanism-driven parametrized test"),
    MarkerDef("negative", "Negative test (wrong key type, invalid params, missing perms)"),
    MarkerDef("lifecycle", "Composite multi-step workflow test"),
    MarkerDef("keygen", "Key generation test"),
    MarkerDef("wrap", "Key wrap/unwrap test"),
    MarkerDef("derive", "Key derivation test"),
    MarkerDef("kem", "Key encapsulation/decapsulation test"),
    MarkerDef("sign_recover", "Sign-recover/verify-recover test"),
    MarkerDef("message_based", "v3.0 message-based operation test"),
    MarkerDef("state_machine", "Operation state machine violation test"),
    MarkerDef("flag_validation", "CKF_* flag correctness test"),
    MarkerDef("digest", "Digest/hash mechanism test"),
]


def should_skip_for_version(marker_name: str, interface_version: str) -> bool:
    """Return True if a test with this marker should be skipped for the given version."""
    min_version = _MARKER_MIN_VERSION.get(marker_name)
    if min_version is None:
        return False
    return _VERSION_ORDER.get(interface_version, 0) < _VERSION_ORDER[min_version]
